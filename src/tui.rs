use crate::report::ReportMode;
use crate::session::AgentSession;
use crate::ui::{AgentEventPayload, ApprovalRequest, SpecialistKind, SpecialistUpdate, UiEvent};
use anyhow::Result;
use crossterm::{
    event::{Event, EventStream, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::StreamExt;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, Paragraph, Tabs, Wrap},
    Frame, Terminal,
};
use rig::message::Message;
use sqlx::SqlitePool;
use std::{io, sync::Arc};
use tokio::sync::mpsc;

const PANE_MIN: u16 = 20;
const PANE_MAX: u16 = 80;
const TAB_COUNT: usize = 4; // ALL + one per specialist
const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

// ── Types ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Focus {
    Input,
    Conv,
    Tool,
}

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Idle,
    Thinking,
}

#[derive(Clone, PartialEq)]
enum Role {
    User,
    Agent,
    Error,
}

#[derive(Clone)]
struct ChatMsg {
    role: Role,
    text: String,
}

enum Cmd {
    None,
    Quit,
    Submit,
}

/// A scrollable log buffer with follow-bottom behavior.
struct LogPane {
    lines: Vec<String>,
    scroll: u16,
    auto_scroll: bool,
}

impl LogPane {
    fn new() -> Self {
        Self {
            lines: Vec::new(),
            scroll: 0,
            auto_scroll: true,
        }
    }

    fn push(&mut self, line: String) {
        self.lines.push(line);
        if self.auto_scroll {
            self.scroll = u16::MAX;
        }
    }
}

enum SpecStatus {
    Idle,
    Running(String), // current stage text
}

/// One specialist sub-tab: its log pane plus live status for badges.
struct SpecialistTab {
    kind: SpecialistKind,
    pane: LogPane,
    status: SpecStatus,
    done: usize,
    failed: usize,
}

impl SpecialistTab {
    fn new(kind: SpecialistKind) -> Self {
        Self {
            kind,
            pane: LogPane::new(),
            status: SpecStatus::Idle,
            done: 0,
            failed: 0,
        }
    }
}

fn spec_idx(kind: SpecialistKind) -> usize {
    match kind {
        SpecialistKind::Image => 0,
        SpecialistKind::Audio => 1,
        SpecialistKind::Sqlite => 2,
    }
}

fn log_line_style(line: &str) -> Style {
    match line.chars().next() {
        Some('▶') => Style::default().fg(Color::Cyan),
        Some('✓') => Style::default().fg(Color::Green),
        Some('✗') => Style::default().fg(Color::Red),
        _ => Style::default().fg(Color::DarkGray),
    }
}

// ── App state ──────────────────────────────────────────────────────────────

struct App {
    messages: Vec<ChatMsg>,
    conv_scroll: u16,

    activity: LogPane,
    specialists: [SpecialistTab; 3],
    active_tab: usize, // 0 = ALL, 1..=3 = specialists

    input: String,
    input_cursor: usize,

    pane_split: u16,
    focus: Focus,

    status: Status,
    spinner_tick: usize,
    pending_approval: Option<ApprovalRequest>,

    // Typewriter animation for the latest agent response
    anim_full: Option<String>,
    anim_pos: usize,

    evidence_label: String,
    provider_label: String,
    notes_count: i64,
    anomaly_count: i64,
    report_enabled: bool,

    session: AgentSession,
    pool: Arc<SqlitePool>,
}

impl App {
    fn new(
        session: AgentSession,
        pool: Arc<SqlitePool>,
        history: Vec<Message>,
        evidence_label: String,
        provider_label: String,
        notes_count: i64,
        anomaly_count: i64,
        report_enabled: bool,
    ) -> Self {
        let messages = history
            .iter()
            .map(|m| {
                let text = extract_msg_text(m);
                match m {
                    Message::User { .. } => ChatMsg {
                        role: Role::User,
                        text,
                    },
                    Message::Assistant { .. } => ChatMsg {
                        role: Role::Agent,
                        text,
                    },
                }
            })
            .collect();

        Self {
            messages,
            conv_scroll: u16::MAX,
            activity: LogPane::new(),
            specialists: [
                SpecialistTab::new(SpecialistKind::Image),
                SpecialistTab::new(SpecialistKind::Audio),
                SpecialistTab::new(SpecialistKind::Sqlite),
            ],
            active_tab: 0,
            input: String::new(),
            input_cursor: 0,
            pane_split: 62,
            focus: Focus::Input,
            status: Status::Idle,
            spinner_tick: 0,
            pending_approval: None,
            anim_full: None,
            anim_pos: 0,
            evidence_label,
            provider_label,
            notes_count,
            anomaly_count,
            report_enabled,
            session,
            pool,
        }
    }

    fn tick(&mut self) {
        self.spinner_tick = (self.spinner_tick + 1) % SPINNER.len();

        // Advance typewriter animation: ~30 chars per tick at 60 ms ≈ 500 chars/sec
        if let Some(ref full) = self.anim_full.clone() {
            let target = (self.anim_pos + 30).min(full.len());
            // Advance to the next valid UTF-8 char boundary
            let pos = (target..=full.len())
                .find(|&i| full.is_char_boundary(i))
                .unwrap_or(full.len());
            self.anim_pos = pos;
            if let Some(last) = self.messages.last_mut() {
                last.text = full[..pos].to_string();
            }
            self.conv_scroll = u16::MAX;
            if pos >= full.len() {
                self.anim_full = None;
            }
        }
    }

    // ── Input handling ────────────────────────────────────────────────────

    fn handle_key(&mut self, key: KeyEvent) -> Cmd {
        // Approval popup captures all input
        if let Some(req) = self.pending_approval.take() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    let _ = req.responder.send(true);
                    self.push_tool("  ✓ Approved.".into());
                }
                _ => {
                    let _ = req.responder.send(false);
                    self.push_tool("  ✗ Denied.".into());
                }
            }
            return Cmd::None;
        }

        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Cmd::Quit,

            // Pane resize
            KeyCode::Left if key.modifiers.contains(KeyModifiers::ALT) => {
                self.pane_split = self.pane_split.saturating_sub(2).max(PANE_MIN);
                Cmd::None
            }
            KeyCode::Right if key.modifiers.contains(KeyModifiers::ALT) => {
                self.pane_split = (self.pane_split + 2).min(PANE_MAX);
                Cmd::None
            }

            // Focus cycling
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Input => Focus::Conv,
                    Focus::Conv => Focus::Tool,
                    Focus::Tool => Focus::Input,
                };
                Cmd::None
            }
            KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::Input => Focus::Tool,
                    Focus::Conv => Focus::Input,
                    Focus::Tool => Focus::Conv,
                };
                Cmd::None
            }

            // Scrolling
            KeyCode::Up => {
                match self.focus {
                    Focus::Conv => self.conv_scroll = self.conv_scroll.saturating_sub(1),
                    Focus::Tool => {
                        let pane = self.active_pane_mut();
                        pane.scroll = pane.scroll.saturating_sub(1);
                        pane.auto_scroll = false;
                    }
                    Focus::Input => {}
                }
                Cmd::None
            }
            KeyCode::Down => {
                match self.focus {
                    Focus::Conv => self.conv_scroll = self.conv_scroll.saturating_add(1),
                    Focus::Tool => {
                        let pane = self.active_pane_mut();
                        pane.scroll = pane.scroll.saturating_add(1);
                    }
                    Focus::Input => {}
                }
                Cmd::None
            }
            KeyCode::PageUp => {
                match self.focus {
                    Focus::Conv => self.conv_scroll = self.conv_scroll.saturating_sub(10),
                    Focus::Tool => {
                        let pane = self.active_pane_mut();
                        pane.scroll = pane.scroll.saturating_sub(10);
                        pane.auto_scroll = false;
                    }
                    Focus::Input => {}
                }
                Cmd::None
            }
            KeyCode::PageDown => {
                match self.focus {
                    Focus::Conv => self.conv_scroll = self.conv_scroll.saturating_add(10),
                    Focus::Tool => {
                        let pane = self.active_pane_mut();
                        pane.scroll = pane.scroll.saturating_add(10);
                    }
                    Focus::Input => {}
                }
                Cmd::None
            }
            KeyCode::Home => {
                if self.focus == Focus::Input {
                    self.input_cursor = 0;
                }
                Cmd::None
            }
            KeyCode::End => {
                match self.focus {
                    Focus::Input => self.input_cursor = self.input.len(),
                    Focus::Tool => self.active_pane_mut().auto_scroll = true,
                    _ => {}
                }
                Cmd::None
            }

            // Sub-tab switching in the activity pane
            KeyCode::Left if self.focus == Focus::Tool => {
                self.active_tab = self.active_tab.checked_sub(1).unwrap_or(TAB_COUNT - 1);
                Cmd::None
            }
            KeyCode::Right if self.focus == Focus::Tool => {
                self.active_tab = (self.active_tab + 1) % TAB_COUNT;
                Cmd::None
            }
            KeyCode::Char(c @ '1'..='4') if self.focus == Focus::Tool => {
                self.active_tab = (c as u8 - b'1') as usize;
                Cmd::None
            }

            // Submit
            KeyCode::Enter => {
                if self.focus == Focus::Input
                    && !self.input.trim().is_empty()
                    && self.status == Status::Idle
                {
                    Cmd::Submit
                } else {
                    Cmd::None
                }
            }

            // Text editing (input pane only)
            KeyCode::Char(c) if self.focus == Focus::Input => {
                self.input.insert(self.input_cursor, c);
                self.input_cursor += c.len_utf8();
                Cmd::None
            }
            KeyCode::Backspace if self.focus == Focus::Input => {
                if self.input_cursor > 0 {
                    let prev = self.input[..self.input_cursor]
                        .char_indices()
                        .last()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    self.input.remove(prev);
                    self.input_cursor = prev;
                }
                Cmd::None
            }
            KeyCode::Delete if self.focus == Focus::Input => {
                if self.input_cursor < self.input.len() {
                    self.input.remove(self.input_cursor);
                }
                Cmd::None
            }
            KeyCode::Left if self.focus == Focus::Input => {
                self.input_cursor = self.input[..self.input_cursor]
                    .char_indices()
                    .last()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                Cmd::None
            }
            KeyCode::Right if self.focus == Focus::Input => {
                if self.input_cursor < self.input.len() {
                    let next = self.input[self.input_cursor..]
                        .char_indices()
                        .nth(1)
                        .map(|(i, _)| self.input_cursor + i)
                        .unwrap_or(self.input.len());
                    self.input_cursor = next;
                }
                Cmd::None
            }

            _ => Cmd::None,
        }
    }

    fn handle_ui_event(&mut self, event: UiEvent) {
        match event {
            UiEvent::ApprovalRequest { request, .. } => self.pending_approval = Some(request),
            UiEvent::Event(event) => match event.payload {
                AgentEventPayload::Log { message, .. } => self.push_tool(message),
                AgentEventPayload::Specialist { kind, update } => {
                    self.push_specialist(kind, update)
                }
                AgentEventPayload::ToolCall {
                    tool_name,
                    arguments,
                    ..
                } => self.push_tool(format!("▶ {tool_name}: {arguments}")),
                AgentEventPayload::ToolResult {
                    tool_name, result, ..
                } => self.push_tool(format!("✓ {tool_name}: {result}")),
                AgentEventPayload::ApprovalResolved { approved, .. } => {
                    self.push_tool(if approved {
                        "  ✓ Approved.".into()
                    } else {
                        "  ✗ Denied.".into()
                    });
                }
                AgentEventPayload::ReportUpdated { export_path } => {
                    self.push_tool(match export_path {
                        Some(path) => format!("  Report updated: {path}"),
                        None => "  Report updated and saved to disk.".into(),
                    });
                }
                AgentEventPayload::TurnStarted => {
                    self.push_tool("Agent turn started.".into());
                }
                AgentEventPayload::TurnCancelled => {
                    self.push_tool("Agent turn cancelled.".into());
                }
                AgentEventPayload::TurnFailed { error } => {
                    self.push_tool(format!("Agent turn failed: {error}"));
                }
                AgentEventPayload::TurnCompleted { .. }
                | AgentEventPayload::ApprovalRequested { .. } => {}
            },
        }
    }

    async fn handle_agent_result(&mut self, result: Result<String, String>) {
        self.status = Status::Idle;
        match result {
            Ok(text) => {
                // Push an empty message slot and animate the text in
                self.messages.push(ChatMsg {
                    role: Role::Agent,
                    text: String::new(),
                });
                self.anim_full = Some(text);
                self.anim_pos = 0;
            }
            Err(e) => {
                self.messages.push(ChatMsg {
                    role: Role::Error,
                    text: e,
                });
            }
        }
        self.conv_scroll = u16::MAX;

        // Refresh notes count
        if let Ok(row) = sqlx::query("SELECT COUNT(*) as cnt FROM investigation_notes")
            .fetch_one(&*self.pool)
            .await
        {
            use sqlx::Row;
            self.notes_count = row.try_get("cnt").unwrap_or(0);
        }
    }

    fn push_tool(&mut self, line: String) {
        self.activity.push(line);
    }

    fn active_pane_mut(&mut self) -> &mut LogPane {
        if self.active_tab == 0 {
            &mut self.activity
        } else {
            &mut self.specialists[self.active_tab - 1].pane
        }
    }

    /// Route a specialist event into its tab pane and update its live status.
    /// Job outcomes (but not stage chatter) are mirrored into the ALL pane.
    fn push_specialist(&mut self, kind: SpecialistKind, update: SpecialistUpdate) {
        let idx = spec_idx(kind);
        let tag = kind.short_label();
        match update {
            SpecialistUpdate::Started { file_id } => {
                let tab = &mut self.specialists[idx];
                tab.status = SpecStatus::Running(format!("analyzing file_id={file_id}"));
                tab.pane.push(format!("▶ analyzing file_id={file_id}"));
                self.activity
                    .push(format!("▶ [{tag}] analyzing file_id={file_id}"));
            }
            SpecialistUpdate::Stage { message: msg } => {
                let tab = &mut self.specialists[idx];
                tab.pane.push(format!("    {msg}"));
                tab.status = SpecStatus::Running(msg);
            }
            SpecialistUpdate::Finished {
                file_name,
                score,
                summary,
                cached,
            } => {
                let cached_tag = if cached { " (cached)" } else { "" };
                let score_tag = score.map(|s| format!(" — score {s}")).unwrap_or_default();
                let tab = &mut self.specialists[idx];
                tab.status = SpecStatus::Idle;
                tab.done += 1;
                tab.pane
                    .push(format!("✓ '{file_name}'{cached_tag}{score_tag}"));
                if !summary.is_empty() {
                    tab.pane.push(format!("    ↳ {summary}"));
                }
                tab.pane.push(String::new());
                self.activity
                    .push(format!("✓ [{tag}] '{file_name}'{cached_tag}{score_tag}"));
                if !summary.is_empty() {
                    self.activity.push(format!("  ↳ {summary}"));
                }
            }
            SpecialistUpdate::Failed { error: err } => {
                let tab = &mut self.specialists[idx];
                tab.status = SpecStatus::Idle;
                tab.failed += 1;
                tab.pane.push(format!("✗ {err}"));
                tab.pane.push(String::new());
                self.activity.push(format!("✗ [{tag}] {err}"));
            }
        }
    }

    // ── Rendering ─────────────────────────────────────────────────────────

    fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(0),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(area);

        self.render_titlebar(frame, rows[0]);

        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(self.pane_split),
                Constraint::Percentage(100 - self.pane_split),
            ])
            .split(rows[1]);

        self.render_conv(frame, cols[0]);
        self.render_tool(frame, cols[1]);
        self.render_input(frame, rows[2]);
        self.render_statusbar(frame, rows[3]);

        if self.pending_approval.is_some() {
            self.render_approval(frame, area);
        }
    }

    fn render_titlebar(&self, frame: &mut Frame, area: Rect) {
        let line = Line::from(vec![
            Span::styled(
                " EXHUME AGENT ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                self.evidence_label.as_str(),
                Style::default().fg(Color::Gray),
            ),
            Span::styled(
                "  │  Tab: switch focus  │  ←/→: activity tabs  │  Alt+←/→: resize  │  Ctrl+C: quit",
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        frame.render_widget(Paragraph::new(line), area);
    }

    fn render_conv(&mut self, frame: &mut Frame, area: Rect) {
        let focused = self.focus == Focus::Conv;
        let border_style = if focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let title = if focused {
            " CONVERSATION [↑↓ PgUp/Dn to scroll] "
        } else {
            " CONVERSATION "
        };
        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style);

        let inner = block.inner(area);
        let lines = self.build_conv_lines();
        let total = approx_line_count(&lines, inner.width);
        let max_scroll = total.saturating_sub(inner.height);
        let para = Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false });
        self.conv_scroll = self.conv_scroll.min(max_scroll);

        let para = para.block(block).scroll((self.conv_scroll, 0));
        frame.render_widget(para, area);
    }

    fn build_conv_lines(&self) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();
        for msg in &self.messages {
            let (label, label_style) = match msg.role {
                Role::User => (
                    " USER ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Blue)
                        .add_modifier(Modifier::BOLD),
                ),
                Role::Agent => (
                    " AGENT ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Role::Error => (
                    " ERROR ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                ),
            };
            lines.push(Line::from(Span::styled(label, label_style)));
            for text_line in msg.text.lines() {
                lines.push(Line::from(Span::raw(text_line.to_owned())));
            }
            lines.push(Line::from(""));
        }
        lines
    }

    fn render_tool(&mut self, frame: &mut Frame, area: Rect) {
        let focused = self.focus == Focus::Tool;
        let border_style = if focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let title = if focused {
            " ACTIVITY [←/→ or 1-4: tab │ ↑↓: scroll │ End: follow] "
        } else {
            " ACTIVITY "
        };
        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        // Row 0: tab strip; specialist tabs add a one-line status header.
        let (tabs_area, status_area, log_area) = if self.active_tab == 0 {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(1), Constraint::Min(0)])
                .split(inner);
            (rows[0], None, rows[1])
        } else {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Min(0),
                ])
                .split(inner);
            (rows[0], Some(rows[1]), rows[2])
        };

        self.render_tab_strip(frame, tabs_area);
        if let Some(status_area) = status_area {
            self.render_specialist_status(frame, status_area, self.active_tab - 1);
        }

        let pane = self.active_pane_mut();
        let lines: Vec<Line<'static>> = pane
            .lines
            .iter()
            .map(|l| Line::from(Span::styled(l.clone(), log_line_style(l))))
            .collect();
        let total = approx_line_count(&lines, log_area.width);
        let max_scroll = total.saturating_sub(log_area.height);
        if pane.auto_scroll {
            pane.scroll = max_scroll;
        } else {
            pane.scroll = pane.scroll.min(max_scroll);
        }
        let scroll = pane.scroll;

        let para = Paragraph::new(Text::from(lines))
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0));
        frame.render_widget(para, log_area);
    }

    fn render_tab_strip(&self, frame: &mut Frame, area: Rect) {
        let mut titles: Vec<Line> = vec![Line::from(" ALL ")];
        for tab in &self.specialists {
            let mut spans = vec![Span::raw(" ")];
            if matches!(tab.status, SpecStatus::Running(_)) {
                spans.push(Span::styled(
                    format!("{} ", SPINNER[self.spinner_tick % SPINNER.len()]),
                    Style::default().fg(Color::Yellow),
                ));
            }
            spans.push(Span::raw(tab.kind.short_label().to_uppercase()));
            if tab.done > 0 {
                spans.push(Span::styled(
                    format!(" ✓{}", tab.done),
                    Style::default().fg(Color::Green),
                ));
            }
            if tab.failed > 0 {
                spans.push(Span::styled(
                    format!(" ✗{}", tab.failed),
                    Style::default().fg(Color::Red),
                ));
            }
            spans.push(Span::raw(" "));
            titles.push(Line::from(spans));
        }

        let tabs = Tabs::new(titles)
            .select(self.active_tab)
            .style(Style::default().fg(Color::Gray))
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .divider(Span::styled("│", Style::default().fg(Color::DarkGray)));
        frame.render_widget(tabs, area);
    }

    fn render_specialist_status(&self, frame: &mut Frame, area: Rect, idx: usize) {
        let tab = &self.specialists[idx];
        let line = match &tab.status {
            SpecStatus::Running(stage) => Line::from(vec![
                Span::styled("● ", Style::default().fg(Color::Yellow)),
                Span::styled(stage.clone(), Style::default().fg(Color::Yellow)),
            ]),
            SpecStatus::Idle if tab.done + tab.failed == 0 => Line::from(Span::styled(
                "○ idle — no delegations this session",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )),
            SpecStatus::Idle => Line::from(Span::styled(
                format!("○ idle — {} completed, {} failed", tab.done, tab.failed),
                Style::default().fg(Color::DarkGray),
            )),
        };
        frame.render_widget(Paragraph::new(line), area);
    }

    fn render_input(&self, frame: &mut Frame, area: Rect) {
        let focused = self.focus == Focus::Input;
        let (border_style, prefix_style) = if focused {
            (
                Style::default().fg(Color::Yellow),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            (
                Style::default().fg(Color::DarkGray),
                Style::default().fg(Color::DarkGray),
            )
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style);

        let inner = block.inner(area);

        let prefix = ">>> ";
        let content = if self.status == Status::Thinking {
            Line::from(vec![
                Span::styled(prefix, prefix_style),
                Span::styled(
                    " Agent is thinking… ",
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::ITALIC),
                ),
            ])
        } else if !focused {
            Line::from(vec![
                Span::styled(prefix, prefix_style),
                Span::styled(
                    " Press Tab to focus input ",
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::ITALIC),
                ),
            ])
        } else {
            Line::from(vec![
                Span::styled(prefix, prefix_style),
                Span::raw(self.input.clone()),
            ])
        };

        let para = Paragraph::new(content).block(block);
        frame.render_widget(para, area);

        if focused && self.status == Status::Idle {
            let chars_before = self.input[..self.input_cursor].chars().count() as u16;
            let cursor_x = inner.x + prefix.len() as u16 + chars_before;
            let cursor_y = inner.y;
            if cursor_x < area.right().saturating_sub(1) {
                frame.set_cursor_position((cursor_x, cursor_y));
            }
        }
    }

    fn render_statusbar(&self, frame: &mut Frame, area: Rect) {
        let (status_label, status_style) = if self.pending_approval.is_some() {
            (
                " ⚠ APPROVAL REQUIRED ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            match self.status {
                Status::Idle => (" IDLE ", Style::default().fg(Color::Black).bg(Color::Green)),
                Status::Thinking => (
                    " THINKING ",
                    Style::default().fg(Color::Black).bg(Color::Yellow),
                ),
            }
        };

        let spinner = if self.anim_full.is_some() {
            " ▍ ".to_string() // writing cursor during typewriter animation
        } else if self.status == Status::Thinking && self.pending_approval.is_none() {
            format!(" {} ", SPINNER[self.spinner_tick % SPINNER.len()])
        } else {
            "   ".to_string()
        };

        let mut spans = vec![
            Span::styled(status_label, status_style),
            Span::raw(spinner),
            Span::styled(
                self.provider_label.as_str(),
                Style::default().fg(Color::White),
            ),
            Span::styled(
                format!(
                    "  │  Notes: {}  │  Anomalies: {}",
                    self.notes_count, self.anomaly_count
                ),
                Style::default().fg(Color::Gray),
            ),
            Span::styled(
                if self.report_enabled {
                    "  │  Report: ON"
                } else {
                    "  │  Report: OFF"
                },
                if self.report_enabled {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            ),
        ];

        let running = self
            .specialists
            .iter()
            .filter(|t| matches!(t.status, SpecStatus::Running(_)))
            .count();
        if running > 0 {
            spans.push(Span::styled(
                format!("  │  Specialists running: {}", running),
                Style::default().fg(Color::Yellow),
            ));
        }

        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn render_approval(&self, frame: &mut Frame, area: Rect) {
        let req = match &self.pending_approval {
            Some(r) => r,
            None => return,
        };

        let popup_w = (area.width * 2 / 3)
            .max(52)
            .min(area.width.saturating_sub(4));
        let popup_h = 8u16;
        let popup_x = area.x + (area.width.saturating_sub(popup_w)) / 2;
        let popup_y = area.y + (area.height.saturating_sub(popup_h)) / 2;
        let popup_area = Rect::new(popup_x, popup_y, popup_w, popup_h);

        frame.render_widget(Clear, popup_area);

        let block = Block::default()
            .title(" ⚠  APPROVAL REQUIRED ")
            .title_alignment(Alignment::Center)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD));

        let max_w = popup_w.saturating_sub(4) as usize;
        let prompt: String = req
            .prompt
            .chars()
            .take(max_w * 3)
            .collect::<String>()
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join(" ");

        let text = Text::from(vec![
            Line::from(""),
            Line::from(Span::raw(prompt)),
            Line::from(""),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    "  Y  Allow  ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("       "),
                Span::styled(
                    "  N  Deny  ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
        ]);

        let para = Paragraph::new(text).block(block);
        frame.render_widget(para, popup_area);
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Approximate visual line count for a wrapped paragraph.
/// Assumes monospace ASCII — sufficient for forensic tool output.
fn approx_line_count(lines: &[Line<'_>], width: u16) -> u16 {
    let w = width.max(1) as usize;
    lines
        .iter()
        .map(|l| {
            let len: usize = l.spans.iter().map(|s| s.content.len()).sum();
            (len.max(1) + w - 1) / w
        })
        .sum::<usize>() as u16
}

// ── Text extraction from rig Messages ──────────────────────────────────────

fn extract_msg_text(msg: &Message) -> String {
    let value = serde_json::to_value(msg).unwrap_or_default();
    let mut chunks = Vec::new();
    collect_text(&value, &mut chunks);
    if chunks.is_empty() {
        value.to_string()
    } else {
        chunks.join("\n")
    }
}

fn collect_text(value: &serde_json::Value, chunks: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) if !s.trim().is_empty() => chunks.push(s.clone()),
        serde_json::Value::Array(items) => items.iter().for_each(|v| collect_text(v, chunks)),
        serde_json::Value::Object(map) => {
            if let Some(s) = map
                .get("text")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            {
                chunks.push(s.to_string());
            } else {
                map.values().for_each(|v| collect_text(v, chunks));
            }
        }
        _ => {}
    }
}

// ── Entry point ────────────────────────────────────────────────────────────

pub async fn run(
    session: AgentSession,
    pool: Arc<SqlitePool>,
    report_mode: ReportMode,
    mut ui_rx: mpsc::Receiver<UiEvent>,
    evidence_path: String,
    provider: String,
    model: String,
) -> Result<()> {
    let history = session.history().await;

    use sqlx::Row;
    let notes_count = sqlx::query("SELECT COUNT(*) as cnt FROM investigation_notes")
        .fetch_one(&*pool)
        .await
        .map(|r| r.try_get::<i64, _>("cnt").unwrap_or(0))
        .unwrap_or(0);
    let anomaly_count =
        sqlx::query("SELECT COUNT(*) as cnt FROM system_files WHERE anomaly_flag = 1")
            .fetch_one(&*pool)
            .await
            .map(|r| r.try_get::<i64, _>("cnt").unwrap_or(0))
            .unwrap_or(0);

    let mut app = App::new(
        session,
        pool,
        history,
        format!("Evidence: {}", evidence_path),
        format!("{} / {}", provider, model),
        notes_count,
        anomaly_count,
        report_mode.enabled,
    );

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let (agent_tx, mut agent_rx) = mpsc::channel::<Result<String, String>>(1);
    let mut event_stream = EventStream::new();
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(60));

    let loop_result: Result<()> = async {
        loop {
            terminal.draw(|f| app.render(f))?;

            tokio::select! {
                // Key / resize events — highest priority
                maybe = event_stream.next() => {
                    match maybe {
                        Some(Ok(Event::Key(key))) => {
                            match app.handle_key(key) {
                                Cmd::Quit => break,
                                Cmd::Submit => submit(&mut app, &agent_tx).await?,
                                Cmd::None => {}
                            }
                        }
                        Some(Ok(Event::Resize(_, _))) => {} // next draw picks up new size
                        Some(Err(e)) => return Err(anyhow::anyhow!(e)),
                        None => break,
                        _ => {}
                    }
                }

                // Events from running agent tools
                Some(ev) = ui_rx.recv() => {
                    app.handle_ui_event(ev);
                }

                // Agent turn completed
                Some(result) = agent_rx.recv() => {
                    app.handle_agent_result(result).await;
                }

                // Spinner + typewriter animation tick — lowest priority
                _ = ticker.tick() => {
                    app.tick();
                }
            }
        }
        Ok(())
    }
    .await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    loop_result
}

async fn submit(app: &mut App, agent_tx: &mpsc::Sender<Result<String, String>>) -> Result<()> {
    let text = std::mem::take(&mut app.input).trim().to_string();
    app.input_cursor = 0;

    app.messages.push(ChatMsg {
        role: Role::User,
        text: text.clone(),
    });
    app.conv_scroll = u16::MAX;
    app.status = Status::Thinking;
    app.activity.auto_scroll = true;

    let tx = agent_tx.clone();
    let session = app.session.clone();
    tokio::spawn(async move {
        let r = session
            .submit(text, None)
            .await
            .map(|(_, response)| response)
            .map_err(|e| e.to_string());
        let _ = tx.send(r).await;
    });

    Ok(())
}
