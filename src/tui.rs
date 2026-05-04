use crate::agent::ExhumeAgent;
use crate::report::ReportMode;
use crate::ui::{ApprovalRequest, UiEvent};
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
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame, Terminal,
};
use rig::message::Message;
use sqlx::SqlitePool;
use std::{io, sync::Arc};
use tokio::sync::mpsc;

const PANE_MIN: u16 = 20;
const PANE_MAX: u16 = 80;
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

// ── App state ──────────────────────────────────────────────────────────────

struct App {
    messages: Vec<ChatMsg>,
    conv_scroll: u16,

    tool_lines: Vec<String>,
    tool_scroll: u16,
    tool_auto_scroll: bool,

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

    history: Vec<Message>,
    agent: ExhumeAgent,
    pool: Arc<SqlitePool>,
}

impl App {
    fn new(
        agent: ExhumeAgent,
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
            tool_lines: Vec::new(),
            tool_scroll: 0,
            tool_auto_scroll: true,
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
            history,
            agent,
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
                        self.tool_scroll = self.tool_scroll.saturating_sub(1);
                        self.tool_auto_scroll = false;
                    }
                    Focus::Input => {}
                }
                Cmd::None
            }
            KeyCode::Down => {
                match self.focus {
                    Focus::Conv => self.conv_scroll = self.conv_scroll.saturating_add(1),
                    Focus::Tool => self.tool_scroll = self.tool_scroll.saturating_add(1),
                    Focus::Input => {}
                }
                Cmd::None
            }
            KeyCode::PageUp => {
                match self.focus {
                    Focus::Conv => self.conv_scroll = self.conv_scroll.saturating_sub(10),
                    Focus::Tool => {
                        self.tool_scroll = self.tool_scroll.saturating_sub(10);
                        self.tool_auto_scroll = false;
                    }
                    Focus::Input => {}
                }
                Cmd::None
            }
            KeyCode::PageDown => {
                match self.focus {
                    Focus::Conv => self.conv_scroll = self.conv_scroll.saturating_add(10),
                    Focus::Tool => self.tool_scroll = self.tool_scroll.saturating_add(10),
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
                    Focus::Tool => self.tool_auto_scroll = true,
                    _ => {}
                }
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
            UiEvent::Log(line) => self.push_tool(line),
            UiEvent::ApprovalRequest(req) => {
                self.pending_approval = Some(req);
            }
            UiEvent::ReportUpdated => {
                self.push_tool("  Report updated and saved to disk.".into());
            }
        }
    }

    async fn handle_agent_result(&mut self, result: Result<String, String>) {
        self.status = Status::Idle;
        match result {
            Ok(text) => {
                let msg = Message::assistant(text.clone());
                let _ = self.agent.save_message(&msg).await;
                self.history.push(msg);
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
        if let Ok(row) =
            sqlx::query("SELECT COUNT(*) as cnt FROM investigation_notes")
                .fetch_one(&*self.pool)
                .await
        {
            use sqlx::Row;
            self.notes_count = row.try_get("cnt").unwrap_or(0);
        }
    }

    fn push_tool(&mut self, line: String) {
        self.tool_lines.push(line);
        if self.tool_auto_scroll {
            self.tool_scroll = u16::MAX;
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
                "  │  Tab: switch focus  │  Alt+←/→: resize panes  │  PgUp/Dn: scroll  │  Ctrl+C: quit",
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
            " TOOL ACTIVITY [↑↓ scroll │ End: jump to bottom] "
        } else {
            " TOOL ACTIVITY "
        };
        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style);

        let inner = block.inner(area);

        let lines: Vec<Line> = self
            .tool_lines
            .iter()
            .map(|l| {
                Line::from(Span::styled(
                    l.clone(),
                    Style::default().fg(Color::DarkGray),
                ))
            })
            .collect();

        let total = approx_line_count(&lines, inner.width);
        let max_scroll = total.saturating_sub(inner.height);
        let para = Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false });

        if self.tool_auto_scroll {
            self.tool_scroll = max_scroll;
        } else {
            self.tool_scroll = self.tool_scroll.min(max_scroll);
        }

        let para = para.block(block).scroll((self.tool_scroll, 0));
        frame.render_widget(para, area);
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
                Status::Idle => (
                    " IDLE ",
                    Style::default().fg(Color::Black).bg(Color::Green),
                ),
                Status::Thinking => (
                    " THINKING ",
                    Style::default().fg(Color::Black).bg(Color::Yellow),
                ),
            }
        };

        let spinner = if self.anim_full.is_some() {
            " ▍ ".to_string()  // writing cursor during typewriter animation
        } else if self.status == Status::Thinking && self.pending_approval.is_none() {
            format!(" {} ", SPINNER[self.spinner_tick % SPINNER.len()])
        } else {
            "   ".to_string()
        };

        let line = Line::from(vec![
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
        ]);

        frame.render_widget(Paragraph::new(line), area);
    }

    fn render_approval(&self, frame: &mut Frame, area: Rect) {
        let req = match &self.pending_approval {
            Some(r) => r,
            None => return,
        };

        let popup_w = (area.width * 2 / 3).max(52).min(area.width.saturating_sub(4));
        let popup_h = 8u16;
        let popup_x = area.x + (area.width.saturating_sub(popup_w)) / 2;
        let popup_y = area.y + (area.height.saturating_sub(popup_h)) / 2;
        let popup_area = Rect::new(popup_x, popup_y, popup_w, popup_h);

        frame.render_widget(Clear, popup_area);

        let block = Block::default()
            .title(" ⚠  APPROVAL REQUIRED ")
            .title_alignment(Alignment::Center)
            .borders(Borders::ALL)
            .border_style(
                Style::default()
                    .fg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            );

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
    agent: ExhumeAgent,
    pool: Arc<SqlitePool>,
    report_mode: ReportMode,
    mut ui_rx: mpsc::UnboundedReceiver<UiEvent>,
    evidence_path: String,
    provider: String,
    model: String,
) -> Result<()> {
    let history = agent.load_history().await.unwrap_or_default();

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
        agent,
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

async fn submit(
    app: &mut App,
    agent_tx: &mpsc::Sender<Result<String, String>>,
) -> Result<()> {
    let text = std::mem::take(&mut app.input).trim().to_string();
    app.input_cursor = 0;

    let user_msg = Message::user(text.clone());
    app.agent.save_message(&user_msg).await?;
    app.history.push(user_msg);
    app.messages.push(ChatMsg {
        role: Role::User,
        text,
    });
    app.conv_scroll = u16::MAX;
    app.status = Status::Thinking;
    app.tool_auto_scroll = true;

    let tx = agent_tx.clone();
    let ag = app.agent.clone();
    let hist = app.history.clone();
    tokio::spawn(async move {
        let r = ag.chat(&hist).await.map_err(|e| e.to_string());
        let _ = tx.send(r).await;
    });

    Ok(())
}
