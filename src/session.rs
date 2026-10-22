use crate::agent::{message_text, ExhumeAgent};
use crate::investigation::{
    CaseBrief, HumanDecision, InvestigationSnapshot, ReviewStatus, StepProposal, StepState,
};
use crate::ui::{unique_id, AgentEvent, AgentEventPayload};
use anyhow::{anyhow, Result};
use rig::message::Message;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSessionStatus {
    Idle,
    Running,
    Closed,
}

impl AgentSessionStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Running => "running",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionMessage {
    pub id: i64,
    pub turn_id: Option<String>,
    pub role: String,
    pub content: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentSessionSnapshot {
    pub session_id: String,
    pub evidence_id: i64,
    pub provider: String,
    pub model: String,
    pub reporting_enabled: bool,
    pub status: AgentSessionStatus,
    pub active_turn_id: Option<String>,
    pub messages: Vec<SessionMessage>,
    pub investigation: InvestigationSnapshot,
    pub case_template: Option<CaseBrief>,
}

#[derive(Clone)]
pub struct AgentSession {
    inner: Arc<AgentSessionInner>,
}

struct AgentSessionInner {
    agent: ExhumeAgent,
    history: RwLock<Vec<Message>>,
    status: RwLock<AgentSessionStatus>,
    active_turn: Mutex<Option<ActiveTurn>>,
    turn_gate: Mutex<()>,
}

struct ActiveTurn {
    id: String,
    cancellation: CancellationToken,
}

impl AgentSession {
    pub async fn open(agent: ExhumeAgent) -> Result<Self> {
        validate_session_id(agent.session_id())?;
        agent.ensure_session().await?;
        agent.investigation().await?;
        let history = agent.load_history().await?;
        Ok(Self {
            inner: Arc::new(AgentSessionInner {
                agent,
                history: RwLock::new(history),
                status: RwLock::new(AgentSessionStatus::Idle),
                active_turn: Mutex::new(None),
                turn_gate: Mutex::new(()),
            }),
        })
    }

    pub fn session_id(&self) -> &str {
        self.inner.agent.session_id()
    }

    pub fn evidence_id(&self) -> i64 {
        self.inner.agent.evidence_id()
    }

    pub fn case_template(&self) -> Result<CaseBrief> {
        self.inner.agent.case_template()
    }

    pub async fn investigation_snapshot(&self) -> Result<InvestigationSnapshot> {
        self.inner.agent.investigation().await?.snapshot().await
    }

    pub async fn prepare_case(&self, brief: CaseBrief) -> Result<InvestigationSnapshot> {
        let _guard = self
            .inner
            .turn_gate
            .try_lock()
            .map_err(|_| anyhow!("A turn is running"))?;
        self.require_open().await?;
        self.inner.agent.prepare_case(brief).await
    }

    /// Desktop brief save uses configured services; CLI briefs retain explicit policies.
    /// Saving still invalidates prior approvals and does not authorize a step.
    pub async fn prepare_case_with_configured_destinations(
        &self,
        mut brief: CaseBrief,
    ) -> Result<InvestigationSnapshot> {
        brief.processing_policy.allowed_destinations =
            self.inner.agent.configured_processing_destinations()?;
        self.prepare_case(brief).await
    }

    pub async fn decide_step(
        &self,
        step_id: &str,
        decision: HumanDecision,
        rationale: &str,
    ) -> Result<InvestigationSnapshot> {
        let _guard = self
            .inner
            .turn_gate
            .try_lock()
            .map_err(|_| anyhow!("A turn is running"))?;
        self.require_open().await?;
        let store = self.inner.agent.investigation().await?;
        store
            .decide_step(step_id, decision, "investigator", rationale)
            .await?;
        store.snapshot().await
    }

    pub async fn review_finding(
        &self,
        finding_id: &str,
        review: ReviewStatus,
        rationale: &str,
    ) -> Result<InvestigationSnapshot> {
        let _guard = self
            .inner
            .turn_gate
            .try_lock()
            .map_err(|_| anyhow!("A turn is running"))?;
        self.require_open().await?;
        let store = self.inner.agent.investigation().await?;
        store
            .review_finding(finding_id, review, "investigator", rationale)
            .await?;
        store.snapshot().await
    }

    pub async fn propose_steps(&self, steps: Vec<StepProposal>) -> Result<InvestigationSnapshot> {
        let _guard = self
            .inner
            .turn_gate
            .try_lock()
            .map_err(|_| anyhow!("A turn is running"))?;
        self.require_open().await?;
        let store = self.inner.agent.investigation().await?;
        store.propose_steps(steps).await?;
        store.snapshot().await
    }

    pub async fn submit(
        &self,
        instruction: impl Into<String>,
        requested_turn_id: Option<String>,
    ) -> Result<(String, String)> {
        let instruction = instruction.into().trim().to_string();
        self.require_open().await?;
        if instruction.is_empty() {
            return Err(anyhow!("Investigation instruction cannot be empty"));
        }

        // Explicit UI/CLI commands are interpreted by the host, never by a model.
        if let Some(reply) = self.human_command(&instruction).await? {
            return Ok((
                requested_turn_id.unwrap_or_else(|| unique_id("decision")),
                reply,
            ));
        }

        let _turn_guard = self
            .inner
            .turn_gate
            .try_lock()
            .map_err(|_| anyhow!("Another agent turn is already running"))?;
        if *self.inner.status.read().await == AgentSessionStatus::Closed {
            return Err(anyhow!("Agent session is closed"));
        }

        let turn_id = requested_turn_id.unwrap_or_else(|| unique_id("turn"));
        let cancellation = CancellationToken::new();
        {
            let mut active = self.inner.active_turn.lock().await;
            *active = Some(ActiveTurn {
                id: turn_id.clone(),
                cancellation: cancellation.clone(),
            });
        }
        if let Err(error) = self.set_status(AgentSessionStatus::Running).await {
            self.clear_active_turn(&turn_id).await;
            return Err(error);
        }

        if let Some(ui) = self.inner.agent.ui() {
            ui.set_turn_id(Some(turn_id.clone()));
            ui.emit(AgentEventPayload::TurnStarted);
        }

        let user_message = Message::user(instruction);
        if let Err(error) = self
            .inner
            .agent
            .save_message_for_turn(&user_message, Some(turn_id.clone()))
            .await
        {
            self.clear_active_turn(&turn_id).await;
            let _ = self.set_status(AgentSessionStatus::Idle).await;
            if let Some(ui) = self.inner.agent.ui() {
                ui.emit(AgentEventPayload::TurnFailed {
                    error: error.to_string(),
                });
                ui.set_turn_id(None);
            }
            return Err(error);
        }
        let history = {
            let mut history = self.inner.history.write().await;
            history.push(user_message);
            history.clone()
        };

        let timeout = Duration::from_secs(self.inner.agent.policy().turn_timeout_secs.max(1));
        let mut outcome = tokio::select! {
            biased;
            _ = cancellation.cancelled() => TurnOutcome::Cancelled,
            result = tokio::time::timeout(timeout, self.inner.agent.chat_for_turn(&history, &turn_id)) => {
                match result {
                    Ok(Ok(response)) => TurnOutcome::Completed(response),
                    Ok(Err(error)) => TurnOutcome::Failed(error.to_string()),
                    Err(_) => TurnOutcome::Failed(format!(
                        "Agent turn exceeded the {} second timeout",
                        timeout.as_secs()
                    )),
                }
            }
        };

        if !matches!(&outcome, TurnOutcome::Completed(_)) {
            let persist_interruption = async {
                let store = self.inner.agent.investigation().await?;
                if store.snapshot().await?.steps.iter().any(|s| s.state == StepState::Running) {
                    let snapshot = store.snapshot().await?;
                    for step in snapshot.steps.iter().filter(|s| s.state == StepState::Running) {
                        if let Some(active_id) = &step.turn_id {
                            store.interrupt_step(active_id, "Turn cancelled, timed out, or failed; unfinished results are unknown and renewed approval is required.").await?;
                        }
                    }
                }
                Ok::<(), anyhow::Error>(())
            }.await;
            if let Err(error) = persist_interruption {
                outcome = TurnOutcome::Failed(format!("Could not persist the interrupted checkpoint; execution remains blocked until report repair: {error}"));
            }
        }

        self.clear_active_turn(&turn_id).await;
        self.set_status(AgentSessionStatus::Idle).await?;

        let result = match outcome {
            TurnOutcome::Completed(response) => {
                let assistant_message = Message::assistant(response.clone());
                if let Err(error) = self
                    .inner
                    .agent
                    .save_message_for_turn(&assistant_message, Some(turn_id.clone()))
                    .await
                {
                    if let Some(ui) = self.inner.agent.ui() {
                        ui.emit(AgentEventPayload::TurnFailed {
                            error: error.to_string(),
                        });
                    }
                    Err(error)
                } else {
                    self.inner.history.write().await.push(assistant_message);
                    if let Some(ui) = self.inner.agent.ui() {
                        ui.emit(AgentEventPayload::TurnCompleted {
                            response: response.clone(),
                        });
                    }
                    Ok((turn_id.clone(), response))
                }
            }
            TurnOutcome::Cancelled => {
                if let Some(ui) = self.inner.agent.ui() {
                    ui.emit(AgentEventPayload::TurnCancelled);
                }
                Err(anyhow!("Agent turn was cancelled"))
            }
            TurnOutcome::Failed(error) => {
                if let Some(ui) = self.inner.agent.ui() {
                    ui.emit(AgentEventPayload::TurnFailed {
                        error: error.clone(),
                    });
                }
                Err(anyhow!(error))
            }
        };

        if let Some(ui) = self.inner.agent.ui() {
            ui.set_turn_id(None);
        }
        result
    }

    pub async fn cancel(&self, turn_id: Option<&str>) -> bool {
        let active = self.inner.active_turn.lock().await;
        let Some(active) = active.as_ref() else {
            return false;
        };
        if turn_id.is_some_and(|requested| requested != active.id) {
            return false;
        }
        active.cancellation.cancel();
        true
    }

    pub async fn clear_history(&self) -> Result<()> {
        let _guard = self
            .inner
            .turn_gate
            .try_lock()
            .map_err(|_| anyhow!("Cannot clear history while an agent turn is running"))?;
        self.require_open().await?;
        self.inner.agent.clear_history().await?;
        self.inner.history.write().await.clear();
        Ok(())
    }

    pub async fn history(&self) -> Vec<Message> {
        self.inner.history.read().await.clone()
    }

    pub async fn close(&self) -> Result<()> {
        self.cancel(None).await;
        let _guard = self.inner.turn_gate.lock().await;
        self.set_status(AgentSessionStatus::Closed).await
    }

    async fn require_open(&self) -> Result<()> {
        if *self.inner.status.read().await == AgentSessionStatus::Closed {
            return Err(anyhow!("Agent session is closed"));
        }
        Ok(())
    }

    pub async fn snapshot(&self) -> Result<AgentSessionSnapshot> {
        let active_turn_id = self
            .inner
            .active_turn
            .lock()
            .await
            .as_ref()
            .map(|turn| turn.id.clone());
        Ok(AgentSessionSnapshot {
            session_id: self.session_id().to_string(),
            evidence_id: self.evidence_id(),
            provider: self.inner.agent.config().provider.clone(),
            model: self.inner.agent.config().model.clone(),
            reporting_enabled: self.inner.agent.reporting_enabled(),
            status: *self.inner.status.read().await,
            active_turn_id,
            messages: self.load_messages().await?,
            investigation: self.investigation_snapshot().await?,
            case_template: self.case_template().ok(),
        })
    }

    async fn human_command(&self, instruction: &str) -> Result<Option<String>> {
        let Some(command) = instruction.strip_prefix('/') else {
            return Ok(None);
        };
        let (name, args) = command.split_once(' ').unwrap_or((command, ""));
        let result = match name {
            "status" => crate::runtime::pending_summary(&self.investigation_snapshot().await?),
            "brief" => {
                if args.trim().is_empty() { serde_json::to_string_pretty(&self.investigation_snapshot().await?.brief.unwrap_or(self.case_template()?))? }
                else { crate::runtime::pending_summary(&self.prepare_case(serde_json::from_str(args)?).await?) }
            },
            "approve" | "reject" => {
                let state = self.decide_step(args.trim(), if name == "approve" {HumanDecision::Approve} else {HumanDecision::Reject}, "Explicit CLI decision").await?;
                format!("Decision saved for {}. {}\nReport: {}", args.trim(), if name == "approve" {"Submit /run to execute the approved step."} else {"Propose another step or revise the case brief."}, state.report_path.display())
            },
            "propose" => crate::runtime::pending_summary(&self.propose_steps(serde_json::from_str(args)?).await?),
            "review" => {
                let mut parts = args.splitn(3, ' ');
                let id = parts.next().unwrap_or("");
                let review = match parts.next().unwrap_or("") { "accept" => ReviewStatus::Accepted, "reject" => ReviewStatus::Rejected, "corroborate" => ReviewStatus::NeedsCorroboration, _ => return Err(anyhow!("Use /review <finding-id> accept|reject|corroborate <reason>")) };
                self.review_finding(id, review, parts.next().unwrap_or("Explicit CLI review")).await?;
                "Finding review saved; original observation preserved.".into()
            },
            "repair-report" => {
                let _guard = self.inner.turn_gate.try_lock().map_err(|_| anyhow!("A turn is running"))?;
                self.require_open().await?;
                self.inner.agent.investigation().await?.repair_exports().await?;
                "Markdown and execution log exports repaired.".into()
            },
            "run" => return Ok(None),
            "help" => "Commands: /brief [JSON], /status, /approve <step-id>, /reject <step-id>, /run, /propose <JSON array>, /review <finding-id> accept|reject|corroborate <reason>, /repair-report. Ordinary chat supplies an initial objective; it never grants approval.".into(),
            _ => return Err(anyhow!("Unknown command. Use /help.")),
        };
        Ok(Some(result))
    }

    async fn load_messages(&self) -> Result<Vec<SessionMessage>> {
        let rows = sqlx::query(
            r#"
            SELECT id, turn_id, role, content, created_at
            FROM agent_messages
            WHERE session_id = ?
            ORDER BY id ASC
            "#,
        )
        .bind(self.session_id())
        .fetch_all(&**self.inner.agent.pool())
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let raw: String = row.try_get("content").ok()?;
                let message: Message = serde_json::from_str(&raw).ok()?;
                Some(SessionMessage {
                    id: row.try_get("id").ok()?,
                    turn_id: row.try_get("turn_id").ok(),
                    role: row.try_get("role").ok()?,
                    content: message_text(&message),
                    created_at: row.try_get("created_at").ok()?,
                })
            })
            .collect())
    }

    async fn clear_active_turn(&self, turn_id: &str) {
        let mut active = self.inner.active_turn.lock().await;
        if active.as_ref().is_some_and(|turn| turn.id == turn_id) {
            *active = None;
        }
    }

    async fn set_status(&self, status: AgentSessionStatus) -> Result<()> {
        *self.inner.status.write().await = status;
        sqlx::query(
            "UPDATE agent_sessions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        )
        .bind(status.as_str())
        .bind(self.session_id())
        .execute(&**self.inner.agent.pool())
        .await?;
        Ok(())
    }
}

fn validate_session_id(session_id: &str) -> Result<()> {
    if session_id.is_empty()
        || session_id.len() > 128
        || !session_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(anyhow!(
            "Session ID must contain 1-128 ASCII letters, digits, '-' or '_'"
        ));
    }
    Ok(())
}

enum TurnOutcome {
    Completed(String),
    Cancelled,
    Failed(String),
}

pub async fn persist_agent_event(pool: &sqlx::SqlitePool, event: &AgentEvent) -> Result<()> {
    let event_json = serde_json::to_string(event)?;
    sqlx::query(
        r#"
        INSERT INTO agent_audit_events (
            session_id, turn_id, evidence_id, event_type, event_json
        ) SELECT ?, ?, ?, ?, ?
        WHERE NOT EXISTS (
            SELECT 1 FROM agent_audit_events
            WHERE session_id = ? AND ? != ''
                AND CASE WHEN json_valid(event_json) THEN json_extract(event_json, '$.event_id') END = ?
        )
        "#,
    )
    .bind(&event.session_id)
    .bind(&event.turn_id)
    .bind(event.evidence_id)
    .bind(event.payload.event_type())
    .bind(event_json)
    .bind(&event.session_id)
    .bind(&event.event_id)
    .bind(&event.event_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::AgentSession;
    use crate::agent::ExhumeAgent;
    use crate::config::AgentConfig;
    use crate::policy::{AgentOptions, AgentPolicy};
    use rig::message::Message;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn config() -> AgentConfig {
        AgentConfig {
            provider: "ollama".to_string(),
            model: "test".to_string(),
            endpoint: "http://127.0.0.1:11434".to_string(),
            api_key: String::new(),
            llm_endpoint: None,
            image_endpoint: None,
            audio_endpoint: None,
            auth_mode: Default::default(),
            account_id: None,
            runtime_path: None,
        }
    }

    fn agent(pool: Arc<sqlx::SqlitePool>, session_id: &str, db_path: PathBuf) -> ExhumeAgent {
        ExhumeAgent::new_with_options(
            config(),
            "/nonexistent/evidence.img".to_string(),
            db_path,
            pool,
            false,
            false,
            None,
            AgentOptions {
                session_id: session_id.to_string(),
                evidence_id: 7,
                policy: AgentPolicy::default(),
            },
        )
    }

    #[tokio::test]
    async fn configured_destinations_include_only_available_media_services() {
        use crate::auth::AuthMode;

        let pool = Arc::new(
            SqlitePoolOptions::new()
                .max_connections(1)
                .connect("sqlite::memory:")
                .await
                .unwrap(),
        );
        let temp = tempfile::tempdir().unwrap();
        let mut agent = agent(pool, "configured-services", temp.path().join("evidence.db"));
        let cases = [
            (
                "ollama",
                AuthMode::ApiKey,
                "http://127.0.0.1:11434",
                vec!["http://127.0.0.1:11434/api"],
            ),
            (
                "openai",
                AuthMode::ApiKey,
                "https://api.openai.com/v1",
                vec![
                    "https://api.openai.com/v1",
                    "https://api.openai.com/v1/chat/completions",
                    "https://api.openai.com/v1/audio/transcriptions",
                ],
            ),
            (
                "openai",
                AuthMode::ApiKey,
                "https://configured.invalid/v1",
                vec![
                    "https://configured.invalid/v1",
                    "https://configured.invalid/v1/chat/completions",
                ],
            ),
            (
                "mistral",
                AuthMode::ApiKey,
                "https://api.mistral.ai/v1",
                vec![
                    "https://api.mistral.ai/v1",
                    "https://api.mistral.ai/v1/chat/completions",
                ],
            ),
            (
                "openai",
                AuthMode::Subscription,
                "https://ignored.invalid/v1",
                vec!["https://api.openai.com/v1"],
            ),
            (
                "mistral",
                AuthMode::Subscription,
                "https://ignored.invalid/v1",
                vec!["https://api.mistral.ai/v1"],
            ),
            (
                "claude",
                AuthMode::ApiKey,
                "https://api.anthropic.com/v1",
                vec!["https://api.anthropic.com/v1"],
            ),
            (
                "copilot",
                AuthMode::ApiKey,
                "http://127.0.0.1",
                vec![
                    "http://127.0.0.1:8000/v1",
                    "http://127.0.0.1:8001/v1/describe",
                    "http://127.0.0.1:8002/v1/transcribe",
                ],
            ),
        ];
        for (provider, mode, endpoint, expected) in cases {
            agent.config = AgentConfig {
                provider: provider.into(),
                endpoint: endpoint.into(),
                model: "current-session-model".into(),
                api_key: if mode == AuthMode::ApiKey {
                    "synthetic-key".into()
                } else {
                    String::new()
                },
                auth_mode: mode,
                account_id: (mode == AuthMode::Subscription).then(|| "selected-account".into()),
                ..config()
            };
            let destinations = agent.configured_processing_destinations().unwrap();
            assert_eq!(
                destinations
                    .iter()
                    .map(|d| d.endpoint.as_str())
                    .collect::<Vec<_>>(),
                expected,
                "{provider} {mode:?}"
            );
            assert_eq!(destinations[0], agent.processing_destination().unwrap());
            assert!(destinations.iter().all(|d| d.provider == provider));
            assert_eq!(destinations[0].model, "current-session-model");
            assert_eq!(destinations[0].account_id, agent.config.account_id);
        }
        agent.config = AgentConfig {
            provider: "openai".into(),
            endpoint: "https://api.openai.com/v1".into(),
            // Missing API credentials means neither media adapter is registered.
            ..config()
        };
        assert_eq!(agent.configured_processing_destinations().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn configured_brief_save_replaces_stale_policy_and_preserves_human_permissions() {
        use crate::investigation::{HumanDecision, ProcessingDestination, StepState};
        use sqlx::sqlite::SqliteConnectOptions;

        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("synthetic-source.img");
        std::fs::write(&source, b"synthetic evidence").unwrap();
        let db_path = temp.path().join("evidence.db");
        let pool = Arc::new(
            SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(
                    SqliteConnectOptions::new()
                        .filename(&db_path)
                        .create_if_missing(true),
                )
                .await
                .unwrap(),
        );
        sqlx::query("CREATE TABLE evidence (id INTEGER PRIMARY KEY, path TEXT NOT NULL)")
            .execute(&*pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO evidence (id, path) VALUES (7, ?)")
            .bind(source.to_str().unwrap())
            .execute(&*pool)
            .await
            .unwrap();
        let mut agent = agent(pool, "brief-policy-save", db_path);
        agent.image_path = source.to_str().unwrap().into();
        let session = AgentSession::open(agent).await.unwrap();
        let current = session.inner.agent.processing_destination().unwrap();
        let stale = ProcessingDestination {
            provider: "old-provider".into(),
            endpoint: "https://stale.invalid/v1".into(),
            model: "old-model".into(),
            authentication_mode: "subscription".into(),
            account_id: Some("old-account".into()),
        };
        let mut brief = session.case_template().unwrap();
        brief.objective = "Check synthetic source coverage".into();
        brief.processing_policy.allowed_destinations = vec![stale.clone()];

        // The original API used by CLI keeps an explicitly selected policy intact.
        let state = session.prepare_case(brief.clone()).await.unwrap();
        assert_eq!(
            state.brief.unwrap().processing_policy.allowed_destinations,
            vec![stale]
        );

        for external_tools in [false, true] {
            brief.processing_policy.allow_external_tools = external_tools;
            let state = session
                .prepare_case_with_configured_destinations(brief.clone())
                .await
                .unwrap();
            let saved = state.brief.as_ref().unwrap();
            assert_eq!(
                saved.processing_policy.allowed_destinations,
                vec![current.clone()]
            );
            assert_eq!(saved.processing_policy.allow_external_tools, external_tools);
            assert!(
                !state.brief_confirmed,
                "saving is not investigator approval"
            );
            let pending = state
                .steps
                .iter()
                .find(|s| s.state == StepState::PendingApproval)
                .unwrap();
            assert!(!pending
                .proposal
                .permitted_tools
                .iter()
                .any(|t| matches!(t.as_str(), "shell" | "describe_image" | "transcribe_audio")));
            assert!(session
                .inner
                .agent
                .investigation()
                .await
                .unwrap()
                .check_destination(&current)
                .await
                .is_err());
            session
                .decide_step(
                    &pending.proposal.id,
                    HumanDecision::Approve,
                    "Synthetic test approval",
                )
                .await
                .unwrap();
            session
                .inner
                .agent
                .investigation()
                .await
                .unwrap()
                .check_destination(&current)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn named_sessions_keep_history_isolated() {
        let pool = Arc::new(
            SqlitePoolOptions::new()
                .max_connections(1)
                .connect("sqlite::memory:")
                .await
                .expect("pool"),
        );
        let temp = tempfile::tempdir().expect("tempdir");
        let db_path = temp.path().join("evidence.db");
        let first = AgentSession::open(agent(pool.clone(), "session-one", db_path.clone()))
            .await
            .expect("first session");
        first
            .inner
            .agent
            .save_message(&Message::user("first finding"))
            .await
            .expect("save message");
        first
            .inner
            .history
            .write()
            .await
            .push(Message::user("first finding"));

        let second = AgentSession::open(agent(pool, "session-two", db_path))
            .await
            .expect("second session");
        assert_eq!(first.history().await.len(), 1);
        assert!(second.history().await.is_empty());
    }

    #[tokio::test]
    async fn rejects_unsafe_session_identifiers() {
        let pool = Arc::new(
            SqlitePoolOptions::new()
                .max_connections(1)
                .connect("sqlite::memory:")
                .await
                .expect("pool"),
        );
        let temp = tempfile::tempdir().expect("tempdir");
        let result = AgentSession::open(agent(
            pool,
            "../other-session",
            temp.path().join("evidence.db"),
        ))
        .await;
        assert!(result.is_err());
    }
}
