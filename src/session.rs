use crate::agent::{message_text, ExhumeAgent};
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

    pub async fn submit(
        &self,
        instruction: impl Into<String>,
        requested_turn_id: Option<String>,
    ) -> Result<(String, String)> {
        let instruction = instruction.into().trim().to_string();
        if instruction.is_empty() {
            return Err(anyhow!("Investigation instruction cannot be empty"));
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
        let outcome = tokio::select! {
            _ = cancellation.cancelled() => TurnOutcome::Cancelled,
            result = tokio::time::timeout(timeout, self.inner.agent.chat(&history)) => {
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
        if self.inner.active_turn.lock().await.is_some() {
            return Err(anyhow!(
                "Cannot clear history while an agent turn is running"
            ));
        }
        self.inner.agent.clear_history().await?;
        self.inner.history.write().await.clear();
        Ok(())
    }

    pub async fn history(&self) -> Vec<Message> {
        self.inner.history.read().await.clone()
    }

    pub async fn close(&self) -> Result<()> {
        self.cancel(None).await;
        self.set_status(AgentSessionStatus::Closed).await
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
        })
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
        ) VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(&event.session_id)
    .bind(&event.turn_id)
    .bind(event.evidence_id)
    .bind(event.payload.event_type())
    .bind(event_json)
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
