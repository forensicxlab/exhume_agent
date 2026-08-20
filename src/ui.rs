use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};

pub const AGENT_EVENT_VERSION: u16 = 2;
const DEFAULT_EVENT_BUFFER: usize = 512;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecialistKind {
    Image,
    Audio,
    Sqlite,
}

impl SpecialistKind {
    pub fn label(&self) -> &'static str {
        match self {
            SpecialistKind::Image => "Image Specialist",
            SpecialistKind::Audio => "Audio Specialist",
            SpecialistKind::Sqlite => "SQLite Specialist",
        }
    }

    pub fn short_label(&self) -> &'static str {
        match self {
            SpecialistKind::Image => "image",
            SpecialistKind::Audio => "audio",
            SpecialistKind::Sqlite => "sqlite",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SpecialistUpdate {
    Started {
        file_id: u64,
    },
    Stage {
        message: String,
    },
    Finished {
        file_name: String,
        score: Option<i64>,
        summary: String,
        cached: bool,
    },
    Failed {
        error: String,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentEventPayload {
    Log {
        level: AgentLogLevel,
        message: String,
    },
    TurnStarted,
    TurnCompleted {
        response: String,
    },
    TurnCancelled,
    TurnFailed {
        error: String,
    },
    ToolCall {
        tool_name: String,
        tool_call_id: Option<String>,
        arguments: String,
    },
    ToolResult {
        tool_name: String,
        tool_call_id: Option<String>,
        result: String,
    },
    Specialist {
        kind: SpecialistKind,
        update: SpecialistUpdate,
    },
    ApprovalRequested {
        request_id: String,
        prompt: String,
    },
    ApprovalResolved {
        request_id: String,
        approved: bool,
    },
    ReportUpdated {
        export_path: Option<String>,
    },
}

impl AgentEventPayload {
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::Log { .. } => "log",
            Self::TurnStarted => "turn_started",
            Self::TurnCompleted { .. } => "turn_completed",
            Self::TurnCancelled => "turn_cancelled",
            Self::TurnFailed { .. } => "turn_failed",
            Self::ToolCall { .. } => "tool_call",
            Self::ToolResult { .. } => "tool_result",
            Self::Specialist { .. } => "specialist",
            Self::ApprovalRequested { .. } => "approval_requested",
            Self::ApprovalResolved { .. } => "approval_resolved",
            Self::ReportUpdated { .. } => "report_updated",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentEvent {
    pub version: u16,
    #[serde(default)]
    pub event_id: String,
    #[serde(default)]
    pub parent_event_id: Option<String>,
    #[serde(default)]
    pub tool_execution_id: Option<String>,
    pub session_id: String,
    pub turn_id: Option<String>,
    pub evidence_id: i64,
    pub timestamp_ms: u64,
    #[serde(flatten)]
    pub payload: AgentEventPayload,
}

pub struct ApprovalRequest {
    pub request_id: String,
    pub prompt: String,
    pub responder: oneshot::Sender<bool>,
}

pub enum UiEvent {
    Event(AgentEvent),
    ApprovalRequest {
        event: AgentEvent,
        request: ApprovalRequest,
    },
}

impl UiEvent {
    pub fn event(&self) -> &AgentEvent {
        match self {
            UiEvent::Event(event) => event,
            UiEvent::ApprovalRequest { event, .. } => event,
        }
    }
}

pub trait AgentEventSink: Send + Sync {
    fn emit(&self, event: AgentEvent) -> bool;

    fn request_approval(
        &self,
        event: AgentEvent,
        request_id: String,
        prompt: String,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;
}

struct ChannelEventSink {
    tx: mpsc::Sender<UiEvent>,
}

impl AgentEventSink for ChannelEventSink {
    fn emit(&self, event: AgentEvent) -> bool {
        if let Err(error) = self.tx.try_send(UiEvent::Event(event)) {
            tracing::warn!("Dropping agent UI event because the event buffer is full: {error}");
            false
        } else {
            true
        }
    }

    fn request_approval(
        &self,
        event: AgentEvent,
        request_id: String,
        prompt: String,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async move {
            let (response_tx, response_rx) = oneshot::channel();
            let request = ApprovalRequest {
                request_id,
                prompt,
                responder: response_tx,
            };
            if self
                .tx
                .send(UiEvent::ApprovalRequest { event, request })
                .await
                .is_err()
            {
                return false;
            }
            response_rx.await.unwrap_or(false)
        })
    }
}

#[derive(Clone)]
pub struct UiHandle {
    sink: Arc<dyn AgentEventSink>,
    session_id: Arc<str>,
    evidence_id: i64,
    turn_id: Arc<RwLock<Option<String>>>,
    supporting_event_ids: Arc<RwLock<Vec<String>>>,
}

impl UiHandle {
    pub fn channel() -> (Self, mpsc::Receiver<UiEvent>) {
        Self::channel_with_context("default", 1, DEFAULT_EVENT_BUFFER)
    }

    pub fn channel_with_context(
        session_id: impl Into<String>,
        evidence_id: i64,
        capacity: usize,
    ) -> (Self, mpsc::Receiver<UiEvent>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Self::new(Arc::new(ChannelEventSink { tx }), session_id, evidence_id),
            rx,
        )
    }

    pub fn new(
        sink: Arc<dyn AgentEventSink>,
        session_id: impl Into<String>,
        evidence_id: i64,
    ) -> Self {
        Self {
            sink,
            session_id: Arc::from(session_id.into()),
            evidence_id,
            turn_id: Arc::new(RwLock::new(None)),
            supporting_event_ids: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn evidence_id(&self) -> i64 {
        self.evidence_id
    }

    pub fn set_turn_id(&self, turn_id: Option<String>) {
        if let Ok(mut current) = self.turn_id.write() {
            *current = turn_id;
        }
        if let Ok(mut event_ids) = self.supporting_event_ids.write() {
            event_ids.clear();
        }
    }

    pub fn current_turn_id(&self) -> Option<String> {
        self.turn_id.read().ok().and_then(|turn| turn.clone())
    }

    fn envelope_with_context(
        &self,
        payload: AgentEventPayload,
        parent_event_id: Option<String>,
        tool_execution_id: Option<String>,
    ) -> AgentEvent {
        AgentEvent {
            version: AGENT_EVENT_VERSION,
            event_id: unique_id("event"),
            parent_event_id,
            tool_execution_id,
            session_id: self.session_id.to_string(),
            turn_id: self.current_turn_id(),
            evidence_id: self.evidence_id,
            timestamp_ms: now_ms(),
            payload,
        }
    }

    fn envelope(&self, payload: AgentEventPayload) -> AgentEvent {
        self.envelope_with_context(payload, None, None)
    }

    pub fn emit(&self, payload: AgentEventPayload) -> String {
        let event = self.envelope(payload);
        let event_id = event.event_id.clone();
        if self.sink.emit(event) {
            event_id
        } else {
            String::new()
        }
    }

    pub fn log<S: Into<String>>(&self, message: S) {
        self.log_with_level(AgentLogLevel::Info, message);
    }

    pub fn log_with_level<S: Into<String>>(&self, level: AgentLogLevel, message: S) {
        self.emit(AgentEventPayload::Log {
            level,
            message: message.into(),
        });
    }

    pub fn specialist(&self, kind: SpecialistKind, update: SpecialistUpdate) {
        self.emit(AgentEventPayload::Specialist { kind, update });
    }

    pub fn tool_call(
        &self,
        tool_name: impl Into<String>,
        tool_call_id: Option<String>,
        tool_execution_id: impl Into<String>,
        arguments: impl Into<String>,
    ) -> String {
        let tool_execution_id = tool_execution_id.into();
        let event = self.envelope_with_context(
            AgentEventPayload::ToolCall {
                tool_name: tool_name.into(),
                tool_call_id,
                arguments: arguments.into(),
            },
            None,
            Some(tool_execution_id),
        );
        let event_id = event.event_id.clone();
        if self.sink.emit(event) {
            event_id
        } else {
            String::new()
        }
    }

    pub fn tool_result(
        &self,
        tool_name: impl Into<String>,
        tool_call_id: Option<String>,
        tool_execution_id: impl Into<String>,
        parent_event_id: Option<String>,
        result: impl Into<String>,
    ) -> String {
        let event = self.envelope_with_context(
            AgentEventPayload::ToolResult {
                tool_name: tool_name.into(),
                tool_call_id,
                result: result.into(),
            },
            parent_event_id,
            Some(tool_execution_id.into()),
        );
        let event_id = event.event_id.clone();
        if self.sink.emit(event) {
            event_id
        } else {
            String::new()
        }
    }

    pub fn register_supporting_event(&self, event_id: impl Into<String>) {
        if let Ok(mut event_ids) = self.supporting_event_ids.write() {
            let event_id = event_id.into();
            if !event_ids.contains(&event_id) {
                event_ids.push(event_id);
            }
        }
    }

    pub fn supporting_event_ids(&self) -> Vec<String> {
        self.supporting_event_ids
            .read()
            .map(|event_ids| event_ids.clone())
            .unwrap_or_default()
    }

    pub async fn request_approval<S: Into<String>>(&self, prompt: S) -> bool {
        let request_id = unique_id("approval");
        let prompt = prompt.into();
        let event = self.envelope(AgentEventPayload::ApprovalRequested {
            request_id: request_id.clone(),
            prompt: prompt.clone(),
        });
        let approved = self
            .sink
            .request_approval(event, request_id.clone(), prompt)
            .await;
        self.emit(AgentEventPayload::ApprovalResolved {
            request_id,
            approved,
        });
        approved
    }

    pub fn report_updated(&self) {
        self.report_updated_at(None);
    }

    pub fn report_updated_at(&self, export_path: Option<String>) {
        self.emit(AgentEventPayload::ReportUpdated { export_path });
    }
}

pub fn unique_id(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    format!(
        "{prefix}-{}-{}",
        now_ms(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{AgentEventPayload, UiEvent, UiHandle};

    #[tokio::test]
    async fn emits_serializable_scoped_events() {
        let (ui, mut receiver) = UiHandle::channel_with_context("session-1", 42, 8);
        ui.set_turn_id(Some("turn-1".to_string()));
        let call_event_id = ui.tool_call(
            "query_index",
            Some("call-1".to_string()),
            "execution-1",
            "{\"sql\":\"SELECT 1\"}",
        );
        ui.tool_result(
            "query_index",
            Some("call-1".to_string()),
            "execution-1",
            Some(call_event_id.clone()),
            "{\"result\":\"1\",\"error\":null}",
        );

        let UiEvent::Event(event) = receiver.recv().await.expect("event") else {
            panic!("expected regular event");
        };
        assert_eq!(event.session_id, "session-1");
        assert_eq!(event.evidence_id, 42);
        assert_eq!(event.turn_id.as_deref(), Some("turn-1"));
        assert_eq!(event.version, 2);
        assert_eq!(event.tool_execution_id.as_deref(), Some("execution-1"));
        assert!(!event.event_id.is_empty());
        assert!(matches!(event.payload, AgentEventPayload::ToolCall { .. }));
        assert!(serde_json::to_string(&event).is_ok());

        let UiEvent::Event(result) = receiver.recv().await.expect("result event") else {
            panic!("expected regular event");
        };
        assert_eq!(
            result.parent_event_id.as_deref(),
            Some(call_event_id.as_str())
        );
        assert_eq!(result.tool_execution_id.as_deref(), Some("execution-1"));
    }

    #[test]
    fn deserializes_legacy_version_one_events() {
        let event: super::AgentEvent = serde_json::from_str(
            r#"{
                "version": 1,
                "session_id": "legacy",
                "turn_id": null,
                "evidence_id": 1,
                "timestamp_ms": 1,
                "type": "turn_started"
            }"#,
        )
        .expect("legacy event");
        assert!(event.event_id.is_empty());
        assert!(event.parent_event_id.is_none());
        assert!(event.tool_execution_id.is_none());
    }

    #[tokio::test]
    async fn approval_round_trip_emits_resolution() {
        let (ui, mut receiver) = UiHandle::channel_with_context("session-1", 42, 8);
        let request_task = tokio::spawn({
            let ui = ui.clone();
            async move { ui.request_approval("Allow?").await }
        });

        let UiEvent::ApprovalRequest { request, .. } =
            receiver.recv().await.expect("approval request")
        else {
            panic!("expected approval request");
        };
        request.responder.send(true).expect("approval response");
        assert!(request_task.await.expect("request task"));

        let UiEvent::Event(event) = receiver.recv().await.expect("resolution") else {
            panic!("expected resolution event");
        };
        assert!(matches!(
            event.payload,
            AgentEventPayload::ApprovalResolved { approved: true, .. }
        ));
    }
}
