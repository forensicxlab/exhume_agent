use exhume_agent::{
    agent::{AgentToolContext, AgentToolProvider, ExhumeAgent},
    config::AgentConfig,
    investigation::{HumanDecision, ProcessingDestination, StepProposal, StepState, ToolStatus},
    policy::AgentOptions,
    session::{AgentSession, AgentSessionStatus},
};
use rig::{
    completion::ToolDefinition,
    tool::{Tool, ToolDyn},
};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
};

struct WaitingTool {
    started: Arc<Notify>,
}

impl Tool for WaitingTool {
    const NAME: &'static str = "wait_for_fixture";
    type Args = Value;
    type Output = Value;
    type Error = std::io::Error;

    async fn definition(&self, _: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.into(),
            description: "Wait for the synthetic fixture".into(),
            parameters: json!({"type":"object","properties":{}}),
        }
    }

    async fn call(&self, _: Value) -> Result<Value, Self::Error> {
        self.started.notify_one();
        std::future::pending().await
    }
}

struct FixtureTools {
    started: Arc<Notify>,
}

struct RebindingTool {
    pool: Arc<sqlx::SqlitePool>,
    replacement: String,
}

impl Tool for RebindingTool {
    const NAME: &'static str = "rebind_synthetic_index";
    type Args = Value;
    type Output = Value;
    type Error = sqlx::Error;

    async fn definition(&self, _: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.into(),
            description: "Simulate concurrent synthetic index replacement".into(),
            parameters: json!({"type":"object","properties":{}}),
        }
    }

    async fn call(&self, _: Value) -> Result<Value, Self::Error> {
        sqlx::query("UPDATE evidence SET path = ? WHERE id = 1")
            .bind(&self.replacement)
            .execute(self.pool.as_ref())
            .await?;
        Ok(json!({"status":"success","value":"received-before-binding-check"}))
    }
}

struct RebindingTools {
    replacement: String,
}

impl AgentToolProvider for RebindingTools {
    fn tools(&self, context: &AgentToolContext) -> Vec<Box<dyn ToolDyn>> {
        vec![Box::new(RebindingTool {
            pool: context.pool.clone(),
            replacement: self.replacement.clone(),
        })]
    }

    fn tool_destinations(&self, name: &str) -> Option<Vec<ProcessingDestination>> {
        (name == RebindingTool::NAME).then(Vec::new)
    }
}

impl AgentToolProvider for FixtureTools {
    fn tools(&self, _: &AgentToolContext) -> Vec<Box<dyn ToolDyn>> {
        vec![Box::new(WaitingTool {
            started: self.started.clone(),
        })]
    }

    fn tool_destinations(&self, name: &str) -> Option<Vec<ProcessingDestination>> {
        (name == WaitingTool::NAME).then(Vec::new)
    }
}

async fn receive_request(socket: &mut tokio::net::TcpStream) {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let count = socket.read(&mut chunk).await.unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&bytes[..end]);
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|s| s.trim().parse::<usize>().ok())
                })
                .unwrap();
            if bytes.len() >= end + 4 + length {
                return;
            }
        }
    }
}

async fn mock_tool_reply(tool_name: &'static str) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        receive_request(&mut socket).await;
        let body = json!({"model":"fixture","choices":[{"finish_reason":"tool_calls","message":{
            "content":null,"tool_calls":[{"id":"fixture-call","type":"function","function":{
                "name":tool_name,"arguments":"{}"}}]}}]})
        .to_string();
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
    });
    (endpoint, server)
}

#[tokio::test]
async fn close_cancels_inflight_tool_and_remains_closed_after_turn_cleanup() {
    let (endpoint, server) = mock_tool_reply(WaitingTool::NAME).await;
    let root = tempfile::tempdir().unwrap();
    let image = root.path().join("source.img");
    std::fs::write(&image, b"synthetic evidence").unwrap();
    let db = root.path().join("case.db");
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&db)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    exhume_indexer::ensure_tables(&pool).await.unwrap();
    exhume_indexer::ensure_evidence_row(&pool, 1, image.to_str().unwrap(), false)
        .await
        .unwrap();
    let config = AgentConfig {
        provider: "openai".into(),
        model: "fixture".into(),
        endpoint,
        api_key: "synthetic".into(),
        auth_mode: Default::default(),
        account_id: None,
        runtime_path: None,
        llm_endpoint: None,
        image_endpoint: None,
        audio_endpoint: None,
    };
    let started = Arc::new(Notify::new());
    let agent = ExhumeAgent::new_with_options(
        config,
        image.display().to_string(),
        db,
        Arc::new(pool.clone()),
        false,
        true,
        None,
        AgentOptions {
            session_id: "cancel-test".into(),
            ..Default::default()
        },
    )
    .with_tool_provider(Arc::new(FixtureTools {
        started: started.clone(),
    }));
    let session = AgentSession::open(agent).await.unwrap();
    session
        .submit("Review synthetic coverage", None)
        .await
        .unwrap();
    session
        .propose_steps(vec![StepProposal {
            id: "cancelled-step".into(),
            question: "Can an in-flight read be cancelled?".into(),
            rationale: "Exercise cancellation persistence with a synthetic read.".into(),
            evidence_ids: vec![1],
            permitted_tools: vec![WaitingTool::NAME.into()],
            recommended: true,
            limits: Default::default(),
            stop_conditions: vec!["Stop when cancelled".into()],
            estimated_effort: "One synthetic read".into(),
            limitations: vec![],
            tool_dependencies: Default::default(),
            source_selectors: Default::default(),
            capability_gap: None,
        }])
        .await
        .unwrap();
    session
        .decide_step(
            "cancelled-step",
            HumanDecision::Approve,
            "Approve the synthetic read",
        )
        .await
        .unwrap();
    let running = session.clone();
    let turn = tokio::spawn(async move {
        running
            .submit("Run approved step", Some("cancelled-turn".into()))
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), session.close())
        .await
        .unwrap()
        .unwrap();
    assert!(turn
        .await
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("cancelled"));
    server.await.unwrap();

    let snapshot = session.snapshot().await.unwrap();
    assert_eq!(snapshot.status, AgentSessionStatus::Closed);
    assert!(snapshot.active_turn_id.is_none());
    assert_eq!(
        snapshot.investigation.steps.last().unwrap().state,
        StepState::Interrupted
    );
    assert_eq!(snapshot.investigation.executions.len(), 1);
    assert_eq!(
        snapshot.investigation.executions[0]
            .outcome
            .as_ref()
            .unwrap()
            .status,
        ToolStatus::Unknown
    );
    assert_eq!(
        snapshot.investigation.revision,
        snapshot.investigation.exported_revision
    );
    let persisted: String =
        sqlx::query_scalar("SELECT status FROM agent_sessions WHERE id = 'cancel-test'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(persisted, "closed");
    let report = std::fs::read_to_string(snapshot.investigation.report_path).unwrap();
    assert!(report.contains("Unknown") || report.contains("unknown"));
    assert!(session.submit("/run", None).await.is_err());
    assert!(session
        .decide_step("cancelled-step", HumanDecision::Approve, "retry")
        .await
        .is_err());
}

#[tokio::test]
async fn source_rebinding_during_tool_preserves_raw_output_as_unknown() {
    let (endpoint, server) = mock_tool_reply(RebindingTool::NAME).await;
    let root = tempfile::tempdir().unwrap();
    let image = root.path().join("source.img");
    let replacement = root.path().join("replacement.img");
    std::fs::write(&image, b"synthetic selected evidence").unwrap();
    std::fs::write(&replacement, b"synthetic other evidence").unwrap();
    let db = root.path().join("case.db");
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&db)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    exhume_indexer::ensure_tables(&pool).await.unwrap();
    exhume_indexer::ensure_evidence_row(&pool, 1, image.to_str().unwrap(), false)
        .await
        .unwrap();
    let config = AgentConfig {
        provider: "openai".into(),
        model: "fixture".into(),
        endpoint,
        api_key: "synthetic".into(),
        auth_mode: Default::default(),
        account_id: None,
        runtime_path: None,
        llm_endpoint: None,
        image_endpoint: None,
        audio_endpoint: None,
    };
    let agent = ExhumeAgent::new_with_options(
        config,
        image.display().to_string(),
        db,
        Arc::new(pool),
        false,
        true,
        None,
        AgentOptions {
            session_id: "rebind-test".into(),
            ..Default::default()
        },
    )
    .with_tool_provider(Arc::new(RebindingTools {
        replacement: replacement.display().to_string(),
    }));
    let session = AgentSession::open(agent).await.unwrap();
    session
        .submit("Review synthetic coverage", None)
        .await
        .unwrap();
    session
        .propose_steps(vec![StepProposal {
            id: "rebound-step".into(),
            question: "Is index drift detected after a read?".into(),
            rationale: "Exercise source attribution after concurrent synthetic index replacement."
                .into(),
            evidence_ids: vec![1],
            permitted_tools: vec![RebindingTool::NAME.into()],
            recommended: true,
            limits: Default::default(),
            stop_conditions: vec!["Stop on index drift".into()],
            estimated_effort: "One synthetic read".into(),
            limitations: vec![],
            tool_dependencies: Default::default(),
            source_selectors: Default::default(),
            capability_gap: None,
        }])
        .await
        .unwrap();
    session
        .decide_step(
            "rebound-step",
            HumanDecision::Approve,
            "Approve the synthetic read",
        )
        .await
        .unwrap();
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        session.submit("Run approved step", None),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(error.to_string().contains("different evidence source"));
    server.await.unwrap();
    let state = session.investigation_snapshot().await.unwrap();
    assert_eq!(state.steps.last().unwrap().state, StepState::Interrupted);
    assert_eq!(state.executions.len(), 1);
    let outcome = state.executions[0].outcome.as_ref().unwrap();
    assert_eq!(outcome.status, ToolStatus::Unknown);
    assert!(outcome.output.contains("received-before-binding-check"));
    assert!(outcome
        .error
        .as_ref()
        .unwrap()
        .contains("different evidence source"));
    assert!(!outcome.coverage.complete);
    assert!(state.findings.is_empty());
    assert_eq!(state.revision, state.exported_revision);
    let log = std::fs::read_to_string(state.execution_log_path).unwrap();
    assert!(log.contains("received-before-binding-check"));
}
