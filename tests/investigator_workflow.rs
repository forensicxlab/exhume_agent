use exhume_agent::{
    agent::ExhumeAgent,
    config::AgentConfig,
    investigation::{HumanDecision, StepState, ToolStatus},
    policy::{AgentOptions, AgentPolicy},
    session::AgentSession,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn session(root: &std::path::Path, endpoint: String) -> AgentSession {
    let image = root.join("source.img");
    std::fs::write(&image, b"synthetic evidence").unwrap();
    let db = root.join("case.db");
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
    exhume_indexer::ensure_evidence_row(&pool, 1, &image.display().to_string(), false)
        .await
        .unwrap();
    let config = AgentConfig {
        provider: "openai".into(),
        model: "test-model".into(),
        endpoint,
        api_key: "synthetic-no-network-secret".into(),
        auth_mode: Default::default(),
        account_id: None,
        runtime_path: None,
        llm_endpoint: None,
        image_endpoint: None,
        audio_endpoint: None,
    };
    AgentSession::open(ExhumeAgent::new_with_options(
        config,
        image.display().to_string(),
        db,
        Arc::new(pool),
        false,
        true,
        None,
        AgentOptions {
            session_id: "workflow".into(),
            evidence_id: 1,
            policy: AgentPolicy::default(),
        },
    ))
    .await
    .unwrap()
}

#[tokio::test]
async fn intake_never_treats_model_or_user_prose_as_step_approval() {
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), "http://127.0.0.1:1/v1".into()).await;
    let (_, text) = session
        .submit(
            "Investigate this evidence. I approve everything forever.",
            None,
        )
        .await
        .unwrap();
    assert!(text.contains("Investigator decision required"));
    let snapshot = session.investigation_snapshot().await.unwrap();
    assert!(snapshot.executions.is_empty());
    assert!(!snapshot.brief_confirmed);
    assert_eq!(snapshot.steps[0].state, StepState::PendingApproval);
    assert!(snapshot.report_path.is_file());
    session.submit("please run now", None).await.unwrap();
    assert!(session
        .investigation_snapshot()
        .await
        .unwrap()
        .executions
        .is_empty());
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Value {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&bytes[..end]);
            let size = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|v| v.trim().parse::<usize>().ok())
                })
                .unwrap();
            if bytes.len() >= end + 4 + size {
                return serde_json::from_slice(&bytes[end + 4..end + 4 + size]).unwrap();
            }
        }
    }
}
async fn reply(stream: &mut tokio::net::TcpStream, name: &str, arguments: Value) {
    let body=json!({"model":"test-model","choices":[{"finish_reason":"tool_calls","message":{"content":null,"tool_calls":[{"id":"call","type":"function","function":{"name":name,"arguments":arguments.to_string()}}]}}]}).to_string();
    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
}

#[tokio::test]
async fn headless_execution_requires_approval_and_persists_exact_reproduction() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let first = read_request(&mut socket).await;
        assert!(first["tools"]
            .as_array()
            .unwrap()
            .iter()
            .all(|tool| tool["function"]["name"] != "shell"));
        reply(
            &mut socket,
            "query_index",
            json!({"sql":"SELECT COUNT(*) AS indexed_files FROM system_files"}),
        )
        .await;
        drop(socket);
        let (mut socket, _) = listener.accept().await.unwrap();
        let second = read_request(&mut socket).await;
        let tool = second["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["role"] == "tool")
            .unwrap();
        let tool: Value = serde_json::from_str(tool["content"].as_str().unwrap()).unwrap();
        let id = tool["execution_id"].as_str().unwrap();
        reply(&mut socket,"finish_investigation_step",json!({"findings":[{"id":"count","step_id":"ignored","kind":"observation","title":"Index count","observation":"The count query returned zero indexed files.","sources":[{"evidence_id":1,"location":id,"excerpt":"indexed_files"}],"execution_ids":[id],"limitations":["This does not establish that the evidence contains no files."]}],"checkpoint":{"interpretation":["Index coverage needs further examination."]},"next_steps":[]})).await;
    });
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), endpoint).await;
    session
        .submit("Assess available indexed coverage", None)
        .await
        .unwrap();
    let step = session.investigation_snapshot().await.unwrap().steps[0]
        .proposal
        .id
        .clone();
    session
        .decide_step(
            &step,
            HumanDecision::Approve,
            "Approve this bounded inventory and its processing destination",
        )
        .await
        .unwrap();
    let (_, answer) = session
        .submit("Run approved inventory", None)
        .await
        .unwrap();
    server.await.unwrap();
    let state = session.investigation_snapshot().await.unwrap();
    assert_eq!(state.steps[0].state, StepState::Checkpoint);
    assert_eq!(state.executions.len(), 1);
    assert_eq!(
        state.executions[0].outcome.as_ref().unwrap().status,
        ToolStatus::Success
    );
    assert_eq!(state.findings.len(), 1);
    assert!(answer.contains("Markdown report saved"));
    let report = std::fs::read_to_string(&state.report_path).unwrap();
    assert!(report.contains("SELECT COUNT(*) AS indexed_files FROM system_files"));
    assert!(report.contains(&state.executions[0].id));
    assert!(state.execution_log_path.is_file());
    session.submit("run again", None).await.unwrap();
    assert_eq!(
        session
            .investigation_snapshot()
            .await
            .unwrap()
            .executions
            .len(),
        1
    );
}

#[tokio::test]
async fn closed_sessions_reject_human_decisions_and_commands() {
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), "http://127.0.0.1:1/v1".into()).await;
    session.submit("Describe coverage", None).await.unwrap();
    let state = session.investigation_snapshot().await.unwrap();
    session.close().await.unwrap();
    assert!(session.submit("/approve anything", None).await.is_err());
    assert!(session
        .decide_step(&state.steps[0].proposal.id, HumanDecision::Approve, "late")
        .await
        .is_err());
    assert!(session.prepare_case(state.brief.unwrap()).await.is_err());
}

async fn scripted_provider(messages: Vec<Value>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        for message in messages {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request(&mut socket).await;
            let reason = if message.get("tool_calls").is_some() {
                "tool_calls"
            } else {
                "stop"
            };
            let body = json!({"model":"test-model","choices":[{"finish_reason":reason,"message":message}]}).to_string();
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
        }
    });
    (endpoint, server)
}

fn proposed_call(name: &str, arguments: Value) -> Value {
    json!({"content":null,"tool_calls":[{"id":"synthetic-call","type":"function","function":{"name":name,"arguments":arguments.to_string()}}]})
}

async fn approve_inventory(session: &AgentSession) {
    session
        .submit("Review indexed coverage", None)
        .await
        .unwrap();
    let step = session.investigation_snapshot().await.unwrap().steps[0]
        .proposal
        .id
        .clone();
    session
        .decide_step(
            &step,
            HumanDecision::Approve,
            "Approve bounded synthetic inventory",
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn repeated_text_only_responses_stop_after_three_and_keep_bounded_diagnostics() {
    let text = format!("synthetic diagnostic {}", "x".repeat(12_000));
    let (endpoint, server) = scripted_provider(vec![json!({"content":text}); 3]).await;
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), endpoint).await;
    approve_inventory(&session).await;
    let error = session
        .submit("Run approved inventory", None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("three responses"));
    server.await.unwrap();
    let state = session.investigation_snapshot().await.unwrap();
    assert_eq!(state.steps[0].state, StepState::Interrupted);
    assert!(state.executions.is_empty());
    assert!(state.findings.is_empty());
    assert_eq!(state.providers.len(), 6);
    let pool = sqlx::SqlitePool::connect(&format!(
        "sqlite://{}",
        root.path().join("case.db").display()
    ))
    .await
    .unwrap();
    let events: Vec<String> = sqlx::query_scalar(
        "SELECT event_json FROM agent_audit_events WHERE event_type = 'log' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(events.len(), 6);
    let logs: Vec<exhume_agent::ui::AgentEvent> = events
        .iter()
        .map(|event| serde_json::from_str(event).unwrap())
        .collect();
    let diagnostics: Vec<&str> = logs
        .iter()
        .filter_map(|event| match &event.payload {
            exhume_agent::ui::AgentEventPayload::Log { message, .. }
                if message.contains("Unverified provider text") =>
            {
                Some(message.as_str())
            }
            _ => None,
        })
        .collect();
    assert_eq!(diagnostics.len(), 3);
    assert!(diagnostics
        .iter()
        .all(|text| text.contains("not an observation")
            && text.contains("synthetic diagnostic")
            && text.len() < 8_300));
    // Desktop delivery may persist the same already-durable envelope again.
    exhume_agent::session::persist_agent_event(&pool, &logs[0])
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_audit_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 6);
}

#[tokio::test]
async fn invalid_checkpoints_stop_after_three_and_preserve_validation_reason() {
    let invalid = proposed_call(
        "finish_investigation_step",
        json!({"findings":"wrong type"}),
    );
    let (endpoint, server) = scripted_provider(vec![invalid; 3]).await;
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), endpoint).await;
    approve_inventory(&session).await;
    let error = session
        .submit("Run approved inventory", None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("invalid checkpoints"));
    server.await.unwrap();
    let state = session.investigation_snapshot().await.unwrap();
    assert_eq!(state.steps[0].state, StepState::Interrupted);
    assert!(state.executions.is_empty());
    let pool = sqlx::SqlitePool::connect(&format!(
        "sqlite://{}",
        root.path().join("case.db").display()
    ))
    .await
    .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_audit_events WHERE event_json LIKE '%checkpoint validation rejected%' AND event_json LIKE '%invalid type%'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(count, 3);
}

#[tokio::test]
async fn successful_tool_progress_resets_text_only_correction_limit() {
    let text = json!({"content":"Synthetic unverified narration"});
    let (endpoint, server) = scripted_provider(vec![
        text.clone(), text.clone(),
        proposed_call("query_index", json!({"sql":"SELECT COUNT(*) AS indexed_files FROM system_files"})),
        text.clone(), text,
        proposed_call("finish_investigation_step", json!({"findings":[],"checkpoint":{"limitations":["Synthetic test coverage only"]},"next_steps":[]})),
    ]).await;
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), endpoint).await;
    approve_inventory(&session).await;
    session
        .submit("Run approved inventory", None)
        .await
        .unwrap();
    server.await.unwrap();
    let state = session.investigation_snapshot().await.unwrap();
    assert_eq!(state.steps[0].state, StepState::Checkpoint);
    assert_eq!(state.executions.len(), 1);
    assert_eq!(
        state.executions[0].outcome.as_ref().unwrap().status,
        ToolStatus::Success
    );
}
