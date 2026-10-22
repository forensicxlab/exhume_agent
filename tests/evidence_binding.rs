use exhume_agent::{
    agent::ExhumeAgent,
    config::AgentConfig,
    investigation::{HumanDecision, StepState},
    policy::{AgentOptions, AgentPolicy},
    session::AgentSession,
};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

async fn fixture(root: &Path) -> (PathBuf, PathBuf, SqlitePool) {
    let image = root.join("source.img");
    std::fs::write(&image, b"synthetic evidence").unwrap();
    let db = root.join("case.db");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&db)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    exhume_indexer::ensure_tables(&pool).await.unwrap();
    exhume_indexer::ensure_evidence_row(&pool, 1, image.to_str().unwrap(), false)
        .await
        .unwrap();
    (image, db, pool)
}

fn agent(image: &Path, db: &Path, pool: &SqlitePool, evidence_id: i64) -> ExhumeAgent {
    let config = AgentConfig {
        provider: "openai".into(),
        model: "synthetic".into(),
        endpoint: "http://127.0.0.1:1/v1".into(),
        api_key: "synthetic".into(),
        auth_mode: Default::default(),
        account_id: None,
        runtime_path: None,
        llm_endpoint: None,
        image_endpoint: None,
        audio_endpoint: None,
    };
    ExhumeAgent::new_with_options(
        config,
        image.display().to_string(),
        db.into(),
        Arc::new(pool.clone()),
        false,
        true,
        None,
        AgentOptions {
            session_id: "binding".into(),
            evidence_id,
            policy: AgentPolicy::default(),
        },
    )
}

async fn prepare(agent: &ExhumeAgent) -> anyhow::Result<()> {
    let mut brief = agent.case_template()?;
    brief.objective = "Review selected source coverage".into();
    agent.prepare_case(brief).await?;
    Ok(())
}

#[tokio::test]
async fn session_cannot_be_relabelled_to_another_evidence() {
    let root = tempfile::tempdir().unwrap();
    let (image, db, pool) = fixture(root.path()).await;
    agent(&image, &db, &pool, 1).ensure_session().await.unwrap();
    let error = agent(&image, &db, &pool, 2)
        .ensure_session()
        .await
        .unwrap_err();
    assert!(error.to_string().contains("belongs to another evidence"));
    let id: i64 = sqlx::query_scalar("SELECT evidence_id FROM agent_sessions WHERE id = 'binding'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(id, 1);
    // Same source resumption remains valid.
    agent(&image, &db, &pool, 1).ensure_session().await.unwrap();
}

#[tokio::test]
async fn intake_rejects_missing_mismatched_and_mixed_evidence_metadata() {
    let root = tempfile::tempdir().unwrap();
    let (image, db, pool) = fixture(root.path()).await;
    let selected = agent(&image, &db, &pool, 1);
    let other = root.path().join("other.img");
    std::fs::write(&other, b"different synthetic evidence").unwrap();
    sqlx::query("UPDATE evidence SET path = ?")
        .bind(other.to_str().unwrap())
        .execute(&pool)
        .await
        .unwrap();
    assert!(prepare(&selected)
        .await
        .unwrap_err()
        .to_string()
        .contains("different evidence source"));
    sqlx::query("UPDATE evidence SET path = ?, id = 2")
        .bind(image.to_str().unwrap())
        .execute(&pool)
        .await
        .unwrap();
    assert!(prepare(&selected)
        .await
        .unwrap_err()
        .to_string()
        .contains("selected evidence metadata"));
    exhume_indexer::ensure_evidence_row(&pool, 1, image.to_str().unwrap(), false)
        .await
        .unwrap();
    assert!(prepare(&selected)
        .await
        .unwrap_err()
        .to_string()
        .contains("selected evidence metadata"));
    sqlx::query("DELETE FROM evidence")
        .execute(&pool)
        .await
        .unwrap();
    assert!(prepare(&selected)
        .await
        .unwrap_err()
        .to_string()
        .contains("selected evidence metadata"));
    assert!(selected
        .investigation()
        .await
        .unwrap()
        .snapshot()
        .await
        .unwrap()
        .providers
        .is_empty());
}

#[tokio::test]
async fn orphan_or_unbound_rows_are_rejected_even_with_correct_source_metadata() {
    let root = tempfile::tempdir().unwrap();
    let (image, db, pool) = fixture(root.path()).await;
    let selected = agent(&image, &db, &pool, 1);
    sqlx::query("INSERT INTO partitions (evidence_id, kind) VALUES (77, 'logical')")
        .execute(&pool)
        .await
        .unwrap();
    assert!(prepare(&selected)
        .await
        .unwrap_err()
        .to_string()
        .contains("table partitions"));
    sqlx::query("DELETE FROM partitions")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE custom_records (evidence_id INTEGER, content TEXT)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO custom_records VALUES (NULL, 'unattributed')")
        .execute(&pool)
        .await
        .unwrap();
    assert!(prepare(&selected)
        .await
        .unwrap_err()
        .to_string()
        .contains("table custom_records"));
    sqlx::query("UPDATE custom_records SET evidence_id = 1")
        .execute(&pool)
        .await
        .unwrap();
    prepare(&selected).await.unwrap();
}

#[tokio::test]
async fn caller_pool_must_be_the_database_that_tools_will_open() {
    let root = tempfile::tempdir().unwrap();
    let (image, _, pool) = fixture(root.path()).await;
    let second = root.path().join("different.db");
    std::fs::write(&second, b"").unwrap();
    let selected = agent(&image, &second, &pool, 1);
    assert!(prepare(&selected)
        .await
        .unwrap_err()
        .to_string()
        .contains("pool does not match"));
}

#[tokio::test]
async fn changed_index_binding_interrupts_approval_before_provider_request() {
    let root = tempfile::tempdir().unwrap();
    let (image, db, pool) = fixture(root.path()).await;
    let session = AgentSession::open(agent(&image, &db, &pool, 1))
        .await
        .unwrap();
    session
        .submit("Describe available coverage", None)
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
            "Approve selected source inventory",
        )
        .await
        .unwrap();
    sqlx::query("INSERT INTO partitions (evidence_id, kind) VALUES (2, 'logical')")
        .execute(&pool)
        .await
        .unwrap();
    let error = session.submit("Run approved step", None).await.unwrap_err();
    assert!(error.to_string().contains("outside the selected evidence"));
    let state = session.investigation_snapshot().await.unwrap();
    assert_eq!(state.steps[0].state, StepState::Interrupted);
    assert!(state.executions.is_empty());
    assert!(state.providers.is_empty());
}
