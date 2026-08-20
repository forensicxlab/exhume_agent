pub mod agent;
pub mod config;
pub mod db_helpers;
pub mod evidence_io;
pub mod paths;
pub mod policy;
pub mod report;
pub mod session;
pub mod tools;
#[cfg(feature = "tui")]
pub mod tui;
pub mod ui;

use anyhow::Result;
use sqlx::SqlitePool;

pub async fn ensure_agent_tables(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS conversations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            content     TEXT NOT NULL,
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS investigation_notes (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id      INTEGER,
            path         TEXT,
            note         TEXT NOT NULL,
            significance INTEGER NOT NULL DEFAULT 0,
            created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );

        CREATE TABLE IF NOT EXISTS agent_sessions (
            id                TEXT PRIMARY KEY,
            evidence_id       INTEGER NOT NULL,
            provider          TEXT NOT NULL,
            model             TEXT NOT NULL,
            reporting_enabled INTEGER NOT NULL DEFAULT 0,
            status            TEXT NOT NULL DEFAULT 'idle',
            created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at        DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS agent_messages (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id   TEXT NOT NULL,
            turn_id      TEXT,
            role         TEXT NOT NULL,
            content      TEXT NOT NULL,
            created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES agent_sessions(id)
        );

        CREATE INDEX IF NOT EXISTS idx_agent_messages_session
            ON agent_messages(session_id, id);

        CREATE TABLE IF NOT EXISTS agent_audit_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id   TEXT NOT NULL,
            turn_id      TEXT,
            evidence_id  INTEGER NOT NULL,
            event_type   TEXT NOT NULL,
            event_json   TEXT NOT NULL,
            created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_agent_audit_session
            ON agent_audit_events(session_id, id);
        "#,
    )
    .execute(pool)
    .await?;

    report::ensure_tables(pool).await?;
    Ok(())
}
