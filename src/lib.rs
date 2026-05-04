pub mod agent;
pub mod config;
pub mod db_helpers;
pub mod evidence_io;
pub mod paths;
pub mod report;
pub mod tools;
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
        "#,
    )
    .execute(pool)
    .await?;

    report::ensure_tables(pool).await?;
    Ok(())
}
