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
        "#,
    )
    .execute(pool)
    .await?;

    report::ensure_tables(pool).await?;
    Ok(())
}
