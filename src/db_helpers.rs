use log::info;
use sqlx::{Row, SqlitePool};

/// Ensures an entry exists in the `artifacts` table for the AI specialist results.
pub async fn ensure_ai_artifact(
    pool: &SqlitePool,
    evidence_id: i64,
    partition_id: i64,
    file_id: i64,
    name: &str,
) -> Result<i64, sqlx::Error> {
    // Check if it already exists
    let existing =
        sqlx::query("SELECT id FROM artifacts WHERE file_id = ? AND evidence_id = ? AND name = ?")
            .bind(file_id)
            .bind(evidence_id)
            .bind(name)
            .fetch_optional(pool)
            .await?;

    if let Some(row) = existing {
        return Ok(row.get(0));
    }

    // Otherwise create it
    let res = sqlx::query(
        r#"INSERT INTO artifacts (evidence_id, file_id, partition_id, name, description, parser, tag, category)
           VALUES (?, ?, ?, ?, 'AI-generated analysis summary', 'ai_specialist', 'AI', 'Analysis')
           RETURNING id"#
    )
    .bind(evidence_id)
    .bind(file_id)
    .bind(partition_id)
    .bind(name)
    .fetch_one(pool)
    .await?;

    Ok(res.get(0))
}

/// Stores the specialist's text and JSON interpretation back into `artifact_objects`.
pub async fn store_specialist_result(
    pool: &SqlitePool,
    evidence_id: i64,
    partition_id: i64,
    file_id: i64,
    artifact_id: i64,
    file_name: &str,
    kind: &str,
    text: Option<&str>,
    json_val: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO artifact_objects (evidence_id, partition_id, artifact_id, file_id, parser, kind, text, json)
         VALUES (?, ?, ?, ?, 'ai_specialist', ?, ?, ?)"
    )
    .bind(evidence_id)
    .bind(partition_id)
    .bind(artifact_id)
    .bind(file_id)
    .bind(kind)
    .bind(text)
    .bind(json_val.to_string())
    .execute(pool)
    .await?;

    info!(
        "Saved specialist output '{}' for file '{}' into database.",
        kind, file_name
    );
    Ok(())
}
