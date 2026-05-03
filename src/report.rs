use crate::paths;
use anyhow::{anyhow, Result};
use sqlx::{Row, SqlitePool};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct ReportMode {
    pub enabled: bool,
    pub export_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ReportUpdateInput {
    pub section: String,
    pub title: String,
    pub summary: String,
    pub details_markdown: String,
    pub methodology_steps: Vec<String>,
    pub supporting_evidence: Vec<String>,
}

#[derive(Clone, Debug)]
struct ReportStats {
    file_count: i64,
    directory_count: i64,
    identified_file_count: i64,
    artifact_count: i64,
    artifact_object_count: i64,
    partition_count: i64,
}

pub async fn ensure_tables(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS digital_reports (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id     INTEGER NOT NULL UNIQUE,
            title           TEXT NOT NULL,
            target_path     TEXT NOT NULL,
            target_type     TEXT NOT NULL,
            markdown        TEXT NOT NULL,
            export_path     TEXT NOT NULL,
            created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS report_updates (
            id                          INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id                   INTEGER NOT NULL,
            section                     TEXT NOT NULL,
            title                       TEXT NOT NULL,
            summary                     TEXT NOT NULL,
            details_markdown            TEXT NOT NULL,
            methodology_steps_json      TEXT NOT NULL,
            supporting_evidence_json    TEXT NOT NULL,
            created_at                  DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn current_evidence_id(pool: &SqlitePool) -> Result<i64> {
    if let Some(evidence_id) =
        sqlx::query_scalar::<_, i64>("SELECT id FROM evidence ORDER BY id LIMIT 1")
            .fetch_optional(pool)
            .await?
    {
        return Ok(evidence_id);
    }

    if let Some(evidence_id) = sqlx::query_scalar::<_, i64>(
        "SELECT DISTINCT evidence_id FROM system_files ORDER BY evidence_id LIMIT 1",
    )
    .fetch_optional(pool)
    .await?
    {
        return Ok(evidence_id);
    }

    Err(anyhow!("No evidence found in the database"))
}

pub fn default_export_path(
    db_path: &Path,
    target_path: &str,
    is_folder: bool,
    is_logical: bool,
) -> PathBuf {
    paths::default_report_export_path(db_path, target_path, is_folder, is_logical)
}

pub async fn initialize_report(
    pool: &SqlitePool,
    db_path: &Path,
    target_path: &str,
    is_folder: bool,
    is_logical: bool,
) -> Result<ReportMode> {
    ensure_tables(pool).await?;
    let evidence_id = current_evidence_id(pool).await?;

    let target_type = if is_folder {
        "Folder"
    } else if is_logical {
        "Logical volume"
    } else {
        "Disk image"
    };
    let export_path = default_export_path(db_path, target_path, is_folder, is_logical);

    let report_id = sqlx::query(
        r#"
        INSERT INTO digital_reports (evidence_id, title, target_path, target_type, markdown, export_path)
        VALUES (?, ?, ?, ?, '', ?)
        ON CONFLICT(evidence_id) DO UPDATE SET
            title = excluded.title,
            target_path = excluded.target_path,
            target_type = excluded.target_type,
            export_path = excluded.export_path,
            updated_at = CURRENT_TIMESTAMP
        RETURNING id
        "#,
    )
    .bind(evidence_id)
    .bind("Digital Forensics Report")
    .bind(target_path)
    .bind(target_type)
    .bind(export_path.to_string_lossy().to_string())
    .fetch_one(pool)
    .await?
    .get::<i64, _>("id");

    rebuild_report(pool, report_id).await?;

    Ok(ReportMode {
        enabled: true,
        export_path,
    })
}

pub async fn append_report_update(pool: &SqlitePool, input: ReportUpdateInput) -> Result<()> {
    ensure_tables(pool).await?;
    let evidence_id = current_evidence_id(pool).await?;

    let report_id: i64 = sqlx::query_scalar("SELECT id FROM digital_reports WHERE evidence_id = ?")
        .bind(evidence_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow!("Digital report has not been initialized"))?;

    sqlx::query(
        r#"
        INSERT INTO report_updates (
            report_id,
            section,
            title,
            summary,
            details_markdown,
            methodology_steps_json,
            supporting_evidence_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(report_id)
    .bind(input.section)
    .bind(input.title)
    .bind(input.summary)
    .bind(input.details_markdown)
    .bind(serde_json::to_string(&input.methodology_steps)?)
    .bind(serde_json::to_string(&input.supporting_evidence)?)
    .execute(pool)
    .await?;

    rebuild_report(pool, report_id).await
}

pub async fn load_markdown(pool: &SqlitePool) -> Result<Option<String>> {
    ensure_tables(pool).await?;
    let evidence_id = current_evidence_id(pool).await?;

    let markdown = sqlx::query_scalar("SELECT markdown FROM digital_reports WHERE evidence_id = ?")
        .bind(evidence_id)
        .fetch_optional(pool)
        .await?;

    Ok(markdown)
}

async fn rebuild_report(pool: &SqlitePool, report_id: i64) -> Result<()> {
    let report_row = sqlx::query(
        "SELECT title, target_path, target_type, export_path FROM digital_reports WHERE id = ?",
    )
    .bind(report_id)
    .fetch_one(pool)
    .await?;

    let title: String = report_row.get("title");
    let target_path: String = report_row.get("target_path");
    let target_type: String = report_row.get("target_type");
    let export_path: String = report_row.get("export_path");

    let stats = gather_stats(pool).await?;
    let updates = sqlx::query(
        r#"
        SELECT section, title, summary, details_markdown, methodology_steps_json, supporting_evidence_json, created_at
        FROM report_updates
        WHERE report_id = ?
        ORDER BY id ASC
        "#,
    )
    .bind(report_id)
    .fetch_all(pool)
    .await?;

    let mut markdown = String::new();
    markdown.push_str(&format!("# {}\n\n", title));
    markdown.push_str("## Scope\n\n");
    markdown.push_str(&format!(
        "- Evidence source: `{}`\n- Evidence type: {}\n- Report orientation: Law enforcement / court-oriented reproducibility\n\n",
        target_path, target_type
    ));

    markdown.push_str("## Evidence Analysed\n\n");
    markdown.push_str("This report summarizes the indexed evidence, artefact extraction outputs, and subsequent investigator-driven findings recorded during analysis.\n\n");
    markdown.push_str(&format!(
        "- Indexed files: {}\n- Indexed directories: {}\n- Discovered partitions or logical volumes: {}\n\n",
        stats.file_count, stats.directory_count, stats.partition_count
    ));

    markdown.push_str("## Processing Summary\n\n");
    markdown.push_str(&format!(
        "- Filesystem indexation: complete\n- File signature identification: {}\n- Artefact extraction: {}\n- Structured artefact objects stored: {}\n\n",
        if stats.identified_file_count > 0 { "performed" } else { "not observed in database" },
        if stats.artifact_count > 0 || stats.artifact_object_count > 0 { "performed" } else { "not observed in database" },
        stats.artifact_object_count
    ));

    markdown.push_str("## Discovery Statistics\n\n");
    markdown.push_str("| Metric | Value |\n| --- | ---: |\n");
    markdown.push_str(&format!("| Indexed files | {} |\n", stats.file_count));
    markdown.push_str(&format!(
        "| Indexed directories | {} |\n",
        stats.directory_count
    ));
    markdown.push_str(&format!(
        "| Files with identified signature metadata | {} |\n",
        stats.identified_file_count
    ));
    markdown.push_str(&format!(
        "| Artefact records | {} |\n",
        stats.artifact_count
    ));
    markdown.push_str(&format!(
        "| Artefact objects | {} |\n\n",
        stats.artifact_object_count
    ));

    markdown.push_str("## Findings\n\n");
    if updates.is_empty() {
        markdown.push_str("No analyst findings have been recorded yet.\n\n");
    } else {
        for (index, row) in updates.iter().enumerate() {
            let section: String = row.get("section");
            let finding_title: String = row.get("title");
            let summary: String = row.get("summary");
            let details: String = row.get("details_markdown");
            markdown.push_str(&format!(
                "### {}. {} ({})\n\n",
                index + 1,
                finding_title,
                section
            ));
            markdown.push_str(&summary);
            markdown.push_str("\n\n");
            markdown.push_str(&details);
            markdown.push_str("\n\n");
        }
    }

    markdown.push_str("## Reproducibility Log\n\n");
    if updates.is_empty() {
        markdown.push_str("No reproducibility steps have been captured yet.\n\n");
    } else {
        for row in &updates {
            let finding_title: String = row.get("title");
            let created_at: String = row.get("created_at");
            let methodology_steps_json: String = row.get("methodology_steps_json");
            let supporting_evidence_json: String = row.get("supporting_evidence_json");
            let methodology_steps: Vec<String> =
                serde_json::from_str(&methodology_steps_json).unwrap_or_default();
            let supporting_evidence: Vec<String> =
                serde_json::from_str(&supporting_evidence_json).unwrap_or_default();

            markdown.push_str(&format!("### {}\n\n", finding_title));
            markdown.push_str(&format!("Recorded: {}\n\n", created_at));
            if methodology_steps.is_empty() {
                markdown.push_str("No reproducibility steps provided.\n\n");
            } else {
                for (step_index, step) in methodology_steps.iter().enumerate() {
                    markdown.push_str(&format!("{}. {}\n", step_index + 1, step));
                }
                markdown.push('\n');
            }

            if !supporting_evidence.is_empty() {
                markdown.push_str("Supporting references:\n");
                for item in supporting_evidence {
                    markdown.push_str(&format!("- {}\n", item));
                }
                markdown.push('\n');
            }
        }
    }

    markdown.push_str("## Analyst Notes\n\n");
    markdown.push_str("This report is iterative. Findings should be refined as additional artefacts, timelines, and corroborating evidence are identified.\n");

    sqlx::query(
        "UPDATE digital_reports SET markdown = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    )
    .bind(&markdown)
    .bind(report_id)
    .execute(pool)
    .await?;

    std::fs::write(&export_path, &markdown)?;
    Ok(())
}

async fn gather_stats(pool: &SqlitePool) -> Result<ReportStats> {
    let file_count = count_query(
        pool,
        "SELECT COUNT(*) FROM system_files WHERE ftype = 'File'",
    )
    .await?;
    let directory_count = count_query(
        pool,
        "SELECT COUNT(*) FROM system_files WHERE ftype = 'Directory'",
    )
    .await?;
    let identified_file_count = count_query(
        pool,
        "SELECT COUNT(*) FROM system_files WHERE sig_name IS NOT NULL AND TRIM(sig_name) != ''",
    )
    .await?;
    let artifact_count = count_query(pool, "SELECT COUNT(*) FROM artifacts").await?;
    let artifact_object_count = count_query(pool, "SELECT COUNT(*) FROM artifact_objects").await?;
    let partition_count = count_query(pool, "SELECT COUNT(*) FROM partitions").await?;

    Ok(ReportStats {
        file_count,
        directory_count,
        identified_file_count,
        artifact_count,
        artifact_object_count,
        partition_count,
    })
}

async fn count_query(pool: &SqlitePool, sql: &str) -> Result<i64> {
    Ok(sqlx::query_scalar::<_, i64>(sql)
        .fetch_one(pool)
        .await
        .unwrap_or(0))
}
