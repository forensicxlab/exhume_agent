use std::io::Write;
use exhume_body::Body;
use exhume_indexer::{index_partition, IndexerEvent, IndexerEventType};
use exhume_partitions::Partitions;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{SqlitePool, Row};
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};

/// Spawns a background task that renders a progress bar from indexer events.
fn spawn_progress_monitor(mut rx: mpsc::Receiver<IndexerEvent>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let pb = ProgressBar::new(0);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"));

        while let Some(event) = rx.recv().await {
            match event.event_type {
                IndexerEventType::Info => pb.set_message(event.message),
                IndexerEventType::Progress { current, total } => {
                    pb.set_length(total);
                    pb.set_position(current);
                },
                IndexerEventType::Success => {
                    pb.finish_with_message(format!("{} {}", "[SUCCESS]".green(), event.message));
                },
                IndexerEventType::Warning => pb.println(format!("      {} {}", "[WARN]".yellow(), event.message)),
                IndexerEventType::Error => pb.println(format!("      {} {}", "[ERROR]".red(), event.message)),
            }
        }
    })
}

pub async fn init_index(target_path: &str, is_folder: bool, is_logical: bool) -> anyhow::Result<SqlitePool> {
    let db_path = if is_folder {
        // For folders, we put the DB inside the folder as a hidden file or next to it
        // Let's put it next to it to avoid indexing the DB itself if it's inside
        format!("{}.exhume.sqlite", target_path.trim_end_matches('/'))
    } else if is_logical {
        format!("{}.logical.sqlite", target_path)
    } else {
        format!("{}.index.sqlite", target_path)
    };
    let index_exists = Path::new(&db_path).exists();

    let opts = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .idle_timeout(Duration::from_secs(60))
        .connect_with(opts)
        .await?;

    // ... (schema tables creation remains the same) ...

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS system_files (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id     INTEGER NOT NULL,
            partition_id    INTEGER NOT NULL,
            identifier      INTEGER NOT NULL,
            absolute_path   TEXT    NOT NULL,
            name            TEXT    NOT NULL,
            ftype           TEXT    NOT NULL,
            size            INTEGER NOT NULL,
            created         INTEGER,
            modified        INTEGER,
            accessed        INTEGER,
            permissions     TEXT,
            owner           TEXT,
            "group"         TEXT,
            sig_name        TEXT,
            sig_mime        TEXT,
            sig_exts        TEXT,
            metadata        JSON    NOT NULL,
            display         TEXT
        );

        CREATE TABLE IF NOT EXISTS mbr_partition_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_byte_addr INTEGER NOT NULL,
            size_sectors    INTEGER NOT NULL,
            fvek TEXT
        );
        CREATE TABLE IF NOT EXISTS gpt_partition_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_byte_addr INTEGER NOT NULL,
            size_sectors    INTEGER NOT NULL,
            fvek TEXT
        );
        CREATE TABLE IF NOT EXISTS logical_partition_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_byte_addr INTEGER NOT NULL,
            size            INTEGER NOT NULL,
            fvek TEXT
        );
        CREATE TABLE IF NOT EXISTS artifacts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id     INTEGER NOT NULL,
            file_id         INTEGER,
            partition_id    INTEGER NOT NULL,
            name            TEXT NOT NULL,
            description     TEXT NOT NULL,
            parser          TEXT,
            tag             TEXT NOT NULL,
            category        TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS artifact_objects (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id     INTEGER NOT NULL,
            partition_id    INTEGER NOT NULL,
            artifact_id     INTEGER NOT NULL,
            file_id         INTEGER,
            parser          TEXT NOT NULL,
            kind            TEXT NOT NULL,
            text            TEXT NOT NULL,
            json            TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS conversations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            content     TEXT NOT NULL,
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )
    .execute(&pool)
    .await?;

    // FTS5 virtual table for full-text search on file metadata
    sqlx::query(
        r#"
        CREATE VIRTUAL TABLE IF NOT EXISTS system_files_fts USING fts5(
            name, absolute_path, sig_name,
            content='system_files', content_rowid='id'
        );
        "#,
    )
    .execute(&pool)
    .await?;

    if index_exists {
        println!("{} Index already exists. Skipping discovery...", "ℹ️".blue());
        return Ok(pool);
    }

    struct WorkPartition {
        id: i64,
        first_byte_addr: u64,
        size_sectors: u64,
        kind: &'static str,
    }

    let mut work = Vec::new();
    let mut sector_size = 512u64; // Default common sector size

    if is_folder {
        println!("{} Processing folder: {}", "📁".blue(), target_path);
        // For folders, we create a dummy partition entry in logical_partition_entries
        let pid_assigned: i64 = sqlx::query("INSERT INTO logical_partition_entries (first_byte_addr, size) VALUES (?, ?) RETURNING id")
            .bind(0i64)
            .bind(0i64) // size unknown/irrelevant for flat folder
            .fetch_one(&pool).await?.get(0);

        work.push(WorkPartition {
            id: pid_assigned,
            first_byte_addr: 0,
            size_sectors: 0,
            kind: "FOLDER",
        });
    } else if !is_logical {
        let mut body = Body::new(target_path.to_string(), "auto");
        sector_size = body.get_sector_size() as u64;
        
        let partitions = match Partitions::new(&mut body) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} Failed to parse partitions: {}", "Error:".red(), e);
                return Ok(pool);
            }
        };

        // We assign dummy/arbitrary IDs since the Agent CLI does not strictly have an Evidence database
        if let Some(mbr) = partitions.mbr {
            for part in mbr.partition_table {
                if part.size_sectors > 0 {
                    let pid_assigned: i64 = sqlx::query("INSERT INTO mbr_partition_entries (first_byte_addr, size_sectors) VALUES (?, ?) RETURNING id")
                        .bind(part.first_byte_addr as i64)
                        .bind(part.size_sectors as i64)
                        .fetch_one(&pool).await?.get(0);

                    work.push(WorkPartition {
                        id: pid_assigned,
                        first_byte_addr: part.first_byte_addr as u64,
                        size_sectors: part.size_sectors as u64,
                        kind: "MBR",
                    });
                }
            }
        }

        if let Some(gpt) = partitions.gpt {
            for part in gpt.partition_entries {
                let pid_assigned: i64 = sqlx::query("INSERT INTO gpt_partition_entries (first_byte_addr, size_sectors) VALUES (?, ?) RETURNING id")
                    .bind(part.starting_lba.saturating_mul(sector_size) as i64)
                    .bind((part.ending_lba - part.starting_lba + 1) as i64)
                    .fetch_one(&pool).await?.get(0);

                work.push(WorkPartition {
                    id: pid_assigned,
                    first_byte_addr: part.starting_lba.saturating_mul(sector_size),
                    size_sectors: (part.ending_lba - part.starting_lba + 1),
                    kind: "GPT",
                });
            }
        }
    }

    if work.is_empty() {
        let size = if is_folder { 0 } else { std::fs::metadata(&target_path)?.len() };
        let size_sectors = if !is_folder && sector_size > 0 { size / sector_size } else { 0 };

        let pid_assigned: i64 = sqlx::query("INSERT INTO logical_partition_entries (first_byte_addr, size) VALUES (?, ?) RETURNING id")
            .bind(0i64)
            .bind(size as i64)
            .fetch_one(&pool).await?.get(0);

        work.push(WorkPartition {
            id: pid_assigned,
            first_byte_addr: 0,
            size_sectors,
            kind: if is_folder { "FOLDER" } else { "LOGICAL" },
        });
    }

    println!("\n{}", "===============================================".blue());
    println!("{}", " Discovered Partitions ".blue().bold());
    println!("{}\n", "===============================================".blue());
    
    for p in &work {
        println!("  - [{}] {} Partition: start={}, size={}", p.id, p.kind, p.first_byte_addr, p.size_sectors);
    }
    println!();

    if index_exists {
        println!("{} Local index database already exists at {}. Skipping filesystem discovery.", "Success:".green(), db_path);
        return Ok(pool);
    }

    print!("{} Do you want to perform a full filesystem discovery to build the index? (y/N): ", "Prompt:".cyan().bold());
    std::io::stdout().flush()?;
    
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();
    
    if !input.eq_ignore_ascii_case("y") && !input.eq_ignore_ascii_case("yes") {
        println!("Skipping indexation.");
        return Ok(pool);
    }

    println!("{} Building local index database at {}", "Info:".yellow(), db_path);

    let total_partitions = work.len();
    for (idx, p) in work.iter().enumerate() {
        println!("  - Indexing {} partition {}/{}", p.kind, idx + 1, total_partitions);

        let (tx, rx) = mpsc::channel::<IndexerEvent>(100);
        let monitor = spawn_progress_monitor(rx);

        if p.kind == "FOLDER" {
            exhume_indexer::index_folder(
                1,
                p.id,
                target_path.to_string(),
                &pool,
                Some(tx.clone()),
            ).await;
        } else {
            loop {
                match index_partition(
                    1, // evidence_id dummy
                    p.id,
                    p.size_sectors,
                    p.first_byte_addr,
                    target_path.to_string(),
                    &pool,
                    Some(tx.clone()),
                ).await {
                    Ok(_) => break,
                    Err(e) if e.to_string().contains("-FVE-FS-") => {
                        if prompt_fvek_and_update_db(&pool, p.id, &p.kind).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        println!("      {} Indexing failed: {}", "[ERROR]".red(), e);
                        break;
                    }
                }
            }
        }

        drop(tx);
        let _ = monitor.await;
    }

    println!("\n{} Local index built successfully.", "Success:".green());

    // Populate Full-Text Search index
    println!("{} Building full-text search index...", "Info:".yellow());
    match sqlx::query("INSERT INTO system_files_fts(system_files_fts) VALUES('rebuild')")
        .execute(&pool)
        .await
    {
        Ok(_) => println!("{} FTS index built.", "Success:".green()),
        Err(e) => println!("{} FTS index build failed (non-fatal, may be read-only volume): {}", "Warning:".yellow(), e),
    }

    print!("{} Do you want to run File Signature Identification? (y/N): ", "Prompt:".cyan().bold());
    std::io::stdout().flush()?;
    
    let mut sig_input = String::new();
    std::io::stdin().read_line(&mut sig_input)?;
    let run_signatures = sig_input.trim().eq_ignore_ascii_case("y") || sig_input.trim().eq_ignore_ascii_case("yes");

    print!("{} Do you want to run Artefact Parsers (EVTX, PE, etc)? (y/N): ", "Prompt:".cyan().bold());
    std::io::stdout().flush()?;

    let mut art_input = String::new();
    std::io::stdin().read_line(&mut art_input)?;
    let run_artefacts = art_input.trim().eq_ignore_ascii_case("y") || art_input.trim().eq_ignore_ascii_case("yes");

    if run_signatures || run_artefacts {
        let registry = exhume_artefacts::parsers::build_registry();
        println!("DEBUG: Registry initialized with {} parsers: {:?}", registry.len(), registry.keys().collect::<Vec<_>>());

        for (idx, p) in work.iter().enumerate() {
            println!("  - Scanning {} partition {}/{}", p.kind, idx + 1, total_partitions);
    
            let partition_fvek_result: Option<String> = sqlx::query_scalar(
                "SELECT fvek FROM mbr_partition_entries WHERE id = ? \
                 UNION SELECT fvek FROM gpt_partition_entries WHERE id = ? \
                 UNION SELECT fvek FROM logical_partition_entries WHERE id = ? LIMIT 1"
            )
            .bind(p.id)
            .bind(p.id)
                .bind(p.id)
                .fetch_optional(&pool)
                .await
                .unwrap_or(None);
    
            let key_material = partition_fvek_result
                .and_then(|h| hex::decode(h).ok())
                .map(|fvek| exhume_filesystem::detected_fs::KeyMaterial { bitlocker_fvek: Some(fvek) });
    
            let mut fs_res = if is_folder {
                exhume_filesystem::detected_fs::detect_filesystem_from_path(target_path)
            } else {
                let mut body_scan = Body::new(target_path.to_string(), "auto");
                let sector_size_scan = body_scan.get_sector_size() as u64;
                let partition_size_bytes = p.size_sectors * sector_size_scan;

                exhume_filesystem::detected_fs::detect_filesystem(
                    &mut body_scan,
                    p.first_byte_addr,
                    partition_size_bytes,
                    key_material.clone(),
                )
            };

            if let Err(e) = &fs_res {
                if e.to_string().contains("-FVE-FS-") {
                    if let Ok(_) = prompt_fvek_and_update_db(&pool, p.id, &p.kind).await {
                        // Reload key material and retry
                        let fvek_hex: Option<String> = sqlx::query_scalar(&format!(
                            "SELECT fvek FROM {} WHERE id = ?",
                            match p.kind {
                                "MBR" => "mbr_partition_entries",
                                "GPT" => "gpt_partition_entries",
                                _ => "logical_partition_entries",
                            }
                        ))
                        .bind(p.id)
                        .fetch_optional(&pool)
                        .await
                        .unwrap_or(None);

                        let km = fvek_hex
                            .and_then(|h| hex::decode(h).ok())
                            .map(|fvek| exhume_filesystem::detected_fs::KeyMaterial { bitlocker_fvek: Some(fvek) });

                        let mut body_scan = Body::new(target_path.to_string(), "auto");
                        let sector_size_scan = body_scan.get_sector_size() as u64;
                        let partition_size_bytes = p.size_sectors * sector_size_scan;

                        fs_res = exhume_filesystem::detected_fs::detect_filesystem(
                            &mut body_scan,
                            p.first_byte_addr,
                            partition_size_bytes,
                            km,
                        );
                    }
                }
            }

            if let Ok(mut fs) = fs_res {
                if run_signatures {
                    println!("    {} File Signatures", "[START]".blue());
                    let (tx, rx) = mpsc::channel::<IndexerEvent>(100);
                    let monitor = spawn_progress_monitor(rx);
            
                    exhume_indexer::identification::identify_file_types(
                        &mut fs,
                        1, 
                        p.id,
                        &pool,
                        Some(tx.clone()),
                    )
                    .await;
            
                    drop(tx);
                    let _ = monitor.await;
                }

                if run_artefacts {
                    println!("    {} Artefact Parsers", "[START]".blue());
                    let (tx1, rx1) = mpsc::channel::<IndexerEvent>(100);
                    let monitor1 = spawn_progress_monitor(rx1);
            
                    exhume_indexer::artifacts::identify_artefacts(
                        1,
                        p.id,
                        &pool,
                        Some(tx1.clone()),
                        None
                    ).await;

                    drop(tx1);
                    let _ = monitor1.await;

                    let (tx2, rx2) = mpsc::channel::<IndexerEvent>(100);
                    let monitor2 = spawn_progress_monitor(rx2);

                    exhume_indexer::artifacts::extract_artefacts(
                        1,
                        p.id,
                        &pool,
                        &mut fs,
                        &registry,
                        Some(tx2.clone())
                    ).await;

                    drop(tx2);
                    let _ = monitor2.await;
                }
            } else {
                println!("      {} Could not rebuild filesystem instance for scanning", "[ERROR]".red());
            }
        }
    }

    Ok(pool)
}

async fn prompt_fvek_and_update_db(pool: &SqlitePool, p_id: i64, kind: &str) -> anyhow::Result<()> {
    print!("\n{} BitLocker detected on partition {}. Please enter FVEK (hex): ", "Prompt:".cyan().bold(), p_id);
    std::io::stdout().flush()?;
    
    let mut fvek_input = String::new();
    std::io::stdin().read_line(&mut fvek_input)?;
    let fvek = fvek_input.trim();
    
    if !fvek.is_empty() {
        let table = match kind {
            "MBR" => "mbr_partition_entries",
            "GPT" => "gpt_partition_entries",
            _ => "logical_partition_entries",
        };
        sqlx::query(&format!("UPDATE {} SET fvek = ? WHERE id = ?", table))
            .bind(fvek)
            .bind(p_id)
            .execute(pool)
            .await?;
        println!("{} FVEK key updated in database.", "Success:".green());
        Ok(())
    } else {
        Err(anyhow::anyhow!("No FVEK provided"))
    }
}
