use exhume_body::Body;
use exhume_indexer::{index_partition, IndexerEvent, IndexerEventType};
use exhume_partitions::Partitions;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;
use colored::*;

pub async fn init_index(image_path: &str) -> anyhow::Result<SqlitePool> {
    let db_path = format!("{}.index.sqlite", image_path);
    let index_exists = Path::new(&db_path).exists();

    let opts = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .idle_timeout(Duration::from_secs(60))
        .connect_with(opts)
        .await?;

    // Create minimal schema required by exhume_indexer
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
            fvek TEXT
        );
        CREATE TABLE IF NOT EXISTS gpt_partition_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fvek TEXT
        );
        CREATE TABLE IF NOT EXISTS logical_partition_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        "#,
    )
    .execute(&pool)
    .await?;

    use std::io::Write;
    let mut body = Body::new(image_path.to_string(), "auto");
    let sector_size = body.get_sector_size() as u64;
    
    let partitions = match Partitions::new(&mut body) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} Failed to parse partitions: {}", "Error:".red(), e);
            return Ok(pool);
        }
    };

    struct WorkPartition {
        id: i64,
        first_byte_addr: u64,
        size_sectors: u64,
        kind: &'static str,
    }

    let mut work = Vec::new();
    let mut pid = 1;

    // We assign dummy/arbitrary IDs since the Agent CLI does not strictly have an Evidence database
    if let Some(mbr) = partitions.mbr {
        for part in mbr.partition_table {
            work.push(WorkPartition {
                id: pid,
                first_byte_addr: part.first_byte_addr as u64,
                size_sectors: part.size_sectors as u64,
                kind: "MBR",
            });
            pid += 1;
        }
    }

    if let Some(gpt) = partitions.gpt {
        for part in gpt.partition_entries {
            work.push(WorkPartition {
                id: pid,
                first_byte_addr: part.starting_lba.saturating_mul(sector_size),
                size_sectors: (part.ending_lba - part.starting_lba + 1),
                kind: "GPT",
            });
            pid += 1;
        }
    }

    if work.is_empty() {
        let size = std::fs::metadata(&image_path)?.len();
        let size_sectors = if sector_size > 0 { size / sector_size } else { 0 };
        work.push(WorkPartition {
            id: pid,
            first_byte_addr: 0,
            size_sectors,
            kind: "LOGICAL",
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

        let (tx, mut rx) = mpsc::channel::<IndexerEvent>(100);

        // Spawn a monitoring task to print the progress from the indexer
        let monitor = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                match event.event_type {
                    IndexerEventType::Info => println!("      [INFO] {}", event.message),
                    IndexerEventType::Success => println!("      {} {}", "[SUCCESS]".green(), event.message),
                    IndexerEventType::Warning => println!("      {} {}", "[WARN]".yellow(), event.message),
                    IndexerEventType::Error => println!("      {} {}", "[ERROR]".red(), event.message),
                }
            }
        });

        index_partition(
            1, // evidence_id dummy
            p.id,
            p.size_sectors,
            p.first_byte_addr,
            image_path.to_string(),
            &pool,
            Some(tx),
        )
        .await;

        let _ = monitor.await;
    }

    println!("\n{} Local index built successfully.", "Success:".green());

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
        let registry = exhume_artefacts::parsers::ParserRegistry::new();

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
    
            let mut body_scan = Body::new(image_path.to_string(), "auto");
            let partition_size_bytes = p.size_sectors * sector_size;
    
            if let Ok(mut fs) = exhume_filesystem::detected_fs::detect_filesystem(
                &mut body_scan,
                p.first_byte_addr,
                partition_size_bytes,
                key_material,
            ) {
                if run_signatures {
                    println!("    {} File Signatures", "[START]".blue());
                    let (tx, mut rx) = mpsc::channel::<IndexerEvent>(100);
            
                    let monitor = tokio::spawn(async move {
                        while let Some(event) = rx.recv().await {
                            match event.event_type {
                                IndexerEventType::Info => println!("      [INFO] {}", event.message),
                                IndexerEventType::Success => println!("      {} {}", "[SUCCESS]".green(), event.message),
                                IndexerEventType::Warning => println!("      {} {}", "[WARN]".yellow(), event.message),
                                IndexerEventType::Error => println!("      {} {}", "[ERROR]".red(), event.message),
                            }
                        }
                    });
            
                    exhume_indexer::identification::identify_file_types(
                        &mut fs,
                        1, 
                        p.id,
                        &pool,
                        Some(tx),
                    )
                    .await;
            
                    let _ = monitor.await;
                }

                if run_artefacts {
                    println!("    {} Artefact Parsers", "[START]".blue());
                    let (tx1, mut rx1) = mpsc::channel::<IndexerEvent>(100);
            
                    let monitor1 = tokio::spawn(async move {
                        while let Some(event) = rx1.recv().await {
                            match event.event_type {
                                IndexerEventType::Info => println!("      [INFO] {}", event.message),
                                IndexerEventType::Success => println!("      {} {}", "[SUCCESS]".green(), event.message),
                                IndexerEventType::Warning => println!("      {} {}", "[WARN]".yellow(), event.message),
                                IndexerEventType::Error => println!("      {} {}", "[ERROR]".red(), event.message),
                            }
                        }
                    });
            
                    exhume_indexer::artifacts::identify_artefacts(
                        1,
                        p.id,
                        &pool,
                        Some(tx1),
                        None
                    ).await;

                    let _ = monitor1.await;

                    let (tx2, mut rx2) = mpsc::channel::<IndexerEvent>(100);
            
                    let monitor2 = tokio::spawn(async move {
                        while let Some(event) = rx2.recv().await {
                            match event.event_type {
                                IndexerEventType::Info => println!("      [INFO] {}", event.message),
                                IndexerEventType::Success => println!("      {} {}", "[SUCCESS]".green(), event.message),
                                IndexerEventType::Warning => println!("      {} {}", "[WARN]".yellow(), event.message),
                                IndexerEventType::Error => println!("      {} {}", "[ERROR]".red(), event.message),
                            }
                        }
                    });

                    exhume_indexer::artifacts::extract_artefacts(
                        1,
                        p.id,
                        &pool,
                        &mut fs,
                        &registry,
                        Some(tx2)
                    ).await;

                    let _ = monitor2.await;
                }
            } else {
                println!("      {} Could not rebuild filesystem instance for scanning", "[ERROR]".red());
            }
        }
    }

    Ok(pool)
}
