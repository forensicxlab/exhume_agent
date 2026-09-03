use exhume_body::Body;
use exhume_filesystem::detected_fs::{
    detect_filesystem, detect_filesystem_from_path, DetectedFs, ImageStream, KeyMaterial,
};
use exhume_filesystem::Filesystem;
use exhume_indexer::get_partition;
use log::error;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::path::{Path, PathBuf};

/// Errors originating from the evidence IO layer.
#[derive(Debug, thiserror::Error)]
#[error("EvidenceIOError: {0}")]
pub struct EvidenceIOError(pub String);

#[derive(Debug)]
pub struct ExtractedFile {
    pub content: Vec<u8>,
    pub file_name: String,
    pub absolute_path: String,
    pub dump_path: PathBuf,
    pub sha256: String,
    pub evidence_id: i64,
    pub partition_id: i64,
    pub database_file_id: i64,
}

/// Resolve a partition's byte offset and size from the index database.
///
/// Returns `(first_byte_addr, size_bytes)`.
pub async fn resolve_partition(
    pool: &SqlitePool,
    partition_id: i64,
    _image_path: &str,
) -> Result<(u64, u64), EvidenceIOError> {
    if let Some(partition) = get_partition(pool, partition_id).await.map_err(|e| {
        EvidenceIOError(format!(
            "Failed to resolve partition {}: {}",
            partition_id, e
        ))
    })? {
        return Ok((partition.first_byte_addr, partition.size_bytes));
    }

    Err(EvidenceIOError(format!(
        "Partition ID {} not found in partitions table",
        partition_id
    )))
}

/// Open a filesystem on a given partition, optionally using a FVEK from the DB.
pub async fn open_filesystem(
    image_path: &str,
    partition_id: i64,
    pool: &SqlitePool,
) -> Result<DetectedFs<ImageStream>, EvidenceIOError> {
    // If it's a folder, use the folder path directly
    if Path::new(image_path).is_dir() {
        return detect_filesystem_from_path(image_path)
            .map_err(|e| EvidenceIOError(format!("Folder FS error: {}", e)));
    }

    let (offset, size) = resolve_partition(pool, partition_id, image_path).await?;

    // Look up optional FVEK
    let fvek_hex = get_partition(pool, partition_id)
        .await
        .ok()
        .flatten()
        .and_then(|partition| partition.fvek);

    let key_material = fvek_hex
        .and_then(|h| hex::decode(h).ok())
        .map(|fvek| KeyMaterial {
            bitlocker_fvek: Some(fvek),
        });

    let body = Body::try_new(image_path.to_string(), "auto").map_err(|error| {
        EvidenceIOError(format!(
            "Unable to open evidence source '{}': {error}",
            image_path
        ))
    })?;
    detect_filesystem(&body, offset, size, key_material)
        .map_err(|e| EvidenceIOError(format!("Filesystem detection failed: {}", e)))
}

/// Extract file bytes from evidence via the index database.
///
pub async fn extract_file_bytes(
    pool: &SqlitePool,
    image_path: &str,
    file_id: u64,
    partition_id: i64,
    extraction_dir: &Path,
) -> Result<ExtractedFile, EvidenceIOError> {
    let file_row = sqlx::query(
        "SELECT id, evidence_id, name, absolute_path FROM system_files WHERE identifier = ? AND partition_id = ? LIMIT 1",
    )
    .bind(file_id as i64)
    .bind(partition_id)
    .fetch_one(pool)
    .await
    .map_err(|_| EvidenceIOError(format!("File ID {} not found in system_files", file_id)))?;

    let file_name: String = file_row.try_get("name").unwrap_or_default();
    let absolute_path: String = file_row.try_get("absolute_path").unwrap_or_default();
    let evidence_id: i64 = file_row.try_get("evidence_id").unwrap_or(0);
    let database_file_id: i64 = file_row.try_get("id").unwrap_or(0);

    let content = if image_path.is_empty() {
        return Err(EvidenceIOError("Empty image path provided".to_string()));
    } else if Path::new(image_path).is_dir() {
        let full_path = Path::new(image_path).join(absolute_path.trim_start_matches('/'));
        std::fs::read(&full_path).map_err(|e| {
            EvidenceIOError(format!("Local FS Error reading {:?}: {}", full_path, e))
        })?
    } else {
        let mut fs = open_filesystem(image_path, partition_id, pool).await?;

        let file = fs.get_file(file_id).map_err(|e| {
            EvidenceIOError(format!("File lookup failed for id {}: {}", file_id, e))
        })?;

        fs.read_file_content(&file)
            .map_err(|e| EvidenceIOError(format!("Failed to read file bytes: {}", e)))?
    };

    let sha256 = hex::encode(Sha256::digest(&content));
    let safe_name = file_name.replace(|c: char| !c.is_alphanumeric() && c != '.', "_");
    let scoped_dir = extraction_dir
        .join(format!("evidence_{evidence_id}"))
        .join(format!("partition_{partition_id}"));
    std::fs::create_dir_all(&scoped_dir).map_err(|error| {
        EvidenceIOError(format!(
            "Failed to create extraction directory {}: {error}",
            scoped_dir.display()
        ))
    })?;
    let dump_filename = format!(
        "{}_{}_{}_{}",
        database_file_id,
        file_id,
        &sha256[..12],
        safe_name
    );
    let dump_path = scoped_dir.join(dump_filename);

    if !dump_path.exists() {
        let temp_path = scoped_dir.join(format!(".{}.tmp", crate::ui::unique_id("extract")));
        if let Err(error) = std::fs::write(&temp_path, &content)
            .and_then(|_| std::fs::rename(&temp_path, &dump_path))
        {
            let _ = std::fs::remove_file(&temp_path);
            error!("Failed to persist extracted file: {}", error);
            return Err(EvidenceIOError(format!(
                "Failed to persist extracted file: {error}"
            )));
        }
    }

    Ok(ExtractedFile {
        content,
        file_name,
        absolute_path,
        dump_path,
        sha256,
        evidence_id,
        partition_id,
        database_file_id,
    })
}
