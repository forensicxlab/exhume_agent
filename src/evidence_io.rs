use exhume_body::Body;
use exhume_filesystem::detected_fs::{
    detect_filesystem, detect_filesystem_from_path, DetectedFs, ImageStream, KeyMaterial,
};
use exhume_filesystem::Filesystem;
use exhume_indexer::get_partition;
use log::error;
use sqlx::{Row, SqlitePool};
use std::path::{Path, PathBuf};

/// Errors originating from the evidence IO layer.
#[derive(Debug, thiserror::Error)]
#[error("EvidenceIOError: {0}")]
pub struct EvidenceIOError(pub String);

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

    let body = Body::new(image_path.to_string(), "auto");
    detect_filesystem(&body, offset, size, key_material)
        .map_err(|e| EvidenceIOError(format!("Filesystem detection failed: {}", e)))
}

/// Extract file bytes from evidence via the index database.
///
/// Returns `(content, file_name, absolute_path, dump_path)`.
pub async fn extract_file_bytes(
    pool: &SqlitePool,
    image_path: &str,
    file_id: u64,
    partition_id: i64,
    extraction_dir: &Path,
) -> Result<(Vec<u8>, String, String, PathBuf), EvidenceIOError> {
    let file_row = sqlx::query(
        "SELECT name, absolute_path FROM system_files WHERE identifier = ? AND partition_id = ? LIMIT 1",
    )
    .bind(file_id as i64)
    .bind(partition_id)
    .fetch_one(pool)
    .await
    .map_err(|_| EvidenceIOError(format!("File ID {} not found in system_files", file_id)))?;

    let file_name: String = file_row.try_get("name").unwrap_or_default();
    let absolute_path: String = file_row.try_get("absolute_path").unwrap_or_default();

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

    // Persistent dump to host
    let safe_name = file_name.replace(|c: char| !c.is_alphanumeric() && c != '.', "_");
    let dump_filename = format!("{}_{}", file_id, safe_name);
    let dump_path = extraction_dir.join(dump_filename);

    if !dump_path.exists() {
        if let Err(e) = std::fs::write(&dump_path, &content) {
            error!("Failed to dump file to host: {}", e);
        }
    }

    Ok((content, file_name, absolute_path, dump_path))
}
