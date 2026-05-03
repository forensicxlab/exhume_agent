use std::path::{Path, PathBuf};

pub fn default_db_path(target_path: &str, is_folder: bool, is_logical: bool) -> PathBuf {
    if is_folder {
        PathBuf::from(format!(
            "{}.exhume.sqlite",
            target_path.trim_end_matches('/')
        ))
    } else if is_logical {
        PathBuf::from(format!("{}.logical.sqlite", target_path))
    } else {
        PathBuf::from(format!("{}.index.sqlite", target_path))
    }
}

pub fn extraction_dir_for_db(db_path: &Path) -> PathBuf {
    db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("extracted")
}

pub fn default_report_export_path(
    db_path: &Path,
    target_path: &str,
    is_folder: bool,
    is_logical: bool,
) -> PathBuf {
    if db_path == default_db_path(target_path, is_folder, is_logical) {
        if is_folder {
            PathBuf::from(format!(
                "{}.exhume.report.md",
                target_path.trim_end_matches('/')
            ))
        } else if is_logical {
            PathBuf::from(format!("{}.logical.report.md", target_path))
        } else {
            PathBuf::from(format!("{}.report.md", target_path))
        }
    } else {
        let parent = db_path.parent().unwrap_or_else(|| Path::new("."));
        let stem = db_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("exhume_index");
        parent.join(format!("{}.report.md", stem))
    }
}
