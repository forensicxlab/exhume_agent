//! Convert native tool contracts to evidence outcomes before any presentation truncation.
use crate::investigation::{ToolOutcome, ToolStatus};
use serde_json::Value;

pub fn classify(tool: &str, raw: Result<String, String>) -> ToolOutcome {
    let output = match raw {
        Ok(value) => value,
        Err(error) => return ToolOutcome::failed(error),
    };
    let mut outcome = ToolOutcome::new(ToolStatus::Unknown, output.clone());
    let Ok(value) = serde_json::from_str::<Value>(&output) else {
        outcome
            .coverage
            .limitations
            .push("Tool did not return a structured outcome; success is unknown.".into());
        return outcome;
    };
    let error = value.get("error").filter(|v| !v.is_null()).map(|v| {
        v.as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| v.to_string())
    });
    let exit = value
        .get("exit_code")
        .and_then(Value::as_i64)
        .map(|n| n as i32);
    outcome.process_exit_code = exit;
    let explicit_status = value.get("status").and_then(Value::as_str);
    if error.is_some()
        || value.get("success") == Some(&Value::Bool(false))
        || exit.is_some_and(|code| code != 0)
        || (tool == "shell" && exit != Some(0))
        || matches!(explicit_status, Some("failed" | "error" | "cancelled"))
    {
        outcome.status = ToolStatus::Failed;
        outcome.error =
            error.or_else(|| Some("Tool reported failure or did not exit successfully.".into()));
        return outcome;
    }
    if explicit_status == Some("unknown") {
        return outcome;
    }
    let recognized = match tool {
        "list_partitions" => {
            value.get("partitions").is_some_and(Value::is_array)
                && value.get("sector_size").is_some()
        }
        "detect_filesystem" => {
            value
                .get("fs_type")
                .and_then(Value::as_str)
                .is_some_and(|s| s != "Unknown" && !s.is_empty())
                && value.get("error") == Some(&Value::Null)
        }
        "list_dir" => {
            value.get("entries").is_some_and(Value::is_array)
                && value.get("error") == Some(&Value::Null)
        }
        "extract_file" => {
            value
                .get("sha256")
                .and_then(Value::as_str)
                .is_some_and(|s| s.len() == 64)
                && value.get("dump_path").and_then(Value::as_str).is_some()
                && value.get("error") == Some(&Value::Null)
        }
        "query_index" | "query_sqlite_file" => {
            value.get("row_count").is_some() && value.get("error") == Some(&Value::Null)
        }
        "shell" => exit == Some(0),
        _ => {
            value.get("success") == Some(&Value::Bool(true))
                || value
                    .get("status")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s == "success" || s == "partial")
        }
    };
    if !recognized {
        outcome.coverage.limitations.push("The tool's success contract is not recognized. This result cannot support an observation.".into());
        return outcome;
    }
    let partial = ["truncated", "is_truncated", "cells_truncated"]
        .iter()
        .any(|key| value.get(*key) == Some(&Value::Bool(true)))
        || value.get("status").and_then(Value::as_str) == Some("partial");
    outcome.status = if partial {
        ToolStatus::Partial
    } else {
        ToolStatus::Success
    };
    outcome.coverage.truncated = partial;
    // Completion of one operation never implies complete coverage of the evidence source.
    outcome.coverage.complete = false;
    if let Some(limitations) = value.get("limitations").and_then(Value::as_array) {
        outcome.coverage.limitations.extend(
            limitations
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
    }
    outcome.coverage.limitations.push("Coverage is limited to the exact parameters and returned records; absence elsewhere has not been established.".into());
    if partial {
        outcome.coverage.limitations.push(
            "The result contains a bounded sample, omitted metadata, or shortened content.".into(),
        );
    }
    outcome
        .verification
        .push("Validated the native tool result contract before display truncation.".into());
    outcome
}

pub fn display_excerpt(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.into();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n[Display truncated; the complete tool result is in the execution log.]",
        &value[..end]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failure_beyond_display_limit_is_never_success() {
        let raw =
            serde_json::json!({"result":"x".repeat(100_000),"row_count":1,"error":"query failed"})
                .to_string();
        assert_eq!(classify("query_index", Ok(raw)).status, ToolStatus::Failed);
    }
    #[test]
    fn exit_status_beats_success_shaped_stdout() {
        assert_eq!(
            classify(
                "shell",
                Ok(r#"{"stdout":"success","exit_code":1,"error":null}"#.into())
            )
            .status,
            ToolStatus::Failed
        );
        assert_eq!(
            classify("plugin", Ok(r#"{"success":true,"status":"failed"}"#.into())).status,
            ToolStatus::Failed
        );
        assert_eq!(
            classify("plugin", Ok(r#"{"success":true,"exit_code":1}"#.into())).status,
            ToolStatus::Failed
        );
        assert_eq!(
            classify(
                "plugin",
                Ok(r#"{"success":true,"status":"unknown"}"#.into())
            )
            .status,
            ToolStatus::Unknown
        );
    }
    #[test]
    fn partial_and_unknown_are_not_complete() {
        let result = classify(
            "query_index",
            Ok(r#"{"result":"one row","row_count":1,"error":null,"truncated":true}"#.into()),
        );
        assert_eq!(result.status, ToolStatus::Partial);
        assert!(!result.coverage.complete);
        assert_eq!(
            classify("plugin", Ok("all good".into())).status,
            ToolStatus::Unknown
        );
    }
    #[test]
    fn unicode_display_boundaries_are_safe() {
        assert!(display_excerpt("évidence", 1).starts_with('\n'));
    }
}
