use serde::{Deserialize, Serialize};
use std::path::PathBuf;

fn default_turn_timeout_secs() -> u64 {
    300
}

fn default_query_timeout_secs() -> u64 {
    30
}

fn default_query_rows() -> usize {
    200
}

fn default_history_messages() -> usize {
    40
}

fn default_history_chars() -> usize {
    120_000
}

fn default_shell_timeout_secs() -> u64 {
    30
}

fn default_shell_output_bytes() -> usize {
    256 * 1024
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentPolicy {
    #[serde(default)]
    pub allow_shell: bool,
    #[serde(default = "default_turn_timeout_secs")]
    pub turn_timeout_secs: u64,
    #[serde(default = "default_query_timeout_secs")]
    pub query_timeout_secs: u64,
    #[serde(default = "default_query_rows")]
    pub max_query_rows: usize,
    #[serde(default = "default_history_messages")]
    pub max_history_messages: usize,
    #[serde(default = "default_history_chars")]
    pub max_history_chars: usize,
    #[serde(default = "default_shell_timeout_secs")]
    pub shell_timeout_secs: u64,
    #[serde(default = "default_shell_output_bytes")]
    pub max_shell_output_bytes: usize,
    #[serde(default)]
    pub shell_working_dir: Option<PathBuf>,
}

impl Default for AgentPolicy {
    fn default() -> Self {
        Self {
            allow_shell: false,
            turn_timeout_secs: default_turn_timeout_secs(),
            query_timeout_secs: default_query_timeout_secs(),
            max_query_rows: default_query_rows(),
            max_history_messages: default_history_messages(),
            max_history_chars: default_history_chars(),
            shell_timeout_secs: default_shell_timeout_secs(),
            max_shell_output_bytes: default_shell_output_bytes(),
            shell_working_dir: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AgentOptions {
    pub session_id: String,
    pub evidence_id: i64,
    pub policy: AgentPolicy,
}

impl Default for AgentOptions {
    fn default() -> Self {
        Self {
            session_id: "default".to_string(),
            evidence_id: 1,
            policy: AgentPolicy::default(),
        }
    }
}
