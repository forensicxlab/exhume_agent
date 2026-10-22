//! Durable investigator decisions, bounded execution and reproducible observations.
//!
//! Only the host's human-facing API may call `decide_step` / `review_finding`.
//! A language model may propose steps and findings; it cannot grant execution.
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSource {
    pub id: i64,
    pub path: String,
    pub role: String,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub modified_unix_secs: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessingDestination {
    pub provider: String,
    pub endpoint: String,
    /// Empty allows any model at this expressly selected provider and endpoint.
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub authentication_mode: String,
    #[serde(default)]
    pub account_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcessingPolicy {
    #[serde(default)]
    pub allowed_destinations: Vec<ProcessingDestination>,
    #[serde(default)]
    pub allow_external_tools: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CaseBrief {
    pub objective: String,
    pub evidence: Vec<EvidenceSource>,
    #[serde(default)]
    pub facts: Vec<String>,
    #[serde(default)]
    pub allegations: Vec<String>,
    #[serde(default)]
    pub constraints: Vec<String>,
    #[serde(default)]
    pub processing_policy: ProcessingPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepLimits {
    pub max_tool_calls: usize,
    pub max_retries_per_tool: usize,
    pub max_duration_secs: u64,
    pub max_output_bytes: usize,
}
impl Default for StepLimits {
    fn default() -> Self {
        Self {
            max_tool_calls: 8,
            max_retries_per_tool: 1,
            max_duration_secs: 300,
            max_output_bytes: 256 * 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityGap {
    pub component: String,
    pub missing_behavior: String,
    pub proposed_external_tool: Option<String>,
    /// This field must contain a synthetic or redacted example, never raw case data.
    pub synthetic_example: String,
    pub acceptance_criteria: Vec<String>,
}
impl CapabilityGap {
    pub fn issue_draft(&self) -> String {
        format!("# Feature request: {}\n\nComponent: {}\n\n## Missing behavior\n\n{}\n\n## Synthetic reproduction\n\n{}\n\n## Developer acceptance criteria\n\n{}\n\nReview this case-neutral draft before opening an issue in the component's GitHub repository. No issue has been published.\n", self.component, self.component, self.missing_behavior, self.synthetic_example, self.acceptance_criteria.iter().map(|v| format!("- {v}")).collect::<Vec<_>>().join("\n"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepProposal {
    pub id: String,
    pub question: String,
    pub rationale: String,
    pub evidence_ids: Vec<i64>,
    pub permitted_tools: Vec<String>,
    #[serde(default)]
    pub limits: StepLimits,
    #[serde(default)]
    pub stop_conditions: Vec<String>,
    #[serde(default)]
    pub recommended: bool,
    #[serde(default)]
    pub estimated_effort: String,
    #[serde(default)]
    pub limitations: Vec<String>,
    /// A failed dependency blocks the dependent tool; unrelated tools remain available.
    #[serde(default)]
    pub tool_dependencies: BTreeMap<String, Vec<String>>,
    /// Tool name -> required top-level argument -> explicitly permitted values.
    #[serde(default)]
    pub source_selectors: BTreeMap<String, BTreeMap<String, Vec<Value>>>,
    #[serde(default)]
    pub capability_gap: Option<CapabilityGap>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    PendingApproval,
    Approved,
    Running,
    Checkpoint,
    Rejected,
    Interrupted,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HumanDecision {
    Approve,
    Reject,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    Success,
    Partial,
    Failed,
    Unknown,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    #[default]
    Provisional,
    Accepted,
    Rejected,
    NeedsCorroboration,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Observation,
    Interpretation,
    Contradiction,
    NegativeResult,
    Limitation,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Coverage {
    #[serde(default)]
    pub examined: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolOutcome {
    pub status: ToolStatus,
    /// Full tool result. Presentation truncation must happen after this is persisted.
    pub output: String,
    #[serde(default)]
    pub coverage: Coverage,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub process_exit_code: Option<i32>,
    #[serde(default)]
    pub verification: Vec<String>,
}
impl ToolOutcome {
    pub fn failed(error: impl Into<String>) -> Self {
        let error = error.into();
        Self {
            status: ToolStatus::Failed,
            output: error.clone(),
            coverage: Coverage::default(),
            error: Some(error),
            process_exit_code: None,
            verification: vec![],
        }
    }
    /// The adapter supplies status from structured tool results, not display text.
    pub fn new(status: ToolStatus, output: impl Into<String>) -> Self {
        Self {
            status,
            output: output.into(),
            coverage: Coverage::default(),
            error: None,
            process_exit_code: None,
            verification: vec![],
        }
    }
    fn validate(&self) -> Result<()> {
        if self.status == ToolStatus::Success
            && (self.error.is_some() || self.process_exit_code.is_some_and(|v| v != 0))
        {
            bail!("Tool success contradicts its error or nonzero exit status");
        }
        if self.coverage.complete && (self.coverage.truncated || self.status != ToolStatus::Success)
        {
            bail!("Incomplete, truncated or unsuccessful output cannot claim complete coverage");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceReference {
    pub evidence_id: i64,
    pub location: String,
    #[serde(default)]
    pub excerpt: String,
    #[serde(default)]
    pub sha256: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub step_id: String,
    pub kind: FindingKind,
    pub title: String,
    pub observation: String,
    #[serde(default)]
    pub interpretation: Option<String>,
    pub sources: Vec<SourceReference>,
    pub execution_ids: Vec<String>,
    #[serde(default)]
    pub contradictions: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(default)]
    pub reproduction_steps: Vec<String>,
    #[serde(default)]
    pub review: ReviewStatus,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StepCheckpoint {
    #[serde(default)]
    pub observations: Vec<String>,
    #[serde(default)]
    pub interpretation: Vec<String>,
    #[serde(default)]
    pub contradictions: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(default)]
    pub proposed_next_step: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepRecord {
    pub proposal: StepProposal,
    pub state: StepState,
    pub turn_id: Option<String>,
    pub started_unix_secs: Option<u64>,
    pub checkpoint: Option<StepCheckpoint>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub target_id: String,
    pub decision: String,
    pub actor: String,
    pub rationale: String,
    pub recorded_unix_secs: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub id: String,
    pub step_id: String,
    pub turn_id: String,
    pub tool_name: String,
    pub parameters: Value,
    pub evidence_ids: Vec<i64>,
    #[serde(default)]
    pub evidence_sources: Vec<EvidenceSource>,
    pub destination: Option<ProcessingDestination>,
    pub started_unix_secs: u64,
    pub completed_unix_secs: Option<u64>,
    pub toolkit_version: String,
    #[serde(default)]
    pub source_hashes: BTreeMap<String, String>,
    pub outcome: Option<ToolOutcome>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderRecord {
    pub turn_id: String,
    pub provider: String,
    pub endpoint: String,
    pub model: String,
    pub authentication_mode: String,
    #[serde(default)]
    pub actual_model: Option<String>,
    pub account: Option<String>,
    #[serde(default)]
    pub usage_source: Option<String>,
    pub recorded_unix_secs: u64,
}
#[derive(Clone, Debug)]
pub struct ExecutionPermit {
    pub id: String,
    pub step_id: String,
    pub turn_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaseBriefRevision {
    pub brief: CaseBrief,
    pub recorded_unix_secs: u64,
    pub revision: i64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InvestigationSnapshot {
    pub session_id: String,
    pub brief: Option<CaseBrief>,
    #[serde(default)]
    pub brief_history: Vec<CaseBriefRevision>,
    pub brief_confirmed: bool,
    pub steps: Vec<StepRecord>,
    pub findings: Vec<Finding>,
    pub decisions: Vec<DecisionRecord>,
    pub executions: Vec<ExecutionRecord>,
    #[serde(default)]
    pub providers: Vec<ProviderRecord>,
    pub revision: i64,
    pub exported_revision: i64,
    pub report_path: PathBuf,
    pub execution_log_path: PathBuf,
}

#[derive(Clone)]
pub struct InvestigationStore {
    pool: SqlitePool,
    session_id: String,
    export_dir: PathBuf,
    gate: Arc<Mutex<()>>,
}
impl InvestigationStore {
    pub async fn open(
        pool: SqlitePool,
        session_id: impl Into<String>,
        export_dir: impl Into<PathBuf>,
    ) -> Result<Self> {
        let session_id = session_id.into();
        if session_id.is_empty()
            || session_id.len() > 128
            || !session_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        {
            bail!("Unsafe investigation session identifier");
        }
        sqlx::query("CREATE TABLE IF NOT EXISTS agent_investigations (session_id TEXT PRIMARY KEY, state_json TEXT NOT NULL, revision INTEGER NOT NULL, exported_revision INTEGER NOT NULL DEFAULT -1)").execute(&pool).await?;
        let store = Self {
            pool,
            session_id,
            export_dir: export_dir.into(),
            gate: Arc::new(Mutex::new(())),
        };
        let _guard = store.gate.lock().await;
        let mut state = store.load().await?;
        let mut interrupted = false;
        for step in &mut state.steps {
            if matches!(step.state, StepState::Running | StepState::Approved) {
                step.state = StepState::Interrupted;
                step.checkpoint = Some(StepCheckpoint { limitations: vec!["Session reopened; previous approval is not reusable. Review partial execution records and approve a fresh step.".into()], ..Default::default() });
                interrupted = true;
            }
        }
        for execution in &mut state.executions {
            if execution.outcome.is_none() {
                execution.outcome = Some(ToolOutcome::new(
                    ToolStatus::Unknown,
                    "Execution was interrupted; completion was not observed.",
                ));
                execution.completed_unix_secs = Some(now());
            }
        }
        if interrupted || state.revision == 0 {
            store.persist(&mut state).await?;
        } else if state.exported_revision != state.revision {
            store.export(&state).await?;
        }
        drop(_guard);
        Ok(store)
    }

    pub async fn snapshot(&self) -> Result<InvestigationSnapshot> {
        self.load().await
    }

    pub async fn set_case_brief(&self, brief: CaseBrief) -> Result<()> {
        if brief.evidence.is_empty() {
            bail!("At least one selected evidence source is required");
        }
        let mut ids = std::collections::BTreeSet::new();
        for source in &brief.evidence {
            if source.path.trim().is_empty() || !ids.insert(source.id) {
                bail!("Evidence paths must be nonempty and evidence IDs unique");
            }
        }
        let _guard = self.gate.lock().await;
        let mut state = self.load().await?;
        if state.steps.iter().any(|s| s.state == StepState::Running) {
            bail!("Cannot change case scope during a running step");
        }
        state.brief_history.push(CaseBriefRevision {
            brief: brief.clone(),
            recorded_unix_secs: now(),
            revision: state.revision + 1,
        });
        state.brief = Some(brief);
        state.brief_confirmed = false;
        for step in &mut state.steps {
            if matches!(step.state, StepState::Approved | StepState::PendingApproval) {
                step.state = StepState::Interrupted;
            }
        }
        self.persist(&mut state).await
    }

    pub async fn propose_steps(&self, proposals: Vec<StepProposal>) -> Result<()> {
        if proposals.is_empty()
            || proposals.len() > 3
            || proposals.iter().filter(|p| p.recommended).count() != 1
        {
            bail!("Propose one to three investigation paths, with exactly one recommendation");
        }
        let _guard = self.gate.lock().await;
        let mut state = self.load().await?;
        let brief = state
            .brief
            .as_ref()
            .ok_or_else(|| anyhow!("Complete the case brief before proposing steps"))?;
        if state.steps.iter().any(|s| s.state == StepState::Running) {
            bail!("Finish the current step before proposing a pivot");
        }
        let mut seen = std::collections::BTreeSet::new();
        for p in &proposals {
            if p.id.trim().is_empty()
                || state.steps.iter().any(|s| s.proposal.id == p.id)
                || !seen.insert(p.id.clone())
            {
                bail!("Each step requires a new, unique ID");
            }
            if p.question.trim().is_empty()
                || p.rationale.trim().is_empty()
                || p.evidence_ids.is_empty()
                || p.permitted_tools.is_empty()
                || p.limits.max_tool_calls == 0
                || p.limits.max_duration_secs == 0
                || p.limits.max_output_bytes == 0
            {
                bail!("Step requires a question, rationale, selected sources, tools and nonzero resource bounds");
            }
            if p.evidence_ids
                .iter()
                .any(|id| !brief.evidence.iter().any(|e| e.id == *id))
            {
                bail!("Step references evidence outside the case brief");
            }
            for (tool, deps) in &p.tool_dependencies {
                if !p.permitted_tools.contains(tool)
                    || deps
                        .iter()
                        .any(|d| d == tool || !p.permitted_tools.contains(d))
                {
                    bail!("Step dependency references an unapproved tool or itself");
                }
            }
        }
        // Previous unselected proposals are retained as history, never quietly reusable.
        for step in &mut state.steps {
            if matches!(step.state, StepState::PendingApproval | StepState::Approved) {
                step.state = StepState::Interrupted;
            }
        }
        state
            .steps
            .extend(proposals.into_iter().map(|proposal| StepRecord {
                proposal,
                state: StepState::PendingApproval,
                turn_id: None,
                started_unix_secs: None,
                checkpoint: None,
            }));
        self.persist(&mut state).await
    }

    /// Call only after an explicit human decision. Approval confirms the displayed case brief too.
    pub async fn decide_step(
        &self,
        step_id: &str,
        decision: HumanDecision,
        actor: &str,
        rationale: &str,
    ) -> Result<()> {
        require_actor(actor)?;
        let _guard = self.gate.lock().await;
        let mut state = self.load().await?;
        if state
            .brief
            .as_ref()
            .is_none_or(|b| b.objective.trim().is_empty())
        {
            bail!("A case brief with a case objective is required");
        }
        if state.steps.iter().any(|s| s.state == StepState::Running) {
            bail!("A step is already running");
        }
        let index = state
            .steps
            .iter()
            .position(|s| s.proposal.id == step_id)
            .ok_or_else(|| anyhow!("Unknown step"))?;
        if state.steps[index].state != StepState::PendingApproval {
            bail!("Only a pending step can receive a decision; create a fresh proposal to resume or pivot");
        }
        if decision == HumanDecision::Approve {
            if state.steps[index]
                .proposal
                .capability_gap
                .as_ref()
                .is_some_and(|gap| gap.proposed_external_tool.is_some())
                && !state
                    .brief
                    .as_ref()
                    .expect("brief checked above")
                    .processing_policy
                    .allow_external_tools
            {
                bail!("The proposed external tool requires an explicit update to the case processing policy before approval");
            }
            for (i, step) in state.steps.iter_mut().enumerate() {
                if i != index
                    && matches!(step.state, StepState::PendingApproval | StepState::Approved)
                {
                    step.state = StepState::Interrupted;
                }
            }
            state.brief_confirmed = true;
            state.steps[index].state = StepState::Approved;
        } else {
            state.steps[index].state = StepState::Rejected;
        }
        state.decisions.push(DecisionRecord {
            target_id: step_id.into(),
            decision: format!("{decision:?}"),
            actor: actor.into(),
            rationale: rationale.into(),
            recorded_unix_secs: now(),
        });
        self.persist(&mut state).await
    }

    pub async fn begin_step(&self, step_id: &str, turn_id: &str) -> Result<()> {
        if turn_id.trim().is_empty() {
            bail!("A step must be bound to a turn ID");
        }
        let _guard = self.gate.lock().await;
        let mut state = self.load().await?;
        ensure_exported(&state)?;
        if !state.brief_confirmed
            || state
                .steps
                .iter()
                .any(|s| s.state == StepState::Running || s.turn_id.as_deref() == Some(turn_id))
        {
            bail!("Case brief must be confirmed and turn ID must be new, with no running step");
        }
        let step = state
            .steps
            .iter_mut()
            .find(|s| s.proposal.id == step_id)
            .ok_or_else(|| anyhow!("Unknown step"))?;
        if step.state != StepState::Approved {
            bail!("Explicit investigator approval is required");
        }
        step.state = StepState::Running;
        step.turn_id = Some(turn_id.into());
        step.started_unix_secs = Some(now());
        self.persist(&mut state).await
    }

    pub async fn authorize_tool(
        &self,
        turn_id: &str,
        tool_name: &str,
        parameters: Value,
        evidence_ids: &[i64],
        destination: Option<&ProcessingDestination>,
    ) -> Result<ExecutionPermit> {
        let _guard = self.gate.lock().await;
        let mut state = self.load().await?;
        ensure_exported(&state)?;
        let step = state
            .steps
            .iter()
            .find(|s| s.state == StepState::Running && s.turn_id.as_deref() == Some(turn_id))
            .cloned()
            .ok_or_else(|| anyhow!("No investigator-approved step is active for this turn"))?;
        let proposal = &step.proposal;
        if !proposal.permitted_tools.iter().any(|t| t == tool_name) {
            bail!("Tool is outside the approved step");
        }
        if let Some(selectors) = proposal.source_selectors.get(tool_name) {
            for (key, allowed) in selectors {
                if !parameters
                    .get(key)
                    .is_some_and(|value| allowed.contains(value))
                {
                    let reason = format!(
                        "Tool argument {key} is missing or outside the approved source selectors"
                    );
                    stop_running_steps(&mut state, &reason);
                    self.persist(&mut state).await?;
                    bail!(reason);
                }
            }
        }
        if evidence_ids.is_empty()
            || evidence_ids
                .iter()
                .any(|id| !proposal.evidence_ids.contains(id))
        {
            let reason = "Tool source is outside the approved evidence selection";
            stop_running_steps(&mut state, reason);
            self.persist(&mut state).await?;
            bail!(reason);
        }
        if now().saturating_sub(step.started_unix_secs.unwrap_or(0))
            >= proposal.limits.max_duration_secs
        {
            bail!("Approved step duration has been exhausted");
        }
        let prior: Vec<_> = state
            .executions
            .iter()
            .filter(|e| e.step_id == proposal.id)
            .collect();
        if prior.len() >= proposal.limits.max_tool_calls {
            bail!("Approved tool call budget has been exhausted");
        }
        let failures = prior
            .iter()
            .filter(|e| {
                e.tool_name == tool_name
                    && e.outcome.as_ref().is_some_and(|o| {
                        matches!(o.status, ToolStatus::Failed | ToolStatus::Unknown)
                    })
            })
            .count();
        if failures > proposal.limits.max_retries_per_tool {
            bail!("Bounded retries exhausted for this failed branch");
        }
        if prior
            .iter()
            .any(|e| e.tool_name == tool_name && e.outcome.is_none())
        {
            bail!("A call on this branch is still in progress");
        }
        if let Some(deps) = proposal.tool_dependencies.get(tool_name) {
            for dep in deps {
                let latest = prior.iter().rev().find(|e| &e.tool_name == dep);
                if !latest.is_some_and(|e| {
                    e.outcome.as_ref().is_some_and(|o| {
                        matches!(o.status, ToolStatus::Success | ToolStatus::Partial)
                    })
                }) {
                    bail!("Required branch {dep} has no verified usable result");
                }
            }
        }
        let brief = state
            .brief
            .as_ref()
            .ok_or_else(|| anyhow!("Missing case brief"))?;
        if let Some(destination) = destination {
            if let Err(error) = ensure_destination(brief, destination) {
                stop_running_steps(&mut state, &error.to_string());
                self.persist(&mut state).await?;
                return Err(error);
            }
        }
        let id = format!(
            "execution-{}-{}",
            state.revision + 1,
            state.executions.len() + 1
        );
        let permit = ExecutionPermit {
            id: id.clone(),
            step_id: proposal.id.clone(),
            turn_id: turn_id.into(),
        };
        let source_hashes = state
            .brief
            .as_ref()
            .expect("brief checked above")
            .evidence
            .iter()
            .filter(|e| evidence_ids.contains(&e.id))
            .filter_map(|e| e.sha256.as_ref().map(|hash| (e.path.clone(), hash.clone())))
            .collect();
        state.executions.push(ExecutionRecord {
            id,
            step_id: proposal.id.clone(),
            turn_id: turn_id.into(),
            tool_name: tool_name.into(),
            parameters,
            evidence_ids: evidence_ids.to_vec(),
            evidence_sources: state
                .brief
                .as_ref()
                .expect("brief checked above")
                .evidence
                .iter()
                .filter(|e| evidence_ids.contains(&e.id))
                .cloned()
                .collect(),
            destination: destination.cloned(),
            started_unix_secs: now(),
            completed_unix_secs: None,
            toolkit_version: format!("exhume_agent {}", env!("CARGO_PKG_VERSION")),
            source_hashes,
            outcome: None,
        });
        self.persist(&mut state).await?;
        Ok(permit)
    }

    pub async fn record_provider(
        &self,
        turn_id: &str,
        destination: &ProcessingDestination,
        authentication_mode: &str,
        account: Option<String>,
    ) -> Result<()> {
        self.record_provider_usage(turn_id, destination, authentication_mode, account, None)
            .await
    }

    pub async fn record_provider_usage(
        &self,
        turn_id: &str,
        destination: &ProcessingDestination,
        authentication_mode: &str,
        account: Option<String>,
        usage_source: Option<String>,
    ) -> Result<()> {
        self.record_provider_response(
            turn_id,
            destination,
            None,
            authentication_mode,
            account,
            usage_source,
        )
        .await
    }

    pub async fn record_provider_response(
        &self,
        turn_id: &str,
        destination: &ProcessingDestination,
        actual_model: Option<String>,
        authentication_mode: &str,
        account: Option<String>,
        usage_source: Option<String>,
    ) -> Result<()> {
        let _guard = self.gate.lock().await;
        let mut state = self.load().await?;
        ensure_exported(&state)?;
        if !state
            .steps
            .iter()
            .any(|s| s.state == StepState::Running && s.turn_id.as_deref() == Some(turn_id))
        {
            bail!("Provider invocation requires an active approved step");
        }
        let brief = state
            .brief
            .as_ref()
            .ok_or_else(|| anyhow!("Missing case brief"))?;
        if let Err(error) = ensure_destination(brief, destination) {
            stop_running_steps(&mut state, &error.to_string());
            self.persist(&mut state).await?;
            return Err(error);
        }
        if (!destination.authentication_mode.is_empty()
            && destination.authentication_mode != authentication_mode)
            || (destination.account_id.is_some() && destination.account_id != account)
        {
            let reason = "Observed authentication mode or account differs from the approved provider request";
            stop_running_steps(&mut state, reason);
            self.persist(&mut state).await?;
            bail!(reason);
        }
        state.providers.push(ProviderRecord {
            turn_id: turn_id.into(),
            provider: destination.provider.clone(),
            endpoint: destination.endpoint.clone(),
            model: destination.model.clone(),
            authentication_mode: authentication_mode.into(),
            actual_model,
            account,
            usage_source,
            recorded_unix_secs: now(),
        });
        self.persist(&mut state).await
    }

    pub async fn authorize_processing(&self, destination: &ProcessingDestination) -> Result<()> {
        self.check_destination(destination).await
    }

    /// Also use before model calls, so provider changes never bypass the case policy.
    pub async fn check_destination(&self, destination: &ProcessingDestination) -> Result<()> {
        let _guard = self.gate.lock().await;
        let mut state = self.load().await?;
        ensure_exported(&state)?;
        let brief = state
            .brief
            .as_ref()
            .filter(|_| state.brief_confirmed)
            .ok_or_else(|| {
                anyhow!("Confirm the case processing policy before sending evidence to a model")
            })?;
        if let Err(error) = ensure_destination(brief, destination) {
            stop_running_steps(&mut state, &error.to_string());
            self.persist(&mut state).await?;
            return Err(error);
        }
        Ok(())
    }

    pub async fn complete_tool(
        &self,
        permit: ExecutionPermit,
        mut outcome: ToolOutcome,
    ) -> Result<()> {
        outcome.validate()?;
        let _guard = self.gate.lock().await;
        let mut state = self.load().await?;
        let record_index = state
            .executions
            .iter()
            .position(|e| {
                e.id == permit.id && e.step_id == permit.step_id && e.turn_id == permit.turn_id
            })
            .ok_or_else(|| anyhow!("Unknown execution permit"))?;
        if state.executions[record_index].outcome.is_some() {
            bail!("Execution outcome is immutable");
        }
        let step_index = state
            .steps
            .iter()
            .position(|s| s.proposal.id == permit.step_id)
            .ok_or_else(|| anyhow!("Unknown execution step"))?;
        if outcome.output.len() > state.steps[step_index].proposal.limits.max_output_bytes {
            outcome.coverage.limitations.push("Tool output exceeded the approved byte limit; the full received output was retained for audit, and the step stopped.".into());
            state.steps[step_index].state = StepState::Checkpoint;
            state.steps[step_index].checkpoint = Some(StepCheckpoint {
                limitations: outcome.coverage.limitations.clone(),
                ..Default::default()
            });
        }
        let record = &mut state.executions[record_index];
        record.completed_unix_secs = Some(now());
        record.outcome = Some(outcome);
        self.persist(&mut state).await
    }

    pub async fn finish_step(&self, turn_id: &str, checkpoint: StepCheckpoint) -> Result<()> {
        self.end_step(turn_id, checkpoint, StepState::Checkpoint)
            .await
    }
    pub async fn interrupt_step(&self, turn_id: &str, reason: &str) -> Result<()> {
        self.end_step(
            turn_id,
            StepCheckpoint {
                limitations: vec![reason.into()],
                ..Default::default()
            },
            StepState::Interrupted,
        )
        .await
    }
    async fn end_step(
        &self,
        turn_id: &str,
        checkpoint: StepCheckpoint,
        next: StepState,
    ) -> Result<()> {
        let _guard = self.gate.lock().await;
        let mut state = self.load().await?;
        let step = state
            .steps
            .iter_mut()
            .find(|s| s.turn_id.as_deref() == Some(turn_id))
            .ok_or_else(|| anyhow!("Unknown step turn"))?;
        if !matches!(step.state, StepState::Running | StepState::Checkpoint) {
            bail!("Step is no longer running");
        }
        step.state = next;
        step.checkpoint = Some(checkpoint);
        for execution in state
            .executions
            .iter_mut()
            .filter(|e| e.turn_id == turn_id && e.outcome.is_none())
        {
            execution.completed_unix_secs = Some(now());
            execution.outcome = Some(ToolOutcome::new(
                ToolStatus::Unknown,
                "Step ended before a completed tool result was recorded.",
            ));
        }
        self.persist(&mut state).await
    }

    pub async fn record_finding(&self, mut finding: Finding) -> Result<()> {
        let _guard = self.gate.lock().await;
        let mut state = self.load().await?;
        if finding.id.trim().is_empty()
            || finding.title.trim().is_empty()
            || finding.observation.trim().is_empty()
            || state.findings.iter().any(|f| f.id == finding.id)
        {
            bail!("Finding requires a new ID, title and observation");
        }
        let step = state
            .steps
            .iter()
            .find(|s| s.proposal.id == finding.step_id)
            .ok_or_else(|| anyhow!("Unknown finding step"))?;
        if finding.execution_ids.is_empty() || finding.sources.is_empty() {
            bail!("A material finding must cite observed tool results and source locations");
        }
        for source in &finding.sources {
            if source.location.trim().is_empty()
                || !step.proposal.evidence_ids.contains(&source.evidence_id)
            {
                bail!("Finding source is outside the step or has no locator");
            }
        }
        for source in &finding.sources {
            let observed_locator = state
                .executions
                .iter()
                .filter(|execution| {
                    finding.execution_ids.contains(&execution.id)
                        && execution.step_id == finding.step_id
                        && execution.evidence_ids.contains(&source.evidence_id)
                })
                .any(|execution| {
                    execution.id == source.location
                        || execution
                            .evidence_sources
                            .iter()
                            .any(|e| e.id == source.evidence_id && e.path == source.location)
                        || result_contains(&execution.parameters.to_string(), &source.location)
                        || execution.outcome.as_ref().is_some_and(|outcome| {
                            result_contains(&outcome.output, &source.location)
                                || outcome
                                    .coverage
                                    .examined
                                    .iter()
                                    .any(|value| value.contains(&source.location))
                        })
                });
            if !observed_locator {
                bail!("Source location was not observed in the cited execution parameters, result or captured evidence identity; use the execution ID for an authoritative query locator");
            }
            if source.excerpt.trim().is_empty() && finding.kind != FindingKind::Limitation {
                bail!("Evidence observations and interpretations require an exact excerpt from their cited tool result");
            }
            if !source.excerpt.is_empty()
                && !state
                    .executions
                    .iter()
                    .filter(|e| {
                        finding.execution_ids.contains(&e.id)
                            && e.step_id == finding.step_id
                            && e.evidence_ids.contains(&source.evidence_id)
                    })
                    .any(|e| {
                        e.outcome
                            .as_ref()
                            .is_some_and(|o| result_contains(&o.output, &source.excerpt))
                    })
            {
                bail!("Source excerpt was not found in any cited tool result for that evidence");
            }
            if let Some(hash) = &source.sha256 {
                if !state
                    .executions
                    .iter()
                    .filter(|e| {
                        finding.execution_ids.contains(&e.id)
                            && e.evidence_ids.contains(&source.evidence_id)
                    })
                    .any(|e| {
                        e.source_hashes.values().any(|h| h == hash)
                            || e.outcome
                                .as_ref()
                                .is_some_and(|o| result_contains(&o.output, hash))
                    })
                {
                    bail!("Source digest was not observed in the cited result or captured evidence identity");
                }
            }
        }
        for id in &finding.execution_ids {
            let execution = state
                .executions
                .iter()
                .find(|e| &e.id == id && e.step_id == finding.step_id)
                .ok_or_else(|| {
                    anyhow!(
                        "Finding references an execution from another step or an unknown execution"
                    )
                })?;
            let outcome = execution
                .outcome
                .as_ref()
                .ok_or_else(|| anyhow!("Finding cannot cite an unfinished tool call"))?;
            if matches!(
                finding.kind,
                FindingKind::Observation
                    | FindingKind::Interpretation
                    | FindingKind::NegativeResult
            ) && !matches!(outcome.status, ToolStatus::Success | ToolStatus::Partial)
            {
                bail!("Evidence findings require a verified usable tool result; record failures as limitations");
            }
            if finding.kind == FindingKind::NegativeResult
                && (!outcome.coverage.complete || outcome.coverage.truncated)
                && finding.limitations.is_empty()
            {
                bail!("A negative result with incomplete coverage must state its limitations");
            }
            let reproduce = format!("Run `{}` with these exact parameters: `{}`. Source evidence IDs: {:?}; toolkit: {}. Execution record: {}.", execution.tool_name, serde_json::to_string(&execution.parameters)?, execution.evidence_ids, execution.toolkit_version, execution.id);
            if !finding.reproduction_steps.contains(&reproduce) {
                finding.reproduction_steps.push(reproduce);
            }
        }
        // Model-supplied review flags cannot promote an interpretation to accepted.
        finding.review = ReviewStatus::Provisional;
        state.findings.push(finding);
        self.persist(&mut state).await
    }

    pub async fn review_finding(
        &self,
        finding_id: &str,
        review: ReviewStatus,
        actor: &str,
        rationale: &str,
    ) -> Result<()> {
        require_actor(actor)?;
        if review == ReviewStatus::Provisional {
            bail!("Choose accept, reject or needs corroboration");
        }
        let _guard = self.gate.lock().await;
        let mut state = self.load().await?;
        let finding = state
            .findings
            .iter_mut()
            .find(|f| f.id == finding_id)
            .ok_or_else(|| anyhow!("Unknown finding"))?;
        finding.review = review;
        state.decisions.push(DecisionRecord {
            target_id: finding_id.into(),
            decision: format!("{review:?}"),
            actor: actor.into(),
            rationale: rationale.into(),
            recorded_unix_secs: now(),
        });
        self.persist(&mut state).await
    }

    /// Explicit repair retries both exports. Execution remains blocked until it succeeds.
    pub async fn repair_exports(&self) -> Result<()> {
        let _guard = self.gate.lock().await;
        self.export(&self.load().await?).await
    }

    async fn load(&self) -> Result<InvestigationSnapshot> {
        if let Some(row) = sqlx::query("SELECT state_json, revision, exported_revision FROM agent_investigations WHERE session_id = ?").bind(&self.session_id).fetch_optional(&self.pool).await? {
            let mut state: InvestigationSnapshot = serde_json::from_str(row.try_get("state_json")?)?;
            state.revision = row.try_get("revision")?;
            state.exported_revision = row.try_get("exported_revision")?;
            Ok(state)
        } else {
            Ok(InvestigationSnapshot { session_id: self.session_id.clone(), report_path: self.export_dir.join(format!("{}-investigation.md", self.session_id)), execution_log_path: self.export_dir.join(format!("{}-executions.jsonl", self.session_id)), ..Default::default() })
        }
    }
    async fn persist(&self, state: &mut InvestigationSnapshot) -> Result<()> {
        let old_revision = state.revision;
        state.revision += 1;
        let json = serde_json::to_string(state)?;
        let changed = if old_revision == 0 {
            sqlx::query("INSERT OR IGNORE INTO agent_investigations(session_id,state_json,revision,exported_revision) VALUES(?,?,?,-1)").bind(&self.session_id).bind(&json).bind(state.revision).execute(&self.pool).await?.rows_affected()
        } else {
            sqlx::query("UPDATE agent_investigations SET state_json = ?, revision = ? WHERE session_id = ? AND revision = ?").bind(&json).bind(state.revision).bind(&self.session_id).bind(old_revision).execute(&self.pool).await?.rows_affected()
        };
        if changed != 1 {
            bail!("Investigation changed concurrently; reload before retrying the decision");
        }
        self.export(state).await.context("Investigation was recorded in the database, but report export failed; execution is blocked until exports are repaired")?;
        state.exported_revision = state.revision;
        Ok(())
    }
    async fn export(&self, state: &InvestigationSnapshot) -> Result<()> {
        let markdown = render_markdown(state);
        let mut jsonl = String::new();
        for execution in &state.executions {
            jsonl.push_str(&serde_json::to_string(execution)?);
            jsonl.push('\n');
        }
        // The SQLite write lock serializes exports across distinct store instances and
        // processes, not only clones sharing the in-memory gate. Check freshness before
        // touching either file so an older exporter cannot overwrite a newer report.
        let mut transaction = self.pool.begin().await?;
        let locked = sqlx::query("UPDATE agent_investigations SET exported_revision = -1 WHERE session_id = ? AND revision = ?")
            .bind(&self.session_id).bind(state.revision).execute(&mut *transaction).await?;
        if locked.rows_affected() != 1 {
            bail!("Investigation changed before export; reload before repairing exports");
        }
        let write_result = (|| -> Result<()> {
            atomic_write(&state.report_path, markdown.as_bytes())?;
            atomic_write(&state.execution_log_path, jsonl.as_bytes())?;
            Ok(())
        })();
        if let Err(error) = write_result {
            // Commit the blocked marker even during a repair of an otherwise-current
            // revision. Returning an error must never leave a successful-export claim.
            transaction.commit().await?;
            return Err(error);
        }
        sqlx::query("UPDATE agent_investigations SET exported_revision = ? WHERE session_id = ? AND revision = ?")
            .bind(state.revision).bind(&self.session_id).bind(state.revision).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(())
    }
}

fn stop_running_steps(state: &mut InvestigationSnapshot, reason: &str) {
    for step in &mut state.steps {
        if step.state == StepState::Running {
            step.state = StepState::Interrupted;
            step.checkpoint = Some(StepCheckpoint {
                limitations: vec![reason.into()],
                proposed_next_step:
                    "Review the scope or processing policy and approve a fresh step.".into(),
                ..Default::default()
            });
        }
    }
}

fn result_contains(raw: &str, excerpt: &str) -> bool {
    if raw.contains(excerpt) {
        return true;
    }
    fn contains(value: &Value, excerpt: &str) -> bool {
        match value {
            Value::String(value) => value.contains(excerpt),
            Value::Array(values) => values.iter().any(|v| contains(v, excerpt)),
            Value::Object(values) => values.values().any(|v| contains(v, excerpt)),
            _ => false,
        }
    }
    serde_json::from_str::<Value>(raw)
        .ok()
        .is_some_and(|value| contains(&value, excerpt))
}

fn ensure_destination(brief: &CaseBrief, destination: &ProcessingDestination) -> Result<()> {
    if !brief
        .processing_policy
        .allowed_destinations
        .iter()
        .any(|a| {
            a.provider == destination.provider
                && a.endpoint.trim_end_matches('/') == destination.endpoint.trim_end_matches('/')
                && (a.model.is_empty() || a.model == destination.model)
                && (a.authentication_mode.is_empty()
                    || a.authentication_mode == destination.authentication_mode)
                && (a.account_id.is_none() || a.account_id == destination.account_id)
        })
    {
        bail!("Provider, endpoint, model, authentication mode or account is outside the investigator-approved processing policy");
    }
    Ok(())
}
fn ensure_exported(state: &InvestigationSnapshot) -> Result<()> {
    if state.revision != state.exported_revision {
        bail!(
            "Report or execution-log persistence is incomplete; repair exports before continuing"
        );
    }
    Ok(())
}
fn require_actor(actor: &str) -> Result<()> {
    if actor.trim().is_empty() {
        bail!("An identified investigator must make this decision");
    }
    Ok(())
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Report requires a parent directory"))?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|e| anyhow!(e.error))?;
    // Unix supports directory fsync; Windows File::open rejects directory handles.
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn bullet_list(out: &mut String, label: &str, values: &[String]) {
    out.push_str(&format!("### {label}\n\n"));
    if values.is_empty() {
        out.push_str("None recorded.\n\n");
    } else {
        for value in values {
            out.push_str(&format!("- {value}\n"));
        }
        out.push('\n');
    }
}
fn fenced(out: &mut String, language: &str, value: &str) {
    let mut fence = "```".to_string();
    while value.contains(&fence) {
        fence.push('`');
    }
    out.push_str(&format!("{fence}{language}\n{value}\n{fence}\n\n"));
}
pub fn render_markdown(state: &InvestigationSnapshot) -> String {
    let mut out = format!("# Investigation working report\n\nSession: `{}` · revision: {}\n\nThis is an investigator-reviewed working record. Tool success verifies execution, not the truth of an interpretation. No case-resolution decision is made by the assistant.\n\n", state.session_id, state.revision);
    if let Some(brief) = &state.brief {
        out.push_str(&format!(
            "## Case brief\n\nObjective: {}\n\nInvestigator confirmed: {}\n\n",
            brief.objective, state.brief_confirmed
        ));
        for source in &brief.evidence {
            out.push_str(&format!(
                "- Evidence {}: `{}`; role: {}; SHA-256: {}; size: {:?}; modified: {:?}.\n",
                source.id,
                source.path,
                source.role,
                source.sha256.as_deref().unwrap_or("not recorded"),
                source.size_bytes,
                source.modified_unix_secs
            ));
        }
        out.push('\n');
        bullet_list(&mut out, "Supplied facts", &brief.facts);
        bullet_list(&mut out, "Allegations", &brief.allegations);
        bullet_list(&mut out, "Scope constraints", &brief.constraints);
        out.push_str("### Processing policy\n\n");
        fenced(
            &mut out,
            "json",
            &serde_json::to_string_pretty(&brief.processing_policy).unwrap_or_default(),
        );
    } else {
        out.push_str("Case brief awaits investigator input.\n\n");
    }
    if state.brief_history.len() > 1 {
        out.push_str("## Case brief revision history\n\n");
        for revision in &state.brief_history {
            out.push_str(&format!(
                "### Brief recorded at revision {} (time {})\n\n",
                revision.revision, revision.recorded_unix_secs
            ));
            fenced(
                &mut out,
                "json",
                &serde_json::to_string_pretty(&revision.brief).unwrap_or_default(),
            );
        }
    }
    out.push_str("## Investigative steps and checkpoints\n\n");
    for step in &state.steps {
        out.push_str(&format!(
            "### {}: {}\n\nState: {:?}. Recommended: {}.\n\nRationale: {}\n\n",
            step.proposal.id,
            step.proposal.question,
            step.state,
            step.proposal.recommended,
            step.proposal.rationale
        ));
        out.push_str("Approved or proposed scope and limits:\n\n");
        fenced(
            &mut out,
            "json",
            &serde_json::to_string_pretty(&step.proposal).unwrap_or_default(),
        );
        if let Some(checkpoint) = &step.checkpoint {
            bullet_list(&mut out, "Observations", &checkpoint.observations);
            bullet_list(
                &mut out,
                "Interpretation (provisional)",
                &checkpoint.interpretation,
            );
            bullet_list(&mut out, "Contradictions", &checkpoint.contradictions);
            bullet_list(&mut out, "Limitations", &checkpoint.limitations);
            out.push_str(&format!(
                "Proposed next step: {}\n\n",
                checkpoint.proposed_next_step
            ));
        }
        if let Some(gap) = &step.proposal.capability_gap {
            out.push_str("#### GitHub issue draft for investigator review\n\n");
            fenced(&mut out, "markdown", &gap.issue_draft());
        }
    }
    out.push_str("## Material findings\n\n");
    if state.findings.is_empty() {
        out.push_str("No material findings have been recorded.\n\n");
    }
    for finding in &state.findings {
        out.push_str(&format!(
            "### {}: {}\n\nType: {:?}. Review: {:?}. Step: {}.\n\nObservation: {}\n\n",
            finding.id,
            finding.title,
            finding.kind,
            finding.review,
            finding.step_id,
            finding.observation
        ));
        if let Some(interpretation) = &finding.interpretation {
            out.push_str(&format!("Interpretation: {interpretation}\n\n"));
        }
        out.push_str("Sources:\n\n");
        for source in &finding.sources {
            out.push_str(&format!(
                "- Evidence {}: `{}`; SHA-256: {}.\n",
                source.evidence_id,
                source.location,
                source.sha256.as_deref().unwrap_or("not recorded")
            ));
            if !source.excerpt.is_empty() {
                fenced(&mut out, "text", &source.excerpt);
            }
        }
        bullet_list(&mut out, "Reproduction steps", &finding.reproduction_steps);
        bullet_list(&mut out, "Contradictions", &finding.contradictions);
        bullet_list(&mut out, "Limitations", &finding.limitations);
    }
    out.push_str("## Provider provenance\n\n");
    for provider in &state.providers {
        out.push_str(&format!(
            "- Turn {}: {} at `{}`, model `{}`, authentication: {}, account: {}, recorded: {}.\n",
            provider.turn_id,
            provider.provider,
            provider.endpoint,
            provider.model,
            provider.authentication_mode,
            provider.account.as_deref().unwrap_or("not supplied"),
            provider.recorded_unix_secs
        ));
        if let Some(actual_model) = &provider.actual_model {
            out.push_str(&format!(
                "  Resolved model reported by provider: `{actual_model}`.\n"
            ));
        }
    }
    out.push_str("\n## Execution and reproduction index\n\n");
    for execution in &state.executions {
        out.push_str(&format!(
            "### {} · {}\n\nStep: {}. Turn: {}. Toolkit: {}.\n\nExact parameters:\n\n",
            execution.id,
            execution.tool_name,
            execution.step_id,
            execution.turn_id,
            execution.toolkit_version
        ));
        fenced(
            &mut out,
            "json",
            &serde_json::to_string_pretty(&execution.parameters).unwrap_or_default(),
        );
        if let Some(outcome) = &execution.outcome {
            out.push_str(&format!(
                "Observed status: {:?}. Exit code: {:?}. Full-result SHA-256: `{}`.\n\n",
                outcome.status,
                outcome.process_exit_code,
                hex::encode(Sha256::digest(outcome.output.as_bytes()))
            ));
            fenced(
                &mut out,
                "json",
                &serde_json::to_string_pretty(&outcome.coverage).unwrap_or_default(),
            );
        } else {
            out.push_str("Execution started; no completion has been observed.\n\n");
        }
    }
    out.push_str(&format!("Full received results and execution provenance are retained in `{}` and the session database.\n\n## Investigator decision history\n\n", state.execution_log_path.display()));
    for decision in &state.decisions {
        out.push_str(&format!(
            "- {}: {} by {} for {}. {}\n",
            decision.recorded_unix_secs,
            decision.decision,
            decision.actor,
            decision.target_id,
            decision.rationale
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn fixture() -> (InvestigationStore, tempfile::TempDir) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store = InvestigationStore::open(pool, "test-session", directory.path())
            .await
            .unwrap();
        store
            .set_case_brief(CaseBrief {
                objective: "Identify evidence supporting or contradicting the alleged access"
                    .into(),
                evidence: vec![EvidenceSource {
                    id: 7,
                    path: "/evidence/image.E01".into(),
                    role: "suspected source system".into(),
                    sha256: Some("sample-digest".into()),
                    size_bytes: None,
                    modified_unix_secs: None,
                }],
                processing_policy: ProcessingPolicy {
                    allowed_destinations: vec![ProcessingDestination {
                        provider: "local".into(),
                        endpoint: "http://localhost:11434".into(),
                        model: "model".into(),
                        authentication_mode: "api_key".into(),
                        account_id: None,
                    }],
                    allow_external_tools: false,
                },
                ..Default::default()
            })
            .await
            .unwrap();
        (store, directory)
    }
    fn proposal(id: &str) -> StepProposal {
        StepProposal {
            id: id.into(),
            question: "Which artefacts are available?".into(),
            rationale: "Bound initial coverage before proposing a pivot".into(),
            evidence_ids: vec![7],
            permitted_tools: vec!["inventory".into(), "read".into(), "independent".into()],
            limits: StepLimits::default(),
            stop_conditions: vec!["Unexpected evidence identity".into()],
            recommended: true,
            estimated_effort: "one bounded pass".into(),
            limitations: vec![],
            tool_dependencies: BTreeMap::from([("read".into(), vec!["inventory".into()])]),
            source_selectors: BTreeMap::new(),
            capability_gap: None,
        }
    }
    async fn approved(store: &InvestigationStore) {
        store.propose_steps(vec![proposal("s1")]).await.unwrap();
        store
            .decide_step(
                "s1",
                HumanDecision::Approve,
                "investigator",
                "Confirm brief and bounded inventory",
            )
            .await
            .unwrap();
        store.begin_step("s1", "turn1").await.unwrap();
    }
    #[tokio::test]
    async fn approval_is_bound_to_one_turn_and_not_reused_after_checkpoint_or_restart() {
        let (store, _directory) = fixture().await;
        store.propose_steps(vec![proposal("s1")]).await.unwrap();
        assert!(store.begin_step("s1", "turn1").await.is_err());
        store
            .decide_step("s1", HumanDecision::Approve, "analyst", "approved")
            .await
            .unwrap();
        store.begin_step("s1", "turn1").await.unwrap();
        assert!(store
            .authorize_tool("another-turn", "inventory", json!({}), &[7], None)
            .await
            .is_err());
        store
            .finish_step("turn1", StepCheckpoint::default())
            .await
            .unwrap();
        assert!(store.begin_step("s1", "turn2").await.is_err());
        store.propose_steps(vec![proposal("s2")]).await.unwrap();
        store
            .decide_step("s2", HumanDecision::Approve, "analyst", "approved")
            .await
            .unwrap();
        let resumed =
            InvestigationStore::open(store.pool.clone(), "test-session", store.export_dir.clone())
                .await
                .unwrap();
        assert!(resumed.begin_step("s2", "turn2").await.is_err());
        assert_eq!(
            resumed
                .snapshot()
                .await
                .unwrap()
                .steps
                .last()
                .unwrap()
                .state,
            StepState::Interrupted
        );
    }
    #[tokio::test]
    async fn failed_dependencies_stop_with_bounded_retries_but_independent_work_continues() {
        let (store, _directory) = fixture().await;
        approved(&store).await;
        for _ in 0..2 {
            let permit = store
                .authorize_tool("turn1", "inventory", json!({}), &[7], None)
                .await
                .unwrap();
            store
                .complete_tool(permit, ToolOutcome::failed("index unavailable"))
                .await
                .unwrap();
        }
        assert!(store
            .authorize_tool("turn1", "inventory", json!({}), &[7], None)
            .await
            .is_err());
        assert!(store
            .authorize_tool("turn1", "read", json!({}), &[7], None)
            .await
            .is_err());
        assert!(store
            .authorize_tool("turn1", "independent", json!({}), &[7], None)
            .await
            .is_ok());
    }
    #[tokio::test]
    async fn failed_report_export_blocks_execution_until_repaired() {
        let (store, _directory) = fixture().await;
        store.propose_steps(vec![proposal("s1")]).await.unwrap();
        let path = store.snapshot().await.unwrap().report_path;
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(store
            .decide_step("s1", HumanDecision::Approve, "analyst", "approved")
            .await
            .is_err());
        assert!(store.begin_step("s1", "turn1").await.is_err());
        fs::remove_dir(&path).unwrap();
        store.repair_exports().await.unwrap();
        store.begin_step("s1", "turn1").await.unwrap();
    }
    #[tokio::test]
    async fn findings_reproduce_actual_calls_and_cannot_self_accept() {
        let (store, _directory) = fixture().await;
        approved(&store).await;
        let permit = store
            .authorize_tool(
                "turn1",
                "inventory",
                json!({"query":"SELECT path FROM system_files LIMIT 2"}),
                &[7],
                None,
            )
            .await
            .unwrap();
        let id = permit.id.clone();
        let mut output = ToolOutcome::new(ToolStatus::Partial, "{\"rows\":[],\"truncated\":true}");
        output.coverage.truncated = true;
        store.complete_tool(permit, output).await.unwrap();
        let mut finding = Finding {
            id: "f1".into(),
            step_id: "s1".into(),
            kind: FindingKind::NegativeResult,
            title: "No rows in bounded result".into(),
            observation: "The bounded query returned no rows".into(),
            interpretation: None,
            sources: vec![SourceReference {
                evidence_id: 7,
                location: id.clone(),
                excerpt: "[]".into(),
                sha256: None,
            }],
            execution_ids: vec![id],
            contradictions: vec![],
            limitations: vec![],
            reproduction_steps: vec![],
            review: ReviewStatus::Accepted,
        };
        assert!(store.record_finding(finding.clone()).await.is_err());
        finding
            .limitations
            .push("Partial result does not establish filesystem-wide absence".into());
        store.record_finding(finding).await.unwrap();
        let state = store.snapshot().await.unwrap();
        assert_eq!(state.findings[0].review, ReviewStatus::Provisional);
        assert!(state.findings[0].reproduction_steps[0]
            .contains("SELECT path FROM system_files LIMIT 2"));
        assert!(fs::read_to_string(state.report_path)
            .unwrap()
            .contains("Partial result does not establish filesystem-wide absence"));
        store
            .review_finding(
                "f1",
                ReviewStatus::NeedsCorroboration,
                "analyst",
                "Need complete coverage",
            )
            .await
            .unwrap();
        assert_eq!(store.snapshot().await.unwrap().decisions.len(), 2);
    }
    #[tokio::test]
    async fn complete_result_is_retained_before_display_limits_and_status_is_consistent() {
        let (store, _directory) = fixture().await;
        approved(&store).await;
        let permit = store
            .authorize_tool("turn1", "inventory", json!({}), &[7], None)
            .await
            .unwrap();
        let mut invalid = ToolOutcome::new(ToolStatus::Success, "ok");
        invalid.process_exit_code = Some(1);
        assert!(store.complete_tool(permit.clone(), invalid).await.is_err());
        let output = format!("{}tail-error", "a".repeat(100_000));
        store
            .complete_tool(permit, ToolOutcome::new(ToolStatus::Failed, &output))
            .await
            .unwrap();
        let state = store.snapshot().await.unwrap();
        assert_eq!(state.executions[0].outcome.as_ref().unwrap().output, output);
        assert!(fs::read_to_string(state.execution_log_path)
            .unwrap()
            .contains("tail-error"));
    }
    #[tokio::test]
    async fn provider_changes_require_explicit_case_policy_and_session_ids_are_safe() {
        let (store, _directory) = fixture().await;
        approved(&store).await;
        assert!(store
            .authorize_processing(&ProcessingDestination {
                provider: "local".into(),
                endpoint: "http://localhost:11434/".into(),
                model: "model".into(),
                authentication_mode: "api_key".into(),
                account_id: None,
            })
            .await
            .is_ok());
        assert!(store
            .authorize_processing(&ProcessingDestination {
                provider: "cloud".into(),
                endpoint: "https://other.invalid".into(),
                model: "model".into(),
                authentication_mode: "api_key".into(),
                account_id: None,
            })
            .await
            .is_err());
        assert!(InvestigationStore::open(
            store.pool.clone(),
            "../escape",
            store.export_dir.clone()
        )
        .await
        .is_err());
    }
    #[tokio::test]
    async fn source_scope_violation_stops_the_whole_step() {
        let (store, _directory) = fixture().await;
        let mut step = proposal("s1");
        step.source_selectors.insert(
            "inventory".into(),
            BTreeMap::from([("partition_id".into(), vec![json!(4)])]),
        );
        store.propose_steps(vec![step]).await.unwrap();
        store
            .decide_step("s1", HumanDecision::Approve, "analyst", "partition 4 only")
            .await
            .unwrap();
        store.begin_step("s1", "turn1").await.unwrap();
        assert!(store
            .authorize_tool("turn1", "inventory", json!({"partition_id":5}), &[7], None)
            .await
            .is_err());
        assert_eq!(
            store.snapshot().await.unwrap().steps[0].state,
            StepState::Interrupted
        );
        assert!(store
            .authorize_tool("turn1", "independent", json!({}), &[7], None)
            .await
            .is_err());
    }
    #[tokio::test]
    async fn fabricated_excerpt_cannot_become_an_observation() {
        let (store, _directory) = fixture().await;
        approved(&store).await;
        let permit = store
            .authorize_tool(
                "turn1",
                "inventory",
                json!({"query":"SELECT 1"}),
                &[7],
                None,
            )
            .await
            .unwrap();
        let id = permit.id.clone();
        store
            .complete_tool(
                permit,
                ToolOutcome::new(ToolStatus::Success, "{\"rows\":[{\"1\":1}]}"),
            )
            .await
            .unwrap();
        let finding = Finding {
            id: "invented".into(),
            step_id: "s1".into(),
            kind: FindingKind::Observation,
            title: "Invented access".into(),
            observation: "Attacker gained access".into(),
            interpretation: None,
            sources: vec![SourceReference {
                evidence_id: 7,
                location: id.clone(),
                excerpt: "exploit succeeded".into(),
                sha256: None,
            }],
            execution_ids: vec![id],
            contradictions: vec![],
            limitations: vec![],
            reproduction_steps: vec![],
            review: ReviewStatus::Provisional,
        };
        assert!(store.record_finding(finding).await.is_err());
        assert!(store.snapshot().await.unwrap().findings.is_empty());
        assert!(result_contains(
            "{\"content\":\"line one\\nline two\"}",
            "line one\nline two"
        ));
    }
    #[tokio::test]
    async fn approved_account_and_authentication_mode_cannot_drift() {
        let (store, _directory) = fixture().await;
        let mut brief = store.snapshot().await.unwrap().brief.unwrap();
        let destination = &mut brief.processing_policy.allowed_destinations[0];
        destination.authentication_mode = "subscription".into();
        destination.account_id = Some("approved-account".into());
        let allowed = destination.clone();
        store.set_case_brief(brief).await.unwrap();
        approved(&store).await;
        assert!(store.authorize_processing(&allowed).await.is_ok());
        let changed = ProcessingDestination {
            account_id: Some("another-account".into()),
            ..allowed
        };
        assert!(store.authorize_processing(&changed).await.is_err());
        assert_eq!(
            store.snapshot().await.unwrap().steps[0].state,
            StepState::Interrupted
        );
    }

    #[tokio::test]
    async fn capability_gap_is_reviewable_before_external_tools_are_allowed() {
        let (store, _directory) = fixture().await;
        let mut step = proposal("gap");
        step.capability_gap = Some(CapabilityGap {
            component: "exhume_agent".into(),
            missing_behavior: "Decode a synthetic format".into(),
            proposed_external_tool: Some("example-decoder".into()),
            synthetic_example: "A fixture containing example rows".into(),
            acceptance_criteria: vec!["Return a typed status and coverage".into()],
        });
        store.propose_steps(vec![step]).await.unwrap();
        let state = store.snapshot().await.unwrap();
        assert!(fs::read_to_string(state.report_path)
            .unwrap()
            .contains("GitHub issue draft"));
        assert!(store
            .decide_step("gap", HumanDecision::Approve, "analyst", "approved")
            .await
            .is_err());
        assert_eq!(
            store.snapshot().await.unwrap().steps[0].state,
            StepState::PendingApproval
        );
    }
    #[tokio::test]
    async fn provider_alias_retains_resolved_model_without_changing_approved_request() {
        let (store, _directory) = fixture().await;
        approved(&store).await;
        let destination = store
            .snapshot()
            .await
            .unwrap()
            .brief
            .unwrap()
            .processing_policy
            .allowed_destinations[0]
            .clone();
        store
            .record_provider_response(
                "turn1",
                &destination,
                Some("model-resolved-2026".into()),
                "api_key",
                None,
                Some("api".into()),
            )
            .await
            .unwrap();
        let state = store.snapshot().await.unwrap();
        assert_eq!(state.providers[0].model, "model");
        assert_eq!(
            state.providers[0].actual_model.as_deref(),
            Some("model-resolved-2026")
        );
        assert!(fs::read_to_string(state.report_path)
            .unwrap()
            .contains("model-resolved-2026"));
        assert!(store
            .record_provider_response(
                "turn1",
                &destination,
                Some("model-resolved-2026".into()),
                "subscription",
                None,
                Some("subscription".into())
            )
            .await
            .is_err());
        assert_eq!(
            store.snapshot().await.unwrap().steps[0].state,
            StepState::Interrupted
        );
    }
    #[tokio::test]
    async fn an_observed_excerpt_cannot_claim_an_unobserved_source_location() {
        let (store, _directory) = fixture().await;
        approved(&store).await;
        let permit = store
            .authorize_tool(
                "turn1",
                "inventory",
                json!({"query":"SELECT 1"}),
                &[7],
                None,
            )
            .await
            .unwrap();
        let id = permit.id.clone();
        store
            .complete_tool(
                permit,
                ToolOutcome::new(ToolStatus::Success, "{\"rows\":[{\"1\":1}]}"),
            )
            .await
            .unwrap();
        let mut finding = Finding {
            id: "located".into(),
            step_id: "s1".into(),
            kind: FindingKind::Observation,
            title: "Query result".into(),
            observation: "The scalar query returned one".into(),
            interpretation: None,
            sources: vec![SourceReference {
                evidence_id: 7,
                location: "/unobserved/history".into(),
                excerpt: "1".into(),
                sha256: None,
            }],
            execution_ids: vec![id.clone()],
            contradictions: vec![],
            limitations: vec![],
            reproduction_steps: vec![],
            review: ReviewStatus::Provisional,
        };
        assert!(store.record_finding(finding.clone()).await.is_err());
        finding.sources[0].location = id;
        store.record_finding(finding).await.unwrap();
    }
    #[tokio::test]
    async fn stale_export_cannot_overwrite_a_newer_durable_report() {
        let (store, _directory) = fixture().await;
        let stale = store.snapshot().await.unwrap();
        let mut brief = stale.brief.clone().unwrap();
        brief.objective = "Updated investigator objective".into();
        store.set_case_brief(brief).await.unwrap();
        assert!(store.export(&stale).await.is_err());
        let current = store.snapshot().await.unwrap();
        assert_eq!(current.revision, current.exported_revision);
        assert!(fs::read_to_string(current.report_path)
            .unwrap()
            .contains("Updated investigator objective"));
    }
    #[tokio::test]
    async fn failed_repair_cannot_leave_a_successful_export_marker() {
        let (store, _directory) = fixture().await;
        approved(&store).await;
        let path = store.snapshot().await.unwrap().report_path;
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(store.repair_exports().await.is_err());
        let state = store.snapshot().await.unwrap();
        assert_ne!(state.revision, state.exported_revision);
        assert!(store
            .authorize_tool("turn1", "inventory", json!({}), &[7], None)
            .await
            .is_err());
    }
}
