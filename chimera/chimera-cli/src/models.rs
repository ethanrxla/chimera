#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
pub struct RunCreationResponse {
    pub run_id: String,
    #[serde(default)]
    pub job_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ActiveRunStatus {
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub phase: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub last_event_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScopeState {
    #[serde(default)]
    pub loaded: bool,
    #[serde(default)]
    pub asset_count: usize,
    #[serde(default)]
    pub scope_hash: String,
    #[serde(default)]
    pub hash_ok: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SafetyState {
    #[serde(default)]
    pub external_exec_allowed: bool,
    #[serde(default)]
    pub live_confirm_required: bool,
    #[serde(default)]
    pub destructive_allowed: bool,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct StatusResponse {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub active_run: Option<ActiveRunStatus>,
    #[serde(default)]
    pub scope_state: ScopeState,
    #[serde(default)]
    pub safety_state: SafetyState,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RunSummary {
    pub run_id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub ended_at: Option<String>,
    #[serde(default)]
    pub stats: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RunDetail {
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub job_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub artifacts_dir: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub ended_at: Option<String>,
    #[serde(default)]
    pub stats: BTreeMap<String, Value>,
    #[serde(default)]
    pub scope_normalized: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FindingSummary {
    pub stable_id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub classification: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub tool: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FindingDetail {
    pub stable_id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub classification: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub tool: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub reproduction: String,
    #[serde(default)]
    pub raw: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ArtifactSummary {
    pub artifact_id: String,
    pub path: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainGraphRecord {
    #[serde(default)]
    pub finding_id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub ascii: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReplayStep {
    #[serde(default)]
    pub step: Option<u64>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub expected_result: Option<String>,
    #[serde(default)]
    pub expected_diff: Option<String>,
    #[serde(default)]
    pub replay_steps: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainFinding {
    #[serde(default)]
    pub finding_id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub chain_parent_ids: Vec<String>,
    #[serde(default)]
    pub replay_steps: Vec<ReplayStep>,
    #[serde(default)]
    pub impact_path: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CliState {
    #[serde(default = "default_api_base")]
    pub api_base: String,
    #[serde(default = "default_ollama_base")]
    pub ollama_base: String,
    #[serde(default)]
    pub ollama_model: Option<String>,
    #[serde(default)]
    pub last_target: Option<String>,
    #[serde(default)]
    pub last_scope_file: Option<String>,
    #[serde(default)]
    pub last_run_id: Option<String>,
    #[serde(default)]
    pub last_pipeline: Option<String>,
    #[serde(default)]
    pub last_program: Option<String>,
}

pub fn default_api_base() -> String {
    "http://127.0.0.1:8000/v1".to_string()
}

pub fn default_ollama_base() -> String {
    "http://127.0.0.1:11434".to_string()
}
