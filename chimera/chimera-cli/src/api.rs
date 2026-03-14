use crate::models::{
    ArtifactSummary, ChainFinding, ChainGraphRecord, FindingDetail, FindingSummary,
    RunCreationResponse, RunDetail, RunSummary, StatusResponse,
};
use anyhow::{Context, Result};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

#[derive(Clone)]
pub struct ApiClient {
    base: String,
    client: Client,
}

impl ApiClient {
    pub fn new(base: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            client,
        })
    }

    pub async fn status(&self) -> Result<StatusResponse> {
        self.get_json("/status").await
    }

    pub async fn list_runs(&self) -> Result<Vec<RunSummary>> {
        self.get_json("/runs").await
    }

    pub async fn get_run(&self, run_id: &str) -> Result<RunDetail> {
        self.get_json(&format!("/runs/{run_id}")).await
    }

    pub async fn create_scan(
        &self,
        scope_text: String,
        pipeline: &str,
        program_name: Option<String>,
        max_workers: u8,
        rate_limit_rps: u16,
        timeout_s: u16,
    ) -> Result<RunCreationResponse> {
        if pipeline == "recon" {
            let payload = json!({
                "scope_text": scope_text,
                "live": true,
                "live_confirm": "I UNDERSTAND",
                "program_name": program_name,
                "rate_limit_rps": rate_limit_rps,
                "timeout_s": timeout_s,
                "max_workers": max_workers,
            });
            self.post_json("/recon/run", &payload).await
        } else {
            let payload = json!({
                "scope_text": scope_text,
                "live": true,
                "live_confirm": "I UNDERSTAND",
                "program_name": program_name,
                "rate_limit_rps": rate_limit_rps,
                "per_task_timeout_s": timeout_s,
                "max_workers": max_workers,
            });
            self.post_json("/runs", &payload).await
        }
    }

    pub async fn events_tail(&self, run_id: &str, limit: usize) -> Result<Vec<String>> {
        self.get_json(&format!("/runs/{run_id}/events_tail?limit={limit}"))
            .await
    }

    pub async fn findings(&self, run_id: &str) -> Result<Vec<FindingSummary>> {
        self.get_json(&format!("/runs/{run_id}/findings")).await
    }

    #[allow(dead_code)]
    pub async fn finding_detail(&self, run_id: &str, stable_id: &str) -> Result<FindingDetail> {
        self.get_json(&format!("/runs/{run_id}/findings/{stable_id}"))
            .await
    }

    pub async fn artifacts(&self, run_id: &str) -> Result<Vec<ArtifactSummary>> {
        self.get_json(&format!("/runs/{run_id}/artifacts")).await
    }

    pub async fn chain_graphs(&self, run_id: &str) -> Result<Vec<ChainGraphRecord>> {
        self.artifact_json(run_id, "chain_graphs.json").await
    }

    pub async fn chains(&self, run_id: &str) -> Result<Vec<ChainFinding>> {
        self.artifact_json(run_id, "chains.json").await
    }

    pub async fn suggested_actions(&self, run_id: &str) -> Result<Value> {
        self.get_json(&format!("/runs/{run_id}/suggested_actions"))
            .await
    }

    async fn artifact_json<T: DeserializeOwned>(&self, run_id: &str, path: &str) -> Result<T> {
        let encoded = urlencoding::encode(path);
        let response = self
            .client
            .get(format!("{}/runs/{run_id}/artifacts/{encoded}", self.base))
            .send()
            .await
            .with_context(|| format!("failed to fetch artifact {path}"))?;
        let response = response
            .error_for_status()
            .context("artifact request failed")?;
        response
            .json::<T>()
            .await
            .context("failed to decode artifact JSON")
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .client
            .get(format!("{}{}", self.base, path))
            .send()
            .await
            .with_context(|| format!("GET {} failed", path))?;
        let response = response
            .error_for_status()
            .with_context(|| format!("GET {} returned error", path))?;
        response
            .json::<T>()
            .await
            .with_context(|| format!("failed to decode {}", path))
    }

    async fn post_json<T: DeserializeOwned>(&self, path: &str, payload: &Value) -> Result<T> {
        let response = self
            .client
            .post(format!("{}{}", self.base, path))
            .json(payload)
            .send()
            .await
            .with_context(|| format!("POST {} failed", path))?;
        let response = response
            .error_for_status()
            .with_context(|| format!("POST {} returned error", path))?;
        response
            .json::<T>()
            .await
            .with_context(|| format!("failed to decode {}", path))
    }
}
