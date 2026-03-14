use crate::models::{ChainFinding, ChainGraphRecord, FindingSummary, RunDetail, StatusResponse};
use anyhow::{anyhow, Result};
use serde_json::Value;

pub fn severity_badge(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => "CRIT",
        "high" => "HIGH",
        "medium" => "MED",
        "low" => "LOW",
        _ => "INFO",
    }
}

pub fn render_status_block(status: &StatusResponse, run: Option<&RunDetail>) -> Vec<String> {
    let active_run = status.active_run.as_ref();
    let mut lines = vec![
        format!("Mode: {}", status.mode),
        format!(
            "Active Run: {}",
            active_run
                .and_then(|item| item.run_id.clone())
                .or_else(|| run.and_then(|item| item.run_id.clone()))
                .unwrap_or_else(|| "none".to_string())
        ),
        format!(
            "Phase: {}",
            active_run
                .and_then(|item| item.phase.clone())
                .or_else(|| run.and_then(|item| item.status.clone()))
                .unwrap_or_else(|| "idle".to_string())
        ),
        format!(
            "Scope: {} assets | hash {}",
            status.scope_state.asset_count,
            if status.scope_state.scope_hash.is_empty() {
                "unloaded".to_string()
            } else {
                status.scope_state.scope_hash.clone()
            }
        ),
    ];
    if !status.safety_state.blocked_reasons.is_empty() {
        lines.push(format!(
            "Blocked: {}",
            status.safety_state.blocked_reasons.join(", ")
        ));
    }
    if let Some(run) = run {
        let findings = stat_u64(&run.stats, "findings_total");
        let chains = stat_u64(&run.stats, "exploit_chains");
        lines.push(format!("Findings: {} | Chains: {}", findings, chains));
    }
    lines
}

pub fn render_finding_lines(findings: &[FindingSummary], width: usize) -> Vec<String> {
    if findings.is_empty() {
        return vec!["No findings yet".to_string()];
    }
    findings
        .iter()
        .take(12)
        .map(|item| {
            let body = format!(
                "[{}] {} ({:.2})",
                severity_badge(&item.severity),
                item.title,
                item.confidence
            );
            truncate(&body, width)
        })
        .collect()
}

pub fn render_chain_ascii(chains: &[ChainGraphRecord]) -> Result<String> {
    if chains.is_empty() {
        return Err(anyhow!("no exploit chains found for this run"));
    }
    let mut output = Vec::new();
    for record in chains {
        output.push(format!(
            "[{}] {}",
            severity_badge(&record.severity),
            if record.title.is_empty() {
                record.finding_id.clone()
            } else {
                record.title.clone()
            }
        ));
        output.push(record.ascii.clone());
        output.push(String::new());
    }
    Ok(output.join("\n"))
}

pub fn render_chain_detail(chain: &ChainFinding) -> String {
    let mut lines = vec![
        format!("[{}] {}", severity_badge(&chain.severity), chain.title),
        format!("Chain ID: {}", chain.finding_id),
        format!("Confidence: {:.2}", chain.confidence),
        format!("Prerequisites: {}", chain.chain_parent_ids.join(", ")),
        String::new(),
        "Replay Manifest".to_string(),
    ];
    if chain.replay_steps.is_empty() {
        lines.push("  No replay manifest stored".to_string());
    } else {
        for step in &chain.replay_steps {
            let label = step.action.clone().unwrap_or_else(|| "step".to_string());
            let expected = step
                .expected_result
                .clone()
                .or(step.expected_diff.clone())
                .unwrap_or_default();
            lines.push(format!("  {}. {}", step.step.unwrap_or(0), label));
            if !expected.is_empty() {
                lines.push(format!("     => {}", expected));
            }
        }
    }
    lines.join("\n")
}

pub fn stat_u64(stats: &std::collections::BTreeMap<String, Value>, key: &str) -> u64 {
    stats.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn truncate(value: &str, width: usize) -> String {
    if value.len() <= width {
        return value.to_string();
    }
    format!("{}...", &value[..width.saturating_sub(3)])
}

#[cfg(test)]
mod tests {
    use super::render_chain_ascii;
    use crate::models::ChainGraphRecord;

    #[test]
    fn chain_ascii_renders_record() {
        let payload = vec![ChainGraphRecord {
            finding_id: "abc".to_string(),
            title: "Exploit chain".to_string(),
            severity: "critical".to_string(),
            ascii: "[CRITICAL] Step".to_string(),
        }];
        let rendered = render_chain_ascii(&payload).expect("rendered");
        assert!(rendered.contains("Exploit chain"));
        assert!(rendered.contains("Step"));
    }
}
