use crate::models::{default_api_base, CliState};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

fn state_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("chimera")
}

fn state_path() -> PathBuf {
    state_dir().join("cli-state.json")
}

pub fn load_state() -> CliState {
    let path = state_path();
    if !path.exists() {
        return CliState {
            api_base: default_api_base(),
            ..CliState::default()
        };
    }
    let Ok(contents) = fs::read_to_string(path) else {
        return CliState {
            api_base: default_api_base(),
            ..CliState::default()
        };
    };
    serde_json::from_str(&contents).unwrap_or(CliState {
        api_base: default_api_base(),
        ..CliState::default()
    })
}

pub fn save_state(state: &CliState) -> Result<()> {
    let path = state_path();
    fs::create_dir_all(state_dir()).context("failed to create Chimera config directory")?;
    let payload =
        serde_json::to_string_pretty(state).context("failed to serialize Chimera CLI state")?;
    fs::write(path, payload).context("failed to write Chimera CLI state")?;
    Ok(())
}

pub fn read_scope_file(path: &Path) -> Result<String> {
    fs::read_to_string(path)
        .with_context(|| format!("failed to read scope file {}", path.display()))
}

pub fn build_scope_text(target: &str) -> Result<String> {
    build_scope_manifest_text(&[target.to_string()])
}

pub fn build_scope_manifest_text(targets: &[String]) -> Result<String> {
    let payload = serde_yaml::to_string(&serde_json::json!({
        "allowlist": targets,
        "denylist": [],
    }))
    .context("failed to build scope manifest")?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::build_scope_text;

    #[test]
    fn scope_text_contains_allowlist_target() {
        let scope = build_scope_text("https://crapi.local").expect("scope");
        assert!(scope.contains("allowlist"));
        assert!(scope.contains("https://crapi.local"));
    }
}
