use crate::action::Action;
use crate::app::WorkflowProfile;
use crate::config::build_scope_manifest_text;
use anyhow::{Context, Result};
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct IntentPreview {
    pub label: String,
    pub summary: String,
    pub entities: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct NlpResolution {
    pub preview: Option<IntentPreview>,
    pub notes: Vec<String>,
    pub actions: Vec<Action>,
}

pub fn interpret_payload(payload: &Value, original_text: &str) -> Result<NlpResolution> {
    let mut resolution = NlpResolution {
        notes: payload
            .get("notes")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        ..NlpResolution::default()
    };

    match payload
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
    {
        "scope" => {
            let manifest = payload
                .get("scope_manifest")
                .cloned()
                .unwrap_or_else(|| Value::Object(Default::default()));
            let targets = extract_allowlist_targets(&manifest);
            let manifest_text =
                serde_yaml::to_string(&manifest).context("failed to serialize scope manifest")?;

            resolution.preview = Some(IntentPreview {
                label: "SetTarget".to_string(),
                summary: format!("Stage {} target(s) from NLP", targets.len()),
                entities: vec![
                    ("Targets".to_string(), targets.join(", ")),
                    ("Source".to_string(), "parser/interpret".to_string()),
                ],
            });

            if let Some(first) = targets.first() {
                resolution.actions.push(Action::SetTarget(first.clone()));
            }
            resolution
                .actions
                .push(Action::StageScopeText(manifest_text));
        }
        "command" => {
            let command = payload.get("command").cloned().unwrap_or(Value::Null);
            let action_name = command
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("scan");
            let targets = command
                .get("targets")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            if let Some(first) = targets.first() {
                resolution.actions.push(Action::SetTarget(first.clone()));
                resolution
                    .actions
                    .push(Action::StageScopeText(build_scope_manifest_text(&targets)?));
            }

            if let Some(program) = command.get("program_name").and_then(Value::as_str) {
                resolution
                    .actions
                    .push(Action::SetProgram(program.to_string()));
            }

            if let Some(pipeline) = command.get("pipeline").and_then(Value::as_str) {
                resolution
                    .actions
                    .push(Action::SetPipeline(pipeline.to_string()));
            }

            if let Some(workflow) = command.get("workflow").and_then(Value::as_str) {
                if let Some(profile) = WorkflowProfile::parse(workflow) {
                    resolution.actions.push(Action::SetWorkflow(profile));
                }
            } else if let Some(profile) = infer_workflow_from_text(original_text) {
                resolution.actions.push(Action::SetWorkflow(profile));
            }

            match action_name {
                "status" => resolution.actions.push(Action::ShowStatus),
                "oracle" => {
                    let question = command
                        .get("question")
                        .and_then(Value::as_str)
                        .unwrap_or(original_text);
                    resolution
                        .actions
                        .push(Action::AskModel(question.to_string()));
                }
                _ => {
                    if requests_launch(original_text) {
                        resolution.actions.push(Action::LaunchScan);
                    }
                }
            }

            resolution.preview = Some(IntentPreview {
                label: action_name.to_ascii_uppercase(),
                summary: format!("NLP mapped to {}", action_name),
                entities: vec![
                    ("Targets".to_string(), targets.join(", ")),
                    (
                        "Pipeline".to_string(),
                        command
                            .get("pipeline")
                            .and_then(Value::as_str)
                            .unwrap_or("unchanged")
                            .to_string(),
                    ),
                ],
            });
        }
        _ => {
            resolution.preview = Some(IntentPreview {
                label: "Unknown".to_string(),
                summary: "The parser could not resolve a safe structured action".to_string(),
                entities: vec![("Input".to_string(), original_text.to_string())],
            });
            resolution.actions.push(Action::ErrorMessage(
                "parser did not recognize the input".to_string(),
            ));
        }
    }

    Ok(resolution)
}

fn extract_allowlist_targets(manifest: &Value) -> Vec<String> {
    manifest
        .get("allowlist")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn infer_workflow_from_text(input: &str) -> Option<WorkflowProfile> {
    let lowered = input.to_ascii_lowercase();
    ["quick", "standard", "full", "custom"]
        .into_iter()
        .find_map(|item| {
            lowered
                .contains(item)
                .then(|| WorkflowProfile::parse(item))
                .flatten()
        })
}

fn requests_launch(input: &str) -> bool {
    let lowered = input.to_ascii_lowercase();
    lowered.contains("run ") || lowered.starts_with("run") || lowered.contains("start workflow")
}

#[cfg(test)]
mod tests {
    use super::interpret_payload;
    use serde_json::json;

    #[test]
    fn scope_payload_maps_to_target_and_scope() {
        let payload = json!({
            "kind": "scope",
            "scope_manifest": {
                "allowlist": ["https://crapi.example.com"],
                "denylist": []
            }
        });
        let resolution = interpret_payload(&payload, "use https://crapi.example.com").expect("nlp");
        assert_eq!(resolution.actions.len(), 2);
        assert!(resolution.preview.is_some());
    }
}
