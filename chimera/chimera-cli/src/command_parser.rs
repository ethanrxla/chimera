use crate::action::Action;
use crate::app::WorkflowProfile;
use crate::theme::ThemeName;
use anyhow::{anyhow, Result};

const COMMAND_INDEX: &[&str] = &[
    "set target example.com",
    "set workflow standard",
    "set pipeline task_runner",
    "set program HackerOne Demo",
    "set ollama model whiterabbitneo-13b",
    "scan quick",
    "scan standard",
    "show status",
    "show runs",
    "show findings",
    "show logs",
    "models",
    "chat hello from whiterabbitneo",
    "theme red",
    "clear",
    "help",
    "oracle why did this command fail",
];

pub fn parse_command(input: &str) -> Result<Vec<Action>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(vec![Action::ShowHelp]);
    }

    let lowered = trimmed.to_ascii_lowercase();
    match lowered.as_str() {
        "help" | "?" => return Ok(vec![Action::ShowHelp]),
        "quit" | "exit" => return Ok(vec![Action::Quit]),
        "refresh" | "reload" => return Ok(vec![Action::Refresh]),
        "status" | "show status" => return Ok(vec![Action::ShowStatus]),
        "runs" | "show runs" => return Ok(vec![Action::ShowRuns]),
        "logs" | "show logs" => return Ok(vec![Action::ShowLogs]),
        "findings" | "show findings" => return Ok(vec![Action::ShowFindings(None)]),
        "models" | "show models" | "ollama models" => return Ok(vec![Action::ShowModels]),
        "clear" => return Ok(vec![Action::ClearOutput]),
        "clear scope" | "unset scope" => return Ok(vec![Action::ClearScope]),
        "clear program" | "unset program" => return Ok(vec![Action::ClearProgram]),
        "run" | "scan" => return Ok(vec![Action::LaunchScan]),
        _ => {}
    }

    if let Some(rest) = trimmed.strip_prefix("set target ") {
        let target = rest.trim();
        if target.is_empty() {
            return Err(anyhow!("set target requires a URL, host, or IP"));
        }
        return Ok(vec![Action::SetTarget(target.to_string())]);
    }

    if let Some(rest) = trimmed.strip_prefix("set workflow ") {
        let workflow = WorkflowProfile::parse(rest.trim())
            .ok_or_else(|| anyhow!("workflow must be quick, standard, full, or custom"))?;
        return Ok(vec![Action::SetWorkflow(workflow)]);
    }

    if let Some(rest) = trimmed.strip_prefix("set pipeline ") {
        let pipeline = canonical_pipeline(rest.trim())
            .ok_or_else(|| anyhow!("pipeline must be recon or task_runner"))?;
        return Ok(vec![Action::SetPipeline(pipeline)]);
    }

    if let Some(rest) = trimmed.strip_prefix("set program ") {
        let program = rest.trim();
        if program.is_empty() {
            return Err(anyhow!("set program requires a value"));
        }
        return Ok(vec![Action::SetProgram(program.to_string())]);
    }

    if let Some(rest) = trimmed.strip_prefix("set ollama model ") {
        let model = rest.trim();
        if model.is_empty() {
            return Err(anyhow!("set ollama model requires a model name"));
        }
        return Ok(vec![Action::SetOllamaModel(model.to_string())]);
    }

    if let Some(rest) = trimmed.strip_prefix("show findings ") {
        let run_id = rest.trim();
        if run_id.is_empty() {
            return Err(anyhow!("show findings requires an optional run id"));
        }
        return Ok(vec![Action::ShowFindings(Some(run_id.to_string()))]);
    }

    if let Some(rest) = trimmed.strip_prefix("use ") {
        let run_id = rest.trim();
        if run_id.is_empty() {
            return Err(anyhow!("use requires a run id or prefix"));
        }
        return Ok(vec![Action::SelectRun(run_id.to_string())]);
    }

    if let Some(rest) = trimmed.strip_prefix("theme ") {
        let name = ThemeName::parse(rest.trim())
            .ok_or_else(|| anyhow!("theme must be matrix, red, or blue"))?;
        return Ok(vec![Action::SetTheme(name)]);
    }

    if let Some(rest) = trimmed.strip_prefix("oracle ") {
        let question = rest.trim();
        if question.is_empty() {
            return Err(anyhow!("oracle requires a question"));
        }
        return Ok(vec![Action::AskModel(question.to_string())]);
    }

    if let Some(rest) = trimmed.strip_prefix("chat ") {
        let prompt = rest.trim();
        if prompt.is_empty() {
            return Err(anyhow!("chat requires a prompt"));
        }
        return Ok(vec![Action::AskOllama(prompt.to_string())]);
    }

    if let Some(rest) = trimmed.strip_prefix("ollama chat ") {
        let prompt = rest.trim();
        if prompt.is_empty() {
            return Err(anyhow!("ollama chat requires a prompt"));
        }
        return Ok(vec![Action::AskOllama(prompt.to_string())]);
    }

    if let Some(rest) = trimmed.strip_prefix("ask ") {
        let question = rest.trim();
        if question.is_empty() {
            return Err(anyhow!("ask requires a question"));
        }
        return Ok(vec![Action::AskModel(question.to_string())]);
    }

    if lowered.starts_with("scan ") || lowered.starts_with("run ") {
        return parse_scan_command(trimmed);
    }

    Err(anyhow!("unknown command: {}", trimmed))
}

pub fn command_help() -> &'static [&'static str] {
    &[
        "set target <value>      stage a target for the next run",
        "set workflow <profile>  choose quick, standard, full, or custom",
        "set pipeline <mode>     choose recon or task_runner",
        "scan quick              run the current target with a workflow profile",
        "show runs               print recent runs into the output pane",
        "show findings [run_id]  print findings for the selected run",
        "show logs               print telemetry into the output pane",
        "models                  list installed Ollama models",
        "set ollama model <name> select the direct Ollama chat model",
        "chat <prompt>           ask the selected Ollama model directly",
        "theme <matrix|red|blue> switch the console theme",
        "oracle <question>       ask Chimera for guidance on the current target",
        "clear                   clear the output pane",
        "help                    open the help modal",
    ]
}

pub fn suggestions(input: &str) -> Vec<String> {
    let needle = input.trim().to_ascii_lowercase();
    let mut matches = COMMAND_INDEX
        .iter()
        .filter(|item| needle.is_empty() || item.starts_with(&needle))
        .map(|item| (*item).to_string())
        .collect::<Vec<_>>();

    if matches.is_empty() {
        matches = COMMAND_INDEX
            .iter()
            .take(5)
            .map(|item| (*item).to_string())
            .collect();
    }

    matches.truncate(5);
    matches
}

fn parse_scan_command(input: &str) -> Result<Vec<Action>> {
    let mut target = None;
    let mut workflow = None;
    let mut pipeline = None;

    for token in input.split_whitespace().skip(1) {
        if workflow.is_none() {
            if let Some(value) = WorkflowProfile::parse(token) {
                workflow = Some(value);
                continue;
            }
        }

        if pipeline.is_none() {
            if let Some(value) = canonical_pipeline(token) {
                pipeline = Some(value);
                continue;
            }
        }

        if target.is_none() {
            target = Some(token.to_string());
            continue;
        }

        return Err(anyhow!(
            "scan accepts at most one target, one workflow, and one pipeline"
        ));
    }

    let mut actions = Vec::new();
    if let Some(target) = target {
        actions.push(Action::SetTarget(target));
    }
    if let Some(workflow) = workflow {
        actions.push(Action::SetWorkflow(workflow));
    }
    if let Some(pipeline) = pipeline {
        actions.push(Action::SetPipeline(pipeline));
    }
    actions.push(Action::LaunchScan);
    Ok(actions)
}

fn canonical_pipeline(value: &str) -> Option<String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "recon" => Some("recon".to_string()),
        "task_runner" | "task-runner" | "taskrunner" | "task" => Some("task_runner".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_command, suggestions};
    use crate::action::Action;
    use crate::app::WorkflowProfile;

    #[test]
    fn scan_command_accepts_target_and_workflow() {
        let parsed = parse_command("scan https://crapi.example.com quick").expect("scan command");
        assert!(matches!(parsed[0], Action::SetTarget(_)));
        assert!(matches!(
            parsed[1],
            Action::SetWorkflow(WorkflowProfile::Quick)
        ));
        assert!(matches!(parsed[2], Action::LaunchScan));
    }

    #[test]
    fn theme_command_maps_to_action() {
        let parsed = parse_command("theme red").expect("theme command");
        assert!(matches!(parsed[0], Action::SetTheme(_)));
    }

    #[test]
    fn unknown_command_returns_error() {
        assert!(parse_command("launch chaos mode").is_err());
    }

    #[test]
    fn suggestions_filter_by_prefix() {
        let matches = suggestions("set");
        assert!(matches.iter().all(|item| item.starts_with("set")));
    }
}
