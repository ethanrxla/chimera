use anyhow::{anyhow, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsoleCommand {
    Help,
    Info,
    Refresh,
    Quit,
    ShowStatus,
    ShowRuns,
    ShowFindings(Option<String>),
    UseRun(String),
    SetTarget(String),
    SetPipeline(String),
    SetProgram(String),
    ClearProgram,
    ClearScope,
    LaunchScan {
        target: Option<String>,
        pipeline: Option<String>,
    },
    Oracle(String),
    NaturalLanguage(String),
}

pub fn parse_console_command(input: &str) -> Result<ConsoleCommand> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(ConsoleCommand::Help);
    }

    let lowered = trimmed.to_ascii_lowercase();
    match lowered.as_str() {
        "help" | "?" => return Ok(ConsoleCommand::Help),
        "info" | "show info" => return Ok(ConsoleCommand::Info),
        "refresh" | "reload" => return Ok(ConsoleCommand::Refresh),
        "quit" | "exit" => return Ok(ConsoleCommand::Quit),
        "status" | "show status" => return Ok(ConsoleCommand::ShowStatus),
        "runs" | "show runs" => return Ok(ConsoleCommand::ShowRuns),
        "clear program" | "unset program" => return Ok(ConsoleCommand::ClearProgram),
        "clear scope" | "unset scope" => return Ok(ConsoleCommand::ClearScope),
        "scan" | "run" => {
            return Ok(ConsoleCommand::LaunchScan {
                target: None,
                pipeline: None,
            });
        }
        _ => {}
    }

    if let Some(rest) = trimmed.strip_prefix("findings ") {
        let run_id = rest.trim();
        return Ok(ConsoleCommand::ShowFindings(Some(run_id.to_string())));
    }
    if lowered == "findings" || lowered == "show findings" {
        return Ok(ConsoleCommand::ShowFindings(None));
    }

    if let Some(rest) = trimmed.strip_prefix("use ") {
        let run_id = rest.trim();
        if run_id.is_empty() {
            return Err(anyhow!("use requires a run id or prefix"));
        }
        return Ok(ConsoleCommand::UseRun(run_id.to_string()));
    }

    if let Some(rest) = trimmed.strip_prefix("set target ") {
        let target = rest.trim();
        if target.is_empty() {
            return Err(anyhow!("set target requires a URL or hostname"));
        }
        return Ok(ConsoleCommand::SetTarget(target.to_string()));
    }

    if let Some(rest) = trimmed.strip_prefix("set pipeline ") {
        let pipeline = canonical_pipeline(rest.trim())
            .ok_or_else(|| anyhow!("pipeline must be recon or task_runner"))?;
        return Ok(ConsoleCommand::SetPipeline(pipeline));
    }

    if let Some(rest) = trimmed.strip_prefix("set program ") {
        let program = rest.trim();
        if program.is_empty() {
            return Err(anyhow!("set program requires a value"));
        }
        return Ok(ConsoleCommand::SetProgram(program.to_string()));
    }

    if let Some(rest) = trimmed.strip_prefix("oracle ") {
        let question = rest.trim();
        if question.is_empty() {
            return Err(anyhow!("oracle requires a question"));
        }
        return Ok(ConsoleCommand::Oracle(question.to_string()));
    }

    if lowered.starts_with("scan ") || lowered.starts_with("run ") {
        return match parse_scan_command(trimmed) {
            Ok(command) => Ok(command),
            Err(_) => Ok(ConsoleCommand::NaturalLanguage(trimmed.to_string())),
        };
    }

    Ok(ConsoleCommand::NaturalLanguage(trimmed.to_string()))
}

pub fn command_help() -> &'static [&'static str] {
    &[
        "set target <url>      stage a target for the next run",
        "set pipeline <mode>   choose recon or task_runner",
        "set program <name>    remember a program label",
        "clear scope           drop any staged manifest input",
        "run                   launch a scan with staged values",
        "scan <target> recon   one-shot launch with overrides",
        "use <run_id>          focus a run in the side panels",
        "show runs             print recent run summaries",
        "show findings         print findings for the selected run",
        "oracle <question>     ask Shannon about the current target",
        "freeform text         stage scope or targets via /parser/interpret",
        "quit                  leave the console",
    ]
}

fn parse_scan_command(input: &str) -> Result<ConsoleCommand> {
    let mut target = None;
    let mut pipeline = None;

    for token in input.split_whitespace().skip(1) {
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
        return Err(anyhow!("scan accepts at most one target and one pipeline"));
    }

    Ok(ConsoleCommand::LaunchScan { target, pipeline })
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
    use super::{parse_console_command, ConsoleCommand};

    #[test]
    fn scan_command_accepts_target_and_pipeline() {
        let parsed =
            parse_console_command("scan https://crapi.example.com recon").expect("scan command");
        assert_eq!(
            parsed,
            ConsoleCommand::LaunchScan {
                target: Some("https://crapi.example.com".to_string()),
                pipeline: Some("recon".to_string()),
            }
        );
    }

    #[test]
    fn set_pipeline_normalizes_aliases() {
        let parsed = parse_console_command("set pipeline task-runner").expect("pipeline command");
        assert_eq!(
            parsed,
            ConsoleCommand::SetPipeline("task_runner".to_string())
        );
    }

    #[test]
    fn findings_command_keeps_run_prefix() {
        let parsed = parse_console_command("findings run-123").expect("findings command");
        assert_eq!(
            parsed,
            ConsoleCommand::ShowFindings(Some("run-123".to_string()))
        );
    }

    #[test]
    fn freeform_text_falls_back_to_natural_language() {
        let parsed = parse_console_command("scan https://example.com with recon pipeline")
            .expect("natural language");
        assert_eq!(
            parsed,
            ConsoleCommand::NaturalLanguage(
                "scan https://example.com with recon pipeline".to_string()
            )
        );
    }
}
