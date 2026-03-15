mod api;
mod config;
mod console;
mod models;
mod render;
mod tui;

use crate::api::ApiClient;
use crate::config::{
    build_scope_manifest_text, build_scope_text, load_state, read_scope_file, save_state,
};
use crate::console::{command_help, parse_console_command, ConsoleCommand};
use crate::models::{
    default_api_base, ChainFinding, CliState, FindingSummary, SafetyState, StatusResponse,
};
use crate::render::{render_chain_ascii, render_chain_detail, render_status_block, stat_u64};
use crate::tui::{
    boot_sequence, run_console, run_dashboard, should_use_tui, ConsoleDirective, ConsoleExit,
    ConsoleSessionState, ConsoleSnapshot, DashboardState,
};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::Value;
use std::path::PathBuf;
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone, ValueEnum)]
enum Pipeline {
    TaskRunner,
    Recon,
}

impl Pipeline {
    fn as_api_value(&self) -> &'static str {
        match self {
            Self::TaskRunner => "task_runner",
            Self::Recon => "recon",
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "chimera",
    version = "1.0.0",
    about = "Matrix-inspired Chimera Rust CLI"
)]
struct Cli {
    #[arg(long, env = "CHIMERA_API_BASE", default_value_t = default_api_base())]
    api_base: String,
    #[arg(long, global = true)]
    target: Option<String>,
    #[arg(long, global = true)]
    scope_file: Option<PathBuf>,
    #[arg(long, global = true)]
    program: Option<String>,
    #[arg(long, global = true, value_enum, default_value_t = Pipeline::TaskRunner)]
    pipeline: Pipeline,
    #[arg(long, global = true, default_value_t = 2)]
    max_workers: u8,
    #[arg(long = "rps", global = true, default_value_t = 10)]
    rate_limit_rps: u16,
    #[arg(long = "timeout", global = true, default_value_t = 1200)]
    timeout_s: u16,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Clone, Subcommand)]
enum Commands {
    Scan {
        #[arg(long)]
        remember: bool,
    },
    Console,
    Status,
    Runs,
    Findings {
        #[arg(long)]
        run: Option<String>,
    },
    Viz {
        #[arg(long)]
        run: Option<String>,
    },
    Chain {
        #[arg(long)]
        run: Option<String>,
        chain_id: Option<String>,
    },
    Exploit {
        #[arg(long)]
        run: Option<String>,
        chain_id: String,
        #[arg(long)]
        replay: bool,
    },
    Oracle {
        #[arg(long)]
        run: Option<String>,
        question: String,
    },
    Ghost {
        #[arg(long)]
        run: Option<String>,
    },
}

#[derive(Debug, Clone)]
struct ScanInvocation {
    title: String,
    primary_target: Option<String>,
    scope_text: String,
    pipeline: String,
    program: Option<String>,
    remember: bool,
    scope_file: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut state = load_state();
    if state.api_base.is_empty() {
        state.api_base = default_api_base();
    }

    let api_base = if cli.api_base == default_api_base() {
        state.api_base.clone()
    } else {
        cli.api_base.clone()
    };
    let client = ApiClient::new(api_base.clone())?;

    let command = match (
        cli.command.clone(),
        cli.target.clone(),
        cli.scope_file.clone(),
    ) {
        (Some(cmd), _, _) => cmd,
        (None, Some(_), _) | (None, None, Some(_)) => Commands::Scan { remember: true },
        (None, None, None) if should_use_tui() => Commands::Console,
        (None, None, None) => Commands::Status,
    };

    match command {
        Commands::Scan { remember } => {
            let target = cli
                .target
                .clone()
                .or_else(|| state.last_target.clone())
                .ok_or_else(|| anyhow!("scan requires --target or a remembered target"))?;
            let invocation = ScanInvocation {
                title: target.clone(),
                primary_target: Some(target.clone()),
                scope_text: resolve_scope_text(&cli, &state, &target)?,
                pipeline: cli.pipeline.as_api_value().to_string(),
                program: cli.program.clone().or_else(|| state.last_program.clone()),
                remember,
                scope_file: remembered_scope_file(&cli, &state),
            };
            let (resolved_run, findings) =
                run_scan_invocation(&client, &mut state, &api_base, &cli, invocation).await?;

            println!("\n\x1b[31mConfirmed findings: {}\x1b[0m", findings.len());
            for item in findings.iter().take(8) {
                println!(
                    "[{}] {} ({:.2})",
                    item.severity.to_uppercase(),
                    item.title,
                    item.confidence
                );
            }
            println!("run_id: {}", resolved_run);
        }
        Commands::Console => {
            run_console_shell(&client, &mut state, &api_base, &cli).await?;
        }
        Commands::Status => {
            let status = client.status().await?;
            let run = if let Some(run_id) = state.last_run_id.as_ref() {
                client.get_run(run_id).await.ok()
            } else {
                None
            };
            for line in render_status_block(&status, run.as_ref()) {
                println!("{}", line);
            }
        }
        Commands::Runs => {
            let runs = client.list_runs().await?;
            for run in runs {
                println!(
                    "{}  {:<10} findings={} chains={}",
                    run.run_id,
                    run.status,
                    stat_u64(&run.stats, "findings_total"),
                    stat_u64(&run.stats, "exploit_chains")
                );
            }
        }
        Commands::Findings { run } => {
            let run_id = resolve_run_id(run, &state)?;
            let findings = client.findings(&run_id).await?;
            for item in findings {
                println!(
                    "[{}] {} | {} | {:.2} | {}",
                    item.severity.to_uppercase(),
                    item.stable_id,
                    item.title,
                    item.confidence,
                    item.target
                );
            }
        }
        Commands::Viz { run } => {
            let run_id = resolve_run_id(run, &state)?;
            let chains = client.chain_graphs(&run_id).await?;
            println!("{}", render_chain_ascii(&chains)?);
        }
        Commands::Chain { run, chain_id } => {
            let run_id = resolve_run_id(run, &state)?;
            let chains = client.chains(&run_id).await?;
            if let Some(chain_id) = chain_id {
                let chain = select_chain(&chains, &chain_id)?;
                println!("{}", render_chain_detail(chain));
            } else {
                for chain in chains {
                    println!(
                        "{}  {}  {:.2}",
                        chain.finding_id, chain.title, chain.confidence
                    );
                }
            }
        }
        Commands::Exploit {
            run,
            chain_id,
            replay,
        } => {
            let run_id = resolve_run_id(run, &state)?;
            let chains = client.chains(&run_id).await?;
            let chain = select_chain(&chains, &chain_id)?;
            println!("{}", render_chain_detail(chain));
            if replay {
                println!("\nREPLAY READY");
                for step in &chain.replay_steps {
                    let nested = step.replay_steps.len();
                    println!(
                        "step={} action={} nested_steps={}",
                        step.step.unwrap_or(0),
                        step.action.clone().unwrap_or_else(|| "step".to_string()),
                        nested
                    );
                }
            }
        }
        Commands::Oracle { run, question } => {
            let run_id = resolve_run_id(run, &state)?;
            let payload = client
                .suggested_actions(&run_id)
                .await
                .unwrap_or(Value::Null);
            println!("[SHANNON]");
            println!("Question: {}", question);
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
            );
        }
        Commands::Ghost { run } => {
            let run_id = resolve_run_id(run, &state)?;
            let artifacts = client.artifacts(&run_id).await?;
            println!("ghost@chimera[{}] >", run_id);
            for item in artifacts.into_iter().filter(|artifact| {
                artifact.path.contains("browser") || artifact.path.contains("playwright")
            }) {
                println!("artifact {} {}", item.kind, item.path);
            }
        }
    }

    Ok(())
}

async fn run_console_shell(
    client: &ApiClient,
    state: &mut CliState,
    api_base: &str,
    cli: &Cli,
) -> Result<()> {
    let mut session = ConsoleSessionState::new(
        state.last_run_id.clone(),
        state.last_target.clone(),
        state
            .last_pipeline
            .clone()
            .unwrap_or_else(|| cli.pipeline.as_api_value().to_string()),
        state.last_program.clone(),
    );
    session.push_log("msfconsole-style control surface online");
    session.push_log("type :help to stage targets, ask Shannon, or launch scans");

    loop {
        let exit = run_console(
            &mut session,
            |session| fetch_console_snapshot(client, state, session),
            |input, snapshot, session| {
                execute_console_command(client, state, input, snapshot, session)
            },
        )?;

        match exit {
            ConsoleExit::Quit => break,
            ConsoleExit::Action(invocation) => {
                match run_scan_invocation(client, state, api_base, cli, invocation).await {
                    Ok((run_id, findings)) => {
                        session.selected_run_id = Some(run_id.clone());
                        session.push_log(format!(
                            "run {} completed with {} findings",
                            run_id,
                            findings.len()
                        ));
                        for item in findings.iter().take(3) {
                            session.push_log(format!(
                                "[{}] {} ({:.2})",
                                item.severity.to_uppercase(),
                                item.title,
                                item.confidence
                            ));
                        }
                    }
                    Err(err) => {
                        session.push_log(format!("scan failed: {err:#}"));
                    }
                }
            }
        }
    }

    state.api_base = api_base.to_string();
    state.last_target = session.last_target.clone();
    state.last_run_id = session
        .selected_run_id
        .clone()
        .or_else(|| state.last_run_id.clone());
    state.last_pipeline = Some(session.last_pipeline.clone());
    state.last_program = session.last_program.clone();
    save_state(state)?;

    Ok(())
}

async fn run_scan_invocation(
    client: &ApiClient,
    state: &mut CliState,
    api_base: &str,
    cli: &Cli,
    invocation: ScanInvocation,
) -> Result<(String, Vec<FindingSummary>)> {
    boot_sequence(&invocation.title, &invocation.pipeline)?;
    let created = client
        .create_scan(
            invocation.scope_text,
            &invocation.pipeline,
            invocation.program.clone(),
            cli.max_workers,
            cli.rate_limit_rps,
            cli.timeout_s,
        )
        .await?;

    let tracking_id = created.job_id.clone().unwrap_or(created.run_id.clone());
    let resolved_run = monitor_run(
        client,
        &invocation.title,
        &invocation.pipeline,
        &tracking_id,
    )
    .await?;
    let findings = client.findings(&resolved_run).await.unwrap_or_default();

    if invocation.remember {
        state.api_base = api_base.to_string();
        state.last_target = invocation.primary_target;
        state.last_scope_file = invocation.scope_file;
        state.last_run_id = Some(resolved_run.clone());
        state.last_pipeline = Some(invocation.pipeline);
        state.last_program = invocation.program;
        save_state(state)?;
    }

    Ok((resolved_run, findings))
}

fn fetch_console_snapshot(
    client: &ApiClient,
    state: &CliState,
    session: &mut ConsoleSessionState,
) -> Result<ConsoleSnapshot> {
    tokio::task::block_in_place(|| {
        let handle = tokio::runtime::Handle::current();
        let status = match handle.block_on(client.status()) {
            Ok(status) => status,
            Err(err) => {
                return Ok(ConsoleSnapshot {
                    status: offline_status(&err.to_string()),
                    runs: Vec::new(),
                    selected_run_id: session.selected_run_id.clone(),
                    selected_run: None,
                    events: Vec::new(),
                    findings: Vec::new(),
                    api_error: Some(err.to_string()),
                });
            }
        };

        let mut api_error = None;
        let runs = match handle.block_on(client.list_runs()) {
            Ok(runs) => runs,
            Err(err) => {
                api_error = Some(err.to_string());
                Vec::new()
            }
        };

        let selected_run_id = session
            .selected_run_id
            .clone()
            .or_else(|| {
                status
                    .active_run
                    .as_ref()
                    .and_then(|item| item.run_id.clone())
            })
            .or_else(|| state.last_run_id.clone())
            .or_else(|| runs.first().map(|run| run.run_id.clone()));
        session.selected_run_id = selected_run_id.clone();

        let selected_run = if let Some(run_id) = selected_run_id.as_ref() {
            match handle.block_on(client.get_run(run_id)) {
                Ok(run) => Some(run),
                Err(err) => {
                    if api_error.is_none() {
                        api_error = Some(err.to_string());
                    }
                    None
                }
            }
        } else {
            None
        };

        let focus_run_id = selected_run
            .as_ref()
            .and_then(|run| run.run_id.clone())
            .or(selected_run_id.clone());
        let events = if let Some(run_id) = focus_run_id.as_ref() {
            handle
                .block_on(client.events_tail(run_id, 60))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let findings = if let Some(run_id) = focus_run_id.as_ref() {
            handle.block_on(client.findings(run_id)).unwrap_or_default()
        } else {
            Vec::new()
        };

        Ok(ConsoleSnapshot {
            status,
            runs,
            selected_run_id: focus_run_id,
            selected_run,
            events,
            findings,
            api_error,
        })
    })
}

fn execute_console_command(
    client: &ApiClient,
    state: &CliState,
    input: &str,
    snapshot: &ConsoleSnapshot,
    session: &mut ConsoleSessionState,
) -> Result<ConsoleDirective<ScanInvocation>> {
    let command = parse_console_command(input)?;
    match command {
        ConsoleCommand::Help => {
            for line in command_help() {
                session.push_log(*line);
            }
            Ok(ConsoleDirective::Continue)
        }
        ConsoleCommand::Info => {
            session.push_log(format!(
                "target={} | pipeline={} | program={} | scope={}",
                session.last_target.as_deref().unwrap_or("unset"),
                session.last_pipeline,
                session.last_program.as_deref().unwrap_or("unset"),
                if session.staged_scope_text.is_some() {
                    "staged"
                } else {
                    "generated"
                }
            ));
            Ok(ConsoleDirective::Continue)
        }
        ConsoleCommand::Refresh => {
            session.push_log("refresh requested");
            Ok(ConsoleDirective::Continue)
        }
        ConsoleCommand::Quit => Ok(ConsoleDirective::Exit(ConsoleExit::Quit)),
        ConsoleCommand::ShowStatus => {
            for line in render_status_block(&snapshot.status, snapshot.selected_run.as_ref()) {
                session.push_log(line);
            }
            Ok(ConsoleDirective::Continue)
        }
        ConsoleCommand::ShowRuns => {
            if snapshot.runs.is_empty() {
                session.push_log("no runs available");
            } else {
                for run in snapshot.runs.iter().take(6) {
                    session.push_log(format!(
                        "{}  {:<10} findings={} chains={}",
                        run.run_id,
                        run.status,
                        stat_u64(&run.stats, "findings_total"),
                        stat_u64(&run.stats, "exploit_chains")
                    ));
                }
            }
            Ok(ConsoleDirective::Continue)
        }
        ConsoleCommand::ShowFindings(run_arg) => {
            let run_id = resolve_console_run_id(run_arg, snapshot, state)?;
            let findings = tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(client.findings(&run_id))
            })?;
            session.selected_run_id = Some(run_id.clone());
            append_findings_preview(session, &run_id, &findings);
            Ok(ConsoleDirective::Continue)
        }
        ConsoleCommand::UseRun(run_arg) => {
            let run_id = resolve_run_from_snapshot(&snapshot.runs, &run_arg)
                .map(|run| run.run_id.clone())
                .unwrap_or(run_arg);
            session.selected_run_id = Some(run_id.clone());
            session.push_log(format!("selected run {}", run_id));
            Ok(ConsoleDirective::Continue)
        }
        ConsoleCommand::SetTarget(target) => {
            session.last_target = Some(target.clone());
            session.staged_scope_text = None;
            session.push_log(format!("staged target {}", target));
            Ok(ConsoleDirective::Continue)
        }
        ConsoleCommand::SetPipeline(pipeline) => {
            session.last_pipeline = pipeline.clone();
            session.push_log(format!("pipeline set to {}", pipeline));
            Ok(ConsoleDirective::Continue)
        }
        ConsoleCommand::SetProgram(program) => {
            session.last_program = Some(program.clone());
            session.push_log(format!("program label set to {}", program));
            Ok(ConsoleDirective::Continue)
        }
        ConsoleCommand::ClearProgram => {
            session.last_program = None;
            session.push_log("cleared program label");
            Ok(ConsoleDirective::Continue)
        }
        ConsoleCommand::ClearScope => {
            session.staged_scope_text = None;
            session.push_log("cleared staged scope manifest");
            Ok(ConsoleDirective::Continue)
        }
        ConsoleCommand::LaunchScan { target, pipeline } => {
            if let Some(target) = target {
                session.last_target = Some(target);
                session.staged_scope_text = None;
            }
            if let Some(pipeline) = pipeline {
                session.last_pipeline = pipeline;
            }

            let scope_text = if let Some(scope_text) = session.staged_scope_text.clone() {
                scope_text
            } else {
                let target = session
                    .last_target
                    .as_deref()
                    .ok_or_else(|| anyhow!("run requires a staged target or scope manifest"))?;
                build_scope_text(target)?
            };
            let title = session
                .last_target
                .clone()
                .unwrap_or_else(|| "scope manifest".to_string());
            session.push_log(format!("launching {} via {}", title, session.last_pipeline));
            Ok(ConsoleDirective::Exit(ConsoleExit::Action(
                ScanInvocation {
                    title,
                    primary_target: session.last_target.clone(),
                    scope_text,
                    pipeline: session.last_pipeline.clone(),
                    program: session.last_program.clone(),
                    remember: true,
                    scope_file: None,
                },
            )))
        }
        ConsoleCommand::Oracle(question) => {
            let target = session.last_target.as_deref();
            let payload = tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(client.shannon_oracle(&question, target))
            })?;
            append_oracle_preview(session, &payload);
            Ok(ConsoleDirective::Continue)
        }
        ConsoleCommand::NaturalLanguage(text) => {
            stage_interpreted_input(client, session, snapshot, &text)?;
            Ok(ConsoleDirective::Continue)
        }
    }
}

fn stage_interpreted_input(
    client: &ApiClient,
    session: &mut ConsoleSessionState,
    snapshot: &ConsoleSnapshot,
    text: &str,
) -> Result<()> {
    let parsed = tokio::task::block_in_place(|| {
        let handle = tokio::runtime::Handle::current();
        handle.block_on(client.interpret_input(text))
    })?;

    if let Some(notes) = parsed.get("notes").and_then(Value::as_array) {
        for note in notes.iter().filter_map(Value::as_str).take(3) {
            session.push_log(note.to_string());
        }
    }

    match parsed
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
    {
        "scope" => {
            let manifest = parsed
                .get("scope_manifest")
                .cloned()
                .ok_or_else(|| anyhow!("parser returned scope without scope_manifest"))?;
            let targets = extract_allowlist_targets(&manifest);
            session.staged_scope_text =
                Some(serde_yaml::to_string(&manifest).context("failed to stage scope text")?);
            if let Some(first) = targets.first() {
                session.last_target = Some(first.clone());
            }
            session.push_log(format!(
                "staged scope manifest with {} allowlisted target(s)",
                targets.len()
            ));
        }
        "command" => {
            let command = parsed.get("command").cloned().unwrap_or(Value::Null);
            if let Some(pipeline) = command.get("pipeline").and_then(Value::as_str) {
                session.last_pipeline = pipeline.to_string();
            }
            if let Some(program) = command.get("program_name").and_then(Value::as_str) {
                session.last_program = Some(program.to_string());
            }
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
            if !targets.is_empty() {
                session.last_target = targets.first().cloned();
                session.staged_scope_text = Some(build_scope_manifest_text(&targets)?);
            }

            match command
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("scan")
            {
                "status" => {
                    for line in
                        render_status_block(&snapshot.status, snapshot.selected_run.as_ref())
                    {
                        session.push_log(line);
                    }
                }
                "oracle" => {
                    let question = command
                        .get("question")
                        .and_then(Value::as_str)
                        .unwrap_or(text);
                    session.push_log(format!("staged question: {}", question));
                    session.push_log("use `oracle <question>` to query Shannon directly");
                }
                _ => {
                    session.push_log("parsed scan context has been staged");
                    session.push_log("use `run` to launch with the staged target or manifest");
                }
            }
        }
        _ => {
            session.push_log("parser did not recognize the input");
        }
    }

    Ok(())
}

fn append_findings_preview(
    session: &mut ConsoleSessionState,
    run_id: &str,
    findings: &[FindingSummary],
) {
    session.push_log(format!("{} findings for {}", findings.len(), run_id));
    for item in findings.iter().take(5) {
        session.push_log(format!(
            "[{}] {} ({:.2})",
            item.severity.to_uppercase(),
            item.title,
            item.confidence
        ));
    }
}

fn append_oracle_preview(session: &mut ConsoleSessionState, payload: &Value) {
    if let Some(answer) = payload.get("answer").and_then(Value::as_str) {
        session.push_log(format!("oracle: {}", answer));
    } else {
        session
            .push_log(serde_json::to_string_pretty(payload).unwrap_or_else(|_| "{}".to_string()));
    }
    if let Some(items) = payload.get("suggestions").and_then(Value::as_array) {
        let suggestions: Vec<String> = items
            .iter()
            .take(3)
            .map(|item| {
                item.get("vector")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
                    .unwrap_or_else(|| item.to_string())
            })
            .collect();
        if !suggestions.is_empty() {
            session.push_log(format!("suggestions: {}", suggestions.join(", ")));
        }
    }
}

fn remembered_scope_file(cli: &Cli, state: &CliState) -> Option<String> {
    if let Some(path) = cli.scope_file.as_ref() {
        return Some(path.display().to_string());
    }
    if cli.target.is_none() {
        return state.last_scope_file.clone();
    }
    None
}

fn resolve_scope_text(cli: &Cli, state: &CliState, target: &str) -> Result<String> {
    if let Some(path) = cli.scope_file.as_ref() {
        return read_scope_file(path);
    }
    if cli.target.is_none() {
        if let Some(path) = state.last_scope_file.as_ref() {
            let path = PathBuf::from(path);
            if path.exists() {
                return read_scope_file(&path);
            }
        }
    }
    build_scope_text(target)
}

fn resolve_run_id(run: Option<String>, state: &CliState) -> Result<String> {
    run.or_else(|| state.last_run_id.clone())
        .ok_or_else(|| anyhow!("no run id supplied and no remembered run id available"))
}

fn resolve_console_run_id(
    run_arg: Option<String>,
    snapshot: &ConsoleSnapshot,
    state: &CliState,
) -> Result<String> {
    if let Some(run_arg) = run_arg {
        if let Some(run) = resolve_run_from_snapshot(&snapshot.runs, &run_arg) {
            return Ok(run.run_id.clone());
        }
        return Ok(run_arg);
    }
    snapshot
        .selected_run_id
        .clone()
        .or_else(|| state.last_run_id.clone())
        .ok_or_else(|| anyhow!("no run selected"))
}

fn resolve_run_from_snapshot<'a>(
    runs: &'a [crate::models::RunSummary],
    run_arg: &str,
) -> Option<&'a crate::models::RunSummary> {
    runs.iter()
        .find(|run| run.run_id == run_arg || run.run_id.starts_with(run_arg))
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
                .collect()
        })
        .unwrap_or_default()
}

fn offline_status(error: &str) -> StatusResponse {
    StatusResponse {
        mode: "offline".to_string(),
        safety_state: SafetyState {
            blocked_reasons: vec![format!("API unreachable: {}", error)],
            ..SafetyState::default()
        },
        ..StatusResponse::default()
    }
}

fn select_chain<'a>(chains: &'a [ChainFinding], chain_id: &str) -> Result<&'a ChainFinding> {
    chains
        .iter()
        .find(|chain| chain.finding_id == chain_id || chain.finding_id.starts_with(chain_id))
        .with_context(|| format!("chain {chain_id} not found"))
}

async fn monitor_run(
    client: &ApiClient,
    target: &str,
    pipeline: &str,
    tracking_id: &str,
) -> Result<String> {
    let tracking = tracking_id.to_string();
    let mut resolved_run_id = tracking.clone();
    let mut last_status = "created".to_string();

    if should_use_tui() {
        run_dashboard(|| {
            tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                let run = handle.block_on(client.get_run(&tracking))?;
                let status = handle.block_on(client.status())?;
                let actual_run_id = run
                    .run_id
                    .clone()
                    .or_else(|| run.job_id.clone())
                    .unwrap_or_else(|| tracking.clone());
                let events = handle
                    .block_on(client.events_tail(&actual_run_id, 120))
                    .unwrap_or_default();
                let findings = handle
                    .block_on(client.findings(&actual_run_id))
                    .unwrap_or_default();
                resolved_run_id = actual_run_id.clone();
                last_status = run.status.clone().unwrap_or_else(|| "running".to_string());
                if matches!(last_status.as_str(), "completed" | "failed" | "cancelled") {
                    return Ok(None);
                }
                Ok(Some(DashboardState {
                    title: target.to_string(),
                    pipeline: pipeline.to_string(),
                    run_id: actual_run_id,
                    phase: last_status.clone(),
                    status,
                    run_detail: Some(run),
                    events,
                    findings,
                }))
            })
        })?;
    } else {
        loop {
            let run = client.get_run(&tracking).await?;
            let actual_run_id = run
                .run_id
                .clone()
                .or_else(|| run.job_id.clone())
                .unwrap_or_else(|| tracking.clone());
            resolved_run_id = actual_run_id.clone();
            let events = client
                .events_tail(&actual_run_id, 5)
                .await
                .unwrap_or_default();
            for item in events.iter().rev().take(3) {
                println!("{}", item);
            }
            last_status = run.status.unwrap_or_else(|| "running".to_string());
            if matches!(last_status.as_str(), "completed" | "failed" | "cancelled") {
                break;
            }
            sleep(Duration::from_secs(1)).await;
        }
    }

    loop {
        let run = client.get_run(&resolved_run_id).await?;
        let status = run.status.unwrap_or_else(|| "completed".to_string());
        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            return Ok(run.run_id.unwrap_or(resolved_run_id));
        }
        sleep(Duration::from_millis(400)).await;
    }
}
