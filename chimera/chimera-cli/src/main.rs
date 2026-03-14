mod api;
mod config;
mod models;
mod render;
mod tui;

use crate::api::ApiClient;
use crate::config::{build_scope_text, load_state, read_scope_file, save_state};
use crate::models::{default_api_base, ChainFinding, CliState};
use crate::render::{render_chain_ascii, render_chain_detail, stat_u64};
use crate::tui::{boot_sequence, run_dashboard, should_use_tui, DashboardState};
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
        (None, None, None) => Commands::Status,
    };

    match command {
        Commands::Scan { remember } => {
            let target = cli
                .target
                .clone()
                .or_else(|| state.last_target.clone())
                .ok_or_else(|| anyhow!("scan requires --target or a remembered target"))?;
            let scope_text = resolve_scope_text(&cli, &state, &target)?;

            boot_sequence(&target, cli.pipeline.as_api_value())?;
            let created = client
                .create_scan(
                    scope_text,
                    cli.pipeline.as_api_value(),
                    cli.program.clone().or_else(|| state.last_program.clone()),
                    cli.max_workers,
                    cli.rate_limit_rps,
                    cli.timeout_s,
                )
                .await?;

            let tracking_id = created.job_id.clone().unwrap_or(created.run_id.clone());
            let resolved_run =
                monitor_run(&client, &target, cli.pipeline.as_api_value(), &tracking_id).await?;
            let findings = client.findings(&resolved_run).await.unwrap_or_default();

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

            if remember {
                state.api_base = api_base;
                state.last_target = Some(target);
                state.last_scope_file = cli.scope_file.map(|item| item.display().to_string());
                state.last_run_id = Some(resolved_run);
                state.last_pipeline = Some(cli.pipeline.as_api_value().to_string());
                state.last_program = cli.program.clone();
                save_state(&state)?;
            }
        }
        Commands::Status => {
            let status = client.status().await?;
            let run = if let Some(run_id) = state.last_run_id.as_ref() {
                client.get_run(run_id).await.ok()
            } else {
                None
            };
            for line in render::render_status_block(&status, run.as_ref()) {
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

fn resolve_scope_text(cli: &Cli, state: &CliState, target: &str) -> Result<String> {
    if let Some(path) = cli.scope_file.as_ref() {
        return read_scope_file(path);
    }
    if let Some(path) = state.last_scope_file.as_ref() {
        let path = PathBuf::from(path);
        if path.exists() {
            return read_scope_file(&path);
        }
    }
    build_scope_text(target)
}

fn resolve_run_id(run: Option<String>, state: &CliState) -> Result<String> {
    run.or_else(|| state.last_run_id.clone())
        .ok_or_else(|| anyhow!("no run id supplied and no remembered run id available"))
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
