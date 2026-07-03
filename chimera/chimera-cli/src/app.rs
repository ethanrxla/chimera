use crate::action::{Action, Effect};
use crate::command_parser::{command_help, parse_command, suggestions};
use crate::models::{FindingSummary, RunDetail, RunSummary, StatusResponse};
use crate::render::{render_status_block, stat_u64};
use crate::theme::ThemeName;
use anyhow::Result;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Command,
    Nlp,
    Help,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Command => "COMMAND",
            Self::Nlp => "NLP",
            Self::Help => "HELP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusedPane {
    Menu,
    Main,
    Output,
    Input,
}

impl FocusedPane {
    pub fn label(self) -> &'static str {
        match self {
            Self::Menu => "MENU",
            Self::Main => "MAIN",
            Self::Output => "OUTPUT",
            Self::Input => "INPUT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowProfile {
    Quick,
    Standard,
    Full,
    Custom,
}

impl WorkflowProfile {
    pub fn label(self) -> &'static str {
        match self {
            Self::Quick => "Quick",
            Self::Standard => "Standard",
            Self::Full => "Full",
            Self::Custom => "Custom",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "quick" => Some(Self::Quick),
            "standard" | "default" => Some(Self::Standard),
            "full" => Some(Self::Full),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputContext {
    CommandPalette,
    SetTarget,
    SetWorkflow,
    SetTheme,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    SetTarget,
    ChooseWorkflow,
    RunWorkflow,
    AskAi,
    ViewOutput,
    Logs,
    Help,
    Settings,
    Exit,
}

impl MenuItem {
    pub const ALL: [MenuItem; 9] = [
        MenuItem::SetTarget,
        MenuItem::ChooseWorkflow,
        MenuItem::RunWorkflow,
        MenuItem::AskAi,
        MenuItem::ViewOutput,
        MenuItem::Logs,
        MenuItem::Help,
        MenuItem::Settings,
        MenuItem::Exit,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::SetTarget => "Set Target",
            Self::ChooseWorkflow => "Choose Workflow",
            Self::RunWorkflow => "Run Workflow",
            Self::AskAi => "Ask AI / NLP",
            Self::ViewOutput => "View Output",
            Self::Logs => "Logs",
            Self::Help => "Help",
            Self::Settings => "Settings",
            Self::Exit => "Exit",
        }
    }

    pub fn summary(self) -> &'static str {
        match self {
            Self::SetTarget => "Stage a host, IP, URL, or file of targets.",
            Self::ChooseWorkflow => "Switch the operator workflow profile.",
            Self::RunWorkflow => "Launch the staged target through the current workflow.",
            Self::AskAi => "Send an NLP request for model-backed actions.",
            Self::ViewOutput => "Review recent operator output and command responses.",
            Self::Logs => "Print the latest telemetry feed into the output pane.",
            Self::Help => "Open the keyboard and command reference.",
            Self::Settings => "Switch the active TUI theme.",
            Self::Exit => "Leave the Chimera operator console.",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppStatus {
    pub text: String,
    pub error: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ConsoleSnapshot {
    pub status: StatusResponse,
    pub runs: Vec<RunSummary>,
    pub selected_run_id: Option<String>,
    pub selected_run: Option<RunDetail>,
    pub events: Vec<String>,
    pub findings: Vec<FindingSummary>,
    pub api_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct App {
    pub running: bool,
    pub mode: Mode,
    pub focus: FocusedPane,
    pub previous_focus: FocusedPane,
    pub input_context: InputContext,
    pub selected_menu: usize,
    pub highlighted_run: usize,
    pub input: String,
    pub target: Option<String>,
    pub workflow: WorkflowProfile,
    pub pipeline: String,
    pub program: Option<String>,
    pub ollama_base: String,
    pub ollama_model: String,
    pub status: AppStatus,
    pub output_lines: Vec<String>,
    pub command_history: Vec<String>,
    pub history_index: Option<usize>,
    pub staged_scope_text: Option<String>,
    pub show_help: bool,
    pub theme: ThemeName,
    pub intent_preview: Option<crate::nlp::IntentPreview>,
    pub snapshot: ConsoleSnapshot,
    pub selected_run_id: Option<String>,
    pub output_scroll: usize,
}

impl App {
    pub fn new(
        selected_run_id: Option<String>,
        target: Option<String>,
        pipeline: String,
        program: Option<String>,
        ollama_base: String,
        ollama_model: Option<String>,
    ) -> Self {
        let mut app = Self {
            running: true,
            mode: Mode::Normal,
            focus: FocusedPane::Menu,
            previous_focus: FocusedPane::Menu,
            input_context: InputContext::CommandPalette,
            selected_menu: 0,
            highlighted_run: 0,
            input: String::new(),
            target,
            workflow: WorkflowProfile::Standard,
            pipeline,
            program,
            ollama_base,
            ollama_model: ollama_model.unwrap_or_else(|| "whiterabbitneo-13b".to_string()),
            status: AppStatus {
                text: "Ready".to_string(),
                error: false,
            },
            output_lines: Vec::new(),
            command_history: Vec::new(),
            history_index: None,
            staged_scope_text: None,
            show_help: false,
            theme: ThemeName::Matrix,
            intent_preview: None,
            snapshot: ConsoleSnapshot::default(),
            selected_run_id,
            output_scroll: 0,
        };
        app.push_output("CHIMERA operator console ready.");
        app.push_output("Primary actions: Set Target, Run Workflow, Ask AI.");
        app.push_output("Direct model chat: use :models, :set ollama model <name>, :chat <prompt>.");
        app.push_output("Press ? for help, : for exact commands, / for model-backed actions.");
        app
    }

    pub fn update(&mut self, action: Action) -> Result<Vec<Effect>> {
        match action {
            Action::Tick => Ok(Vec::new()),
            Action::Refresh => {
                self.set_status("Refreshing snapshot", false);
                Ok(vec![Effect::RefreshSnapshot])
            }
            Action::SnapshotLoaded(snapshot) => {
                let previous_snapshot = self.snapshot.clone();
                let previous_selected_run_id = self.selected_run_id.clone();
                self.snapshot = snapshot;
                if let Some(run_id) = self.snapshot.selected_run_id.clone() {
                    self.selected_run_id = Some(run_id.clone());
                    if let Some(index) = self
                        .snapshot
                        .runs
                        .iter()
                        .position(|run| run.run_id == run_id)
                    {
                        self.highlighted_run = index;
                    }
                } else if !self.snapshot.runs.is_empty() {
                    self.highlighted_run = self.highlighted_run.min(self.snapshot.runs.len() - 1);
                }

                self.append_live_snapshot_changes(
                    &previous_snapshot,
                    previous_selected_run_id.as_deref(),
                );

                if let Some(err) = self.snapshot.api_error.clone() {
                    self.set_status(format!("API degraded: {}", err), true);
                } else {
                    self.set_status("Snapshot refreshed", false);
                }
                Ok(Vec::new())
            }
            Action::SnapshotFailed(error) => {
                self.set_status(format!("Refresh failed: {}", error), true);
                self.push_output(format!("refresh failed: {}", error));
                Ok(Vec::new())
            }
            Action::Quit => {
                self.running = false;
                Ok(Vec::new())
            }
            Action::Back => {
                if self.mode != Mode::Normal {
                    return self.update(Action::ExitInputMode);
                }
                if self.focus != FocusedPane::Menu {
                    self.focus = FocusedPane::Menu;
                    self.set_status("Focus returned to menu", false);
                    return Ok(Vec::new());
                }
                self.running = false;
                Ok(Vec::new())
            }
            Action::ShowHelp => {
                self.mode = Mode::Help;
                self.show_help = true;
                self.set_status("Help open", false);
                Ok(Vec::new())
            }
            Action::HideHelp => {
                self.mode = Mode::Normal;
                self.show_help = false;
                self.set_status("Help closed", false);
                Ok(Vec::new())
            }
            Action::FocusNext => {
                if self.mode != Mode::Normal {
                    return Ok(Vec::new());
                }
                self.focus = match self.focus {
                    FocusedPane::Menu => FocusedPane::Main,
                    FocusedPane::Main => FocusedPane::Output,
                    FocusedPane::Output => FocusedPane::Menu,
                    FocusedPane::Input => FocusedPane::Menu,
                };
                self.set_status(format!("Focus: {}", self.focus.label()), false);
                Ok(Vec::new())
            }
            Action::FocusPrev => {
                if self.mode != Mode::Normal {
                    return Ok(Vec::new());
                }
                self.focus = match self.focus {
                    FocusedPane::Menu => FocusedPane::Output,
                    FocusedPane::Main => FocusedPane::Menu,
                    FocusedPane::Output => FocusedPane::Main,
                    FocusedPane::Input => FocusedPane::Output,
                };
                self.set_status(format!("Focus: {}", self.focus.label()), false);
                Ok(Vec::new())
            }
            Action::MoveUp => self.move_selection(-1),
            Action::MoveDown => self.move_selection(1),
            Action::Select => self.select_focused_item(),
            Action::EnterCommandMode(context) => {
                self.previous_focus = self.focus;
                self.focus = FocusedPane::Input;
                self.mode = Mode::Command;
                self.input_context = context.unwrap_or(InputContext::CommandPalette);
                self.input.clear();
                self.history_index = None;
                self.set_status(self.input_prompt().to_string(), false);
                Ok(Vec::new())
            }
            Action::EnterNlpMode => {
                self.previous_focus = self.focus;
                self.focus = FocusedPane::Input;
                self.mode = Mode::Nlp;
                self.input_context = InputContext::CommandPalette;
                self.input.clear();
                self.history_index = None;
                self.set_status("NLP prompt ready", false);
                Ok(Vec::new())
            }
            Action::ExitInputMode => {
                self.mode = Mode::Normal;
                self.focus = self.previous_focus;
                self.input.clear();
                self.history_index = None;
                self.show_help = false;
                self.set_status("Navigation mode", false);
                Ok(Vec::new())
            }
            Action::PushInput(ch) => {
                self.input.push(ch);
                Ok(Vec::new())
            }
            Action::PopInput => {
                self.input.pop();
                Ok(Vec::new())
            }
            Action::HistoryPrev => {
                self.history_prev();
                Ok(Vec::new())
            }
            Action::HistoryNext => {
                self.history_next();
                Ok(Vec::new())
            }
            Action::SubmitInput => self.submit_input(),
            Action::SetTarget(target) => {
                self.target = Some(target.clone());
                self.staged_scope_text = None;
                self.intent_preview = None;
                self.push_output(format!("Target staged: {}", target));
                self.set_status("Target updated", false);
                Ok(Vec::new())
            }
            Action::StageScopeText(scope) => {
                self.staged_scope_text = Some(scope);
                self.push_output("Scope manifest staged from structured input.");
                self.set_status("Scope manifest staged", false);
                Ok(Vec::new())
            }
            Action::SetWorkflow(workflow) => {
                self.workflow = workflow;
                self.push_output(format!("Workflow set to {}", workflow.label()));
                self.set_status(format!("Workflow: {}", workflow.label()), false);
                Ok(Vec::new())
            }
            Action::SetPipeline(pipeline) => {
                self.pipeline = pipeline.clone();
                self.push_output(format!("Pipeline set to {}", pipeline));
                self.set_status(format!("Pipeline: {}", pipeline), false);
                Ok(Vec::new())
            }
            Action::SetProgram(program) => {
                self.program = Some(program.clone());
                self.push_output(format!("Program label set to {}", program));
                self.set_status("Program updated", false);
                Ok(Vec::new())
            }
            Action::ClearProgram => {
                self.program = None;
                self.push_output("Program label cleared.");
                self.set_status("Program cleared", false);
                Ok(Vec::new())
            }
            Action::ClearScope => {
                self.staged_scope_text = None;
                self.push_output("Staged scope manifest cleared.");
                self.set_status("Scope cleared", false);
                Ok(Vec::new())
            }
            Action::SelectRun(run_id) => {
                self.selected_run_id = Some(run_id.clone());
                self.push_output(format!("Focused run {}", run_id));
                self.set_status("Loading run context", false);
                Ok(vec![Effect::RefreshSnapshot])
            }
            Action::ShowStatus => {
                for line in
                    render_status_block(&self.snapshot.status, self.snapshot.selected_run.as_ref())
                {
                    self.push_output(line);
                }
                self.set_status("Status written to output", false);
                Ok(Vec::new())
            }
            Action::ShowRuns => {
                if self.snapshot.runs.is_empty() {
                    self.push_output("No runs available.");
                } else {
                    let lines = self
                        .snapshot
                        .runs
                        .iter()
                        .take(8)
                        .map(|run| {
                            format!(
                                "{}  {:<10} findings={} chains={}",
                                run.run_id,
                                run.status,
                                stat_u64(&run.stats, "findings_total"),
                                stat_u64(&run.stats, "exploit_chains")
                            )
                        })
                        .collect::<Vec<_>>();
                    for line in lines {
                        self.push_output(line);
                    }
                }
                self.set_status("Runs written to output", false);
                Ok(Vec::new())
            }
            Action::ShowFindings(run_id) => {
                if let Some(run_id) = run_id {
                    if self.selected_run_id.as_deref() != Some(run_id.as_str()) {
                        self.set_status("Loading findings", false);
                        return Ok(vec![Effect::FetchFindings(Some(run_id))]);
                    }
                }

                let active_run = self
                    .selected_run_id
                    .clone()
                    .unwrap_or_else(|| "current run".to_string());
                let findings = self.snapshot.findings.clone();
                self.append_findings_preview(&active_run, &findings);
                self.set_status("Findings written to output", false);
                Ok(Vec::new())
            }
            Action::ShowLogs => {
                self.focus = FocusedPane::Output;
                if self.snapshot.events.is_empty() {
                    self.push_output("No telemetry events available.");
                } else {
                    self.push_output("Telemetry tail:");
                    let items = self
                        .snapshot
                        .events
                        .iter()
                        .rev()
                        .take(8)
                        .cloned()
                        .collect::<Vec<_>>();
                    for item in items.into_iter().rev() {
                        self.push_output(item);
                    }
                }
                self.set_status("Telemetry written to output", false);
                Ok(Vec::new())
            }
            Action::ShowModels => {
                self.focus = FocusedPane::Output;
                self.push_output("Listing installed Ollama models…");
                self.set_status("Querying Ollama /api/tags", false);
                Ok(vec![Effect::FetchOllamaModels])
            }
            Action::LaunchScan => {
                if self.target.is_none() && self.staged_scope_text.is_none() {
                    self.set_status("No target or scope is staged", true);
                    self.push_output("Run blocked: set a target or stage a scope manifest first.");
                    return Ok(Vec::new());
                }
                self.push_output(format!(
                    "Launching {} workflow on {}",
                    self.workflow.label(),
                    self.target.as_deref().unwrap_or("staged scope")
                ));
                self.set_status("Handing off to scan monitor", false);
                Ok(vec![Effect::LaunchScan])
            }
            Action::AskModel(question) => {
                self.push_output(format!("Oracle request: {}", question));
                self.set_status("Querying model-backed action service", false);
                Ok(vec![Effect::FetchOracle(question)])
            }
            Action::AskOllama(prompt) => {
                self.focus = FocusedPane::Output;
                self.push_output(format!("Ollama prompt: {}", prompt));
                self.set_status(format!("Querying Ollama ({})", self.ollama_model), false);
                Ok(vec![Effect::FetchOllamaChat(prompt)])
            }
            Action::SetOllamaModel(model) => {
                self.ollama_model = model.clone();
                self.push_output(format!("Direct Ollama model set to {}", model));
                self.set_status(format!("Ollama model: {}", model), false);
                Ok(Vec::new())
            }
            Action::AddOutputs(lines) => {
                for line in lines {
                    self.push_output(line);
                }
                Ok(Vec::new())
            }
            Action::ClearOutput => {
                self.output_lines.clear();
                self.output_scroll = 0;
                self.push_output("Output cleared.");
                self.set_status("Output cleared", false);
                Ok(Vec::new())
            }
            Action::ErrorMessage(message) => {
                self.push_output(message.clone());
                self.set_status(message, true);
                Ok(Vec::new())
            }
            Action::SetTheme(theme) => {
                self.theme = theme;
                self.push_output(format!("Theme switched to {}", theme.label()));
                self.set_status(format!("Theme: {}", theme.label()), false);
                Ok(Vec::new())
            }
            Action::PreviewIntent(preview) => {
                self.intent_preview = Some(preview);
                self.set_status("Intent preview updated", false);
                Ok(Vec::new())
            }
            Action::SetFocus(focus) => {
                self.focus = focus;
                Ok(Vec::new())
            }
        }
    }

    pub fn selected_menu_item(&self) -> MenuItem {
        MenuItem::ALL[self.selected_menu]
    }

    pub fn selected_run_summary(&self) -> Option<&RunSummary> {
        self.snapshot.runs.get(self.highlighted_run)
    }

    pub fn input_prompt(&self) -> &str {
        match self.mode {
            Mode::Command => match self.input_context {
                InputContext::CommandPalette => "Command >",
                InputContext::SetTarget => "Set Target >",
                InputContext::SetWorkflow => "Set Workflow >",
                InputContext::SetTheme => "Set Theme >",
            },
            Mode::Nlp => "Ask Chimera >",
            _ => "Ready >",
        }
    }

    pub fn input_hint(&self) -> &'static str {
        match self.mode {
            Mode::Command => match self.input_context {
                InputContext::CommandPalette => {
                    "Examples: models | chat hello | set ollama model whiterabbitneo-13b"
                }
                InputContext::SetTarget => {
                    "Examples: 10.0.0.8 | example.com | https://target.local"
                }
                InputContext::SetWorkflow => "Examples: quick | standard | full | custom",
                InputContext::SetTheme => "Examples: matrix | red | blue",
            },
            Mode::Nlp => "Examples: set the target to example.com and show the next step",
            _ => "Enter select  : command  / ask-ai  ? help  Tab switch  q back/quit",
        }
    }

    pub fn command_suggestions(&self) -> Vec<String> {
        if self.mode != Mode::Command {
            return Vec::new();
        }
        match self.input_context {
            InputContext::CommandPalette => suggestions(&self.input),
            InputContext::SetTarget => vec![
                "example.com".to_string(),
                "10.0.0.8".to_string(),
                "https://juice-shop.local".to_string(),
            ],
            InputContext::SetWorkflow => vec![
                "quick".to_string(),
                "standard".to_string(),
                "full".to_string(),
                "custom".to_string(),
            ],
            InputContext::SetTheme => {
                vec!["matrix".to_string(), "red".to_string(), "blue".to_string()]
            }
        }
    }

    pub fn context_lines(&self) -> Vec<String> {
        if self.run_is_active() {
            let findings = self.snapshot.findings.len();
            let chains = self
                .snapshot
                .selected_run
                .as_ref()
                .map(|run| stat_u64(&run.stats, "exploit_chains"))
                .unwrap_or(0);
            let phase = self
                .snapshot
                .selected_run
                .as_ref()
                .and_then(|run| run.status.clone())
                .or_else(|| {
                    self.snapshot
                        .status
                        .active_run
                        .as_ref()
                        .and_then(|run| run.phase.clone())
                })
                .unwrap_or_else(|| "running".to_string());
            let latest_task = self
                .latest_task_summary()
                .unwrap_or_else(|| "waiting for task telemetry".to_string());
            let latest_action = self
                .latest_action_summary()
                .unwrap_or_else(|| "no recent operator events".to_string());
            let latest_finding = self
                .snapshot
                .findings
                .first()
                .map(|finding| format!("[{}] {}", severity_badge(&finding.severity), finding.title))
                .unwrap_or_else(|| "none yet".to_string());

            return vec![
                format!("Target: {}", self.target.as_deref().unwrap_or("not set")),
                format!("Workflow: {}", self.workflow.label()),
                format!("Pipeline: {}", self.pipeline),
                format!("Program: {}", self.program.as_deref().unwrap_or("unset")),
                String::new(),
                format!(
                    "Active Run: {}",
                    self.selected_run_id.as_deref().unwrap_or("none")
                ),
                format!("Phase: {}", phase),
                format!("Findings: {} | Chains: {}", findings, chains),
                String::new(),
                "Latest Task".to_string(),
                latest_task,
                String::new(),
                "Latest Action".to_string(),
                latest_action,
                String::new(),
                "Latest Finding".to_string(),
                latest_finding,
            ];
        }

        let mut lines = vec![
            format!("Target: {}", self.target.as_deref().unwrap_or("not set")),
            format!("Workflow: {}", self.workflow.label()),
            format!("Pipeline: {}", self.pipeline),
            format!("Program: {}", self.program.as_deref().unwrap_or("unset")),
            format!("Connection: {}", self.connection_label()),
            format!("Ollama: {}", self.ollama_base),
            format!("Ollama Model: {}", self.ollama_model),
            format!(
                "Selected Run: {}",
                self.selected_run_id.as_deref().unwrap_or("none")
            ),
            format!("Last Action: {}", self.status.text),
            String::new(),
            format!("Menu: {}", self.selected_menu_item().title()),
            self.selected_menu_item().summary().to_string(),
            String::new(),
            "Suggested next steps:".to_string(),
        ];

        for item in self.primary_suggestions() {
            lines.push(format!("- {}", item));
        }

        if let Some(preview) = self.intent_preview.as_ref() {
            lines.push(String::new());
            lines.push(format!("Intent: {}", preview.label));
            lines.push(preview.summary.clone());
            for (label, value) in preview.entities.iter().take(2) {
                if !value.is_empty() {
                    lines.push(format!("{}: {}", label, value));
                }
            }
        }

        lines
    }

    pub fn footer_hint(&self) -> &'static str {
        if self.mode == Mode::Normal {
            "Enter select  |  : command  |  / ask-ai  |  ? help  |  Tab switch  |  q back/quit"
        } else {
            "Enter submit  |  Esc cancel  |  Up/Down history  |  ? help"
        }
    }

    pub fn connection_label(&self) -> &'static str {
        if self.snapshot.api_error.is_some() {
            "Degraded"
        } else {
            "Connected"
        }
    }

    pub fn run_is_active(&self) -> bool {
        if let Some(status) = self
            .snapshot
            .selected_run
            .as_ref()
            .and_then(|run| run.status.as_deref())
        {
            return !matches!(status, "completed" | "failed" | "cancelled");
        }
        self.snapshot.status.active_run.is_some()
    }

    pub fn append_findings_preview(&mut self, run_id: &str, findings: &[FindingSummary]) {
        self.push_output(format!("{} findings for {}", findings.len(), run_id));
        if findings.is_empty() {
            self.push_output("No findings found for the selected run.");
            return;
        }
        for item in findings.iter().take(5) {
            self.push_output(format!(
                "[{}] {} ({:.2})",
                item.severity.to_uppercase(),
                item.title,
                item.confidence
            ));
        }
    }

    pub fn push_output(&mut self, line: impl Into<String>) {
        self.output_lines.push(line.into());
        if self.output_lines.len() > 240 {
            let drain = self.output_lines.len().saturating_sub(240);
            self.output_lines.drain(0..drain);
        }
        self.scroll_to_bottom();
    }

    pub fn set_status(&mut self, text: impl Into<String>, error: bool) {
        self.status = AppStatus {
            text: text.into(),
            error,
        };
    }

    fn move_selection(&mut self, delta: isize) -> Result<Vec<Effect>> {
        if self.mode != Mode::Normal {
            return Ok(Vec::new());
        }

        match self.focus {
            FocusedPane::Menu => {
                self.selected_menu = wrapped_index(self.selected_menu, MenuItem::ALL.len(), delta);
                self.set_status(self.selected_menu_item().title(), false);
            }
            FocusedPane::Main => {
                if !self.snapshot.runs.is_empty() {
                    self.highlighted_run =
                        wrapped_index(self.highlighted_run, self.snapshot.runs.len(), delta);
                    if let Some(run) = self.selected_run_summary() {
                        self.set_status(format!("Run {}", run.run_id), false);
                    }
                }
            }
            FocusedPane::Output => {
                let max_offset = self.output_lines.len().saturating_sub(1);
                self.output_scroll = if delta.is_negative() {
                    self.output_scroll.saturating_sub(delta.unsigned_abs())
                } else {
                    (self.output_scroll + delta as usize).min(max_offset)
                };
            }
            FocusedPane::Input => {}
        }
        Ok(Vec::new())
    }

    fn select_focused_item(&mut self) -> Result<Vec<Effect>> {
        if self.mode != Mode::Normal {
            return Ok(Vec::new());
        }

        match self.focus {
            FocusedPane::Menu => match self.selected_menu_item() {
                MenuItem::SetTarget => {
                    self.update(Action::EnterCommandMode(Some(InputContext::SetTarget)))
                }
                MenuItem::ChooseWorkflow => {
                    self.update(Action::EnterCommandMode(Some(InputContext::SetWorkflow)))
                }
                MenuItem::RunWorkflow => self.update(Action::LaunchScan),
                MenuItem::AskAi => self.update(Action::EnterNlpMode),
                MenuItem::ViewOutput => self.update(Action::SetFocus(FocusedPane::Output)),
                MenuItem::Logs => self.update(Action::ShowLogs),
                MenuItem::Help => self.update(Action::ShowHelp),
                MenuItem::Settings => {
                    self.update(Action::EnterCommandMode(Some(InputContext::SetTheme)))
                }
                MenuItem::Exit => self.update(Action::Quit),
            },
            FocusedPane::Main => {
                if let Some(run) = self.selected_run_summary() {
                    return self.update(Action::SelectRun(run.run_id.clone()));
                }
                Ok(Vec::new())
            }
            FocusedPane::Output => Ok(Vec::new()),
            FocusedPane::Input => Ok(Vec::new()),
        }
    }

    fn submit_input(&mut self) -> Result<Vec<Effect>> {
        let submitted = self.input.trim().to_string();
        if submitted.is_empty() {
            return self.update(Action::ExitInputMode);
        }

        self.command_history.push(submitted.clone());
        if self.command_history.len() > 100 {
            let drain = self.command_history.len().saturating_sub(100);
            self.command_history.drain(0..drain);
        }
        self.history_index = None;

        let mode = self.mode;
        let input_context = self.input_context;
        self.mode = Mode::Normal;
        self.focus = self.previous_focus;
        self.input.clear();

        match mode {
            Mode::Command => match input_context {
                InputContext::CommandPalette => {
                    self.push_output(format!(": {}", submitted));
                    let actions = parse_command(&submitted)?;
                    let mut effects = Vec::new();
                    for action in actions {
                        effects.extend(self.update(action)?);
                    }
                    Ok(effects)
                }
                InputContext::SetTarget => self.update(Action::SetTarget(submitted)),
                InputContext::SetWorkflow => {
                    if let Some(workflow) = WorkflowProfile::parse(&submitted) {
                        self.update(Action::SetWorkflow(workflow))
                    } else {
                        self.update(Action::ErrorMessage(
                            "workflow must be quick, standard, full, or custom".to_string(),
                        ))
                    }
                }
                InputContext::SetTheme => {
                    if let Some(theme) = ThemeName::parse(&submitted) {
                        self.update(Action::SetTheme(theme))
                    } else {
                        self.update(Action::ErrorMessage(
                            "theme must be matrix, red, or blue".to_string(),
                        ))
                    }
                }
            },
            Mode::Nlp => {
                self.push_output(format!("/ {}", submitted));
                self.set_status("Resolving NLP request", false);
                Ok(vec![Effect::InterpretNlp(submitted)])
            }
            _ => Ok(Vec::new()),
        }
    }

    fn history_prev(&mut self) {
        if self.command_history.is_empty() {
            return;
        }
        let next = match self.history_index {
            Some(index) => index.saturating_sub(1),
            None => self.command_history.len().saturating_sub(1),
        };
        self.history_index = Some(next);
        self.input = self.command_history[next].clone();
    }

    fn history_next(&mut self) {
        let Some(index) = self.history_index else {
            return;
        };
        if index + 1 >= self.command_history.len() {
            self.history_index = None;
            self.input.clear();
            return;
        }
        self.history_index = Some(index + 1);
        self.input = self.command_history[index + 1].clone();
    }

    fn primary_suggestions(&self) -> Vec<String> {
        if self.target.is_none() {
            return vec![
                "Set a target from the menu or with :set target example.com".to_string(),
                "Press / and ask what target format Chimera expects".to_string(),
                "Use :show runs to inspect the latest activity".to_string(),
            ];
        }

        vec![
            format!("Run the {} workflow", self.workflow.label()),
            "Review the selected run telemetry".to_string(),
            "Ask AI for the next recommended step".to_string(),
        ]
    }

    fn scroll_to_bottom(&mut self) {
        self.output_scroll = self.output_lines.len().saturating_sub(1);
    }

    fn append_live_snapshot_changes(
        &mut self,
        previous_snapshot: &ConsoleSnapshot,
        previous_selected_run_id: Option<&str>,
    ) {
        let current_run_id = self.snapshot.selected_run_id.as_deref();
        let new_events = if current_run_id != previous_selected_run_id {
            if self.run_is_active() {
                self.snapshot
                    .events
                    .iter()
                    .rev()
                    .filter(|event| is_operator_relevant_event(event))
                    .take(6)
                    .cloned()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        } else {
            diff_events(&previous_snapshot.events, &self.snapshot.events)
                .into_iter()
                .filter(|event| is_operator_relevant_event(event))
                .collect::<Vec<_>>()
        };

        for event in new_events {
            for line in expand_event_lines(&event) {
                self.push_output(line);
            }
        }
    }

    fn latest_task_summary(&self) -> Option<String> {
        self.snapshot.events.iter().rev().find_map(|raw| {
            let val: Value = serde_json::from_str(raw).ok()?;
            let event_type = val["event_type"].as_str()?;
            let payload = &val["payload"];
            match event_type {
                "task_executing" => {
                    let adapter = payload["adapter"].as_str().unwrap_or("?");
                    let target = payload["target"].as_str().unwrap_or("");
                    Some(format!("{adapter} -> {target}"))
                }
                "task_started" | "task_finished" => payload["tool"]
                    .as_str()
                    .or(payload["adapter"].as_str())
                    .map(|tool| tool.to_string()),
                "task_failed" => payload["adapter"]
                    .as_str()
                    .map(|adapter| format!("{adapter} failed")),
                _ => None,
            }
        })
    }

    fn latest_action_summary(&self) -> Option<String> {
        self.snapshot
            .events
            .iter()
            .rev()
            .find(|raw| is_operator_relevant_event(raw))
            .map(|raw| format_event_for_output(raw))
    }

    pub fn help_lines(&self) -> Vec<String> {
        let mut lines = vec![
            "Modes".to_string(),
            "NORMAL   j/k or arrows move  |  Enter select  |  Tab switch panes".to_string(),
            "COMMAND  : exact commands like set target example.com".to_string(),
            "NLP      / model-backed actions like explain this module".to_string(),
            String::new(),
            "Examples".to_string(),
        ];
        lines.extend(command_help().iter().map(|line| line.to_string()));
        lines.push(String::new());
        lines.push("Esc or q closes help.".to_string());
        lines
    }
}

fn wrapped_index(current: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    if delta.is_negative() {
        current.checked_sub(delta.unsigned_abs()).unwrap_or(len - 1)
    } else {
        (current + delta as usize) % len
    }
}

fn severity_badge(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => "CRIT",
        "high" => "HIGH",
        "medium" => "MED",
        "low" => "LOW",
        _ => "INFO",
    }
}

fn diff_events(previous: &[String], current: &[String]) -> Vec<String> {
    if previous.is_empty() {
        return current.to_vec();
    }
    if current.starts_with(previous) {
        return current[previous.len()..].to_vec();
    }
    if let Some(last_seen) = previous.last() {
        if let Some(index) = current.iter().rposition(|item| item == last_seen) {
            return current[index + 1..].to_vec();
        }
    }
    current
        .iter()
        .rev()
        .take(4)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn is_operator_relevant_event(raw: &str) -> bool {
    let Ok(val) = serde_json::from_str::<Value>(raw) else {
        return true;
    };
    matches!(
        val["event_type"].as_str().unwrap_or_default(),
        "task_started"
            | "task_executing"
            | "cmd_started"
            | "cmd_finished"
            | "stdout_chunk"
            | "task_failed"
            | "task_finished"
            | "artifact_saved"
            | "sink_error"
            | "execution_phase_started"
            | "execution_phase_completed"
            | "run_failed"
            | "run_completed"
            | "shannon_oracle"
            | "ai_query_sent"
            | "ai_analysis"
    )
}

/// Like `format_event_for_output` but may expand a single event into multiple lines
/// (e.g. `stdout_chunk` carries an array of output lines).
fn expand_event_lines(raw: &str) -> Vec<String> {
    let Ok(val) = serde_json::from_str::<Value>(raw) else {
        return vec![raw.to_string()];
    };
    let event_type = val["event_type"].as_str().unwrap_or("event");
    let payload = &val["payload"];

    match event_type {
        "stdout_chunk" => {
            let cmd = payload["command"].as_str().unwrap_or("cmd");
            payload["lines"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(|line| format!("[tool] {cmd}: {line}"))
                        .collect()
                })
                .unwrap_or_default()
        }
        "ai_query_sent" => {
            let excerpt = payload["query_excerpt"].as_str().unwrap_or("…");
            let short = truncate(excerpt, 120);
            vec![format!("[ai] Sending to AI: {short}")]
        }
        "ai_analysis" => {
            let count = payload["findings_count"].as_u64().unwrap_or(0);
            let titles = payload["finding_titles"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let line = if count == 0 {
                "[ai] AI analysis complete — no findings".to_string()
            } else if titles.is_empty() {
                format!("[ai] AI found {count} finding(s)")
            } else {
                format!("[ai] AI found {count}: {titles}")
            };
            vec![line]
        }
        _ => vec![format_event_for_output(raw)],
    }
}

fn format_event_for_output(raw: &str) -> String {
    let Ok(val) = serde_json::from_str::<Value>(raw) else {
        return raw.to_string();
    };
    let event_type = val["event_type"].as_str().unwrap_or("event");
    let payload = &val["payload"];

    match event_type {
        "task_started" => {
            let tool = payload["tool"].as_str().unwrap_or("?");
            let task_id = payload["task_id"].as_str().unwrap_or("task");
            format!("[*] {tool} started ({task_id})")
        }
        "task_executing" => {
            let adapter = payload["adapter"].as_str().unwrap_or("?");
            let target = payload["target"].as_str().unwrap_or("");
            format!("[*] {adapter} -> {target}")
        }
        "cmd_started" => {
            let command = payload["command"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| item.as_str())
                        .take(12)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_else(|| "?".to_string());
            format!("[cmd] {command}")
        }
        "cmd_finished" => {
            let returncode = payload["returncode"].as_i64().unwrap_or_default();
            if returncode == 0 {
                format!("[+] command completed (rc={returncode})")
            } else {
                format!("[!] command exited non-zero (rc={returncode})")
            }
        }
        "task_failed" => {
            let adapter = payload["adapter"].as_str().unwrap_or("?");
            let err = payload["error"].as_str().unwrap_or("unknown error");
            let short = err.lines().next().unwrap_or(err);
            format!("[x] {adapter} failed: {}", truncate(short, 96))
        }
        "task_finished" => {
            let tool = payload["tool"]
                .as_str()
                .or(payload["adapter"].as_str())
                .unwrap_or("?");
            format!("[+] {tool} completed")
        }
        "artifact_saved" => {
            if let Some(stream) = payload["stream"].as_str() {
                let path = payload["path"].as_str().map(short_path).unwrap_or_default();
                format!("[artifact] {stream} captured -> {path}")
            } else {
                let artifact_type = payload["artifact_type"]
                    .as_str()
                    .or(payload["tool"].as_str())
                    .unwrap_or("artifact");
                let path = payload["path"].as_str().map(short_path).unwrap_or_default();
                format!("[artifact] {artifact_type} saved -> {path}")
            }
        }
        "sink_error" => {
            let message = payload["message"].as_str().unwrap_or("unknown sink error");
            format!("[!] sink error: {}", truncate(message, 96))
        }
        "execution_phase_started" => {
            let message = payload["message"].as_str().unwrap_or("execution started");
            format!("[*] {message}")
        }
        "execution_phase_completed" | "run_completed" => "[+] run complete".to_string(),
        "run_failed" => {
            let tasks = payload["failed_tasks"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| item.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            format!("[x] run failed: {tasks}")
        }
        "shannon_oracle" => "[ai] shannon oracle response received".to_string(),
        other if other.contains("oracle") || other.contains("agent") => {
            format!("[ai] {other}")
        }
        _ => format!("[*] {event_type}"),
    }
}

fn short_path(path: &str) -> String {
    let parts = path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let keep = parts.len().min(3);
    parts[parts.len().saturating_sub(keep)..].join("/")
}

fn truncate(value: &str, width: usize) -> String {
    if value.len() <= width {
        return value.to_string();
    }
    format!("{}...", &value[..width.saturating_sub(3)])
}
