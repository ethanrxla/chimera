use crate::app::{ConsoleSnapshot, FocusedPane, InputContext, WorkflowProfile};
use crate::nlp::IntentPreview;
use crate::theme::ThemeName;

#[derive(Debug, Clone)]
pub enum Action {
    Tick,
    Refresh,
    SnapshotLoaded(ConsoleSnapshot),
    SnapshotFailed(String),
    Quit,
    Back,
    ShowHelp,
    HideHelp,
    FocusNext,
    FocusPrev,
    MoveUp,
    MoveDown,
    Select,
    EnterCommandMode(Option<InputContext>),
    EnterNlpMode,
    ExitInputMode,
    PushInput(char),
    PopInput,
    HistoryPrev,
    HistoryNext,
    SubmitInput,
    SetTarget(String),
    StageScopeText(String),
    SetWorkflow(WorkflowProfile),
    SetPipeline(String),
    SetProgram(String),
    ClearProgram,
    ClearScope,
    SelectRun(String),
    ShowStatus,
    ShowRuns,
    ShowFindings(Option<String>),
    ShowLogs,
    LaunchScan,
    AskModel(String),
    AddOutputs(Vec<String>),
    ClearOutput,
    ErrorMessage(String),
    SetTheme(ThemeName),
    PreviewIntent(IntentPreview),
    SetFocus(FocusedPane),
}

#[derive(Debug, Clone)]
pub enum Effect {
    RefreshSnapshot,
    FetchFindings(Option<String>),
    FetchOracle(String),
    InterpretNlp(String),
    LaunchScan,
}
