# Phase 1 Audit (Chimera migration)

## Build/run instructions discovered
- D:\whitehat\README.md: install Python deps with `pip install -r requirements.txt` and run `python integrate_hackingtool.py`, `python awesome_hacking_browser.py`, and `python dataset_manager.py list`.
- D:\whitehat\README.md: use `python ml_cybersec_integration.py list-datasets` and training scripts such as `python train_cybersec_model.py`.
- D:\whitehat\whitehat-vscode-simple\README_STARGUARD.md: PowerShell launchers `launch_starguard_simple.ps1` and `launch_starguard_ide.ps1`.
- No Linux/Docker instructions were present; multiple scripts hard-code `D:/whitehat` paths.

## Entry points
GUI
- D:\whitehat\whitehat_launcher.py: Tkinter GUI launcher with navigation and theming (main() creates Tk and starts MatrixRain).
- D:\whitehat\awesome_hacking_browser.py: Tkinter GUI for Awesome-Hacking (loads README.md).

CLI
- D:\whitehat\dataset_manager.py: argparse CLI for dataset management.
- D:\whitehat\hacking_toolkit.py: menu-driven CLI wrapper over network tools.
- D:\whitehat\train_model.py, D:\whitehat\finetune_starcoder.py: training and fine-tuning scripts.

Services
- D:\whitehat\ai_model_server.py: Flask HTTP API for AI model inference.

## Inventory
| Component | Path | Status | Confidence | Evidence |
| --- | --- | --- | --- | --- |
| GUI shell launcher | D:\whitehat\whitehat_launcher.py | Partially working | High | Tkinter UI with sidebar/navigation; hard-coded `D:/whitehat` paths and calls to external scripts/models. |
| Awesome Hacking browser | D:\whitehat\awesome_hacking_browser.py | Partially working | Medium | Tkinter app parses Awesome-Hacking README; depends on `markdown` module and repo checkout. |
| AI model server | D:\whitehat\ai_model_server.py | Broken (Linux) | High | Imports `ai_agent` and uses `D:/whitehat` paths; requires heavy model deps and local weights. |
| AI agents | D:\whitehat\ai_agent.py | Partially working | Medium | Uses Torch/Transformers and absolute paths for model outputs and cache. |
| Dataset manager | D:\whitehat\dataset_manager.py | Partially working | Medium | Uses relative paths but depends on network downloads and pandas/requests. |
| Hacking toolkit CLI | D:\whitehat\hacking_toolkit.py | Placeholder | High | Menu options print "coming soon" for most categories. |
| VSCode fork launcher | D:\whitehat\whitehat-vscode-simple | Broken (Linux) | High | PowerShell-based Windows launchers and VSCode settings. |
| Model artifacts | D:\whitehat\model_outputs\* | Data only | Medium | Referenced by ai_agent/whitehat_launcher but not validated in this audit. |
| External repos | D:\whitehat\cybersec_repos\*, D:\whitehat\evilginx2 | Out-of-scope/unsafe | High | Contains password crackers, keyloggers, phishing tools, etc. |

## Dependencies map
Runtime/frameworks
- Python 3
- Tkinter (GUI)
- Flask + flask_cors (AI model server)
- Torch, Transformers, PEFT, Safetensors (model inference/fine-tuning)
- Requests, pandas, tqdm, markdown (dataset/tools utilities)

External services/tools
- Hugging Face and GitHub downloads (datasets)
- OS shell utilities (PowerShell scripts, `xdg-open`, `os.startfile`)
- Nmap and other external tools referenced by wrappers

## Build verification
- No build/run commands were executed in this environment (read-only sandbox + network restricted). Any "working" status is based on code inspection and entry point structure.
## Launcher refactor (Chimera)
- D:\whitehat\chimera-ui\launcher.py: Refactored to preserve OG visuals but removed eager model imports and Windows-only paths.
- Linux failures expected previously: absolute `D:/whitehat` paths and import-time model dependencies (`torch`, `transformers`) from `whitehat_launcher.py`.
- Profiling not executed in this environment; likely startup bottlenecks were model imports and preflight checks. These are now deferred/disabled.
