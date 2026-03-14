# Chimera Bug Bounty AI Penetration Testing Suite

## Overview

Chimera is a modular penetration testing orchestration system that runs security tools (adapters) against defined scopes. It supports both "fixture" (mock/testing) and "live" (real execution) modes.

## Architecture

### Core Components

1. **Orchestrator** (`chimera_core/orchestrator.py`)
   - Creates and manages jobs
   - Coordinates the full testing pipeline
   - Handles scope validation, planning, execution, and results analysis

2. **Runtime** (`chimera_core/runtime.py`)
   - Executes commands with safety enforcement
   - Validates scope and rate limits
   - Manages subprocess execution and output capture

3. **Adapters** (`chimera_core/adapters/`)
   - **Strix**: Web application testing
   - **Autoswagger**: API endpoint discovery and testing
   - **Shannon**: Verification and advanced testing
   - **NetUtils**: Network utilities
   - Each adapter can run in fixture or live mode

4. **API** (`chimera_core/api/`)
   - FastAPI backend exposing REST endpoints
   - Manages runs and provides streaming events
   - Serves artifacts and findings

5. **UI** (`chimera-ui/launcher.py`)
   - Tkinter-based GUI for managing scans
   - Provides console, findings, artifacts, and replay/diff views
   - Handles live mode authorization

## Configuration

### Environment Variables (.env)

The `.env` file in the project root contains:

```env
# Supabase Database (auto-enabled if both vars present)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key

# API Keys
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-proj-...
OPENROUTER_API_KEY=sk-or-v1-...
SERPAPI_API_KEY=...
FIRECRAWL_API_KEY=...

# HackerOne Integration
H1_TOKEN_ID=your-token-id
H1_TOKEN_VALUE=your-token-value

# Optional: LangSmith Tracing
LANGSMITH_TRACING=true
LANGSMITH_API_KEY=lsv2_sk_...
LANGSMITH_PROJECT=Decepticon
```

### Scope Configuration (scope.yml)

Define your testing scope:

```yaml
allowlist:
  - "https://crypto.com"
  - "https://crypto.com/nft"
  - "https://*.crypto.com"

denylist:
  - "*.thirdparty.com"

auth_notes: |
  - Include header: X-Hackerone: rxla

rate_limits:
  requests_per_second: 1
  concurrency: 1

allowed_methods:
  - "GET"
  - "HEAD"
```

## Running the System

### Using Docker Compose (Recommended)

1. **Start the services:**
   ```bash
   docker-compose up -d
   ```

2. **Check logs:**
   ```bash
   docker-compose logs -f
   ```

3. **Stop services:**
   ```bash
   docker-compose down
   ```

### Service Endpoints

- **API**: http://localhost:8000/v1
- **API Health**: http://localhost:8000/v1/health
- **UI**: Launches automatically (check chimera-ui logs)

### Artifacts Location

- **Host**: `./kali_data/artifacts/`
- **Container**: `/artifacts/`

Each run creates a directory: `/artifacts/{run_id}/`

## Operating Modes

### Fixture Mode (Safe/Testing)

- **Purpose**: Testing without making real network requests
- **Behavior**: Returns mock data from fixture files
- **Use Case**: Development, CI/CD, testing changes
- **Default**: Yes (for safety)

### Live Mode (Real Execution)

- **Purpose**: Real penetration testing
- **Behavior**: Executes actual tools against targets
- **Requirements**:
  - Check "Enable Live Mode" in UI
  - Check "I authorize live execution"
  - Type "I UNDERSTAND" in confirmation field
  - Confirm dialog prompt
- **Safety**: Enforces scope, rate limits, and timeouts

## Using the UI

### 1. Runs Tab
- View run history
- Start new scans
- Select runs for review
- **Workflow**:
  1. Paste scope YAML
  2. Configure settings (workers, rate limits, timeouts)
  3. Select mode (Fixture/Live)
  4. Generate plan (review what will execute)
  5. Submit run

### 2. Console Tab
- Stream real-time events
- Monitor tool execution
- View status updates
- Pause/resume streaming

### 3. Findings Tab
- View discovered vulnerabilities
- Filter by severity, tool, classification
- Search findings
- Export results

### 4. Replay & Diff Tab
- Compare two runs
- See what changed (new/removed/modified findings)
- Track improvements over time

### 5. Artifacts Tab
- Browse generated files
- View reports, logs, raw outputs
- Access tool-specific artifacts

### 6. Settings Tab
- Configure API URL
- Set artifacts directory
- Adjust execution parameters

## Workflow Visibility

### Event Streaming

The system emits comprehensive events during execution:

```json
{
  "event_type": "task_started",
  "payload": {
    "run_id": "uuid",
    "task_id": "strix-scan-0",
    "adapter": "strix",
    "target": "https://example.com"
  }
}
```

**Event Types:**
- `run_created`: Run initialized
- `scope_validated`: Scope checked
- `plan_created`: Execution plan generated
- `task_started`: Tool adapter starting
- `cmd_started`: Command execution beginning
- `cmd_finished`: Command completed
- `artifact_saved`: File written
- `task_finished`: Tool adapter done
- `finding_created`: Vulnerability discovered
- `run_finished`: Complete

### Monitoring Live Runs

1. **Via UI Console**: Real-time streaming
2. **Via API**: GET `/v1/runs/{run_id}/events?tail=true`
3. **Via CLI**: `python -m chimera_core events tail --run {run_id}`
4. **Via Logs**: `docker-compose logs -f chimera-core`

## Troubleshooting

### Issue: Tasks completing instantly, no real execution

**Cause**: Running in fixture mode instead of live mode

**Fix**:
- Ensure "Live Mode" is enabled in UI
- Complete authorization steps
- Verify mode shows "LIVE" in status banner

### Issue: Supabase errors

**Cause**: Environment variables not loaded or incorrect

**Fix**:
1. Verify `.env` file exists in project root
2. Check `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are set
3. Restart containers: `docker-compose down && docker-compose up -d`

### Issue: xdg-open errors (WSL/Headless)

**Fixed**: System now shows file paths instead of trying to open them

### Issue: 404 errors on replay/diff

**Fixed**: System now resolves both job_id and run_id properly

### Issue: No findings generated

**Possible Causes:**
1. Running in fixture mode with no fixture data
2. Targets out of scope
3. Tools not finding vulnerabilities (expected in many cases)
4. Rate limits too restrictive

## API Usage

### Create a Run

```bash
curl -X POST http://localhost:8000/v1/runs \
  -H "Content-Type: application/json" \
  -d '{
    "scope_text": "allowlist:\n  - https://example.com",
    "live": false,
    "max_workers": 2,
    "rate_limit_rps": 10,
    "per_task_timeout_s": 60,
    "program_name": "Example Program"
  }'
```

### Stream Events

```bash
curl http://localhost:8000/v1/runs/{run_id}/events?tail=true
```

### Get Findings

```bash
curl http://localhost:8000/v1/runs/{run_id}/findings
```

## Development

### Adding a New Adapter

1. Create adapter class in `chimera_core/adapters/your_tool_adapter.py`
2. Inherit from `AdapterBase`
3. Implement:
   - `__init__`: Initialize with runtime and options
   - `validate_targets`: Ensure targets are in scope
   - `build_command`: Construct tool command
   - `run`: Execute (check live flag)
   - `normalize`: Convert output to findings
4. Register in `runner.py` `_adapter_for_task` method
5. Update planner to include your tool

### Testing Changes

1. **Unit Tests**: `pytest chimera/chimera-core/tests/`
2. **Fixture Mode**: Test without real execution
3. **Live Mode**: Test against controlled targets only

## Security Considerations

### Live Mode Safety

- **Scope Enforcement**: All targets validated against allowlist
- **Rate Limiting**: Prevents overwhelming targets
- **Timeouts**: Prevents runaway execution
- **Private IP Blocking**: Prevents scanning internal networks (configurable)
- **Command Validation**: Blocks injection attempts
- **Authorization Required**: Multi-step confirmation for live mode

### Responsible Usage

- Only test systems you own or have explicit permission to test
- Respect rate limits and scope
- Review findings before reporting to bug bounty programs
- Follow program-specific rules and guidelines

## Key Files Reference

```
kali-docker/
├── .env                          # Environment variables
├── scope.yml                     # Target scope definition
├── docker-compose.yml            # Service orchestration
├── chimera/
│   ├── chimera-core/
│   │   └── chimera_core/
│   │       ├── orchestrator.py   # Main coordinator
│   │       ├── runtime.py        # Command executor
│   │       ├── runner.py         # Task runner
│   │       ├── adapters/         # Tool integrations
│   │       ├── api/              # REST API
│   │       └── config.py         # Configuration
│   └── chimera-ui/
│       └── launcher.py           # GUI application
├── tools/                        # Security tools
│   ├── strix/
│   ├── autoswagger/
│   └── shannon/
└── kali_data/
    └── artifacts/                # Output files
```

## Recent Fixes (2026-01-04)

1. **Live Mode**: Fixed mode not being set from API payload
2. **Supabase**: Auto-enabled when env vars present
3. **Artifacts UI**: Graceful handling in headless environments
4. **Replay/Diff**: Improved ID resolution (job_id vs run_id)
5. **Config Loading**: Better environment variable integration

## Support

For issues or questions:
1. Check logs: `docker-compose logs chimera-core chimera-ui`
2. Review events: Check Console tab in UI
3. Verify configuration: `.env` and `scope.yml`
4. Check artifacts: Look for error files in run directories

## Next Steps

1. Enable live mode and run a test scan
2. Review findings and artifacts
3. Compare multiple runs using Replay & Diff
4. Configure Supabase for persistent storage
5. Integrate with bug bounty platforms (HackerOne)
