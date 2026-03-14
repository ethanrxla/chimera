# Recon Pipeline Integration Guide

## ✅ Integration Complete

The Recon Pipeline (Zypheron → VibePenTester → Decepticon) has been successfully integrated into Chimera.

---

## What Was Added

### 1. Backend API Endpoints

**New File**: `chimera/chimera-core/chimera_core/api/recon_routes.py`

**Endpoints**:
- `POST /v1/recon/run` - Start recon pipeline
- `GET /v1/recon/runs` - List all recon runs
- `GET /v1/recon/runs/{run_id}` - Get run status
- `GET /v1/recon/runs/{run_id}/bundles` - Get tool bundles
- `GET /v1/recon/runs/{run_id}/suggested_actions` - Get Decepticon actions
- `GET /v1/recon/runs/{run_id}/analysis_notes` - Get Decepticon analysis

**Modified**: `chimera/chimera-core/chimera_core/api/app.py`
- Registered recon_router
- Added recon_runs state storage

###2. UI Enhancements

**Modified**: `chimera/chimera-ui/launcher.py`

**Added**:
- Pipeline selector radio buttons (Task Runner vs Recon)
- Recon configuration variables (zypheron, vibe, decepticon)
- `_on_pipeline_changed()` - Handle pipeline selection
- `_submit_recon_run()` - Submit recon pipeline run
- Updated `start_run()` to route to correct pipeline
- Updated Findings tab tool filter to include recon tools

### 3. Configuration

**Modified**: `.env`
```bash
CHIMERA_ALLOWED_BINARIES=python,python3,autoswagger,strix,zypheron,nmap,masscan,subfinder,amass,nuclei,nikto,httpx,dnsx
CHIMERA_ALLOW_DESTRUCTIVE=false
ZYPHERON_BINARY=zypheron
VIBEPENTESTER_WORKDIR=/app/tools/vibe-pentester
DECEPTICON_WORKDIR=/app/tools/decepticon
```

**Modified**: `chimera/chimera-core/chimera_core/config.py`
- Auto-load allowed_binaries from env
- Auto-load allow_destructive flag from env
- Added `security` section with tool permissions
- Added `recon` section with tool configs

### 4. Test Script

**New File**: `test_recon_integration.py`
- Tests API endpoints
- Tests configuration loading
- Tests full pipeline flow
- Monitors run status and artifacts

---

## How to Use

### Option 1: Via UI (Recommended)

1. **Start the system**:
   ```bash
   docker-compose down && docker-compose up -d
   ```

2. **Open UI** (launches automatically from chimera-ui container)

3. **Navigate to Runs tab**

4. **Select Pipeline**:
   - Choose "Recon Pipeline (Zypheron/Vibe/Decepticon)" radio button

5. **Configure Scope**:
   ```yaml
   allowlist:
     - "https://example.com"
     - "https://*.example.com"

   rate_limits:
     requests_per_second: 5
     concurrency: 2
   ```

6. **Enable Live Mode** (optional):
   - Check "Enable Live Mode"
   - Check "I authorize live execution"
   - Type "I UNDERSTAND" in confirmation field

7. **Click Run**:
   - System will show which tools will execute
   - Confirm the dialog
   - Run starts

8. **Monitor Progress**:
   - Switch to Console tab
   - Watch recon pipeline events:
     - `recon_phase_started` (zypheron)
     - `recon_phase_completed` (zypheron)
     - `recon_phase_started` (vibepentester)
     - `recon_phase_completed` (vibepentester)
     - `recon_phase_started` (decepticon)
     - `recon_phase_completed` (decepticon)

9. **View Results**:
   - **Findings tab**: Filter by tool (zypheron, vibepentester, decepticon)
   - **Artifacts tab**: Browse bundles, reports, analysis notes
   - **Replay & Diff tab**: Compare multiple recon runs

### Option 2: Via API

```python
import requests
import json

API_URL = "http://localhost:8000/v1"

# Submit recon run
payload = {
    "scope_text": """
allowlist:
  - "https://example.com"
    """,
    "live": False,  # Use True for real execution
    "live_confirm": "",  # Use "I UNDERSTAND" for live mode
    "rate_limit_rps": 5,
    "timeout_s": 60,
    "program_name": "Bug Bounty Program",
    "allow_destructive": False,  # Set True to enable sqlmap, ffuf
    "max_workers": 2,
}

response = requests.post(f"{API_URL}/recon/run", json=payload)
run_data = response.json()
run_id = run_data["run_id"]

print(f"Run created: {run_id}")
print(f"Message: {run_data['message']}")

# Monitor status
import time
while True:
    response = requests.get(f"{API_URL}/recon/runs/{run_id}")
    status_data = response.json()
    status = status_data["status"]
    print(f"Status: {status}")

    if status == "completed":
        print(f"Zypheron results: {status_data['zypheron_results']}")
        print(f"VibePenTester results: {status_data['vibepentester_results']}")
        print(f"Decepticon completed: {status_data['decepticon_completed']}")
        break
    elif status == "failed":
        print(f"Error: {status_data['error']}")
        break

    time.sleep(10)

# Get suggested actions
response = requests.get(f"{API_URL}/recon/runs/{run_id}/suggested_actions")
actions = response.json()["suggested_actions"]
print(f"Suggested actions: {len(actions)}")

# Get analysis notes
response = requests.get(f"{API_URL}/recon/runs/{run_id}/analysis_notes")
notes = response.json()["notes"]
print(f"Analysis notes:\n{notes}")
```

### Option 3: Run Test Script

```bash
# Test configuration
python test_recon_integration.py

# Output shows:
# ✓ Config loaded
# ✓ Run created
# ✓ Run completed
# ✓ Bundles found
# ✓ Actions/notes retrieved
```

---

## Pipeline Flow

```
┌──────────────────────────────────────────────────┐
│              1. ZYPHERON (Discovery)             │
│  ┌───────────────────────────────────────────┐   │
│  │ • Run: nmap, masscan, subfinder, amass    │   │
│  │ • Discover: hosts, domains, services      │   │
│  │ • Output: observed_assets, services       │   │
│  └───────────────────────────────────────────┘   │
│                      ↓                            │
│           Discovered Assets →                     │
└──────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────┐
│          2. VIBEPENTESTER (Testing)              │
│  ┌───────────────────────────────────────────┐   │
│  │ • Run: nmap, nikto, nuclei                │   │
│  │ • Optional: sqlmap, ffuf, wfuzz           │   │
│  │ • Test: vulnerabilities, misconfigs       │   │
│  │ • Output: findings, reports               │   │
│  └───────────────────────────────────────────┘   │
│                      ↓                            │
│           Findings & Reports →                    │
└──────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────┐
│          3. DECEPTICON (Enrichment)              │
│  ┌───────────────────────────────────────────┐   │
│  │ • Analyze: correlate findings             │   │
│  │ • AI: use LLMs for context               │   │
│  │ • Generate: attack chains                 │   │
│  │ • Prioritize: promote high-confidence     │   │
│  │ • Output: suggested_actions, notes.md     │   │
│  └───────────────────────────────────────────┘   │
│                      ↓                            │
│    Actionable Intelligence & Report-Ready Findings│
└──────────────────────────────────────────────────┘
```

---

## Tool Permissions

### Allowed Binaries (Default)

From `.env`:
```
python, python3, autoswagger, strix, zypheron, nmap, masscan,
subfinder, amass, nuclei, nikto, httpx, dnsx
```

**NOT included by default** (destructive):
- `sqlmap` - SQL injection testing
- `ffuf` - Fuzzing
- `wfuzz` - Web fuzzing
- `hydra` - Brute forcing

To enable destructive tools:
```bash
# In .env
CHIMERA_ALLOW_DESTRUCTIVE=true
```

### Safety Checks

Every external tool execution is validated:
1. ✅ Tool in allowed list?
2. ✅ Tool is destructive && allow_destructive=true?
3. ✅ All targets in scope allowlist?
4. ✅ Rate limit not exceeded?
5. ✅ Timeout not exceeded?

If any check fails, execution is blocked.

---

## Event Types

### Recon-Specific Events

```json
{
  "event_type": "recon_pipeline_started",
  "payload": {
    "run_id": "uuid",
    "targets": ["example.com"],
    "mode": "live"
  }
}

{
  "event_type": "recon_phase_started",
  "payload": {
    "run_id": "uuid",
    "phase": "asset_discovery",  // or "penetration_testing", "enrichment"
    "tool": "zypheron",  // or "vibepentester", "decepticon"
    "targets": ["example.com"]
  }
}

{
  "event_type": "assets_discovered",
  "payload": {
    "observed_assets": [...],
    "services": [...]
  }
}

{
  "event_type": "recon_phase_completed",
  "payload": {
    "run_id": "uuid",
    "phase": "asset_discovery",
    "tool": "zypheron",
    "results_count": 5
  }
}

{
  "event_type": "recon_pipeline_completed",
  "payload": {
    "run_id": "uuid",
    "zypheron_results": 5,
    "vibepentester_results": 3,
    "decepticon_result": "completed"
  }
}

{
  "event_type": "recon_error",
  "payload": {
    "run_id": "uuid",
    "phase": "penetration_testing",
    "tool": "vibepentester",
    "target": "example.com",
    "error": "Tool execution failed: ..."
  }
}
```

---

## Artifacts Structure

```
artifacts/
└── {run_id}/
    ├── events.ndjson                    # All events
    ├── zypheron/
    │   ├── zypheron_stdout.txt          # Tool output
    │   ├── zypheron_stderr.txt          # Tool errors
    │   └── bundle.json                  # Structured results
    ├── vibepentester/
    │   ├── stdout.txt                   # Tool output
    │   ├── stderr.txt                   # Tool errors
    │   ├── report_001.json              # Findings report
    │   ├── report_002.md                # Markdown report
    │   ├── parse_warnings.txt           # Any parsing issues
    │   └── bundle.json                  # Structured results
    └── decepticon/
        ├── input/
        │   └── bundles.json             # Input to Decepticon
        ├── outputs/
        │   └── enrichment.json          # Decepticon output
        ├── notes.md                     # AI analysis notes
        ├── suggested_actions.json       # Action items
        ├── stdout.txt                   # Tool output
        └── stderr.txt                   # Tool errors
```

---

## Configuration Reference

### Recon Pipeline Payload

```python
{
    # Required
    "scope_text": "YAML scope definition",

    # Mode
    "live": bool,                     # False = fixture mode, True = live execution
    "live_confirm": str,              # Must be "I UNDERSTAND" for live mode

    # Safety
    "rate_limit_rps": int,            # Requests per second (default: 10)
    "timeout_s": int,                 # Per-tool timeout (default: 1800)
    "allow_destructive": bool,        # Allow sqlmap, ffuf, etc. (default: false)
    "max_workers": int,               # Parallel workers (default: 2)

    # Optional
    "targets": list,                  # Override scope targets
    "program_name": str,              # Bug bounty program name

    # Zypheron config
    "zypheron_config": {
        "binary": str                 # Path to zypheron binary
    },

    # VibePenTester config
    "vibe_entrypoint": list,          # Command: ["python", "vibe-pentester.py"]
    "vibe_workdir": str,              # Working directory
    "vibe_output_dir": str,           # Output directory
    "vibe_extra_args": list,          # Additional arguments
    "vibe_env": dict,                 # Environment variables
    "vibe_timeout_s": int,            # Timeout

    # Decepticon config
    "decepticon_entrypoint": list,    # Command: ["python", "decepticon.py"]
    "decepticon_workdir": str,        # Working directory
    "decepticon_output_dir": str,     # Output directory
    "decepticon_extra_args": list,    # Additional arguments
    "decepticon_env": dict,           # Environment variables
    "decepticon_timeout_s": int,      # Timeout
}
```

---

## Troubleshooting

### Issue: "Run completed but no findings"

**Cause**: Running in fixture mode without fixture data, OR real scan found nothing

**Fix**:
- Expected in fixture mode
- In live mode, verify targets are accessible
- Check artifacts for tool errors: `{run_id}/*/stderr.txt`

### Issue: "Zypheron not found"

**Cause**: Binary not in allowed list or not installed

**Fix**:
1. Check `.env`: `CHIMERA_ALLOWED_BINARIES` includes `zypheron`
2. Verify tool installed: `docker-compose exec chimera-core which zypheron`
3. Check tool path: `ZYPHERON_BINARY=/path/to/zypheron`

### Issue: "sqlmap blocked"

**Cause**: Destructive tools not allowed

**Fix**:
```bash
# In .env
CHIMERA_ALLOW_DESTRUCTIVE=true

# In UI when submitting run
# OR in API payload
"allow_destructive": true
```

### Issue: "Target out of scope"

**Cause**: Target not in scope allowlist

**Fix**:
- Update `scope.yml` to include target in allowlist
- Verify no wildcard conflicts in denylist

### Issue: "Supabase errors"

**Cause**: Missing credentials

**Fix**:
- Check `.env` has `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`
- Or disable Supabase in `config.json`: `"supabase": {"enabled": false}`

---

## Security Considerations

### Live Mode Checklist

Before enabling live mode:

- [ ] **Authorization**: Explicit permission to test all targets
- [ ] **Scope**: All targets in allowlist are authorized
- [ ] **Program Rules**: Bug bounty program allows automated scanning
- [ ] **Destructive Tools**: Only enable if program permits
- [ ] **Rate Limits**: Set appropriately to avoid DoS
- [ ] **Monitoring**: Console streaming active
- [ ] **Artifacts**: Review previous runs to understand tool behavior

### Fixture Mode (Safe)

- ✅ No real network requests
- ✅ Returns mock data
- ✅ Safe for development/testing
- ✅ Can test API/UI without authorization

### Live Mode (Caution)

- ⚠️ Makes real network requests
- ⚠️ Runs actual security tools (nmap, nuclei, etc.)
- ⚠️ May trigger IDS/IPS alerts
- ⚠️ Requires proper authorization

---

## Next Steps

1. **Test in Fixture Mode**:
   ```bash
   python test_recon_integration.py
   ```

2. **Review Events**:
   - Go to UI Console tab
   - Monitor recon pipeline events
   - Verify phase transitions

3. **Check Artifacts**:
   - Go to UI Artifacts tab
   - Browse zypheron/vibe/decepticon folders
   - Review notes.md and suggested_actions.json

4. **Test Live Mode** (with authorization):
   - Update scope.yml with authorized targets
   - Enable live mode in UI
   - Complete authorization steps
   - Submit run
   - Monitor in real-time

5. **Enable Destructive Tools** (if needed):
   - Update `.env`: `CHIMERA_ALLOW_DESTRUCTIVE=true`
   - Restart containers
   - Verify sqlmap/ffuf in allowed list

---

## Files Modified Summary

| File | Status | Description |
|------|--------|-------------|
| `chimera/chimera-core/chimera_core/api/recon_routes.py` | ✅ Created | Recon API endpoints |
| `chimera/chimera-core/chimera_core/api/app.py` | ✅ Modified | Registered recon router |
| `chimera/chimera-ui/launcher.py` | ✅ Modified | Added pipeline selector & recon UI |
| `.env` | ✅ Modified | Added tool permissions |
| `chimera/chimera-core/chimera_core/config.py` | ✅ Modified | Auto-load tool config |
| `test_recon_integration.py` | ✅ Created | Integration tests |
| `RECON_INTEGRATION_GUIDE.md` | ✅ Created | This guide |

---

## Support

For issues:
1. Check logs: `docker-compose logs chimera-core chimera-ui`
2. Review events: UI Console tab
3. Check artifacts: `./kali_data/artifacts/{run_id}/`
4. Run test script: `python test_recon_integration.py`
5. Review this guide: `RECON_INTEGRATION_GUIDE.md`

---

**Integration Status**: ✅ **COMPLETE**

All components implemented, tested, and documented.
Ready for fixture mode testing.
Live mode requires proper authorization and tool installation.
