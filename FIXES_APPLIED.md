# Fixes Applied - 2026-01-04

## Summary

All major issues have been identified and resolved. The system is now ready for live execution with proper workflow visibility and environment variable loading.

---

## 1. ✅ Live Mode / Fixture Mode Issue (CRITICAL FIX)

### Problem
- All runs were executing in fixture mode regardless of UI settings
- Tasks were completing instantly without real execution
- Events showed `"mode": "fixture"` even when live mode was selected

### Root Cause
- **Location**: `chimera/chimera-core/chimera_core/api/routes.py:486`
- Mode was hardcoded to `"safe"` instead of using the `live` parameter from the API request
- The UI was correctly sending `live=True`, but the backend ignored it

### Fix Applied
```python
# Before:
job = orchestrator.create_job_from_manifest(scope_manifest, mode="safe", scope_raw=scope_text)

# After:
job = orchestrator.create_job_from_manifest(scope_manifest, mode="live" if live else "safe", scope_raw=scope_text)
```

### Verification
1. Enable "Live Mode" in UI
2. Complete authorization steps
3. Submit run
4. Check Console tab - should see `"mode": "live"` in events
5. Tasks should take actual time to execute (not instant)

---

## 2. ✅ Environment Variables / Supabase Configuration

### Problem
- Supabase sink errors appearing: "Supabase enabled but missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY"
- `.env` file exists with correct values but wasn't being used properly
- Supabase was disabled by default in config

### Root Cause
- **Location**: `chimera/chimera-core/chimera_core/config.py`
- DEFAULT_CONFIG had `"supabase": {"enabled": False}`
- No logic to auto-enable when environment variables were present

### Fix Applied
1. **Modified config.py** to auto-detect and enable Supabase:
```python
def _get_default_config() -> Dict[str, Any]:
    """Generate default config with supabase auto-enabled if env vars are present."""
    supabase_enabled = bool(os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_SERVICE_ROLE_KEY"))

    return {
        ...
        "supabase": {
            "enabled": supabase_enabled,
        },
        ...
    }
```

2. **Updated load_config** to merge file config with environment-aware defaults

### Verification
1. Ensure `.env` file has `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`
2. Restart containers: `docker-compose down && docker-compose up -d`
3. Check logs - no more Supabase errors
4. Events should be saved to Supabase database

---

## 3. ✅ Artifacts / xdg-open Failures

### Problem
- `xdg-open` errors when trying to view artifacts
- System tried to open files with GUI tools in headless/WSL environment
- `Error: Unable to open {path}. Missing opener: xdg-open`

### Root Cause
- **Location**: `chimera/chimera-ui/launcher.py:92-101`
- No fallback for headless environments
- No detection of WSL/Docker environments

### Fix Applied
```python
def open_path(path: Path) -> None:
    """
    Open a path with the system's default opener.
    In headless/WSL environments, show the path instead.
    """
    # ... Windows handling ...

    opener = "open" if platform.system() == "Darwin" else "xdg-open"
    try:
        # Check if we're in a headless environment (WSL, Docker, no DISPLAY)
        if _is_wsl() or not os.getenv("DISPLAY"):
            messagebox.showinfo("Artifact Path",
                f"File location:\n{path}\n\nUse 'cat' or 'less' to view in terminal.")
            return
        subprocess.run([opener, str(path)], check=False)
    except FileNotFoundError:
        messagebox.showinfo("Artifact Path",
            f"File location:\n{path}\n\nOpener '{opener}' not found. Use terminal to view.")
```

### Verification
1. Click "Open" on any artifact in Artifacts tab
2. Should see dialog with file path instead of error
3. Can copy path and use terminal to view: `cat /path/to/artifact`

---

## 4. ✅ Replay/Diff 404 Errors (job_id vs run_id)

### Problem
- 404 errors when using Replay & Diff feature
- UI was passing IDs that the API couldn't find
- Confusion between job_id (returned immediately) and run_id (created async)

### Root Cause
- **Location**: `chimera/chimera-core/chimera_core/api/routes.py:333-342`
- The API returns `job.job_id` immediately when a run is created
- The actual `run_id` (used for artifacts) is generated later in background thread
- `_resolve_artifacts_dir` wasn't handling both ID types properly

### Fix Applied
1. **Enhanced `_resolve_artifacts_dir`** to resolve both job_id and run_id:
```python
def _resolve_artifacts_dir(request: Request, run_id: str) -> Optional[Path]:
    """
    Resolve artifacts directory for a given run_id or job_id.
    Handles both cases:
    - run_id is a job_id (stored in app.state.runs)
    - run_id is an actual run_id (stored on disk)
    """
    # First check if this is a job_id in app.state.runs
    run_info = request.app.state.runs.get(run_id)
    if run_info:
        # If we have the artifacts_dir, use it
        if run_info.get("artifacts_dir"):
            return Path(run_info["artifacts_dir"])
        # If we have the actual run_id, try to find it on disk
        if run_info.get("run_id"):
            actual_run_id = run_info["run_id"]
            artifacts_path = Path(request.app.state.artifacts_root) / actual_run_id
            if artifacts_path.exists():
                return artifacts_path

    # Try as a direct run_id on disk
    # ... (fallback logic)
```

2. **Clarified create_run response** to include both IDs:
```python
return JSONResponse({
    "run_id": job.job_id,  # This is actually a job_id
    "job_id": job.job_id,  # Also return as job_id for clarity
    "status": "created",
    ...
    "note": "Poll /runs/{job_id} to get actual run_id once background execution starts"
})
```

### Verification
1. Start two runs
2. Go to Replay & Diff tab
3. Select both runs
4. Should load and compare successfully - no 404 errors

---

## 5. ✅ Agentic Workflow Visibility

### Problem
- Limited visibility into what each tool/sub-tool was doing
- Hard to understand execution flow
- Events lacked context about mode and progress

### Improvements Applied

#### Enhanced Event Logging in Runner
**Location**: `chimera/chimera-core/chimera_core/runner.py`

Added:
- `task_executing` event with mode and detailed message
- `task_completed` event with findings/artifacts counts
- Mode information in all log events

```python
self.runtime.event_store.emit({
    "event_type": "task_executing",
    "payload": {
        "run_id": self.runtime.run_id,
        "task_id": task.task_id,
        "adapter": task.tool,
        "target": task.target,
        "mode": self.runtime.mode,
        "message": f"Executing {task.tool} against {task.target} in {self.runtime.mode} mode"
    }
})
```

#### Enhanced Orchestrator Events
**Location**: `chimera/chimera-core/chimera_core/orchestrator.py`

Added:
- `execution_phase_started` with task count and mode
- `execution_phase_completed` with completion summary

```python
sink.emit_event({
    "event_type": "execution_phase_started",
    "payload": {
        "run_id": run.run_id,
        "job_id": job_id,
        "mode": "live" if self.live else "fixture",
        "task_count": len(plan.tasks),
        "message": f"Starting execution of {len(plan.tasks)} tasks in {'LIVE' if self.live else 'FIXTURE'} mode"
    }
})
```

### Event Flow Example
```
1. run_created → Job initialized
2. scope_validated → Scope checked
3. plan_created → Execution plan generated (tasks: 3)
4. execution_phase_started → Starting 3 tasks in LIVE mode
5. task_started → strix-scan-0 starting
6. task_executing → Executing strix against https://crypto.com in live mode
7. cmd_started → Running command: python -m strix...
8. artifact_saved → Saved raw_output.json
9. cmd_finished → Command completed (returncode: 0)
10. task_completed → Task done (findings: 0, artifacts: 2)
11. task_finished → strix-scan-0 finished
... (repeat for other tasks)
12. execution_phase_completed → Completed 3 tasks
13. run_finished → Run complete
```

### Verification
1. Start a run (fixture or live mode)
2. Go to Console tab
3. Should see detailed execution flow with mode indicators
4. Each tool execution should show clear start/execute/complete events

---

## 6. ✅ Documentation

### Created Files

1. **SETUP_AND_OPERATION.md** - Comprehensive guide covering:
   - Architecture overview
   - Configuration (env vars, scope)
   - Running the system
   - Operating modes (fixture vs live)
   - UI usage walkthrough
   - Workflow visibility
   - Troubleshooting
   - API usage examples
   - Development guide
   - Security considerations
   - File structure reference

2. **FIXES_APPLIED.md** (this file) - Detailed changelog of all fixes

### Verification
- Review documentation: `cat SETUP_AND_OPERATION.md`
- Follow setup instructions
- Reference troubleshooting section as needed

---

## Testing the Fixes

### Quick Test Procedure

1. **Test Live Mode**
   ```bash
   docker-compose restart
   # Open UI
   # Paste scope.yml content
   # Enable Live Mode
   # Complete authorization
   # Submit run
   # Verify "LIVE" in console
   ```

2. **Test Environment Loading**
   ```bash
   docker-compose logs chimera-core | grep -i supabase
   # Should NOT see "missing SUPABASE_URL" errors
   ```

3. **Test Artifacts**
   ```bash
   # In UI: Go to Artifacts tab
   # Click any artifact
   # Should see file path dialog (not error)
   ```

4. **Test Replay/Diff**
   ```bash
   # Start 2 runs
   # Go to Replay & Diff
   # Select both runs
   # Should load successfully
   ```

5. **Test Workflow Visibility**
   ```bash
   # Start any run
   # Go to Console tab
   # Should see detailed events with mode indicators
   ```

---

## Files Modified

### Critical Fixes
1. `chimera/chimera-core/chimera_core/api/routes.py` - Live mode fix, ID resolution
2. `chimera/chimera-core/chimera_core/config.py` - Env var auto-detection
3. `chimera/chimera-ui/launcher.py` - Headless artifact handling

### Enhancements
4. `chimera/chimera-core/chimera_core/runner.py` - Enhanced event logging
5. `chimera/chimera-core/chimera_core/orchestrator.py` - Phase events
6. `chimera/chimera-core/chimera_core/cli.py` - Mode clarification

### Documentation
7. `SETUP_AND_OPERATION.md` - Complete operations guide (NEW)
8. `FIXES_APPLIED.md` - This changelog (NEW)

---

## Known Limitations / Future Improvements

### Current Limitations
1. **Async ID Handling**: The system returns job_id immediately, but run_id is created async. This can cause brief confusion. Consider:
   - WebSocket notifications when run_id is available
   - Polling mechanism in UI
   - Or unify to single ID system

2. **Live Confirmation**: Multiple steps required for live mode (checkbox + text + confirm). Consider:
   - Simplified one-step authorization
   - Remember preference per session

3. **Artifact Viewing**: In headless mode, shows path but doesn't open. Consider:
   - Built-in text viewer in UI
   - Copy-to-clipboard button
   - Web-based artifact viewer

### Future Enhancements
1. **Real-time Progress**: Show percentage complete for long-running tasks
2. **Tool Output Streaming**: Stream tool stdout/stderr to console in real-time
3. **Retry Logic**: Automatic retry for failed tasks with backoff
4. **Dependency Graphs**: Visual representation of task dependencies
5. **Custom Adapters**: Plugin system for user-defined tools
6. **Report Generation**: Automated vulnerability reports in PDF/HTML
7. **Notification System**: Email/Slack alerts on completion or findings

---

## Rollback Instructions

If issues occur, rollback with:

```bash
# Stop services
docker-compose down

# Rollback specific files
git diff HEAD -- chimera/chimera-core/chimera_core/api/routes.py
git checkout HEAD -- chimera/chimera-core/chimera_core/api/routes.py
# (repeat for other files)

# Or rollback all changes
git reset --hard HEAD

# Restart
docker-compose up -d
```

---

## Support Contact

For issues with these fixes:
1. Check logs: `docker-compose logs -f`
2. Review this document
3. Check SETUP_AND_OPERATION.md troubleshooting section
4. Verify .env file contents
5. Test with fixture mode first

---

## Conclusion

All critical issues have been resolved:
- ✅ Live mode now works correctly
- ✅ Environment variables load properly
- ✅ Artifacts accessible in headless mode
- ✅ Replay/diff handles ID resolution
- ✅ Comprehensive workflow visibility
- ✅ Complete documentation provided

The system is ready for live penetration testing. Remember to:
- Only test authorized targets
- Review scope carefully
- Start with fixture mode for testing
- Enable live mode only when ready
- Monitor console for execution flow
