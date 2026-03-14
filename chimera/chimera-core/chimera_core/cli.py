import argparse
import json
import sys
import platform
from pathlib import Path
from typing import List, Optional

from .config import get_config_path, load_config, write_default_config
from .config_manager import (
    get_unified_config_path,
    import_registry,
    load_unified_config,
    save_unified_config,
    set_unified_value,
    validate_unified_config,
    write_default_unified_config,
)
from .events import DiskEventBus, EventCursor, EventLogSink, EventStore
from .logging import setup_logging
from .orchestrator import Orchestrator
from .event_store import EventStore as LegacyEventStore
from .run_manager import RunManager
from .runtime import Runtime
from .scope import ScopeGraph, ScopePolicy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chimera",
        description="Chimera core CLI (skeleton)",
    )
    parser.add_argument("--version", action="store_true", help="Show version and exit")

    subparsers = parser.add_subparsers(dest="command", required=True)
    config_cmd = subparsers.add_parser("config", help="Inspect or initialize config")
    config_cmd.add_argument("--init", action="store_true", help="Write default config")
    config_cmd.add_argument("--print", action="store_true", help="Print config JSON")
    config_cmd.add_argument("--unified-init", action="store_true", help="Write default unified config YAML")
    config_cmd.add_argument("--unified-show", action="store_true", help="Print unified config YAML")
    config_cmd.add_argument("--unified-validate", action="store_true", help="Validate unified config YAML")
    config_cmd.add_argument("--unified-set", nargs=2, metavar=("KEY", "VALUE"), help="Set unified config key")
    config_cmd.add_argument("--unified-import-registry", action="store_true", help="Import tools/registry.json")
    
    run_cmd = subparsers.add_parser("run", help="Run a new job based on a scope file")
    run_cmd.add_argument("scope_file", help="Path to the scope YAML file")

    run_mock_cmd = subparsers.add_parser("run-mock", help="Run a safe mock command")

    events_cmd = subparsers.add_parser("events", help="Event log utilities")
    events_sub = events_cmd.add_subparsers(dest="events_command", required=True)
    tail_cmd = events_sub.add_parser("tail", help="Replay events from a run")
    tail_cmd.add_argument("--run", required=True, help="Run ID to replay")
    tail_cmd.add_argument("--cursor", type=int, default=0, help="Byte offset cursor")
    
    status_cmd = subparsers.add_parser("status", help="Get job status")
    status_cmd.add_argument("job_id", help="ID of the job to check")

    findings_cmd = subparsers.add_parser("findings", help="Get job findings")
    findings_cmd.add_argument("job_id", help="ID of the job to get findings for")

    smoke_cmd = subparsers.add_parser("smoke-test", help="Run a smoke test to validate the environment")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    orchestrator = Orchestrator()

    if args.version:
        print("chimera-core 0.1.0")
        return 0

    if args.command == "config":
        if args.unified_init:
            path = write_default_unified_config()
            print(f"Wrote unified config to {path}")
            return 0
        if args.unified_show:
            config = load_unified_config()
            print(json.dumps(config, indent=2))
            return 0
        if args.unified_validate:
            config = load_unified_config()
            errors = validate_unified_config(config)
            if errors:
                print("Unified config validation failed:")
                for error in errors:
                    print(f"- {error}")
                return 1
            print("Unified config is valid.")
            return 0
        if args.unified_import_registry:
            registry_path = Path.cwd() / "tools" / "registry.json"
            if not registry_path.exists():
                print(f"Registry not found: {registry_path}")
                return 1
            path = import_registry(registry_path)
            print(f"Imported registry into {path}")
            return 0
        if args.unified_set:
            key, value = args.unified_set
            config = load_unified_config()
            set_unified_value(config, key, value)
            save_unified_config(config)
            print(f"Updated unified config: {key}={value}")
            return 0
        if args.init:
            path = write_default_config()
            print(f"Wrote default config to {path}")
            return 0
        if args.print:
            config = load_config()
            print(config)
            return 0
        print(get_config_path())
        return 0

    if args.command == "run":
        job = orchestrator.create_job(args.scope_file, mode="live")
        artifacts_dir = Path("/artifacts") / job.job_id
        events_path = artifacts_dir / "events.ndjson"
        store = EventStore(events_path)
        sink = EventLogSink(store, run_id=job.job_id, source="cli")
        bus = DiskEventBus(sink)

        orchestrator.start_run(job.job_id, event_sink=bus)
        
        print("\n--- Final Findings ---")
        findings = orchestrator.get_job_findings(job.job_id)
        if findings:
            for finding in findings:
                print(json.dumps(finding, indent=2))
        else:
            print("No findings were generated.")
        return 0

    if args.command == "run-mock":
        artifacts_root = Path.cwd() / "artifacts"
        run_manager = RunManager(artifacts_root)
        scope_manifest = {"allowlist": ["invalid.example"], "denylist": []}
        scope_graph = ScopeGraph(scope_manifest)
        scope_policy = ScopePolicy(scope_manifest)
        run = run_manager.create_run(scope_hash="mock-scope", mode="safe")
        events_file = run.artifacts_dir / "events.jsonl"
        event_store = LegacyEventStore(events_file)

        runtime = Runtime(
            scope_graph=scope_graph,
            scope_policy=scope_policy,
            event_store=event_store,
            artifacts_root=artifacts_root,
            run_id=run.run_id,
        )

        event_store.emit({"event_type": "run_created", "payload": {"run_id": run.run_id}})
        event_store.emit({"event_type": "task_started", "payload": {"run_id": run.run_id, "task_id": "mock-task"}})

        command = [sys.executable, "-c", "print('chimera mock ok')", "https://invalid.example"]
        runtime.run_cmd(command, task_id="mock-task")

        event_store.emit({"event_type": "task_finished", "payload": {"run_id": run.run_id, "task_id": "mock-task"}})
        event_store.emit({"event_type": "run_finished", "payload": {"run_id": run.run_id}})

        print(f"Run ID: {run.run_id}")
        print(f"Artifacts: {run.artifacts_dir}")
        print(f"Events: {events_file}")
        return 0

    if args.command == "events" and args.events_command == "tail":
        events_path = Path("/artifacts") / args.run / "events.ndjson"
        if not events_path.exists():
            print(f"Event log not found: {events_path}")
            return 1
        store = EventStore(events_path)
        cursor = EventCursor(offset=args.cursor)
        last_cursor = cursor
        for next_cursor, event in store.replay(cursor):
            print(json.dumps(event, indent=2))
            last_cursor = next_cursor
        print(f"cursor={last_cursor.offset}")
        return 0
    
    if args.command == "status":
        print("Note: Job state is not yet persisted across CLI runs.")
        status = orchestrator.get_job_status(args.job_id)
        if status:
            print(f"Job {args.job_id} status: {status.value}")
        else:
            print(f"Job {args.job_id} not found.")
        return 0

    if args.command == "findings":
        print("Note: Job state is not yet persisted across CLI runs.")
        findings = orchestrator.get_job_findings(args.job_id)
        if findings:
            print(f"Findings for job {args.job_id}:")
            for finding in findings:
                print(json.dumps(finding, indent=2))
        else:
            print(f"No findings found for job {args.job_id} or job not found.")
        return 0

    if args.command == "smoke-test":
        print("--- Chimera Smoke Test ---")
        print(f"Python Version: {sys.version.split()[0]}")
        print(f"Platform: {platform.platform()}")
        
        try:
            from chimera_core import scope, planner, scheduler, runner
            print("[+] Core modules imported successfully.")
        except ImportError as e:
            print(f"[-] Failed to import core modules: {e}")
            return 1
        
        test_file = "/tmp/chimera_smoke_test.txt"
        try:
            with open(test_file, "w") as f:
                f.write("test")
            print(f"[+] Write permissions to {test_file} are OK.")
        except IOError as e:
            print(f"[-] Failed to write to {test_file}: {e}")
            return 1

        print("\nSmoke test passed!")
        return 0

    parser.print_help()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
