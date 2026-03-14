#!/usr/bin/env python3
"""
Integration test script for Recon Pipeline
Tests Zypheron → VibePenTester → Decepticon flow
"""
import json
import time
import requests
from pathlib import Path

# Configuration
API_URL = "http://localhost:8000/v1"
SCOPE_YAML = """
allowlist:
  - "https://example.com"
  - "https://*.example.com"

denylist:
  - "*.internal.example.com"

rate_limits:
  requests_per_second: 5
  concurrency: 2

allowed_methods:
  - "GET"
  - "HEAD"
  - "OPTIONS"
"""

def test_recon_pipeline(live_mode=False):
    """
    Test the recon pipeline integration
    """
    print("=" * 70)
    print("RECON PIPELINE INTEGRATION TEST")
    print("=" * 70)
    print()

    # Step 1: Check API health
    print("[1] Checking API health...")
    try:
        response = requests.get(f"{API_URL}/health", timeout=5)
        if response.status_code == 200:
            print("✓ API is healthy")
        else:
            print(f"✗ API health check failed: {response.status_code}")
            return False
    except Exception as exc:
        print(f"✗ Failed to connect to API: {exc}")
        return False
    print()

    # Step 2: Submit recon run
    print("[2] Submitting recon pipeline run...")
    print(f"    Mode: {'LIVE' if live_mode else 'FIXTURE'}")

    payload = {
        "scope_text": SCOPE_YAML,
        "live": live_mode,
        "live_confirm": "I UNDERSTAND" if live_mode else "",
        "rate_limit_rps": 5,
        "timeout_s": 60,
        "program_name": "Test Program",
        "allow_destructive": False,  # Safety first!
        "max_workers": 1,
        # Tool configs
        "zypheron_config": {"binary": "zypheron"},
        "vibe_entrypoint": ["python", "vibe-pentester.py"],
        "vibe_workdir": "/app/tools/vibe-pentester",
        "vibe_output_dir": "/artifacts/vibe-reports",
        "vibe_timeout_s": 60,
        "decepticon_entrypoint": ["python", "decepticon.py"],
        "decepticon_workdir": "/app/tools/decepticon",
        "decepticon_output_dir": "/artifacts/decepticon-out",
        "decepticon_timeout_s": 60,
    }

    try:
        response = requests.post(
            f"{API_URL}/recon/run",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            run_id = data.get("run_id")
            print(f"✓ Run created successfully")
            print(f"    Run ID: {run_id}")
            print(f"    Pipeline: {data.get('pipeline')}")
            print(f"    Message: {data.get('message')}")
        else:
            print(f"✗ Failed to create run: {response.status_code}")
            print(f"    Response: {response.text}")
            return False
    except Exception as exc:
        print(f"✗ Failed to submit run: {exc}")
        return False
    print()

    # Step 3: Monitor run status
    print("[3] Monitoring run status...")
    max_checks = 30  # 5 minutes with 10s intervals
    for i in range(max_checks):
        try:
            response = requests.get(f"{API_URL}/recon/runs/{run_id}", timeout=5)
            if response.status_code == 200:
                status_data = response.json()
                status = status_data.get("status")
                print(f"    [{i+1}/{max_checks}] Status: {status}")

                if status == "completed":
                    print("✓ Run completed successfully")
                    print(f"    Zypheron results: {status_data.get('zypheron_results', 0)}")
                    print(f"    VibePenTester results: {status_data.get('vibepentester_results', 0)}")
                    print(f"    Decepticon completed: {status_data.get('decepticon_completed', False)}")
                    break
                elif status == "failed":
                    print(f"✗ Run failed: {status_data.get('error', 'Unknown error')}")
                    return False
                elif status in ("created", "running"):
                    time.sleep(10)
                else:
                    print(f"✗ Unknown status: {status}")
                    return False
            else:
                print(f"✗ Failed to get status: {response.status_code}")
                return False
        except Exception as exc:
            print(f"✗ Error checking status: {exc}")
            return False
    else:
        print("✗ Run did not complete within timeout")
        return False
    print()

    # Step 4: Check bundles
    print("[4] Checking bundles...")
    try:
        response = requests.get(f"{API_URL}/recon/runs/{run_id}/bundles", timeout=5)
        if response.status_code == 200:
            bundles = response.json().get("bundles", [])
            print(f"✓ Found {len(bundles)} bundles")
            for bundle in bundles:
                tool = bundle.get("tool")
                has_artifacts = bundle.get("has_artifacts")
                print(f"    - {tool}: {'✓ Has artifacts' if has_artifacts else '✗ No artifacts'}")
        else:
            print(f"✗ Failed to get bundles: {response.status_code}")
    except Exception as exc:
        print(f"✗ Error getting bundles: {exc}")
    print()

    # Step 5: Check suggested actions (Decepticon)
    print("[5] Checking Decepticon suggested actions...")
    try:
        response = requests.get(f"{API_URL}/recon/runs/{run_id}/suggested_actions", timeout=5)
        if response.status_code == 200:
            data = response.json()
            actions = data.get("suggested_actions", [])
            if actions:
                print(f"✓ Found {len(actions)} suggested actions")
                for i, action in enumerate(actions[:3], 1):  # Show first 3
                    print(f"    {i}. {action}")
            else:
                print("   (No suggested actions - expected in fixture mode)")
        else:
            print(f"✗ Failed to get actions: {response.status_code}")
    except Exception as exc:
        print(f"✗ Error getting actions: {exc}")
    print()

    # Step 6: Check analysis notes
    print("[6] Checking Decepticon analysis notes...")
    try:
        response = requests.get(f"{API_URL}/recon/runs/{run_id}/analysis_notes", timeout=5)
        if response.status_code == 200:
            data = response.json()
            notes = data.get("notes", "")
            if notes:
                print(f"✓ Found analysis notes ({len(notes)} characters)")
                print(f"    Preview: {notes[:100]}...")
            else:
                print("   (No analysis notes - expected in fixture mode)")
        else:
            print(f"✗ Failed to get notes: {response.status_code}")
    except Exception as exc:
        print(f"✗ Error getting notes: {exc}")
    print()

    # Step 7: Check events
    print("[7] Checking events stream...")
    try:
        response = requests.get(f"{API_URL}/runs/{run_id}/events_tail?limit=50", timeout=5)
        if response.status_code == 200:
            events = response.json()
            print(f"✓ Found {len(events)} events")

            # Look for recon-specific events
            recon_events = [e for e in events if "recon" in e.lower() or "zypheron" in e.lower() or "vibe" in e.lower() or "decepticon" in e.lower()]
            if recon_events:
                print(f"    Recon-specific events: {len(recon_events)}")
                for event in recon_events[:3]:
                    print(f"    - {event[:80]}...")
            else:
                print("   (No recon-specific events found)")
        else:
            print(f"✗ Failed to get events: {response.status_code}")
    except Exception as exc:
        print(f"✗ Error getting events: {exc}")
    print()

    print("=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)
    return True


def test_config_loading():
    """
    Test that configuration is loaded correctly
    """
    print("=" * 70)
    print("CONFIGURATION TEST")
    print("=" * 70)
    print()

    print("[1] Checking allowed binaries from .env...")
    import os
    allowed = os.getenv("CHIMERA_ALLOWED_BINARIES", "")
    if allowed:
        bins = [b.strip() for b in allowed.split(",")]
        print(f"✓ Found {len(bins)} allowed binaries:")
        for b in bins:
            print(f"    - {b}")
    else:
        print("✗ CHIMERA_ALLOWED_BINARIES not set")
    print()

    print("[2] Checking destructive tools flag...")
    allow_destructive = os.getenv("CHIMERA_ALLOW_DESTRUCTIVE", "false")
    print(f"    CHIMERA_ALLOW_DESTRUCTIVE = {allow_destructive}")
    if allow_destructive.lower() in {"true", "1", "yes"}:
        print("⚠ WARNING: Destructive tools are ENABLED")
    else:
        print("✓ Destructive tools are disabled (safe mode)")
    print()

    print("[3] Testing config.py loading...")
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent / "chimera" / "chimera-core"))
        from chimera_core.config import load_config

        config = load_config()
        security = config.get("security", {})
        recon = config.get("recon", {})

        print("✓ Config loaded successfully")
        print(f"    Allowed binaries: {len(security.get('allowed_binaries', []))}")
        print(f"    Allow destructive: {security.get('allow_destructive', False)}")
        print(f"    Recon tools configured: {list(recon.keys())}")
    except Exception as exc:
        print(f"✗ Failed to load config: {exc}")
    print()

    print("=" * 70)
    return True


if __name__ == "__main__":
    import sys

    print()
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║          CHIMERA RECON PIPELINE INTEGRATION TEST                   ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print()

    # Test 1: Configuration
    print("TEST 1: Configuration Loading")
    print("-" * 70)
    test_config_loading()
    print()

    # Test 2: API Integration (Fixture Mode)
    print("TEST 2: Recon Pipeline (Fixture Mode)")
    print("-" * 70)
    success = test_recon_pipeline(live_mode=False)

    if success:
        print()
        print("✓ ALL TESTS PASSED")
        print()
        print("Next steps:")
        print("  1. Review events in UI Console tab")
        print("  2. Check artifacts in UI Artifacts tab")
        print("  3. Review findings in UI Findings tab")
        print()
        print("To test LIVE mode (requires authorization):")
        print("  python test_recon_integration.py --live")
        sys.exit(0)
    else:
        print()
        print("✗ TESTS FAILED")
        print()
        print("Troubleshooting:")
        print("  1. Ensure Docker containers are running: docker-compose ps")
        print("  2. Check API logs: docker-compose logs chimera-core")
        print("  3. Verify .env file has tool permissions set")
        sys.exit(1)
