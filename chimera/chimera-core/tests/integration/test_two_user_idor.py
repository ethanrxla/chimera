from pathlib import Path

from chimera_core.artifacts import ArtifactWriter
from chimera_core.event_store import EventStore
from chimera_core.exploits.session_bootstrap import SessionBootstrapper
from chimera_core.exploits.two_user_idor import TwoUserIDORExploitHandler
from chimera_core.shannon.session import AuthToken, BrowserSession, SessionRole


class FakeResponse:
    def __init__(self, status_code: int, payload: dict) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = str(payload)
        self.headers = {"content-type": "application/json"}

    def json(self):
        return dict(self._payload)


class FakeHTTPClient:
    def request(self, method: str, url: str, headers=None, cookies=None, params=None, json=None):
        return FakeResponse(200, {"basket": {"id": 1, "owner": "user-a", "items": ["apple"]}})


def test_idor_two_user_confirmation(tmp_path: Path) -> None:
    events = EventStore(tmp_path / "events.jsonl", run_id="run-two-user")
    writer = ArtifactWriter(tmp_path / "artifacts", event_store=events)

    def bootstrap_callable(role, credentials: dict, target_url: str, login_config: dict, cache_key: str) -> BrowserSession:
        suffix = "a" if cache_key.endswith("_a") else "b"
        return BrowserSession(
            session_id=f"{cache_key}-session",
            role=SessionRole.LOW_PRIVILEGE,
            cookies={"sid": suffix},
            headers={"Authorization": f"Bearer token-{suffix}"},
            tokens=[AuthToken(type="JWT", value=f"token-{suffix}", source="test")],
            storage={"token": f"token-{suffix}"},
        )

    bootstrapper = SessionBootstrapper(
        target_url="https://example.com",
        artifact_writer=writer,
        run_id="run-two-user",
        task_id="task-two-user",
        bootstrap_callable=bootstrap_callable,
    )
    user_a = bootstrapper.bootstrap_authenticated_session("low_privilege", {"email": "user-a@example.com"}, cache_key="low_privilege_a")
    user_b = bootstrapper.bootstrap_authenticated_session("low_privilege", {"email": "user-b@example.com"}, cache_key="low_privilege_b")

    assert user_a.session_id != user_b.session_id
    assert user_a.tokens[0].value != user_b.tokens[0].value

    session_context = {
        "run_id": "run-two-user",
        "task_id": "task-two-user",
        "target_url": "https://example.com",
        "http_client": FakeHTTPClient(),
        "session_bootstrapper": bootstrapper,
        "session_credentials": [{"email": "user-a@example.com"}, {"email": "user-b@example.com"}],
        "user_a_session": user_a,
        "user_b_session": user_b,
    }
    handler = TwoUserIDORExploitHandler(session_context=session_context, artifact_writer=writer)
    result = handler.run(
        candidate={
            "candidate_id": "cand-idor-1",
            "claim_type": "idor",
            "target": "https://example.com",
            "metadata": {"target": {"method": "GET", "endpoint": "/rest/basket/1", "params": {}}},
        }
    )

    assert result.classification == "EXPLOITED"
    assert len(result.session_refs) == 2
    assert len(result.final_evidence_refs) >= 4
    assert (tmp_path / "artifacts" / "run-two-user" / "sessions" / "low_privilege_a-session.json").exists()
    assert (tmp_path / "artifacts" / "run-two-user" / "sessions" / "low_privilege_b-session.json").exists()
