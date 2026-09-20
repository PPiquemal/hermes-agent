"""Skills publication never forks and stops on the first unsuccessful write."""
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

from hermes_cli.skills_hub import _github_publish


@pytest.mark.parametrize("target", ["NousResearch/hermes-agent", "", "Other/hermes-agent"])
def test_unapproved_skill_target_has_zero_http_calls(tmp_path, monkeypatch, target):
    def unexpected(*args, **kwargs):
        pytest.fail("HTTP reached before whitelist validation")
    for method in ("get", "post", "put"):
        monkeypatch.setattr(httpx, method, unexpected)
    ok, message = _github_publish(tmp_path, "test-skill", target, SimpleNamespace(get_headers=lambda: {}))
    assert not ok
    assert message.startswith("BLOCKED")


@pytest.mark.parametrize("failed_step", [None, "branch", "upload", "pr", "read"])
def test_skill_publication_checks_every_response_and_never_forks(tmp_path, monkeypatch, failed_step):
    (tmp_path / "SKILL.md").write_text("---\nname: test-skill\ndescription: test\n---\n")
    calls = []
    def transport(method, url, **kwargs):
        calls.append((method, url, kwargs))
        assert url.startswith("https://api.github.com/repos/PPiquemal/hermes-agent")
        assert not url.endswith("/forks")
        step = {"/git/refs": "branch", "/pulls": "pr"}.get(url[url.rfind("/"):], "upload")
        if method == "get":
            step = "read"
            data = {"full_name": "PPiquemal/hermes-agent", "default_branch": "main"}
            if "/git/ref/" in url:
                data = {
                    "ref": "refs/heads/main",
                    "object": {"type": "commit", "sha": "a" * 40},
                }
        else:
            if url.endswith("/git/refs"):
                step = "branch"
            data = {"html_url": "https://github.com/PPiquemal/hermes-agent/pull/1"}
        code = 403 if failed_step == step else (200 if method == "get" else 201)
        return httpx.Response(code, json=data)
    for method in ("get", "post", "put"):
        monkeypatch.setattr(httpx, method, lambda url, _method=method, **kw: transport(_method, url, **kw))
    auth = SimpleNamespace(get_headers=lambda: {})
    ok, message = _github_publish(tmp_path, "test-skill", "PPiquemal/hermes-agent", auth)
    if failed_step:
        assert not ok and message.startswith("BLOCKED")
        if failed_step != "pr":
            assert not any(url.endswith("/pulls") for _, url, _ in calls)
        assert len(calls) == {"read": 1, "branch": 3, "upload": 4, "pr": 5}[failed_step]
    else:
        assert ok
        assert calls[-1][2]["json"]["head"] == "add-skill-test-skill"
        assert calls[-1][2]["json"]["base"] == "main"
