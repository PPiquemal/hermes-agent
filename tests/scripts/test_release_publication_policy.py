"""Release publication is outside automated Hermes authorization."""

import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "release.py"


def _load_release_module():
    spec = importlib.util.spec_from_file_location("release_policy_test", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_publish_is_blocked_before_any_release_or_git_work(monkeypatch, capsys):
    release = _load_release_module()
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--publish", "--bump", "patch"])
    monkeypatch.setattr(
        release,
        "next_available_tag",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("release work started before BLOCKED")),
    )

    assert release.main() == 1
    output = capsys.readouterr().out
    assert "BLOCKED" in output
    assert "new explicit user authorization" in output
