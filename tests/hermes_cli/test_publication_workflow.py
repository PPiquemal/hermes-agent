"""Exercise the workflow admission step without executing its publication steps."""
import os
from pathlib import Path
import subprocess
import sys

import yaml


def test_js_autofix_checks_repository_before_credentials_and_writes():
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load((root / ".github/workflows/js-autofix.yml").read_text())
    steps = workflow["jobs"]["apply-patch"]["steps"]
    check_index = next(i for i, step in enumerate(steps) if step.get("name") == "Enforce publication whitelist before obtaining write credentials")
    token_index = next(i for i, step in enumerate(steps) if step.get("id") == "app-token")
    assert check_index < token_index
    script = steps[check_index]["run"]
    for repository, code in [("NousResearch/hermes-agent", 1), ("unknown/repository", 1), ("PPiquemal/hermes-agent", 0)]:
        env = {**os.environ, "GITHUB_REPOSITORY": repository, "PATH": f"{Path(sys.executable).parent}:{os.environ['PATH']}"}
        result = subprocess.run(["bash", "-c", script], cwd=root, env=env, capture_output=True, text=True)
        assert result.returncode == code, result.stderr
        if code:
            assert "BLOCKED" in result.stdout


def test_js_autofix_never_merges_closes_or_deletes_the_pr():
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load((root / ".github/workflows/js-autofix.yml").read_text())
    scripts = "\n".join(
        step.get("run", "")
        for step in workflow["jobs"]["apply-patch"]["steps"]
    )

    assert "gh pr merge" not in scripts
    assert "gh pr close" not in scripts
    assert "--delete-branch" not in scripts
