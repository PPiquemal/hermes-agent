"""Bounded RSIP workflow-dispatch and publication-plan invariants."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from hermes_cli import publication_policy as policy


_REPOSITORY = "PPiquemal/rsip"
_WORKFLOW_ID = 265670631
_WORKFLOW_PATH = ".github/workflows/test.yml"
_WORKFLOW_NAME = "RSIP Tests"
_BRANCH = "fix/nightly-regression-auth-memory"
_REF = f"refs/heads/{_BRANCH}"
_SHA = "074fe946ab03da249bf4187f24f42af0d4f62e85"


def _workflow_metadata(*, state: str = "active", path: str = _WORKFLOW_PATH) -> dict:
    return {
        "id": _WORKFLOW_ID,
        "name": _WORKFLOW_NAME,
        "path": path,
        "state": state,
    }


def _remote_ref(*, sha: str = _SHA) -> dict:
    return {"ref": _REF, "object": {"type": "commit", "sha": sha}}


def _run(run_id: int, *, status: str, conclusion=None, sha: str = _SHA) -> dict:
    return {
        "id": run_id,
        "html_url": f"https://github.com/PPiquemal/rsip/actions/runs/{run_id}",
        "workflow_id": _WORKFLOW_ID,
        "path": _WORKFLOW_PATH,
        "event": "workflow_dispatch",
        "head_branch": _BRANCH,
        "head_sha": sha,
        "repository": {"full_name": _REPOSITORY},
        "status": status,
        "conclusion": conclusion,
    }


class ScriptedGh:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []

    def __call__(self, args):
        self.calls.append(list(args))
        if not self.outputs:
            pytest.fail(f"unexpected gh call: {args}")
        value = self.outputs.pop(0)
        if isinstance(value, tuple):
            return value
        return 0, json.dumps(value), ""


def _plan():
    return policy.resolve_workflow_dispatch_plan(
        repository=_REPOSITORY,
        operation="checked_workflow_dispatch",
        ref=_REF,
        expected_sha=_SHA,
    )


def _publication_git(writes):
    def git(args):
        if "push" in args:
            writes.append(args)
            return 0, "", ""
        outputs = {
            ("config", "--get-all", "remote.origin.pushurl"): (1, "", ""),
            ("config", "--get-all", "remote.origin.url"): (
                0, "git@github-rsip:PPiquemal/rsip.git\n", "",
            ),
            ("remote", "get-url", "--push", "--all", "origin"): (
                0, "git@github-rsip:PPiquemal/rsip.git\n", "",
            ),
            ("symbolic-ref", "--quiet", "--short", "HEAD"): (0, f"{_BRANCH}\n", ""),
            ("rev-parse", "--verify", f"refs/heads/{_BRANCH}^{{commit}}"): (
                0, f"{_SHA}\n", "",
            ),
        }
        if args[:2] == ["config", "--get-regexp"]:
            return 1, "", ""
        if args[0] == "check-ref-format":
            return 0, "", ""
        return outputs[tuple(args)]

    return git


def _ssh_config(alias):
    return {"host": alias, "hostname": "github.com", "user": "git"}


def test_checked_workflow_plan_is_exact_and_rejects_unbounded_identity():
    plan = _plan()
    assert plan.repository == _REPOSITORY
    assert plan.workflow_id == _WORKFLOW_ID
    assert plan.workflow_path == _WORKFLOW_PATH
    assert plan.workflow_name == _WORKFLOW_NAME
    assert plan.ref == _REF
    assert plan.branch == _BRANCH
    assert plan.expected_sha == _SHA

    invalid = [
        {"repository": "PPiquemal/hermes-agent"},
        {"operation": "direct_github_write"},
        {"ref": _BRANCH},
        {"ref": "refs/tags/v1"},
        {"ref": "refs/heads/../main"},
        {"expected_sha": _SHA[:12]},
        {"expected_sha": _SHA.upper()},
    ]
    defaults = {
        "repository": _REPOSITORY,
        "operation": "checked_workflow_dispatch",
        "ref": _REF,
        "expected_sha": _SHA,
    }
    for override in invalid:
        with pytest.raises(policy.PublicationBlocked, match="BLOCKED"):
            policy.resolve_workflow_dispatch_plan(**(defaults | override))


def test_checked_dispatch_verifies_exact_head_identifies_one_run_and_emits_receipt():
    old = _run(100, status="completed", conclusion="success")
    queued = _run(101, status="queued")
    complete = _run(101, status="completed", conclusion="success")
    gh = ScriptedGh([
        {"full_name": _REPOSITORY},
        _workflow_metadata(),
        _remote_ref(),
        {"total_count": 1, "workflow_runs": [old]},
        _remote_ref(),
        (0, "", ""),
        {"total_count": 2, "workflow_runs": [queued, old]},
        queued,
        complete,
    ])

    receipt = policy.execute_checked_workflow_dispatch(
        gh,
        _plan(),
        sleep=lambda _seconds: None,
        identify_attempts=1,
        completion_attempts=2,
    )

    writes = [call for call in gh.calls if "POST" in call]
    assert writes == [[
        "api", "--hostname", "github.com", "--method", "POST",
        f"repos/{_REPOSITORY}/actions/workflows/{_WORKFLOW_ID}/dispatches",
        "-f", f"ref={_BRANCH}",
    ]]
    post_index = gh.calls.index(writes[0])
    assert all("POST" not in call for call in gh.calls[:post_index])
    assert receipt == {
        "repository": _REPOSITORY,
        "run_id": 101,
        "url": "https://github.com/PPiquemal/rsip/actions/runs/101",
        "workflow_id": _WORKFLOW_ID,
        "workflow_name": _WORKFLOW_NAME,
        "workflow_path": _WORKFLOW_PATH,
        "event": "workflow_dispatch",
        "ref": _REF,
        "sha": _SHA,
        "conclusion": "success",
    }


@pytest.mark.parametrize(
    "bad_preflight",
    [
        _workflow_metadata(state="disabled_manually"),
        _workflow_metadata(path=".github/workflows/other.yml"),
        _remote_ref(sha="f" * 40),
    ],
)
def test_checked_dispatch_blocks_every_preflight_mismatch_before_write(bad_preflight):
    outputs = [{"full_name": _REPOSITORY}]
    if "state" in bad_preflight:
        outputs.append(bad_preflight)
    else:
        outputs.extend([_workflow_metadata(), bad_preflight])
    gh = ScriptedGh(outputs)

    with pytest.raises(policy.PublicationBlocked, match="BLOCKED"):
        policy.execute_checked_workflow_dispatch(gh, _plan(), sleep=lambda _: None)

    assert all("POST" not in call for call in gh.calls)


def test_checked_dispatch_rejects_ambiguous_new_runs_without_redispatch():
    first = _run(201, status="queued")
    second = _run(202, status="queued")
    gh = ScriptedGh([
        {"full_name": _REPOSITORY},
        _workflow_metadata(),
        _remote_ref(),
        {"total_count": 0, "workflow_runs": []},
        _remote_ref(),
        (0, "", ""),
        {"total_count": 2, "workflow_runs": [first, second]},
    ])

    with pytest.raises(policy.PublicationBlocked, match="ambiguous"):
        policy.execute_checked_workflow_dispatch(
            gh,
            _plan(),
            sleep=lambda _: None,
            identify_attempts=1,
        )

    assert sum("POST" in call for call in gh.calls) == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event", "pull_request"),
        ("head_branch", "main"),
        ("head_sha", "f" * 40),
        ("workflow_id", 1),
        ("path", ".github/workflows/other.yml"),
        ("repository", {"full_name": "Other/rsip"}),
    ],
)
def test_checked_dispatch_rejects_any_resulting_run_mismatch(field, value):
    mismatched = _run(250, status="queued")
    mismatched[field] = value
    gh = ScriptedGh([
        {"full_name": _REPOSITORY},
        _workflow_metadata(),
        _remote_ref(),
        {"total_count": 0, "workflow_runs": []},
        _remote_ref(),
        (0, "", ""),
        {"total_count": 1, "workflow_runs": [mismatched]},
    ])

    with pytest.raises(policy.PublicationBlocked, match="does not match"):
        policy.execute_checked_workflow_dispatch(
            gh,
            _plan(),
            sleep=lambda _: None,
            identify_attempts=1,
        )

    assert sum("POST" in call for call in gh.calls) == 1


def test_checked_dispatch_failure_is_one_terminal_attempt():
    gh = ScriptedGh([
        {"full_name": _REPOSITORY},
        _workflow_metadata(),
        _remote_ref(),
        {"total_count": 0, "workflow_runs": []},
        _remote_ref(),
        (1, "", "denied"),
    ])

    with pytest.raises(policy.PublicationBlocked, match="dispatch failed"):
        policy.execute_checked_workflow_dispatch(gh, _plan(), sleep=lambda _: None)

    assert sum("POST" in call for call in gh.calls) == 1


def test_checked_dispatch_returns_auditable_non_success_conclusion_without_retry():
    failed = _run(301, status="completed", conclusion="failure")
    gh = ScriptedGh([
        {"full_name": _REPOSITORY},
        _workflow_metadata(),
        _remote_ref(),
        {"total_count": 0, "workflow_runs": []},
        _remote_ref(),
        (0, "", ""),
        {"total_count": 1, "workflow_runs": [failed]},
        failed,
    ])

    receipt = policy.execute_checked_workflow_dispatch(
        gh,
        _plan(),
        sleep=lambda _: None,
        identify_attempts=1,
        completion_attempts=1,
    )

    assert receipt["conclusion"] == "failure"
    assert receipt["run_id"] == 301
    assert sum("POST" in call for call in gh.calls) == 1


def test_checked_dispatch_cli_prints_the_verified_receipt(capsys):
    complete = _run(401, status="completed", conclusion="success")
    gh = ScriptedGh([
        {"full_name": _REPOSITORY},
        _workflow_metadata(),
        _remote_ref(),
        {"total_count": 0, "workflow_runs": []},
        _remote_ref(),
        (0, "", ""),
        {"total_count": 1, "workflow_runs": [complete]},
        complete,
    ])

    result = policy.main(
        [
            "--repository", _REPOSITORY,
            "--operation", "checked_workflow_dispatch",
            "--dispatch-workflow",
            "--ref", _REF,
            "--expected-sha", _SHA,
        ],
        gh=gh,
        sleep=lambda _: None,
    )

    assert result == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["run_id"] == 401
    assert receipt["sha"] == _SHA
    assert receipt["conclusion"] == "success"


def test_checked_dispatch_subprocess_pins_github_host(monkeypatch, capsys):
    complete = _run(402, status="completed", conclusion="success")
    outputs = [
        json.dumps({"full_name": _REPOSITORY}),
        json.dumps(_workflow_metadata()),
        json.dumps(_remote_ref()),
        json.dumps({"total_count": 0, "workflow_runs": []}),
        json.dumps(_remote_ref()),
        "",
        json.dumps({"total_count": 1, "workflow_runs": [complete]}),
        json.dumps(complete),
    ]
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs["env"]))
        return SimpleNamespace(returncode=0, stdout=outputs.pop(0), stderr="")

    monkeypatch.setenv("GH_HOST", "attacker.example")
    monkeypatch.setenv("GH_REPO", "Other/repository")
    monkeypatch.setattr(policy.subprocess, "run", run)

    assert policy.main(
        [
            "--repository", _REPOSITORY,
            "--operation", "checked_workflow_dispatch",
            "--dispatch-workflow", "--ref", _REF, "--expected-sha", _SHA,
        ],
        sleep=lambda _: None,
    ) == 0

    assert json.loads(capsys.readouterr().out)["run_id"] == 402
    assert all(env["GH_HOST"] == "github.com" and "GH_REPO" not in env for _, env in calls)
    api_calls = [argv for argv, _ in calls if argv[1] == "api"]
    assert all(argv[2:4] == ["--hostname", "github.com"] for argv in api_calls)


def test_rsip_push_cli_preflights_pr_and_regression_before_first_remote_write(capsys):
    git_writes = []
    gh = ScriptedGh([
        {"full_name": _REPOSITORY},
        _workflow_metadata(state="disabled_manually"),
    ])
    result = policy.main(
        [
            "--repository", _REPOSITORY,
            "--operation", "checked_branch_push",
            "--push", "--remote", "origin", "--branch", _BRANCH,
            "--base", "main", "--head", _BRANCH,
            "--ref", _REF, "--expected-sha", _SHA,
        ],
        git=_publication_git(git_writes),
        gh=gh,
        ssh_config=_ssh_config,
    )

    assert result == 1
    assert "BLOCKED" in capsys.readouterr().out
    assert git_writes == []


def test_publication_plan_rejects_an_existing_pr_before_push():
    git_writes = []
    gh = ScriptedGh([
        {"full_name": _REPOSITORY},
        _workflow_metadata(),
        {"name": "main"},
        [{"number": 140}],
    ])

    with pytest.raises(policy.PublicationBlocked, match="already has an open PR"):
        policy.preflight_publication_plan(
            _publication_git(git_writes),
            gh,
            repository=_REPOSITORY,
            remote="origin",
            branch=_BRANCH,
            base="main",
            head=_BRANCH,
            ref=_REF,
            expected_sha=_SHA,
            ssh_config=_ssh_config,
        )

    assert git_writes == []
