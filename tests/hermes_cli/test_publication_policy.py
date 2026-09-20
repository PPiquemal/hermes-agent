"""Shared policy and workflow CLI acceptance contracts."""
import json
import logging
from pathlib import Path

import pytest

from hermes_cli import publication_policy as policy


@pytest.mark.parametrize("target", [None, "", "NousResearch/hermes-agent", "Other/hermes-agent", " PPiquemal/hermes-agent", "PPiquemal/hermes-agent/extra"])
def test_only_exact_repository_is_authorized(target):
    with pytest.raises(policy.PublicationBlocked, match="BLOCKED"):
        policy.require_repository(target, "checked_branch_push")
    assert policy.require_repository(
        "PPiquemal/hermes-agent", "checked_branch_push"
    ) == "PPiquemal/hermes-agent"
    assert policy.require_repository(
        "PPiquemal/rsip", "checked_branch_push"
    ) == "PPiquemal/rsip"


@pytest.mark.parametrize("operation", ["merge", "auto_merge", "release", "skills", "autofix", "update", "workflow_dispatch", "direct_github_write"])
def test_rsip_allows_only_bounded_checked_publication_operations(operation):
    with pytest.raises(policy.PublicationBlocked, match="operation"):
        policy.require_repository("PPiquemal/rsip", operation)
    assert policy.require_repository("PPiquemal/rsip", "checked_branch_push")
    assert policy.require_repository("PPiquemal/rsip", "checked_pr_create")
    assert policy.require_repository("PPiquemal/rsip", "checked_workflow_dispatch")


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("operations", ["checked_branch_push", "checked_pr_create", "checked_workflow_dispatch", "workflow_dispatch"]),
        ("workflow_id", 265670632),
        ("workflow_path", ".github/workflows/other.yml"),
    ],
)
def test_rsip_workflow_policy_drift_fails_closed(monkeypatch, key, value):
    raw = json.loads(
        (Path(policy.__file__).with_suffix(".json")).read_text(encoding="utf-8")
    )
    rsip = raw["repositories"]["PPiquemal/rsip"]
    if key == "operations":
        rsip["operations"] = value
    else:
        field = "id" if key == "workflow_id" else "path"
        rsip["workflows"]["checked_workflow_dispatch"][field] = value
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda _self, **_kwargs: json.dumps(raw),
    )

    with pytest.raises(policy.PublicationBlocked, match="policy unavailable"):
        policy.load_policy()


@pytest.mark.parametrize("url", ["https://github.com/PPiquemal/hermes-agent.git", "git@github.com:PPiquemal/hermes-agent.git", "ssh://git@github.com/PPiquemal/hermes-agent"])
def test_supported_urls_keep_the_selected_protocol(url):
    assert policy.require_push_url(
        url, "PPiquemal/hermes-agent", "checked_branch_push"
    ) == url


@pytest.mark.parametrize("url", ["https://github.com/NousResearch/hermes-agent.git", "https://github.com.evil/PPiquemal/hermes-agent", "https://github.com/PPiquemal/hermes-agent?x=1", "https://user@github.com/PPiquemal/hermes-agent", "file:///tmp/repo", "https://github.com/PPiquemal/hermes-agent\nhttps://github.com/NousResearch/hermes-agent"])
def test_unverifiable_urls_are_blocked(url):
    with pytest.raises(policy.PublicationBlocked, match="BLOCKED"):
        policy.require_push_url(
            url, "PPiquemal/hermes-agent", "checked_branch_push"
        )


def test_rsip_exact_ssh_alias_requires_verified_github_destination():
    url = "git@github-rsip:PPiquemal/rsip.git"
    assert policy.require_push_url(
        url,
        "PPiquemal/rsip",
        "checked_branch_push",
        ssh_config=lambda alias: {"host": alias, "hostname": "github.com", "user": "git"},
    ) == url


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/PPiquemal/rsip.git",
        "git@github.com:PPiquemal/rsip.git",
        "ssh://git@github.com/PPiquemal/rsip.git",
    ],
)
def test_rsip_rejects_non_alias_protocols(url):
    with pytest.raises(policy.PublicationBlocked, match="BLOCKED"):
        policy.require_push_url(url, "PPiquemal/rsip", "checked_branch_push")


@pytest.mark.parametrize(
    "resolved",
    [
        {"host": "github-rsip", "hostname": "evil.example", "user": "git"},
        {"host": "github-rsip", "hostname": "github.com", "user": "root"},
        {"host": "other-alias", "hostname": "github.com", "user": "git"},
        {},
    ],
)
def test_rsip_ssh_alias_fails_closed_when_effective_destination_is_wrong(resolved):
    with pytest.raises(policy.PublicationBlocked, match="BLOCKED"):
        policy.require_push_url(
            "git@github-rsip:PPiquemal/rsip.git",
            "PPiquemal/rsip",
            "checked_branch_push",
            ssh_config=lambda _alias: resolved,
        )


def test_cross_repository_url_is_rejected():
    with pytest.raises(policy.PublicationBlocked, match="BLOCKED"):
        policy.require_push_url(
            "git@github-rsip:PPiquemal/rsip.git",
            "PPiquemal/hermes-agent",
            "checked_branch_push",
            ssh_config=lambda alias: {"host": alias, "hostname": "github.com", "user": "git"},
        )


def test_workflow_cli_blocks_wrong_repository_without_running_git(capsys):
    assert callable(getattr(policy, "main", None)), "workflow has no policy entry point"
    def git(args):
        pytest.fail("Git invoked before target authorization")
    assert policy.main(["--repository", "NousResearch/hermes-agent", "--operation", "checked_branch_push", "--push", "--remote", "origin", "--branch", "bot/js-autofix"], git=git) == 1
    assert "BLOCKED" in capsys.readouterr().out


@pytest.mark.parametrize("failed", [False, True])
def test_workflow_cli_explicit_push_is_single_attempt(failed, capsys):
    assert callable(getattr(policy, "main", None)), "workflow has no policy entry point"
    writes = []
    def git(args):
        if "push" in args:
            writes.append(args)
            return int(failed), "", ""
        outputs = {
            ("config", "--get-all", "remote.fork.pushurl"): (1, "", ""),
            ("config", "--get-all", "remote.fork.url"): (0, "https://github.com/PPiquemal/hermes-agent.git\n", ""),
            ("remote", "get-url", "--push", "--all", "fork"): (0, "https://github.com/PPiquemal/hermes-agent.git\n", ""),
            ("symbolic-ref", "--quiet", "--short", "HEAD"): (0, "main\n", ""),
            ("rev-parse", "--verify", "refs/heads/main^{commit}"): (0, "a" * 40, ""),
        }
        if args[:2] == ["config", "--get-regexp"]:
            return 1, "", ""
        if args[0] == "check-ref-format":
            return 0, "", ""
        return outputs[tuple(args)]
    result = policy.main(["--repository", "PPiquemal/hermes-agent", "--operation", "checked_branch_push", "--push", "--remote", "fork", "--branch", "bot/js-autofix"], git=git)
    assert result == int(failed)
    assert len(writes) == 1
    assert writes[0][-2:] == ["https://github.com/PPiquemal/hermes-agent.git", f"{'a' * 40}:refs/heads/bot/js-autofix"]
    if failed:
        assert "BLOCKED" in capsys.readouterr().out


@pytest.mark.parametrize("repository", ["PPiquemal/rsip", "github.com/PPiquemal/rsip"])
def test_workflow_cli_checked_pr_create_is_exact_verified_and_non_draft(repository, capsys):
    calls = []
    head = "refactor/2a1-governance-eligibility"
    sha = "a" * 40
    outputs = [
        (0, json.dumps({"full_name": "PPiquemal/rsip"}), ""),
        (0, json.dumps({"name": "main"}), ""),
        (0, "[]", ""),
        (0, json.dumps({
            "ref": f"refs/heads/{head}",
            "object": {"type": "commit", "sha": sha},
        }), ""),
        (0, "https://github.com/PPiquemal/rsip/pull/129\n", ""),
        (0, json.dumps({
            "number": 129,
            "html_url": "https://github.com/PPiquemal/rsip/pull/129",
            "state": "open",
            "draft": False,
            "base": {"ref": "main", "repo": {"full_name": "PPiquemal/rsip"}},
            "head": {
                "ref": head,
                "sha": sha,
                "repo": {"full_name": "PPiquemal/rsip"},
            },
        }), ""),
    ]

    def gh(args):
        calls.append(args)
        return outputs.pop(0)

    result = policy.main(
        [
            "--repository", repository,
            "--operation", "checked_pr_create",
            "--create-pr",
            "--base", "main",
            "--head", head,
            "--ref", f"refs/heads/{head}",
            "--expected-sha", sha,
        ],
        gh=gh,
    )

    assert result == 0
    writes = [call for call in calls if call[:2] == ["pr", "create"]]
    assert writes == [[
        "pr", "create",
        "--repo", "github.com/PPiquemal/rsip",
        "--base", "main",
        "--head", f"PPiquemal:{head}",
        "--fill",
    ]]
    assert "--draft" not in writes[0]
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["pr_number"] == 129
    assert receipt["sha"] == sha


def test_checked_pr_readback_mismatch_is_terminal_without_retry():
    calls = []
    head = "feature/readback"
    sha = "c" * 40
    outputs = [
        (0, json.dumps({"full_name": "PPiquemal/rsip"}), ""),
        (0, json.dumps({"name": "main"}), ""),
        (0, "[]", ""),
        (0, json.dumps({
            "ref": f"refs/heads/{head}",
            "object": {"type": "commit", "sha": sha},
        }), ""),
        (0, "https://github.com/PPiquemal/rsip/pull/130\n", ""),
        (0, json.dumps({
            "number": 130,
            "html_url": "https://github.com/PPiquemal/rsip/pull/130",
            "state": "open",
            "draft": False,
            "base": {"ref": "main", "repo": {"full_name": "PPiquemal/rsip"}},
            "head": {
                "ref": head,
                "sha": "d" * 40,
                "repo": {"full_name": "PPiquemal/rsip"},
            },
        }), ""),
    ]

    def gh(args):
        calls.append(args)
        return outputs.pop(0)

    with pytest.raises(policy.PublicationBlocked, match="created PR does not match"):
        policy.execute_checked_pr_create(
            gh,
            repository="PPiquemal/rsip",
            base="main",
            head=head,
            ref=f"refs/heads/{head}",
            expected_sha=sha,
        )

    assert sum(call[:2] == ["pr", "create"] for call in calls) == 1


def test_workflow_cli_checked_pr_create_is_bounded_to_rsip(capsys):
    def gh(_args):
        pytest.fail("gh invoked for a repository outside the bounded RSIP executor")

    assert policy.main(
        [
            "--repository", "PPiquemal/hermes-agent",
            "--operation", "checked_pr_create",
            "--create-pr", "--base", "main", "--head", "feature/unsafe",
        ],
        gh=gh,
    ) == 1
    assert "BLOCKED" in capsys.readouterr().out


def test_workflow_cli_checked_pr_create_does_not_run_gh_when_policy_rejects(capsys):
    def gh(_args):
        pytest.fail("gh invoked before policy authorization")

    assert policy.main(
        [
            "--repository", "NousResearch/hermes-agent",
            "--operation", "checked_pr_create",
            "--create-pr", "--base", "main", "--head", "feature/unsafe",
        ],
        gh=gh,
    ) == 1
    assert "BLOCKED" in capsys.readouterr().out


def test_workflow_cli_checked_pr_create_failure_is_not_retried(capsys):
    calls = []
    head = "feature/unsafe"
    sha = "b" * 40
    outputs = [
        (0, json.dumps({"full_name": "PPiquemal/rsip"}), ""),
        (0, json.dumps({"name": "main"}), ""),
        (0, "[]", ""),
        (0, json.dumps({
            "ref": f"refs/heads/{head}",
            "object": {"type": "commit", "sha": sha},
        }), ""),
        (1, "", "denied"),
    ]

    def gh(args):
        calls.append(args)
        return outputs.pop(0)

    assert policy.main(
        [
            "--repository", "PPiquemal/rsip",
            "--operation", "checked_pr_create",
            "--create-pr", "--base", "main", "--head", head,
            "--ref", f"refs/heads/{head}", "--expected-sha", sha,
        ],
        gh=gh,
    ) == 1
    assert sum(call[:2] == ["pr", "create"] for call in calls) == 1
    assert "BLOCKED" in capsys.readouterr().out


@pytest.mark.parametrize(
    "arguments",
    [
        ["--repository", "PPiquemal/rsip", "--operation", "checked_branch_push",
         "--create-pr", "--base", "main", "--head", "feature/unsafe"],
        ["--repository", "PPiquemal/rsip", "--operation", "checked_pr_create",
         "--create-pr", "--base", "develop", "--head", "feature/unsafe"],
        ["--repository", "PPiquemal/rsip", "--operation", "checked_pr_create",
         "--create-pr", "--base", "main", "--head", "main"],
        ["--repository", "PPiquemal/rsip", "--operation", "checked_pr_create",
         "--create-pr", "--base", "main", "--head", "feature/../unsafe"],
    ],
)
def test_workflow_cli_checked_pr_create_rejects_wrong_operation_base_or_head(arguments, capsys):
    def gh(_args):
        pytest.fail("gh invoked before complete PR validation")

    assert policy.main(arguments, gh=gh) == 1
    assert "BLOCKED" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("target", "canonical"),
    [
        ("PPiquemal/rsip", "PPiquemal/rsip"),
        ("github.com/PPiquemal/rsip", "PPiquemal/rsip"),
    ],
)
def test_repository_target_parser_accepts_only_canonical_github_identity(target, canonical):
    assert policy.canonical_repository_target(target) == canonical


@pytest.mark.parametrize(
    "target",
    [
        "github.example/PPiquemal/rsip",
        "https://github.com/PPiquemal/rsip",
        "git@github.com:PPiquemal/rsip.git",
        "github.com/PPiquemal/rsip/extra",
        " github.com/PPiquemal/rsip",
    ],
)
def test_repository_target_parser_rejects_host_and_protocol_tricks(target):
    with pytest.raises(policy.PublicationBlocked, match="BLOCKED"):
        policy.canonical_repository_target(target)


def test_policy_load_logs_and_retains_original_local_cause(monkeypatch, caplog):
    missing = FileNotFoundError("missing publication_policy.json")

    def fail_read(_self, **_kwargs):
        raise missing

    monkeypatch.setattr(Path, "read_text", fail_read)
    with caplog.at_level(logging.ERROR), pytest.raises(policy.PublicationBlocked) as caught:
        policy.load_policy()

    assert caught.value.__cause__ is missing
    assert "missing publication_policy.json" in caplog.text


def test_publication_policy_json_is_declared_as_package_data():
    pyproject = (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    assert '"publication_policy.json"' in pyproject


def test_checked_branch_push_cannot_target_protected_base_branch():
    def git(args):
        outputs = {
            ("config", "--get-all", "remote.fork.pushurl"): (1, "", ""),
            ("config", "--get-all", "remote.fork.url"): (
                0, "https://github.com/PPiquemal/hermes-agent.git\n", "",
            ),
            ("remote", "get-url", "--push", "--all", "fork"): (
                0, "https://github.com/PPiquemal/hermes-agent.git\n", "",
            ),
            ("rev-parse", "--verify", "refs/heads/main^{commit}"): (0, "a" * 40, ""),
        }
        if args[:2] == ["config", "--get-regexp"]:
            return 1, "", ""
        if args[0] == "check-ref-format":
            return 0, "", ""
        return outputs[tuple(args)]

    with pytest.raises(policy.PublicationBlocked, match="base branch"):
        policy.resolve_push_plan(
            git,
            repository="PPiquemal/hermes-agent",
            operation="hermes_branch",
            branch="main",
        )


def test_update_main_sync_requires_main_source_branch():
    def git(args):
        outputs = {
            ("config", "--get-all", "remote.origin.pushurl"): (1, "", ""),
            ("config", "--get-all", "remote.origin.url"): (
                0, "https://github.com/PPiquemal/hermes-agent.git\n", "",
            ),
            ("remote", "get-url", "--push", "--all", "origin"): (
                0, "https://github.com/PPiquemal/hermes-agent.git\n", "",
            ),
            ("rev-parse", "--verify", "refs/heads/feature/unsafe^{commit}"): (
                0, "b" * 40, "",
            ),
        }
        if args[:2] == ["config", "--get-regexp"]:
            return 1, "", ""
        if args[0] == "check-ref-format":
            return 0, "", ""
        return outputs[tuple(args)]

    with pytest.raises(policy.PublicationBlocked, match="main-to-main"):
        policy.resolve_push_plan(
            git,
            repository="PPiquemal/hermes-agent",
            operation="update",
            remote="origin",
            branch="feature/unsafe",
            destination_branch="main",
        )
