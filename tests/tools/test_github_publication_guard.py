"""Terminal publication guard behavior."""

import json
from contextlib import ExitStack
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest


def _install_policy(
    monkeypatch,
    require_repository,
    require_push_url=lambda target, repository, operation: target,
):
    policy = ModuleType("hermes_cli.publication_policy")
    policy.__dict__.update(
        PUBLICATION_INVARIANT="PUBLICATION_INVARIANT",
        canonical_repository_target=lambda target: target.removeprefix("github.com/"),
        require_repository=require_repository,
        require_push_url=require_push_url,
    )
    monkeypatch.setitem(__import__("sys").modules, "hermes_cli.publication_policy", policy)


def _terminal_config():
    return {
        "env_type": "local",
        "timeout": 180,
        "cwd": "/tmp",
        "host_cwd": None,
        "modal_mode": "auto",
        "docker_image": "",
        "singularity_image": "",
        "modal_image": "",
        "daytona_image": "",
    }


def test_historical_forbidden_pr_create_is_blocked_before_terminal_execution(monkeypatch):
    """Known forbidden direct publication cannot reach the terminal backend."""
    from tools.terminal_tool import terminal_tool

    def require_repository(target, operation):
        assert target == "NousResearch/hermes-agent"
        assert operation == "checked_pr_create"
        raise RuntimeError("write forbidden")

    _install_policy(monkeypatch, require_repository)
    env = MagicMock()
    env.execute.return_value = {"output": "unexpected", "returncode": 0}
    env.cwd = "/tmp"
    with ExitStack() as stack:
        stack.enter_context(patch("tools.terminal_tool._get_env_config", return_value=_terminal_config()))
        stack.enter_context(patch("tools.terminal_tool._start_cleanup_thread"))
        stack.enter_context(patch("tools.terminal_tool._active_environments", {"default": env}))
        stack.enter_context(patch("tools.terminal_tool._last_activity", {"default": 0}))
        stack.enter_context(patch("tools.terminal_tool._check_all_guards", return_value={"approved": True}))
        result = json.loads(terminal_tool(
            "gh pr create --repo NousResearch/hermes-agent --base main "
            "--head PPiquemal:fix/kanban-conditional-archive"
        ))

    assert result["status"] == "blocked"
    assert "PUBLICATION_INVARIANT" in result["error"]
    env.execute.assert_not_called()


def test_explicit_authorized_gh_target_passes_policy_check(monkeypatch):
    """The terminal guard delegates an explicit canonical target to the policy."""
    from tools.github_publication_guard import github_publication_block

    seen = []
    _install_policy(monkeypatch, lambda target, operation: seen.append((target, operation)) or target)

    assert github_publication_block(
        "gh pr create --repo PPiquemal/hermes-agent --base main --head fix/guard"
    ) is None
    assert seen == [("PPiquemal/hermes-agent", "checked_pr_create")]


def test_exact_github_host_qualified_rsip_pr_requires_checked_publisher(monkeypatch):
    from tools.github_publication_guard import github_publication_block

    seen = []
    _install_policy(monkeypatch, lambda target, operation: seen.append((target, operation)) or target)

    blocked = github_publication_block(
        "gh pr create --repo github.com/PPiquemal/rsip --base main --head PPiquemal:feature"
    )
    assert blocked is not None and "checked publisher" in blocked.lower()
    assert seen == []


def test_recognized_gh_write_without_explicit_target_is_blocked(monkeypatch):
    """No current-directory resolution is trusted for a direct publication write."""
    from tools.github_publication_guard import github_publication_block

    _install_policy(monkeypatch, lambda target, operation: target)

    blocked = github_publication_block("gh pr create --title guarded")

    assert blocked is not None
    assert "BLOCKED" in blocked
    assert "explicit --repo target" in blocked


def test_direct_push_requires_checked_publisher(monkeypatch):
    from tools.github_publication_guard import github_publication_block

    seen = []
    _install_policy(
        monkeypatch,
        lambda target, operation: target,
        require_push_url=lambda url, repository, operation: seen.append((url, repository, operation)) or url,
    )

    sha = "a" * 40
    blocked = github_publication_block(
        f"git push https://github.com/PPiquemal/hermes-agent {sha}:refs/heads/fix/guard"
    )
    assert blocked is not None and "checked publisher" in blocked.lower()
    assert seen == []


@pytest.mark.parametrize("flag", ["--all", "--mirror", "--tags", "--delete"])
def test_direct_bulk_or_deleting_push_is_blocked(monkeypatch, flag):
    from tools.github_publication_guard import github_publication_block

    _install_policy(
        monkeypatch,
        lambda target, operation: target,
        require_push_url=lambda url, repository, operation: url,
    )
    blocked = github_publication_block(
        f"git push {flag} https://github.com/PPiquemal/hermes-agent"
    )
    assert blocked is not None and "BLOCKED" in blocked


@pytest.mark.parametrize(
    "refspec",
    ["refs/heads/*:refs/heads/*", ":refs/heads/main", "HEAD:refs/tags/v1"],
)
def test_direct_push_requires_one_exact_commit_to_branch_refspec(monkeypatch, refspec):
    from tools.github_publication_guard import github_publication_block

    _install_policy(
        monkeypatch,
        lambda target, operation: target,
        require_push_url=lambda url, repository, operation: url,
    )
    blocked = github_publication_block(
        f"git push https://github.com/PPiquemal/hermes-agent {refspec}"
    )
    assert blocked is not None and "BLOCKED" in blocked


def test_direct_push_to_protected_base_branch_is_blocked(monkeypatch):
    from tools.github_publication_guard import github_publication_block

    _install_policy(
        monkeypatch,
        lambda target, operation: target,
        require_push_url=lambda url, repository, operation: url,
    )
    blocked = github_publication_block(
        f"git push https://github.com/PPiquemal/hermes-agent {'a' * 40}:refs/heads/main"
    )
    assert blocked is not None and "base branch" in blocked.lower()


def test_rsip_direct_pr_create_and_merge_are_both_blocked(monkeypatch):
    from tools.github_publication_guard import github_publication_block

    allowed = {("PPiquemal/rsip", "checked_pr_create")}

    def require_repository(target, operation):
        if (target, operation) not in allowed:
            raise RuntimeError("operation forbidden")
        return target

    _install_policy(monkeypatch, require_repository)
    create_blocked = github_publication_block(
        "gh pr create --repo PPiquemal/rsip --base main --head PPiquemal:feature"
    )
    merge_blocked = github_publication_block("gh pr merge --repo PPiquemal/rsip 123")
    assert create_blocked is not None and "checked publisher" in create_blocked.lower()
    assert merge_blocked is not None and "BLOCKED" in merge_blocked


@pytest.mark.parametrize("key", [
    "url.https://github.com/evil/.pushInsteadOf",
    "url.https://github.com/evil/.insteadOf",
])
def test_git_url_rewrite_configuration_is_always_blocked(monkeypatch, key):
    from tools.github_publication_guard import github_publication_block

    _install_policy(monkeypatch, lambda target, operation: target)
    blocked = github_publication_block(
        f"git config {key} https://github.com/PPiquemal/"
    )
    assert blocked is not None and "BLOCKED" in blocked


def test_rsip_generic_workflow_dispatch_stays_blocked(monkeypatch):
    from tools.github_publication_guard import github_publication_block

    allowed = {
        ("PPiquemal/rsip", "checked_pr_create"),
        ("PPiquemal/rsip", "checked_workflow_dispatch"),
    }

    def require_repository(target, operation):
        if (target, operation) not in allowed:
            raise RuntimeError("operation forbidden")
        return target

    _install_policy(monkeypatch, require_repository)
    commands = [
        "gh workflow run 265670631 --repo PPiquemal/rsip "
        "--ref fix/nightly-regression-auth-memory",
        "gh api --method POST --repo PPiquemal/rsip "
        "repos/PPiquemal/rsip/actions/workflows/265670631/dispatches "
        "-f ref=fix/nightly-regression-auth-memory",
    ]
    for command in commands:
        blocked = github_publication_block(command)
        assert blocked is not None and "BLOCKED" in blocked


def test_destructive_hermes_gh_operation_is_not_generic_publication(monkeypatch):
    from tools.github_publication_guard import github_publication_block

    allowed = {("PPiquemal/hermes-agent", "checked_pr_create")}

    def require_repository(target, operation):
        if (target, operation) not in allowed:
            raise RuntimeError("operation forbidden")
        return target

    _install_policy(monkeypatch, require_repository)
    blocked = github_publication_block(
        "gh repo delete --repo PPiquemal/hermes-agent --yes"
    )
    assert blocked is not None and "BLOCKED" in blocked


def test_gh_api_write_cannot_disagree_with_repo_flag(monkeypatch):
    from tools.github_publication_guard import github_publication_block

    _install_policy(
        monkeypatch,
        lambda target, operation: (_ for _ in ()).throw(RuntimeError("operation forbidden")),
    )
    blocked = github_publication_block(
        "gh api --method POST --repo PPiquemal/hermes-agent "
        "repos/NousResearch/hermes-agent/issues -f title=x"
    )
    assert blocked is not None and "BLOCKED" in blocked


def test_gh_pr_repo_option_before_subcommand_cannot_bypass_operation(monkeypatch):
    from tools.github_publication_guard import github_publication_block

    _install_policy(
        monkeypatch,
        lambda target, operation: (_ for _ in ()).throw(RuntimeError("operation forbidden")),
    )
    blocked = github_publication_block(
        "gh pr --repo PPiquemal/rsip merge 1 --auto"
    )
    assert blocked is not None and "BLOCKED" in blocked


@pytest.mark.parametrize(
    "command",
    [
        "gh pr create --repo PPiquemal/hermes-agent --repo NousResearch/hermes-agent",
        "gh pr create -RPPiquemal/hermes-agent -RNousResearch/hermes-agent",
        "gh pr create --repo PPiquemal/hermes-agent -RNousResearch/hermes-agent",
    ],
)
def test_repeated_gh_repository_options_are_blocked(monkeypatch, command):
    from tools.github_publication_guard import github_publication_block

    _install_policy(monkeypatch, lambda target, operation: target)
    blocked = github_publication_block(command)
    assert blocked is not None and "repository option" in blocked.lower()


def test_gh_api_attached_short_method_cannot_bypass_write_guard(monkeypatch):
    from tools.github_publication_guard import github_publication_block

    _install_policy(
        monkeypatch,
        lambda target, operation: (_ for _ in ()).throw(RuntimeError("operation forbidden")),
    )
    blocked = github_publication_block(
        "gh api -XPOST --repo PPiquemal/hermes-agent "
        "repos/NousResearch/hermes-agent/issues -f title=x"
    )
    assert blocked is not None and "BLOCKED" in blocked


@pytest.mark.parametrize("flag", ["--force", "-f", "--force-with-lease"])
def test_direct_force_push_is_always_blocked(monkeypatch, flag):
    from tools.github_publication_guard import github_publication_block

    _install_policy(
        monkeypatch,
        lambda target, operation: target,
        require_push_url=lambda url, repository, operation: url,
    )
    blocked = github_publication_block(
        f"git push {flag} https://github.com/PPiquemal/hermes-agent HEAD:refs/heads/fix"
    )
    assert blocked is not None and "force" in blocked.lower()


def test_git_global_options_do_not_bypass_ambiguous_push_block(monkeypatch):
    """The checked publisher's `git -c ... push` shape is still a direct push."""
    from tools.github_publication_guard import github_publication_block

    blocked = github_publication_block("git -c push.followTags=false push origin main")

    assert blocked is not None
    assert "BLOCKED" in blocked


def test_shell_wrapper_does_not_bypass_forbidden_pr_target(monkeypatch):
    """The exact historical mutation remains blocked when nested under sh -c."""
    from tools.github_publication_guard import github_publication_block

    _install_policy(monkeypatch, lambda target, operation: (_ for _ in ()).throw(RuntimeError("write forbidden")))

    blocked = github_publication_block(
        "sh -c 'gh pr create --repo NousResearch/hermes-agent --base main "
        "--head PPiquemal:fix/kanban-conditional-archive'"
    )

    assert blocked is not None
    assert "BLOCKED" in blocked


@pytest.mark.parametrize(
    "prefix",
    [
        "env -i PATH=/usr/bin:/bin",
        "env --ignore-environment PATH=/usr/bin:/bin",
        "env -u GH_REPO",
    ],
)
def test_env_options_do_not_hide_forbidden_gh_write(monkeypatch, prefix):
    from tools.github_publication_guard import github_publication_block

    _install_policy(
        monkeypatch,
        lambda target, operation: (_ for _ in ()).throw(RuntimeError("write forbidden")),
    )
    blocked = github_publication_block(
        f"{prefix} gh pr create --repo NousResearch/hermes-agent --fill"
    )
    assert blocked is not None and "BLOCKED" in blocked


def test_env_split_string_is_fail_closed(monkeypatch):
    from tools.github_publication_guard import github_publication_block

    _install_policy(monkeypatch, lambda target, operation: target)
    blocked = github_publication_block(
        "env -S 'git push https://github.com/NousResearch/hermes-agent.git "
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:refs/heads/fix/env-split'"
    )
    assert blocked is not None and "BLOCKED" in blocked


def test_git_dash_c_does_not_bypass_forbidden_push_url(monkeypatch):
    """A worktree selector cannot hide an explicit forbidden destination."""
    from tools.github_publication_guard import github_publication_block

    _install_policy(
        monkeypatch,
        lambda target, operation: target,
        require_push_url=lambda target, repository, operation: (_ for _ in ()).throw(RuntimeError("write forbidden")),
    )

    blocked = github_publication_block(
        "git -C /tmp/worktree push https://github.com/NousResearch/hermes-agent.git HEAD:refs/heads/fix"
    )

    assert blocked is not None
    assert "BLOCKED" in blocked


@pytest.mark.parametrize(
    "command",
    [
        f"command git push https://github.com/PPiquemal/hermes-agent.git {'a' * 40}:refs/heads/fix/wrapped",
        f"FOO=bar git push https://github.com/PPiquemal/hermes-agent.git {'a' * 40}:refs/heads/fix/wrapped",
        f"exec git push https://github.com/PPiquemal/hermes-agent.git {'a' * 40}:refs/heads/fix/wrapped",
        f"sudo git push https://github.com/PPiquemal/hermes-agent.git {'a' * 40}:refs/heads/fix/wrapped",
        f"sudo sh -c 'git push https://github.com/PPiquemal/hermes-agent.git {'a' * 40}:refs/heads/fix/wrapped'",
        "doas sh -c 'gh api --method POST --repo PPiquemal/rsip repos/PPiquemal/rsip/issues -f title=x'",
        f"nice sh -c 'git-push https://github.com/PPiquemal/hermes-agent.git {'a' * 40}:refs/heads/fix/wrapped'",
        f"nohup sh -c 'git push https://github.com/PPiquemal/hermes-agent.git {'a' * 40}:refs/heads/fix/wrapped'",
        f"git.exe push https://github.com/PPiquemal/hermes-agent.git {'a' * 40}:refs/heads/fix/wrapped",
        f"/usr/lib/git-core/git-push https://github.com/PPiquemal/hermes-agent.git {'a' * 40}:refs/heads/fix/wrapped",
        "command gh pr create --repo PPiquemal/rsip --base main --head PPiquemal:fix/wrapped",
        "FOO=bar git config url.https://github.com/evil/.pushInsteadOf https://github.com/PPiquemal/",
    ],
)
def test_standard_wrappers_and_git_push_executable_cannot_bypass_guard(monkeypatch, command):
    from tools.github_publication_guard import github_publication_block

    _install_policy(monkeypatch, lambda target, operation: target)
    blocked = github_publication_block(command)
    assert blocked is not None and "BLOCKED" in blocked


@pytest.mark.parametrize(
    "command",
    [
        "gh api --repo PPiquemal/rsip "
        "repos/PPiquemal/rsip/actions/workflows/265670631/dispatches "
        "-f ref=fix/nightly-regression-auth-memory",
        "gh api graphql --repo PPiquemal/rsip -f query='mutation { viewer { login } }'",
    ],
)
def test_gh_api_payload_flags_are_writes_without_explicit_get(monkeypatch, command):
    from tools.github_publication_guard import github_publication_block

    _install_policy(
        monkeypatch,
        lambda target, operation: (_ for _ in ()).throw(RuntimeError("write forbidden")),
    )
    blocked = github_publication_block(command)
    assert blocked is not None and "BLOCKED" in blocked


def test_gh_api_explicit_get_with_query_fields_remains_read_only(monkeypatch):
    from tools.github_publication_guard import github_publication_block

    _install_policy(monkeypatch, lambda target, operation: target)
    assert github_publication_block(
        "gh api --method GET repos/PPiquemal/rsip/actions/runs -f per_page=1"
    ) is None
