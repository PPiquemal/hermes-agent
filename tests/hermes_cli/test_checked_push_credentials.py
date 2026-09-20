"""Checked HTTPS publication credentials and exact-ref receipts."""

from __future__ import annotations

import json
import subprocess

import pytest

from hermes_cli import publication_policy as policy


_REPOSITORY = "PPiquemal/hermes-agent"
_BRANCH = "security/checked-workflow-dispatch"
_SHA = "1" * 40
_EXPECTED_REMOTE_SHA = "f453330405a18147fdd04a1a54fc2ef3c364a606"
_NEW_LOCAL_SHA = "b9b99430731de58ea68723b53b1660e6cac9803a"
_GH = "/opt/hermes/bin/gh"
_ORIGINAL_GH_VALIDATOR = policy.validate_gh_executable_path


@pytest.fixture(autouse=True)
def _validated_fake_gh_path(monkeypatch):
    def validate(path, **_):
        if path != _GH:
            raise policy.blocked("unexpected test gh path")
        return path

    monkeypatch.setattr(policy, "validate_gh_executable_path", validate)


def _plan() -> policy.PushPlan:
    return policy.PushPlan(
        repository=_REPOSITORY,
        operation="checked_branch_push",
        url="https://github.com/PPiquemal/hermes-agent.git",
        branch=_BRANCH,
        sha=_SHA,
        base="main",
    )


def _update_plan() -> policy.PushPlan:
    return policy.PushPlan(
        repository=_REPOSITORY,
        operation="checked_branch_push",
        url="https://github.com/PPiquemal/hermes-agent.git",
        branch=_BRANCH,
        sha=_NEW_LOCAL_SHA,
        base="main",
        expected_remote_sha=_EXPECTED_REMOTE_SHA,
    )


def _identity(login: str = "PPiquemal") -> dict:
    return {"login": login}


def _repository(push: bool = True) -> dict:
    return {"full_name": _REPOSITORY, "permissions": {"push": push}}


def _ref(sha: str = _SHA) -> dict:
    return {
        "ref": f"refs/heads/{_BRANCH}",
        "object": {"type": "commit", "sha": sha},
    }


_MISSING = (
    1,
    '{"message":"Not Found","status":"404"}',
    "gh: Not Found (HTTP 404)",
)


class ScriptedGh:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []

    def __call__(self, args):
        self.calls.append(args)
        output = self.outputs.pop(0)
        if isinstance(output, tuple):
            return output
        return 0, json.dumps(output), ""


def _credential_ok(paths):
    def check(path):
        paths.append(path)
    return check


def _recording_git(calls):
    def git(args):
        calls.append(args)
        return 99, "", "unexpected git invocation"
    return git


def test_valid_authenticated_gh_helper_pushes_once_and_reads_back_exact_sha():
    gh = ScriptedGh([_identity(), _repository(), _MISSING, _ref()])
    git_calls = []
    credential_paths = []

    def git(args):
        git_calls.append(args)
        return 0, "", ""

    receipt = policy.execute_checked_push(
        git,
        gh,
        _plan(),
        gh_path=_GH,
        credential_check=_credential_ok(credential_paths),
    )

    assert credential_paths == [_GH]
    assert len(git_calls) == 1
    command = git_calls[0]
    assert command[:4] == [
        "-c", "credential.helper=",
        "-c", f"credential.helper=!{_GH} auth git-credential",
    ]
    assert "credential.helper=store" not in command
    assert command[-2:] == [
        "https://github.com/PPiquemal/hermes-agent.git",
        f"{_SHA}:refs/heads/{_BRANCH}",
    ]
    assert receipt == {
        "repository": _REPOSITORY,
        "ref": f"refs/heads/{_BRANCH}",
        "sha": _SHA,
        "remote_url": "https://github.com/PPiquemal/hermes-agent.git",
        "result": "pushed",
        "write_performed": True,
        "readback_verified": True,
    }


def test_missing_credential_fails_before_git_push():
    gh = ScriptedGh([_identity(), _repository()])
    git_calls = []

    def missing(_):
        raise policy.blocked("CREDENTIAL_UNAVAILABLE: no credential")

    with pytest.raises(policy.PublicationBlocked, match="CREDENTIAL_UNAVAILABLE"):
        policy.execute_checked_push(
            _recording_git(git_calls),
            gh,
            _plan(),
            gh_path=_GH,
            credential_check=missing,
        )

    assert git_calls == []


def test_wrong_authenticated_identity_fails_before_credential_or_push():
    gh = ScriptedGh([_identity("other-user")])
    credential_paths = []
    git_calls = []

    with pytest.raises(policy.PublicationBlocked, match="GITHUB_IDENTITY_MISMATCH"):
        policy.execute_checked_push(
            _recording_git(git_calls),
            gh,
            _plan(),
            gh_path=_GH,
            credential_check=_credential_ok(credential_paths),
        )

    assert credential_paths == []
    assert git_calls == []


def test_insufficient_repository_permission_fails_before_credential_or_push():
    gh = ScriptedGh([_identity(), _repository(push=False)])
    credential_paths = []
    git_calls = []

    with pytest.raises(policy.PublicationBlocked, match="GITHUB_PUSH_PERMISSION_DENIED"):
        policy.execute_checked_push(
            _recording_git(git_calls),
            gh,
            _plan(),
            gh_path=_GH,
            credential_check=_credential_ok(credential_paths),
        )

    assert credential_paths == []
    assert git_calls == []


def test_checked_hermes_push_rejects_ssh_destination_before_write():
    with pytest.raises(policy.PublicationBlocked, match="requires the exact authorized HTTPS"):
        policy.require_push_url(
            "git@github.com:PPiquemal/hermes-agent.git",
            _REPOSITORY,
            "checked_branch_push",
        )


def test_git_write_failure_preserves_sanitized_status_and_stderr_without_token():
    token = "opaque-sensitive-token-123"
    evidence = "remote rejected " + "Author" + "ization: " + "Bear" + "er " + token
    gh = ScriptedGh([_identity(), _repository(), _MISSING])

    with pytest.raises(policy.PublicationBlocked) as caught:
        policy.execute_checked_push(
            lambda _: (23, "", evidence),
            gh,
            _plan(),
            gh_path=_GH,
            credential_check=lambda _: None,
        )

    message = str(caught.value)
    assert "GIT_PUSH_FAILED" in message
    assert "exit_status=23" in message
    assert "remote rejected" in message
    assert "[REDACTED]" in message
    assert token not in message


def test_sanitizer_redacts_raw_basic_credential_value():
    secret = "Z2l0OnJldXNhYmxlLXRva2Vu"
    evidence = "Author" + "ization: " + "Bas" + "ic " + secret

    sanitized = policy.sanitize_publication_evidence(evidence)

    assert secret not in sanitized
    assert "[REDACTED]" in sanitized


@pytest.mark.parametrize(
    ("field", "separator", "secret"),
    [
        ("token", "=", "opaque-reusable-token"),
        ("access_token", ': "', "opaque-access-token"),
        ("client_secret", "=", "opaque-client-secret"),
    ],
)
def test_sanitizer_redacts_named_secret_forms(field, separator, secret):
    evidence = field + separator + secret
    sanitized = policy.sanitize_publication_evidence(evidence)
    assert secret not in sanitized
    assert "[REDACTED]" in sanitized


def test_receipt_and_push_arguments_never_contain_a_credential_token():
    token = "github_pat_" + "B" * 40
    gh = ScriptedGh([_identity(), _repository(), _MISSING, _ref()])
    git_calls = []

    receipt = policy.execute_checked_push(
        lambda args: (git_calls.append(args) or (0, "", "")),
        gh,
        _plan(),
        gh_path=_GH,
        credential_check=lambda _: None,
    )

    serialized = json.dumps({"receipt": receipt, "argv": git_calls})
    assert token not in serialized
    assert "password=" not in serialized
    assert "credential.helper=store" not in serialized


def test_conflicting_existing_ref_is_blocked_without_push():
    conflicting = "2" * 40
    gh = ScriptedGh([_identity(), _repository(), _ref(conflicting)])
    git_calls = []

    with pytest.raises(policy.PublicationBlocked, match="REMOTE_REF_CONFLICT"):
        policy.execute_checked_push(
            _recording_git(git_calls),
            gh,
            _plan(),
            gh_path=_GH,
            credential_check=lambda _: None,
        )

    assert git_calls == []


def test_existing_exact_ref_is_verified_success_without_push():
    gh = ScriptedGh([_identity(), _repository(), _ref()])
    git_calls = []

    receipt = policy.execute_checked_push(
        _recording_git(git_calls),
        gh,
        _plan(),
        gh_path=_GH,
        credential_check=lambda _: None,
    )

    assert git_calls == []
    assert receipt["result"] == "already_present"
    assert receipt["write_performed"] is False
    assert receipt["sha"] == _SHA


def test_post_push_readback_failure_is_terminal_without_second_write():
    gh = ScriptedGh([
        _identity(),
        _repository(),
        _MISSING,
        (1, "", '{"status":"500"}\ngh: server error (HTTP 500)'),
    ])
    git_calls = []

    with pytest.raises(policy.PublicationBlocked, match="REMOTE_REF_READBACK_FAILED"):
        policy.execute_checked_push(
            lambda args: (git_calls.append(args) or (0, "", "")),
            gh,
            _plan(),
            gh_path=_GH,
            credential_check=lambda _: None,
        )

    assert len(git_calls) == 1


def test_ambiguous_404_text_cannot_be_treated_as_an_absent_ref():
    gh = ScriptedGh([
        _identity(),
        _repository(),
        (
            1,
            '{"message":"server error","status":"500"}',
            "gh: Internal Server Error (HTTP 500); cached HTTP 404",
        ),
    ])
    git_calls = []

    with pytest.raises(policy.PublicationBlocked, match="REMOTE_REF_PREFLIGHT_FAILED"):
        policy.execute_checked_push(
            _recording_git(git_calls),
            gh,
            _plan(),
            gh_path=_GH,
            credential_check=lambda _: None,
        )

    assert git_calls == []


def test_post_push_readback_sha_mismatch_is_terminal_without_second_write():
    gh = ScriptedGh([_identity(), _repository(), _MISSING, _ref("3" * 40)])
    git_calls = []

    with pytest.raises(policy.PublicationBlocked, match="REMOTE_REF_READBACK_MISMATCH"):
        policy.execute_checked_push(
            lambda args: (git_calls.append(args) or (0, "", "")),
            gh,
            _plan(),
            gh_path=_GH,
            credential_check=lambda _: None,
        )

    assert len(git_calls) == 1


def test_credential_probe_accepts_complete_helper_response_without_leaking_token(capsys):
    token = "gho_" + "C" * 40

    def run(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=f"username=x-access-token\npassword={token}\n",
            stderr="",
        )

    policy.validate_gh_credential(_GH, run=run)
    assert token not in capsys.readouterr().out


def test_credential_probe_requires_username_and_password_and_keeps_prompts_disabled():
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout="username=x-access-token\n", stderr="")

    with pytest.raises(policy.PublicationBlocked, match="CREDENTIAL_UNAVAILABLE"):
        policy.validate_gh_credential(_GH, run=run)

    argv, kwargs = calls[0]
    assert argv == [_GH, "auth", "git-credential", "get"]
    assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert kwargs["env"]["GCM_INTERACTIVE"] == "Never"


def test_gh_executable_is_resolved_to_an_absolute_validated_gh(tmp_path):
    executable = tmp_path / "gh"
    executable.write_text("#!/bin/sh\necho 'gh version 2.99.0'\n", encoding="utf-8")
    executable.chmod(0o755)

    assert _ORIGINAL_GH_VALIDATOR(str(executable)) == str(executable.resolve())


def test_arbitrary_absolute_executable_is_rejected_as_gh(tmp_path):
    executable = tmp_path / "not-gh"
    executable.write_text("#!/bin/sh\necho 'not github cli'\n", encoding="utf-8")
    executable.chmod(0o755)

    with pytest.raises(policy.PublicationBlocked, match="does not identify as GitHub CLI"):
        _ORIGINAL_GH_VALIDATOR(str(executable))


def test_gh_symlink_resolution_loop_fails_closed(monkeypatch):
    def loop(*_, **__):
        raise RuntimeError("Symlink loop")

    monkeypatch.setattr(policy.Path, "resolve", loop)
    with pytest.raises(policy.PublicationBlocked, match="executable cannot be resolved"):
        _ORIGINAL_GH_VALIDATOR("/tmp/looped-gh")


class FastForwardGit:
    def __init__(self, *, expected_present=True, descendant=True, push_result=(0, "", "")):
        self.expected_present = expected_present
        self.descendant = descendant
        self.push_result = push_result
        self.calls = []

    def __call__(self, args):
        self.calls.append(args)
        if args == ["rev-parse", "--verify", f"{_EXPECTED_REMOTE_SHA}^{{commit}}"]:
            if self.expected_present:
                return 0, _EXPECTED_REMOTE_SHA, ""
            return 128, "", "unknown revision"
        if args == ["rev-parse", "--verify", f"{_NEW_LOCAL_SHA}^{{commit}}"]:
            return 0, _NEW_LOCAL_SHA, ""
        if args == ["symbolic-ref", "--quiet", "--short", "HEAD"]:
            return 0, _BRANCH, ""
        if args == ["rev-parse", "--verify", f"refs/heads/{_BRANCH}^{{commit}}"]:
            return 0, _NEW_LOCAL_SHA, ""
        if args == ["merge-base", "--is-ancestor", _EXPECTED_REMOTE_SHA, _NEW_LOCAL_SHA]:
            return (0, "", "") if self.descendant else (1, "", "")
        if args == ["merge-base", "--is-ancestor", _NEW_LOCAL_SHA, _NEW_LOCAL_SHA]:
            return 0, "", ""
        if "push" in args:
            return self.push_result
        raise AssertionError(f"unexpected git call: {args}")

    @property
    def pushes(self):
        return [args for args in self.calls if "push" in args]


def test_checked_fast_forward_update_pushes_exact_ref_once_and_reads_back_new_sha():
    git = FastForwardGit()
    gh = ScriptedGh([
        _identity(),
        _repository(),
        _ref(_EXPECTED_REMOTE_SHA),
        _ref(_EXPECTED_REMOTE_SHA),
        _ref(_NEW_LOCAL_SHA),
    ])

    receipt = policy.execute_checked_push(
        git,
        gh,
        _update_plan(),
        gh_path=_GH,
        credential_check=lambda _: None,
    )

    assert len(git.pushes) == 1
    command = git.pushes[0]
    assert command[-1] == f"{_NEW_LOCAL_SHA}:refs/heads/{_BRANCH}"
    assert any(argument.startswith("core.hooksPath=/") for argument in command)
    assert not any(argument.startswith("--force") for argument in command)
    assert "--delete" not in command
    assert receipt["expected_remote_sha"] == _EXPECTED_REMOTE_SHA
    assert receipt["remote_readback_sha"] == _NEW_LOCAL_SHA
    assert receipt["result"] == "fast_forward_updated"


def test_pre_push_compare_and_swap_hook_accepts_only_expected_advertised_sha(tmp_path):
    hook = policy._install_expected_remote_hook(str(tmp_path), _BRANCH, _EXPECTED_REMOTE_SHA)
    exact = subprocess.run(
        [hook, "fork", "https://github.com/PPiquemal/hermes-agent.git"],
        input=(
            f"refs/heads/{_BRANCH} {_NEW_LOCAL_SHA} "
            f"refs/heads/{_BRANCH} {_EXPECTED_REMOTE_SHA}\n"
        ),
        capture_output=True,
        text=True,
    )
    moved = subprocess.run(
        [hook, "fork", "https://github.com/PPiquemal/hermes-agent.git"],
        input=(
            f"refs/heads/{_BRANCH} {_NEW_LOCAL_SHA} "
            f"refs/heads/{_BRANCH} {'8' * 40}\n"
        ),
        capture_output=True,
        text=True,
    )

    assert exact.returncode == 0
    assert moved.returncode == 42
    assert "remote ref moved" in moved.stderr


def test_fast_forward_executor_rejects_crafted_repository_before_remote_checks():
    plan = policy.PushPlan(
        repository="NousResearch/hermes-agent",
        operation="checked_branch_push",
        url="https://github.com/NousResearch/hermes-agent.git",
        branch=_BRANCH,
        sha=_NEW_LOCAL_SHA,
        base="main",
        expected_remote_sha=_EXPECTED_REMOTE_SHA,
    )
    gh = ScriptedGh([])

    with pytest.raises(policy.PublicationBlocked, match="CHECKED_PUSH_NOT_AUTHORIZED"):
        policy.execute_checked_push(
            FastForwardGit(), gh, plan, gh_path=_GH, credential_check=lambda _: None,
        )

    assert gh.calls == []


def test_fast_forward_executor_rechecks_target_reachability_before_remote_checks():
    base_git = FastForwardGit()

    def git(args):
        if args == ["rev-parse", "--verify", f"refs/heads/{_BRANCH}^{{commit}}"]:
            return 0, "8" * 40, ""
        if args == ["merge-base", "--is-ancestor", _NEW_LOCAL_SHA, "8" * 40]:
            return 1, "", ""
        return base_git(args)

    gh = ScriptedGh([])
    with pytest.raises(policy.PublicationBlocked, match="LOCAL_NEW_SHA_UNREACHABLE"):
        policy.execute_checked_push(
            git, gh, _update_plan(), gh_path=_GH, credential_check=lambda _: None,
        )

    assert gh.calls == []


def test_fast_forward_executor_requires_destination_branch_to_be_checked_out():
    base_git = FastForwardGit()

    def git(args):
        if args == ["symbolic-ref", "--quiet", "--short", "HEAD"]:
            return 0, "another-branch", ""
        return base_git(args)

    gh = ScriptedGh([])
    with pytest.raises(policy.PublicationBlocked, match="destination branch is not checked out"):
        policy.execute_checked_push(
            git, gh, _update_plan(), gh_path=_GH, credential_check=lambda _: None,
        )

    assert gh.calls == []


def test_checked_fast_forward_rejects_missing_expected_local_sha_before_remote_checks():
    git = FastForwardGit(expected_present=False)
    gh = ScriptedGh([])

    with pytest.raises(policy.PublicationBlocked, match="LOCAL_EXPECTED_SHA_MISSING"):
        policy.execute_checked_push(
            git, gh, _update_plan(), gh_path=_GH, credential_check=lambda _: None,
        )

    assert git.pushes == []
    assert gh.calls == []


def test_checked_fast_forward_rejects_local_divergence_before_remote_checks():
    git = FastForwardGit(descendant=False)
    gh = ScriptedGh([])

    with pytest.raises(policy.PublicationBlocked, match="LOCAL_FAST_FORWARD_REQUIRED"):
        policy.execute_checked_push(
            git, gh, _update_plan(), gh_path=_GH, credential_check=lambda _: None,
        )

    assert git.pushes == []
    assert gh.calls == []


def test_checked_fast_forward_rejects_missing_expected_remote_ref_without_push():
    git = FastForwardGit()
    gh = ScriptedGh([_identity(), _repository(), _MISSING])

    with pytest.raises(policy.PublicationBlocked, match="REMOTE_EXPECTED_SHA_MISSING"):
        policy.execute_checked_push(
            git, gh, _update_plan(), gh_path=_GH, credential_check=lambda _: None,
        )

    assert git.pushes == []


def test_checked_fast_forward_rejects_remote_movement_without_push():
    git = FastForwardGit()
    gh = ScriptedGh([_identity(), _repository(), _ref("4" * 40)])

    with pytest.raises(policy.PublicationBlocked, match="REMOTE_REF_MOVED"):
        policy.execute_checked_push(
            git, gh, _update_plan(), gh_path=_GH, credential_check=lambda _: None,
        )

    assert git.pushes == []


def test_checked_fast_forward_rereads_remote_immediately_before_push():
    git = FastForwardGit()
    gh = ScriptedGh([
        _identity(),
        _repository(),
        _ref(_EXPECTED_REMOTE_SHA),
        _ref("5" * 40),
    ])

    with pytest.raises(policy.PublicationBlocked, match="REMOTE_REF_MOVED"):
        policy.execute_checked_push(
            git, gh, _update_plan(), gh_path=_GH, credential_check=lambda _: None,
        )

    assert git.pushes == []


def test_checked_fast_forward_rejects_post_push_readback_mismatch():
    git = FastForwardGit()
    gh = ScriptedGh([
        _identity(),
        _repository(),
        _ref(_EXPECTED_REMOTE_SHA),
        _ref(_EXPECTED_REMOTE_SHA),
        _ref("6" * 40),
    ])

    with pytest.raises(policy.PublicationBlocked, match="REMOTE_REF_READBACK_MISMATCH"):
        policy.execute_checked_push(
            git, gh, _update_plan(), gh_path=_GH, credential_check=lambda _: None,
        )

    assert len(git.pushes) == 1


def _fast_forward_plan_git(*, target_reachable=True):
    branch_head = "7" * 40

    def git(args):
        values = {
            ("config", "--get-all", "remote.fork.pushurl"): (1, "", ""),
            ("config", "--get-all", "remote.fork.url"): (
                0, "https://github.com/PPiquemal/hermes-agent.git\n", "",
            ),
            ("remote", "get-url", "--push", "--all", "fork"): (
                0, "https://github.com/PPiquemal/hermes-agent.git\n", "",
            ),
            ("symbolic-ref", "--quiet", "--short", "HEAD"): (0, f"{_BRANCH}\n", ""),
            ("rev-parse", "--verify", f"refs/heads/{_BRANCH}^{{commit}}"): (
                0, branch_head, "",
            ),
            ("rev-parse", "--verify", f"{_EXPECTED_REMOTE_SHA}^{{commit}}"): (
                0, _EXPECTED_REMOTE_SHA, "",
            ),
            ("rev-parse", "--verify", f"{_NEW_LOCAL_SHA}^{{commit}}"): (
                0, _NEW_LOCAL_SHA, "",
            ),
            ("merge-base", "--is-ancestor", _EXPECTED_REMOTE_SHA, _NEW_LOCAL_SHA): (
                0, "", "",
            ),
            ("merge-base", "--is-ancestor", _NEW_LOCAL_SHA, branch_head): (
                0 if target_reachable else 1, "", "",
            ),
        }
        if args[:2] == ["config", "--get-regexp"]:
            return 1, "", ""
        if args[0] == "check-ref-format":
            return 0, "", ""
        return values[tuple(args)]

    return git


def test_resolve_push_plan_binds_expected_remote_and_explicit_new_sha():
    plan = policy.resolve_push_plan(
        _fast_forward_plan_git(),
        repository=_REPOSITORY,
        operation="checked_branch_push",
        remote="fork",
        destination_branch=_BRANCH,
        expected_remote_sha=_EXPECTED_REMOTE_SHA,
        new_sha=_NEW_LOCAL_SHA,
    )

    assert plan.sha == _NEW_LOCAL_SHA
    assert plan.expected_remote_sha == _EXPECTED_REMOTE_SHA
    assert plan.branch == _BRANCH


def test_resolve_push_plan_rejects_new_sha_not_reachable_from_checked_out_branch():
    with pytest.raises(policy.PublicationBlocked, match="LOCAL_NEW_SHA_UNREACHABLE"):
        policy.resolve_push_plan(
            _fast_forward_plan_git(target_reachable=False),
            repository=_REPOSITORY,
            operation="checked_branch_push",
            remote="fork",
            destination_branch=_BRANCH,
            expected_remote_sha=_EXPECTED_REMOTE_SHA,
            new_sha=_NEW_LOCAL_SHA,
        )


def test_cli_checked_fast_forward_binds_both_exact_sha_arguments(capsys):
    read_git = _fast_forward_plan_git()
    pushes = []

    def git(args):
        if "push" in args:
            pushes.append(args)
            return 0, "", ""
        return read_git(args)

    gh = ScriptedGh([
        _identity(),
        _repository(),
        _ref(_EXPECTED_REMOTE_SHA),
        _ref(_EXPECTED_REMOTE_SHA),
        _ref(_NEW_LOCAL_SHA),
    ])
    result = policy.main(
        [
            "--repository", _REPOSITORY,
            "--operation", "checked_branch_push",
            "--push",
            "--remote", "fork",
            "--branch", _BRANCH,
            "--expected-sha", _EXPECTED_REMOTE_SHA,
            "--new-sha", _NEW_LOCAL_SHA,
        ],
        git=git,
        gh=gh,
        gh_path=_GH,
        credential_check=lambda _: None,
    )

    assert result == 0
    assert len(pushes) == 1
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["expected_remote_sha"] == _EXPECTED_REMOTE_SHA
    assert receipt["sha"] == _NEW_LOCAL_SHA
