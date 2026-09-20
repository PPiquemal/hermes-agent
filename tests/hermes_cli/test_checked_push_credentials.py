"""Checked HTTPS publication credentials and exact-ref receipts."""

from __future__ import annotations

import json
import subprocess

import pytest

from hermes_cli import publication_policy as policy


_REPOSITORY = "PPiquemal/hermes-agent"
_BRANCH = "security/checked-workflow-dispatch"
_SHA = "1" * 40
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
