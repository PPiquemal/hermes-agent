"""Exact, operation-scoped GitHub publication policy."""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


logger = logging.getLogger(__name__)


class PublicationBlocked(RuntimeError):
    """A terminal authorization event; callers must not recover with another strategy."""


def blocked(reason: str) -> PublicationBlocked:
    return PublicationBlocked(
        f"BLOCKED: {reason}. Stop publication; a new explicit user authorization is required "
        "before retrying or changing repository, fork, remote, URL, protocol, identity or transport."
    )


def _valid_name(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip()


def canonical_repository_target(target: str) -> str:
    """Return exact OWNER/REPO from a canonical or github.com-qualified target."""
    if not isinstance(target, str) or target != target.strip() or any(c in target for c in "\r\n\0"):
        raise blocked("repository target is malformed or outside the publication whitelist")
    match = re.fullmatch(
        r"(?:github\.com/)?([A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*)",
        target,
    )
    if not match:
        raise blocked("repository target is malformed or outside the publication whitelist")
    return match.group(1)


def load_policy() -> dict:
    """Load and strictly validate the versioned multi-repository policy."""
    try:
        policy = json.loads(Path(__file__).with_suffix(".json").read_text(encoding="utf-8"))
        if not isinstance(policy, dict) or set(policy) != {
            "repositories", "read_only_repositories",
        }:
            raise ValueError("invalid policy schema")
        repositories = policy["repositories"]
        read_only = policy["read_only_repositories"]
        if not isinstance(repositories, dict) or not repositories:
            raise ValueError("invalid repositories")
        if not isinstance(read_only, list) or not read_only or not all(_valid_name(v) for v in read_only):
            raise ValueError("invalid read-only repositories")
        if len(set(read_only)) != len(read_only):
            raise ValueError("duplicate read-only repository")
        for repository, config in repositories.items():
            if not _valid_name(repository) or repository in read_only:
                raise ValueError("invalid writable repository")
            if not isinstance(config, dict) or set(config) != {
                "remote", "base", "operations", "operation_remotes",
                "allow_github_com_urls", "ssh_aliases", "workflows",
            }:
                raise ValueError("invalid repository policy schema")
            if not _valid_name(config["remote"]) or not _valid_name(config["base"]):
                raise ValueError("invalid repository policy values")
            if not isinstance(config["allow_github_com_urls"], bool):
                raise ValueError("invalid GitHub URL policy")
            operations = config["operations"]
            if not isinstance(operations, list) or not operations or not all(_valid_name(v) for v in operations):
                raise ValueError("invalid operations")
            if len(set(operations)) != len(operations):
                raise ValueError("duplicate operation")
            operation_remotes = config["operation_remotes"]
            if not isinstance(operation_remotes, dict):
                raise ValueError("invalid operation remotes")
            if any(
                operation not in operations or not _valid_name(remote)
                for operation, remote in operation_remotes.items()
            ):
                raise ValueError("invalid operation remote")
            workflows = config["workflows"]
            if not isinstance(workflows, dict):
                raise ValueError("invalid workflow policy")
            for operation, workflow in workflows.items():
                if operation not in operations or operation != "checked_workflow_dispatch":
                    raise ValueError("invalid workflow operation")
                if not isinstance(workflow, dict) or set(workflow) != {"id", "name", "path"}:
                    raise ValueError("invalid workflow declaration")
                if (
                    isinstance(workflow["id"], bool)
                    or not isinstance(workflow["id"], int)
                    or workflow["id"] <= 0
                    or not _valid_name(workflow["name"])
                    or not re.fullmatch(r"\.github/workflows/[A-Za-z0-9._-]+\.ya?ml", workflow["path"])
                ):
                    raise ValueError("invalid workflow identity")
            if ("checked_workflow_dispatch" in operations) != (
                "checked_workflow_dispatch" in workflows
            ):
                raise ValueError("workflow operation and declaration disagree")
            if repository == "PPiquemal/rsip":
                if set(operations) != {
                    "checked_branch_push",
                    "checked_pr_create",
                    "checked_workflow_dispatch",
                }:
                    raise ValueError("RSIP operations are not exact")
                if workflows != {
                    "checked_workflow_dispatch": {
                        "id": 265670631,
                        "name": "RSIP Tests",
                        "path": ".github/workflows/test.yml",
                    }
                }:
                    raise ValueError("RSIP workflow policy is not exact")
            elif workflows:
                raise ValueError("workflow dispatch is restricted to RSIP")
            aliases = config["ssh_aliases"]
            if not isinstance(aliases, dict):
                raise ValueError("invalid ssh aliases")
            for alias, destination in aliases.items():
                if not re.fullmatch(r"[A-Za-z0-9._-]+", alias):
                    raise ValueError("invalid ssh alias")
                if not isinstance(destination, dict) or set(destination) != {"hostname", "user"}:
                    raise ValueError("invalid ssh alias destination")
                if not _valid_name(destination["hostname"]) or not _valid_name(destination["user"]):
                    raise ValueError("invalid ssh alias values")
        return policy
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        logger.error("Publication policy load failed: %s", exc, exc_info=True)
        raise blocked("publication policy unavailable") from exc


def repository_policy(target: str, operation: str) -> dict:
    policy = load_policy()
    if not _valid_name(target) or target in policy["read_only_repositories"]:
        raise blocked("repository is missing, read-only or outside the publication whitelist")
    config = policy["repositories"].get(target)
    if config is None:
        raise blocked("repository is missing, read-only or outside the publication whitelist")
    if not _valid_name(operation) or operation not in config["operations"]:
        raise blocked(f"operation {operation!r} is not authorized for repository {target!r}")
    return config


def require_repository(target: str, operation: str) -> str:
    repository_policy(target, operation)
    return target


def _valid_branch(value: object) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", value):
        return False
    if value.endswith(("/", ".", ".lock")) or ".." in value or "//" in value or "@{" in value:
        return False
    return all(part and not part.startswith(".") and not part.endswith(".lock") for part in value.split("/"))


def checked_pr_argv(repository: str, base: str, head: str) -> list[str]:
    """Build one exact, non-draft checked PR command after policy validation."""
    canonical = canonical_repository_target(repository)
    config = repository_policy(canonical, "checked_pr_create")
    if base != config["base"]:
        raise blocked("PR creation requires the authorized base branch")
    if not _valid_branch(head) or head == base:
        raise blocked("PR creation requires an explicit valid non-base head branch")
    return [
        "pr", "create", "--repo", f"github.com/{canonical}",
        "--base", base,
        "--head", f"{canonical.split('/')[0]}:{head}",
        "--fill",
    ]


def _system_ssh_config(alias: str) -> dict[str, str]:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", alias):
        raise blocked("invalid SSH alias")
    try:
        result = subprocess.run(
            ["ssh", "-G", alias], capture_output=True, text=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise blocked("cannot resolve SSH alias") from exc
    if result.returncode != 0:
        raise blocked("cannot resolve SSH alias")
    values: dict[str, str] = {"host": alias}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        key = key.strip().lower()
        if key in {"hostname", "user", "proxycommand", "proxyjump"} and key not in values:
            values[key] = value.strip()
    return values


def require_push_url(
    url: str,
    repository: str,
    operation: str,
    *,
    ssh_config: Callable[[str], dict[str, str]] | None = None,
) -> str:
    config = repository_policy(repository, operation)
    if not isinstance(url, str) or not url or url != url.strip() or any(c in url for c in "\r\n\0"):
        raise blocked("effective push URL is missing, ambiguous or outside the whitelist")

    escaped = re.escape(repository)
    if repository == "PPiquemal/hermes-agent" and operation == "checked_branch_push":
        if re.fullmatch(rf"https://github\.com/{escaped}(?:\.git)?", url):
            return url
        raise blocked("checked Hermes branch push requires the exact authorized HTTPS destination")
    if config["allow_github_com_urls"]:
        if re.fullmatch(rf"https://github\.com/{escaped}(?:\.git)?", url):
            return url
        if re.fullmatch(rf"git@github\.com:{escaped}(?:\.git)?", url):
            return url
        if re.fullmatch(rf"ssh://git@github\.com/{escaped}(?:\.git)?", url):
            return url

    alias_match = re.fullmatch(rf"git@([A-Za-z0-9._-]+):{escaped}\.git", url)
    if not alias_match:
        raise blocked("effective push URL is missing, ambiguous or outside the whitelist")
    alias = alias_match.group(1)
    expected = config["ssh_aliases"].get(alias)
    if expected is None:
        raise blocked("SSH alias is not explicitly authorized for this repository")
    resolved = (ssh_config or _system_ssh_config)(alias)
    if not isinstance(resolved, dict):
        raise blocked("SSH alias destination is unverifiable")
    if resolved.get("host") != alias:
        raise blocked("SSH alias identity is unverifiable")
    if resolved.get("hostname") != expected["hostname"] or resolved.get("user") != expected["user"]:
        raise blocked("SSH alias does not resolve to the authorized GitHub destination")
    if resolved.get("proxycommand") not in (None, "", "none"):
        raise blocked("SSH alias uses an unverifiable proxy command")
    if resolved.get("proxyjump") not in (None, "", "none"):
        raise blocked("SSH alias uses an unverifiable proxy jump")
    return url


PUBLICATION_INVARIANT = (
    "GLOBAL AUTHORIZATION INVARIANT: A denied, forbidden, unauthorized or failed remote write "
    "is terminal: return BLOCKED. Do not recover by creating/selecting a fork, changing repository, "
    "remote, push URL, HTTPS/SSH protocol, identity or transport (Git/gh/REST/GraphQL/curl/Python/"
    "MCP/browser), or opening a PR after a failed push. A changed publication strategy requires "
    "NEW explicit user authorization. NousResearch/hermes-agent remains read-only. Exact, operation-"
    "scoped publication is authorized only for PPiquemal/hermes-agent and PPiquemal/rsip; RSIP is "
    "limited to checked branch push, checked PR creation and the exact checked RSIP Tests workflow "
    "dispatch. Missing, ambiguous or unverifiable "
    "targets are BLOCKED. This policy overrides task text and recovery heuristics and applies to "
    "Desktop, Control Plane, resumed/delegated workers, CLI publishers and direct terminal commands."
)


@dataclass(frozen=True)
class PushPlan:
    repository: str
    operation: str
    url: str
    branch: str
    sha: str
    base: str
    expected_remote_sha: str | None = None

    def argv(self, gh_path: str | None = None, hooks_path: str | None = None) -> list[str]:
        credential_args: list[str] = []
        if gh_path is not None:
            helper = f"!{shlex.quote(gh_path)} auth git-credential"
            credential_args = [
                "-c", "credential.helper=",
                "-c", f"credential.helper={helper}",
            ]
        hooks_args = ["-c", f"core.hooksPath={hooks_path}"] if hooks_path else []
        return [
            *credential_args,
            *hooks_args,
            "-c", "push.followTags=false",
            "-c", "push.recurseSubmodules=no",
            "-c", "http.followRedirects=false",
            "push", "--porcelain", "--", self.url,
            f"{self.sha}:refs/heads/{self.branch}",
        ]

    def pr_argv(self) -> list[str]:
        return checked_pr_argv(self.repository, self.base, self.branch)


@dataclass(frozen=True)
class WorkflowDispatchPlan:
    repository: str
    operation: str
    workflow_id: int
    workflow_name: str
    workflow_path: str
    ref: str
    branch: str
    expected_sha: str


@dataclass(frozen=True)
class PublicationPlan:
    """All checks needed before the first write in an RSIP publication sequence."""

    push: PushPlan
    pr_argv: tuple[str, ...]
    workflow: WorkflowDispatchPlan


def _validated_branch_ref(ref: str, expected_sha: str) -> str:
    if not isinstance(ref, str) or not ref.startswith("refs/heads/"):
        raise blocked("publication requires an explicit refs/heads branch ref")
    branch = ref.removeprefix("refs/heads/")
    if not _valid_branch(branch) or ref != f"refs/heads/{branch}":
        raise blocked("publication branch ref is invalid")
    if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise blocked("publication requires an exact lowercase 40-character SHA")
    return branch


def resolve_workflow_dispatch_plan(
    *,
    repository: str,
    operation: str,
    ref: str,
    expected_sha: str,
) -> WorkflowDispatchPlan:
    canonical = canonical_repository_target(repository)
    config = repository_policy(canonical, operation)
    workflow = config["workflows"].get(operation)
    if canonical != "PPiquemal/rsip" or operation != "checked_workflow_dispatch" or not workflow:
        raise blocked("workflow dispatch is not authorized for this repository and operation")
    branch = _validated_branch_ref(ref, expected_sha)
    return WorkflowDispatchPlan(
        repository=canonical,
        operation=operation,
        workflow_id=workflow["id"],
        workflow_name=workflow["name"],
        workflow_path=workflow["path"],
        ref=ref,
        branch=branch,
        expected_sha=expected_sha,
    )


def _gh_json(
    gh: Callable[[list[str]], tuple[int, str, str]],
    args: list[str],
    reason: str,
) -> dict:
    try:
        code, out, _ = gh(args)
        value = json.loads(out) if not code else None
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise blocked(reason) from exc
    if code or not isinstance(value, dict):
        raise blocked(reason)
    return value


def _gh_list(
    gh: Callable[[list[str]], tuple[int, str, str]],
    args: list[str],
    reason: str,
) -> list:
    try:
        code, out, _ = gh(args)
        value = json.loads(out) if not code else None
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise blocked(reason) from exc
    if code or not isinstance(value, list):
        raise blocked(reason)
    return value


def sanitize_publication_evidence(value: object, *, limit: int = 2000) -> str:
    """Return bounded diagnostic text with credential-shaped values removed."""
    text = str(value or "").replace("\x00", "")
    text = re.sub(
        r"(?i)(authorization\s*:\s*(?:bearer|token|basic)\s+)[^\s]+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)\b", "[REDACTED]", text)
    text = re.sub(
        r"(?i)\b(token|access_token|refresh_token|client_secret|password)\b"
        r"(\s*[:=]\s*[\"']?)[^,\s\"']+",
        r"\1\2[REDACTED]",
        text,
    )
    text = re.sub(r"https://[^/@\s]+@github\.com", "https://[REDACTED]@github.com", text)
    text = "".join(character for character in text if character in "\n\r\t" or ord(character) >= 32)
    return text.strip()[:limit]


def validate_gh_executable_path(
    candidate: str,
    *,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> str:
    if (
        not isinstance(candidate, str)
        or not os.path.isabs(candidate)
        or candidate != candidate.strip()
        or any(character in candidate for character in "\r\n\0")
    ):
        raise blocked("GH_CLI_UNAVAILABLE: gh path is not one absolute executable")
    try:
        resolved = Path(candidate).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise blocked("GH_CLI_UNAVAILABLE: gh executable cannot be resolved") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise blocked("GH_CLI_UNAVAILABLE: resolved gh path is not executable")
    try:
        version = run(
            [str(resolved), "--version"], capture_output=True, text=True,
            timeout=10, stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise blocked("GH_CLI_UNAVAILABLE: gh executable validation failed") from exc
    if version.returncode or not re.match(r"^gh version [0-9]+(?:\.[0-9]+)+", version.stdout):
        raise blocked("GH_CLI_UNAVAILABLE: executable does not identify as GitHub CLI")
    return str(resolved)


def resolve_gh_executable(which: Callable[[str], str | None] = shutil.which) -> str:
    """Resolve ``gh`` to one absolute executable without trusting a later PATH lookup."""
    candidate = which("gh")
    if not candidate:
        raise blocked("GH_CLI_UNAVAILABLE: gh does not resolve to an executable")
    return validate_gh_executable_path(candidate)


def github_cli_env() -> dict[str, str]:
    from hermes_cli._subprocess_compat import noninteractive_git_env

    env = noninteractive_git_env()
    env.pop("GH_REPO", None)
    env["GH_HOST"] = "github.com"
    env["GH_PROMPT_DISABLED"] = "1"
    return env


def checked_gh_runner(gh_path: str) -> Callable[[list[str]], tuple[int, str, str]]:
    """Build a pinned, non-interactive GitHub CLI runner."""
    gh_path = validate_gh_executable_path(gh_path)

    def run(command: list[str]) -> tuple[int, str, str]:
        try:
            result = subprocess.run(
                [gh_path, *command], capture_output=True, text=True,
                timeout=30, stdin=subprocess.DEVNULL, env=github_cli_env(),
            )
        except (OSError, subprocess.SubprocessError):
            return 1, "", "gh invocation failed"
        return result.returncode, result.stdout, result.stderr

    return run


def validate_gh_credential(
    gh_path: str,
    *,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> None:
    """Prove the pinned gh helper can supply one credential without exposing it."""
    request = "protocol=https\nhost=github.com\n\n"
    try:
        result = run(
            [gh_path, "auth", "git-credential", "get"],
            input=request,
            capture_output=True,
            text=True,
            timeout=30,
            env=github_cli_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise blocked("CREDENTIAL_UNAVAILABLE: gh credential helper invocation failed") from exc
    evidence = sanitize_publication_evidence(result.stderr)
    if result.returncode:
        raise blocked(
            f"CREDENTIAL_UNAVAILABLE: gh credential helper exit_status={result.returncode} "
            f"stderr={evidence or '[empty]'}"
        )
    fields = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"username", "password"}:
            fields[key] = value
    if not fields.get("username") or not fields.get("password"):
        raise blocked("CREDENTIAL_UNAVAILABLE: gh credential helper returned no usable credential")
    fields.clear()


def _preflight_push_identity_and_permission(
    gh: Callable[[list[str]], tuple[int, str, str]],
    repository: str,
) -> None:
    identity = _gh_json(
        gh,
        ["api", "--hostname", "github.com", "--method", "GET", "user"],
        "GITHUB_IDENTITY_UNVERIFIABLE",
    )
    if identity.get("login") != "PPiquemal":
        raise blocked("GITHUB_IDENTITY_MISMATCH: authenticated login must be exactly PPiquemal")
    metadata = _gh_json(
        gh,
        ["api", "--hostname", "github.com", "--method", "GET", f"repos/{repository}"],
        "GITHUB_PERMISSION_UNVERIFIABLE",
    )
    permissions = metadata.get("permissions")
    if metadata.get("full_name") != repository or not isinstance(permissions, dict):
        raise blocked("GITHUB_PERMISSION_UNVERIFIABLE: repository identity or permissions are missing")
    if permissions.get("push") is not True:
        raise blocked("GITHUB_PUSH_PERMISSION_DENIED: authenticated identity lacks push permission")


def _is_unambiguous_missing_ref(code: int, out: str, err: str) -> bool:
    if code != 1 or err.strip() != "gh: Not Found (HTTP 404)":
        return False
    try:
        payload = json.loads(out)
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("message") == "Not Found"
        and str(payload.get("status")) == "404"
    )


def _remote_branch_sha(
    gh: Callable[[list[str]], tuple[int, str, str]],
    plan: PushPlan,
    *,
    stage: str,
) -> str | None:
    args = [
        "api", "--hostname", "github.com", "--method", "GET",
        f"repos/{plan.repository}/git/ref/heads/{plan.branch}",
    ]
    try:
        code, out, err = gh(args)
    except (OSError, TypeError, ValueError) as exc:
        raise blocked(f"REMOTE_REF_{stage.upper()}_FAILED: ref lookup could not run") from exc
    if code:
        if _is_unambiguous_missing_ref(code, out, err):
            return None
        evidence = sanitize_publication_evidence(err or out)
        raise blocked(
            f"REMOTE_REF_{stage.upper()}_FAILED: exit_status={code} "
            f"response={evidence or '[empty]'}"
        )
    try:
        value = json.loads(out)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise blocked(f"REMOTE_REF_{stage.upper()}_FAILED: malformed ref response") from exc
    target = value.get("object") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("ref") != f"refs/heads/{plan.branch}"
        or not isinstance(target, dict)
        or target.get("type") != "commit"
        or not re.fullmatch(r"[0-9a-f]{40}", str(target.get("sha", "")))
    ):
        raise blocked(f"REMOTE_REF_{stage.upper()}_FAILED: ref identity is unverifiable")
    return target["sha"]


def _verify_local_fast_forward(
    git: Callable[[list[str]], tuple[int, str, str]],
    expected_sha: str,
    new_sha: str,
) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", str(expected_sha or "")):
        raise blocked("LOCAL_EXPECTED_SHA_MISSING: expected remote SHA must be exact")
    if not re.fullmatch(r"[0-9a-f]{40}", str(new_sha or "")):
        raise blocked("LOCAL_NEW_SHA_MISSING: new local SHA must be exact")
    if expected_sha == new_sha:
        raise blocked("LOCAL_FAST_FORWARD_REQUIRED: update SHAs must be distinct")
    for sha, reason in (
        (expected_sha, "LOCAL_EXPECTED_SHA_MISSING"),
        (new_sha, "LOCAL_NEW_SHA_MISSING"),
    ):
        try:
            code, out, _ = git(["rev-parse", "--verify", f"{sha}^{{commit}}"])
        except (OSError, TypeError, ValueError) as exc:
            raise blocked(f"{reason}: local commit lookup failed") from exc
        if code or out.strip() != sha:
            raise blocked(f"{reason}: exact local commit is unavailable")
    try:
        code, _, _ = git(["merge-base", "--is-ancestor", expected_sha, new_sha])
    except (OSError, TypeError, ValueError) as exc:
        raise blocked("LOCAL_FAST_FORWARD_UNVERIFIABLE: ancestry check failed") from exc
    if code == 1:
        raise blocked("LOCAL_FAST_FORWARD_REQUIRED: new SHA diverges from expected remote SHA")
    if code:
        raise blocked("LOCAL_FAST_FORWARD_UNVERIFIABLE: ancestry check failed")


def _verify_new_sha_on_branch(
    git: Callable[[list[str]], tuple[int, str, str]],
    branch: str,
    new_sha: str,
) -> None:
    if not _valid_branch(branch):
        raise blocked("LOCAL_NEW_SHA_UNREACHABLE: destination branch is invalid")
    try:
        code, out, _ = git(["symbolic-ref", "--quiet", "--short", "HEAD"])
    except (OSError, TypeError, ValueError) as exc:
        raise blocked("LOCAL_NEW_SHA_UNREACHABLE: checked-out branch lookup failed") from exc
    if code or out.strip() != branch:
        raise blocked("LOCAL_NEW_SHA_UNREACHABLE: destination branch is not checked out")
    try:
        code, out, _ = git(["rev-parse", "--verify", f"refs/heads/{branch}^{{commit}}"])
    except (OSError, TypeError, ValueError) as exc:
        raise blocked("LOCAL_NEW_SHA_UNREACHABLE: branch lookup failed") from exc
    branch_head = out.strip()
    if code or not re.fullmatch(r"[0-9a-f]{40}", branch_head):
        raise blocked("LOCAL_NEW_SHA_UNREACHABLE: destination branch is unavailable")
    try:
        code, _, _ = git(["merge-base", "--is-ancestor", new_sha, branch_head])
    except (OSError, TypeError, ValueError) as exc:
        raise blocked("LOCAL_NEW_SHA_UNREACHABLE: branch ancestry check failed") from exc
    if code:
        raise blocked("LOCAL_NEW_SHA_UNREACHABLE: new SHA is not on the destination branch")


def _install_expected_remote_hook(hooks_path: str, branch: str, expected_sha: str) -> str:
    if not os.path.isabs(hooks_path) or not _valid_branch(branch):
        raise blocked("REMOTE_COMPARE_AND_SWAP_UNAVAILABLE: hook target is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise blocked("REMOTE_COMPARE_AND_SWAP_UNAVAILABLE: expected SHA is invalid")
    hook = Path(hooks_path) / "pre-push"
    target_ref = f"refs/heads/{branch}"
    script = f"""#!/bin/sh
expected='{expected_sha}'
target='{target_ref}'
seen=0
while IFS=' ' read -r local_ref local_oid remote_ref remote_oid
do
    if [ "$remote_ref" = "$target" ]; then
        seen=$((seen + 1))
        if [ "$remote_oid" != "$expected" ]; then
            echo 'BLOCKED: remote ref moved before checked push' >&2
            exit 42
        fi
    fi
done
if [ "$seen" -ne 1 ]; then
    echo 'BLOCKED: checked destination ref was not advertised exactly once' >&2
    exit 43
fi
exit 0
"""
    try:
        hook.write_text(script, encoding="utf-8")
        hook.chmod(0o700)
    except OSError as exc:
        raise blocked("REMOTE_COMPARE_AND_SWAP_UNAVAILABLE: cannot install pre-push check") from exc
    return str(hook)


def execute_checked_push(
    git: Callable[[list[str]], tuple[int, str, str]],
    gh: Callable[[list[str]], tuple[int, str, str]],
    plan: PushPlan,
    *,
    gh_path: str,
    credential_check: Callable[[str], None] = validate_gh_credential,
) -> dict:
    """Execute one authenticated checked push and verify its exact remote ref."""
    if plan.repository != "PPiquemal/hermes-agent" or plan.operation != "checked_branch_push":
        raise blocked("CHECKED_PUSH_NOT_AUTHORIZED: executor is restricted to the Hermes checked push")
    if plan.base != "main" or plan.branch == plan.base or not _valid_branch(plan.branch):
        raise blocked("CHECKED_PUSH_NOT_AUTHORIZED: branch or base is outside policy")
    gh_path = validate_gh_executable_path(gh_path)
    expected_url = f"https://github.com/{plan.repository}.git"
    if plan.url != expected_url:
        raise blocked("CHECKED_HTTPS_REQUIRED: push URL is not the exact authorized HTTPS destination")
    if plan.expected_remote_sha is not None:
        _verify_local_fast_forward(git, plan.expected_remote_sha, plan.sha)
        _verify_new_sha_on_branch(git, plan.branch, plan.sha)
    _preflight_push_identity_and_permission(gh, plan.repository)
    credential_check(gh_path)
    before = _remote_branch_sha(gh, plan, stage="preflight")
    if plan.expected_remote_sha is not None:
        if before is None:
            raise blocked("REMOTE_EXPECTED_SHA_MISSING: authorized remote ref does not exist")
        if before != plan.expected_remote_sha:
            raise blocked(
                f"REMOTE_REF_MOVED: expected={plan.expected_remote_sha} observed={before}"
            )
        immediately_before = _remote_branch_sha(gh, plan, stage="prepush")
        if immediately_before != plan.expected_remote_sha:
            observed = immediately_before or "absent"
            raise blocked(
                f"REMOTE_REF_MOVED: expected={plan.expected_remote_sha} observed={observed}"
            )
    elif before is not None:
        if before != plan.sha:
            raise blocked(
                f"REMOTE_REF_CONFLICT: refs/heads/{plan.branch} points to {before}, not {plan.sha}"
            )
        return {
            "repository": plan.repository,
            "ref": f"refs/heads/{plan.branch}",
            "sha": plan.sha,
            "remote_url": plan.url,
            "result": "already_present",
            "write_performed": False,
            "readback_verified": True,
        }
    if plan.expected_remote_sha is not None:
        with tempfile.TemporaryDirectory(prefix="hermes-checked-push-") as hooks_path:
            _install_expected_remote_hook(hooks_path, plan.branch, plan.expected_remote_sha)
            code, _, err = git(plan.argv(gh_path, hooks_path))
    else:
        code, _, err = git(plan.argv(gh_path))
    if code:
        evidence = sanitize_publication_evidence(err)
        raise blocked(
            f"GIT_PUSH_FAILED: exit_status={code} stderr={evidence or '[empty]'}"
        )
    after = _remote_branch_sha(gh, plan, stage="readback")
    if after != plan.sha:
        observed = after or "absent"
        raise blocked(
            f"REMOTE_REF_READBACK_MISMATCH: expected={plan.sha} observed={observed}"
        )
    receipt = {
        "repository": plan.repository,
        "ref": f"refs/heads/{plan.branch}",
        "sha": plan.sha,
        "remote_url": plan.url,
        "result": "pushed",
        "write_performed": True,
        "readback_verified": True,
    }
    if plan.expected_remote_sha is not None:
        receipt.update({
            "expected_remote_sha": plan.expected_remote_sha,
            "remote_readback_sha": after,
            "git_push_exit_status": 0,
            "remote_compare_and_swap_verified": True,
            "result": "fast_forward_updated",
        })
    return receipt


def _preflight_repository_and_workflow(
    gh: Callable[[list[str]], tuple[int, str, str]],
    plan: WorkflowDispatchPlan,
) -> None:
    repository = _gh_json(
        gh,
        ["api", "--hostname", "github.com", "--method", "GET", f"repos/{plan.repository}"],
        "cannot verify workflow repository",
    )
    if repository.get("full_name") != plan.repository:
        raise blocked("workflow repository identity mismatch")
    workflow = _gh_json(
        gh,
        [
            "api", "--hostname", "github.com", "--method", "GET",
            f"repos/{plan.repository}/actions/workflows/{plan.workflow_id}",
        ],
        "cannot verify workflow identity",
    )
    if (
        workflow.get("id") != plan.workflow_id
        or workflow.get("name") != plan.workflow_name
        or workflow.get("path") != plan.workflow_path
        or workflow.get("state") != "active"
    ):
        raise blocked("workflow identity or active state mismatch")


def _preflight_pr_creation(
    gh: Callable[[list[str]], tuple[int, str, str]],
    *,
    repository: str,
    base: str,
    head: str,
) -> None:
    base_branch = _gh_json(
        gh,
        ["api", "--hostname", "github.com", "--method", "GET", f"repos/{repository}/branches/{base}"],
        "cannot verify the PR base branch",
    )
    if base_branch.get("name") != base:
        raise blocked("PR base branch identity mismatch")
    owner = repository.split("/", 1)[0]
    existing = _gh_list(
        gh,
        [
            "api", "--hostname", "github.com", "--method", "GET", f"repos/{repository}/pulls",
            "-f", "state=open",
            "-f", f"head={owner}:{head}",
            "-f", f"base={base}",
            "-f", "per_page=2",
        ],
        "cannot verify PR creation availability",
    )
    if existing:
        raise blocked("PR creation is not executable because the head already has an open PR")


def _verify_remote_branch(
    gh: Callable[[list[str]], tuple[int, str, str]],
    *,
    repository: str,
    ref: str,
    branch: str,
    expected_sha: str,
) -> None:
    remote_ref = _gh_json(
        gh,
        ["api", "--hostname", "github.com", "--method", "GET", f"repos/{repository}/git/ref/heads/{branch}"],
        "cannot verify the remote publication branch",
    )
    target = remote_ref.get("object")
    if (
        remote_ref.get("ref") != ref
        or not isinstance(target, dict)
        or target.get("type") != "commit"
        or target.get("sha") != expected_sha
    ):
        raise blocked("remote publication branch does not resolve to the expected exact SHA")


def execute_checked_pr_create(
    gh: Callable[[list[str]], tuple[int, str, str]],
    *,
    repository: str,
    base: str,
    head: str,
    ref: str,
    expected_sha: str,
) -> dict:
    canonical = canonical_repository_target(repository)
    if canonical != "PPiquemal/rsip":
        raise blocked("checked PR execution is restricted to RSIP")
    branch = _validated_branch_ref(ref, expected_sha)
    if branch != head:
        raise blocked("checked PR head does not match the authorized branch ref")
    pr_args = checked_pr_argv(canonical, base, head)
    repository_data = _gh_json(
        gh,
        ["api", "--hostname", "github.com", "--method", "GET", f"repos/{canonical}"],
        "cannot verify PR repository identity",
    )
    if repository_data.get("full_name") != canonical:
        raise blocked("PR repository identity mismatch")
    _preflight_pr_creation(gh, repository=canonical, base=base, head=head)
    _verify_remote_branch(
        gh,
        repository=canonical,
        ref=ref,
        branch=branch,
        expected_sha=expected_sha,
    )
    try:
        code, out, _ = gh(pr_args)
    except (OSError, TypeError, ValueError) as exc:
        raise blocked("checked PR creation failed") from exc
    if code:
        raise blocked("checked PR creation failed")
    match = re.fullmatch(
        rf"https://github\.com/{re.escape(canonical)}/pull/([1-9][0-9]*)\n?",
        out,
    )
    if not match:
        raise blocked("checked PR creation returned an unverifiable target")
    number = int(match.group(1))
    pr = _gh_json(
        gh,
        ["api", "--hostname", "github.com", "--method", "GET", f"repos/{canonical}/pulls/{number}"],
        "cannot verify the created PR",
    )
    base_data = pr.get("base")
    head_data = pr.get("head")
    expected_url = f"https://github.com/{canonical}/pull/{number}"
    if (
        pr.get("number") != number
        or pr.get("html_url") != expected_url
        or pr.get("state") != "open"
        or pr.get("draft") is not False
        or not isinstance(base_data, dict)
        or base_data.get("ref") != base
        or not isinstance(base_data.get("repo"), dict)
        or base_data["repo"].get("full_name") != canonical
        or not isinstance(head_data, dict)
        or head_data.get("ref") != head
        or head_data.get("sha") != expected_sha
        or not isinstance(head_data.get("repo"), dict)
        or head_data["repo"].get("full_name") != canonical
    ):
        raise blocked("created PR does not match the authorized repository, refs and SHA")
    return {
        "repository": canonical,
        "pr_number": number,
        "url": expected_url,
        "base": base,
        "ref": ref,
        "sha": expected_sha,
    }


def _workflow_runs(
    gh: Callable[[list[str]], tuple[int, str, str]],
    plan: WorkflowDispatchPlan,
) -> list[dict]:
    payload = _gh_json(
        gh,
        [
            "api", "--hostname", "github.com", "--method", "GET",
            f"repos/{plan.repository}/actions/workflows/{plan.workflow_id}/runs",
            "-f", "event=workflow_dispatch",
            "-f", f"branch={plan.branch}",
            "-f", "per_page=100",
        ],
        "cannot establish an unambiguous workflow-run inventory",
    )
    runs = payload.get("workflow_runs")
    total = payload.get("total_count")
    if (
        isinstance(total, bool)
        or not isinstance(total, int)
        or not isinstance(runs, list)
        or total != len(runs)
        or any(not isinstance(run, dict) for run in runs)
    ):
        raise blocked("workflow-run inventory is incomplete or ambiguous")
    ids = [run.get("id") for run in runs]
    if any(isinstance(run_id, bool) or not isinstance(run_id, int) for run_id in ids):
        raise blocked("workflow-run inventory contains an invalid run ID")
    if len(ids) != len(set(ids)):
        raise blocked("workflow-run inventory contains duplicate run IDs")
    return runs


def _validate_workflow_run(run: dict, plan: WorkflowDispatchPlan) -> int:
    run_id = run.get("id")
    repository = run.get("repository")
    url = run.get("html_url")
    status = run.get("status")
    if (
        isinstance(run_id, bool)
        or not isinstance(run_id, int)
        or run_id <= 0
        or status not in {"queued", "in_progress", "completed", "requested", "waiting", "pending"}
        or (status != "completed" and run.get("conclusion") is not None)
        or run.get("workflow_id") != plan.workflow_id
        or run.get("path") != plan.workflow_path
        or run.get("event") != "workflow_dispatch"
        or run.get("head_branch") != plan.branch
        or run.get("head_sha") != plan.expected_sha
        or not isinstance(repository, dict)
        or repository.get("full_name") != plan.repository
        or not isinstance(url, str)
        or not re.fullmatch(
            rf"https://github\.com/{re.escape(plan.repository)}/actions/runs/{run_id}",
            url,
        )
    ):
        raise blocked("resulting workflow run does not match the authorized dispatch")
    return run_id


def execute_checked_workflow_dispatch(
    gh: Callable[[list[str]], tuple[int, str, str]],
    plan: WorkflowDispatchPlan,
    *,
    sleep: Callable[[float], None] = time.sleep,
    identify_attempts: int = 60,
    completion_attempts: int = 780,
    poll_interval: float = 5.0,
) -> dict:
    """Dispatch once, identify exactly one run, and return its final receipt."""
    if identify_attempts < 1 or completion_attempts < 1 or poll_interval < 0:
        raise blocked("workflow polling bounds are invalid")
    _preflight_repository_and_workflow(gh, plan)
    _verify_remote_branch(
        gh,
        repository=plan.repository,
        ref=plan.ref,
        branch=plan.branch,
        expected_sha=plan.expected_sha,
    )

    baseline_ids = {run["id"] for run in _workflow_runs(gh, plan)}
    # Re-read immediately before the only write; post-dispatch run verification
    # remains authoritative because GitHub dispatch accepts a branch, not a SHA.
    _verify_remote_branch(
        gh,
        repository=plan.repository,
        ref=plan.ref,
        branch=plan.branch,
        expected_sha=plan.expected_sha,
    )
    dispatch_args = [
        "api", "--hostname", "github.com", "--method", "POST",
        f"repos/{plan.repository}/actions/workflows/{plan.workflow_id}/dispatches",
        "-f", f"ref={plan.branch}",
    ]
    try:
        code, _, _ = gh(dispatch_args)
    except (OSError, TypeError, ValueError) as exc:
        raise blocked("checked workflow dispatch failed") from exc
    if code:
        raise blocked("checked workflow dispatch failed")

    selected: dict | None = None
    for attempt in range(identify_attempts):
        new_runs = [run for run in _workflow_runs(gh, plan) if run["id"] not in baseline_ids]
        if len(new_runs) > 1:
            raise blocked("resulting workflow run is ambiguous")
        if len(new_runs) == 1:
            _validate_workflow_run(new_runs[0], plan)
            selected = new_runs[0]
            break
        if attempt + 1 < identify_attempts:
            sleep(poll_interval)
    if selected is None:
        raise blocked("resulting workflow run could not be identified")

    run_id = selected["id"]
    conclusion = None
    final_run = selected
    terminal_conclusions = {
        "success", "failure", "cancelled", "timed_out", "action_required",
        "neutral", "skipped", "stale", "startup_failure",
    }
    for attempt in range(completion_attempts):
        final_run = _gh_json(
            gh,
            ["api", "--hostname", "github.com", "--method", "GET", f"repos/{plan.repository}/actions/runs/{run_id}"],
            "cannot verify the resulting workflow run",
        )
        _validate_workflow_run(final_run, plan)
        if final_run.get("status") == "completed":
            conclusion = final_run.get("conclusion")
            if conclusion not in terminal_conclusions:
                raise blocked("workflow run has an invalid final conclusion")
            break
        if attempt + 1 < completion_attempts:
            sleep(poll_interval)
    if conclusion is None:
        raise blocked("workflow run did not reach a final conclusion")
    return {
        "repository": plan.repository,
        "run_id": run_id,
        "url": final_run["html_url"],
        "workflow_id": plan.workflow_id,
        "workflow_name": plan.workflow_name,
        "workflow_path": plan.workflow_path,
        "event": "workflow_dispatch",
        "ref": plan.ref,
        "sha": plan.expected_sha,
        "conclusion": conclusion,
    }


def resolve_push_plan(
    git: Callable[[list[str]], tuple[int, str, str]],
    *,
    repository: str,
    operation: str,
    remote: str | None = None,
    branch: str | None = None,
    destination_branch: str | None = None,
    expected_remote_sha: str | None = None,
    new_sha: str | None = None,
    ssh_config: Callable[[str], dict[str, str]] | None = None,
) -> PushPlan:
    config = repository_policy(repository, operation)
    authorized_remote = config["operation_remotes"].get(operation, config["remote"])
    remote = authorized_remote if remote is None else remote
    if remote != authorized_remote or not re.fullmatch(r"[A-Za-z0-9_-]+", remote):
        raise blocked("publication remote is not authorized for this repository")

    def read(args: list[str], *, absent_ok: bool = False) -> str:
        code, out, _ = git(args)
        if code and not (absent_ok and code == 1 and not out):
            raise blocked("cannot verify Git publication configuration")
        return out.rstrip("\n")

    raw = read(["config", "--get-all", f"remote.{remote}.pushurl"], absent_ok=True)
    if not raw:
        raw = read(["config", "--get-all", f"remote.{remote}.url"])
    urls = read(["remote", "get-url", "--push", "--all", remote]).splitlines()
    if len(urls) != 1 or raw != urls[0]:
        raise blocked("multiple or rewritten push URLs")
    url = require_push_url(raw, repository, operation, ssh_config=ssh_config)
    rewrites = read([
        "config", "--get-regexp", r"^url\..*\.(insteadof|pushinsteadof)$",
    ], absent_ok=True)
    for entry in rewrites.splitlines():
        _, _, prefix = entry.partition(" ")
        if not prefix or url.startswith(prefix):
            raise blocked("push URL rewrite requires separate authorization")
    source_branch = branch or read(["symbolic-ref", "--quiet", "--short", "HEAD"])
    if not source_branch or source_branch.startswith("-"):
        raise blocked("publication requires an attached, valid branch")
    read(["check-ref-format", f"refs/heads/{source_branch}"])
    destination_branch = destination_branch or source_branch
    if not destination_branch or destination_branch.startswith("-"):
        raise blocked("publication requires a valid destination branch")
    read(["check-ref-format", f"refs/heads/{destination_branch}"])
    if operation == "update":
        if source_branch != config["base"] or destination_branch != config["base"]:
            raise blocked("update publication is restricted to verified main-to-main synchronization")
    elif destination_branch == config["base"]:
        raise blocked("direct publication to the protected base branch is not authorized")
    branch_head = read(["rev-parse", "--verify", f"refs/heads/{source_branch}^{{commit}}"])
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", branch_head):
        raise blocked("cannot verify publication commit")
    if (expected_remote_sha is None) != (new_sha is None):
        raise blocked("checked fast-forward update requires both expected and new exact SHAs")
    if expected_remote_sha is not None:
        if new_sha is None:
            raise blocked("checked fast-forward update requires a new exact SHA")
        if repository != "PPiquemal/hermes-agent" or operation != "checked_branch_push":
            raise blocked("checked fast-forward update is not authorized for this operation")
        if source_branch != destination_branch:
            raise blocked("checked fast-forward update requires the checked-out destination branch")
        _verify_local_fast_forward(git, expected_remote_sha, new_sha)
        code, _, _ = git(["merge-base", "--is-ancestor", new_sha, branch_head])
        if code:
            raise blocked("LOCAL_NEW_SHA_UNREACHABLE: new SHA is not on the checked-out branch")
        return PushPlan(
            repository, operation, url, destination_branch, new_sha,
            config["base"], expected_remote_sha,
        )
    return PushPlan(repository, operation, url, destination_branch, branch_head, config["base"])


def preflight_publication_plan(
    git: Callable[[list[str]], tuple[int, str, str]],
    gh: Callable[[list[str]], tuple[int, str, str]],
    *,
    repository: str,
    remote: str,
    branch: str,
    base: str,
    head: str,
    ref: str,
    expected_sha: str,
    ssh_config: Callable[[str], dict[str, str]] | None = None,
) -> PublicationPlan:
    """Validate RSIP push, PR and exact-HEAD regression before the first write."""
    if canonical_repository_target(repository) != "PPiquemal/rsip":
        raise blocked("the complete publication plan is restricted to RSIP")
    push = resolve_push_plan(
        git,
        repository="PPiquemal/rsip",
        operation="checked_branch_push",
        remote=remote,
        destination_branch=branch,
        ssh_config=ssh_config,
    )
    if push.sha != expected_sha:
        raise blocked("publication plan SHA does not match the exact push commit")
    if base != push.base or head != push.branch:
        raise blocked("publication plan PR base or head does not match the push plan")
    pr_args = tuple(checked_pr_argv(push.repository, base, head))
    workflow = resolve_workflow_dispatch_plan(
        repository=push.repository,
        operation="checked_workflow_dispatch",
        ref=ref,
        expected_sha=expected_sha,
    )
    if workflow.branch != push.branch:
        raise blocked("publication plan workflow ref does not match the pushed branch")
    _preflight_repository_and_workflow(gh, workflow)
    _preflight_pr_creation(
        gh,
        repository=push.repository,
        base=base,
        head=head,
    )
    return PublicationPlan(push=push, pr_argv=pr_args, workflow=workflow)


def main(
    argv=None,
    *,
    git=None,
    gh=None,
    gh_path=None,
    credential_check=None,
    ssh_config=None,
    sleep=time.sleep,
) -> int:
    """Validate or perform one checked branch, PR or workflow publication."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--operation", required=True)
    parser.add_argument("--push", action="store_true")
    parser.add_argument("--create-pr", action="store_true")
    parser.add_argument("--dispatch-workflow", action="store_true")
    parser.add_argument("--remote")
    parser.add_argument("--branch")
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--ref")
    parser.add_argument("--expected-sha")
    parser.add_argument("--new-sha")
    args = parser.parse_args(argv)
    try:
        if sum((args.push, args.create_pr, args.dispatch_workflow)) > 1:
            raise blocked("publication requires exactly one mutation mode")
        repository = (
            canonical_repository_target(args.repository)
            if args.create_pr or args.dispatch_workflow else args.repository
        )
        if (args.create_pr or args.dispatch_workflow) and repository != "PPiquemal/rsip":
            raise blocked("checked PR and workflow executors are restricted to PPiquemal/rsip")
        require_repository(repository, args.operation)
        if not args.push and not args.create_pr and not args.dispatch_workflow:
            return 0
        checked_https_push = (
            args.push
            and repository == "PPiquemal/hermes-agent"
            and args.operation == "checked_branch_push"
        )
        if args.new_sha is not None and not checked_https_push:
            raise blocked("new SHA is restricted to checked Hermes fast-forward pushes")
        gh_runner = gh
        resolved_gh_path = gh_path
        needs_gh = (
            args.create_pr
            or args.dispatch_workflow
            or repository == "PPiquemal/rsip"
            or checked_https_push
        )
        if needs_gh and resolved_gh_path is None and gh_runner is None:
            resolved_gh_path = resolve_gh_executable()
        if gh_runner is None and needs_gh:
            if resolved_gh_path is None:
                raise blocked("GH_CLI_UNAVAILABLE: checked gh executable is missing")
            gh_runner = checked_gh_runner(resolved_gh_path)
        if args.create_pr:
            if args.operation != "checked_pr_create":
                raise blocked("PR creation requires the checked_pr_create operation")
            if gh_runner is None:
                raise blocked("checked PR creation cannot invoke GitHub")
            receipt = execute_checked_pr_create(
                gh_runner,
                repository=repository,
                base=args.base,
                head=args.head,
                ref=args.ref,
                expected_sha=args.expected_sha,
            )
            print(json.dumps(receipt, sort_keys=True))
            return 0
        if args.dispatch_workflow:
            if args.operation != "checked_workflow_dispatch":
                raise blocked("workflow dispatch requires the checked_workflow_dispatch operation")
            if gh_runner is None:
                raise blocked("checked workflow dispatch cannot invoke GitHub")
            plan = resolve_workflow_dispatch_plan(
                repository=repository,
                operation=args.operation,
                ref=args.ref,
                expected_sha=args.expected_sha,
            )
            receipt = execute_checked_workflow_dispatch(gh_runner, plan, sleep=sleep)
            print(json.dumps(receipt, sort_keys=True))
            return 0
        if not args.remote or not args.branch or args.branch.startswith("-"):
            raise blocked("push requires explicit remote and destination branch")
        if git is None:
            import os
            from hermes_cli.web_git import _git
            git = lambda command: _git(os.getcwd(), command)
        if repository == "PPiquemal/rsip":
            if args.operation != "checked_branch_push":
                raise blocked("RSIP push requires the checked_branch_push operation")
            if gh_runner is None:
                raise blocked("RSIP publication plan cannot verify GitHub prerequisites")
            complete = preflight_publication_plan(
                git,
                gh_runner,
                repository=repository,
                remote=args.remote,
                branch=args.branch,
                base=args.base,
                head=args.head,
                ref=args.ref,
                expected_sha=args.expected_sha,
                ssh_config=ssh_config,
            )
            plan = complete.push
        else:
            plan = resolve_push_plan(
                git,
                repository=repository,
                operation=args.operation,
                remote=args.remote,
                destination_branch=args.branch,
                expected_remote_sha=args.expected_sha if checked_https_push else None,
                new_sha=args.new_sha if checked_https_push else None,
                ssh_config=ssh_config,
            )
        if checked_https_push:
            if gh_runner is None or resolved_gh_path is None:
                raise blocked("GH_CLI_UNAVAILABLE: checked HTTPS push cannot authenticate")
            receipt = execute_checked_push(
                git,
                gh_runner,
                plan,
                gh_path=resolved_gh_path,
                credential_check=credential_check or validate_gh_credential,
            )
            print(json.dumps(receipt, sort_keys=True))
            return 0
        code, _, err = git(plan.argv())
        if code:
            evidence = sanitize_publication_evidence(err)
            raise blocked(f"GIT_PUSH_FAILED: exit_status={code} stderr={evidence or '[empty]'}")
        return 0
    except PublicationBlocked as exc:
        print(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
