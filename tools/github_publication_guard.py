"""Fail-closed lexical guard for direct terminal GitHub publication commands.

This is deliberately not a shell sandbox.  It covers direct ``gh`` and ``git``
write invocations that can be recognized from one command segment.  Wrapped
commands and arbitrary Python, curl, or MCP clients remain outside this lexical
boundary and must use the checked publisher path instead.
"""

from __future__ import annotations

import shlex
import re
from pathlib import PurePath
from typing import Iterable, Optional


_SHELL_SEPARATORS = frozenset({"&&", "||", ";", "|"})
_GH_WRITES = frozenset({
    ("pr", "create"), ("pr", "edit"), ("pr", "merge"), ("pr", "close"), ("pr", "reopen"),
    ("pr", "ready"), ("pr", "review"), ("issue", "create"), ("issue", "edit"),
    ("issue", "close"), ("issue", "reopen"), ("issue", "delete"), ("repo", "create"),
    ("repo", "edit"), ("repo", "delete"), ("repo", "fork"), ("repo", "sync"),
    ("release", "create"), ("release", "edit"), ("release", "delete"), ("release", "upload"),
    ("workflow", "run"), ("workflow", "enable"), ("workflow", "disable"),
    ("variable", "set"), ("variable", "delete"), ("secret", "set"), ("secret", "delete"),
    ("label", "create"), ("label", "edit"), ("label", "delete"), ("project", "create"),
    ("project", "edit"), ("project", "delete"), ("project", "link"), ("ruleset", "create"),
    ("ruleset", "edit"), ("ruleset", "delete"), ("gist", "create"), ("gist", "edit"),
    ("gist", "delete"), ("ssh-key", "add"), ("ssh-key", "delete"),
})
_GIT_REMOTE_MUTATIONS = frozenset({"add", "remove", "rename", "set-url", "set-branches"})
_GIT_CONFIG_READ_FLAGS = frozenset({"--get", "--get-all", "--get-regexp", "--list", "--show-origin"})
_GIT_GLOBAL_OPTIONS_WITH_VALUE = frozenset({
    "-C", "-c", "--config-env", "--exec-path", "--git-dir", "--namespace", "--super-prefix", "--work-tree",
})
_GH_OPERATIONS = {
    ("pr", "create"): "checked_pr_create",
}
_GH_OPTIONS_WITH_VALUE = frozenset({
    "--repo", "-R", "--hostname", "--method", "-X", "--input",
    "--title", "--body", "--head", "--base",
})
_GH_API_BODY_OPTIONS = ("-f", "--raw-field", "-F", "--field", "--input")
_ENV_FLAGS = frozenset({"-i", "--ignore-environment", "-0", "--null"})
_ENV_OPTIONS_WITH_VALUE = frozenset({
    "-u", "--unset", "-C", "--chdir", "--argv0",
})


def _policy() -> tuple:
    """Load the parent-owned policy at decision time, not tool-import time."""
    from hermes_cli.publication_policy import (
        PUBLICATION_INVARIANT,
        require_push_url,
        require_repository,
    )

    return PUBLICATION_INVARIANT, require_repository, require_push_url


def _blocked(reason: str, invariant: Optional[str] = None) -> str:
    if invariant is None:
        invariant = "Publication policy unavailable; GitHub publication is BLOCKED."
    return f"BLOCKED: {invariant} {reason}"


def _command_segments(command: str) -> Optional[Iterable[list[str]]]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return None
    segments, current = [], []
    for token in tokens:
        if token in _SHELL_SEPARATORS:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def _direct_program(segment: list[str]) -> tuple[Optional[str], list[str]]:
    """Resolve common shell wrappers without losing a possible GitHub write."""
    index = 0
    assignment = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*")
    while index < len(segment) and assignment.fullmatch(segment[index]):
        index += 1
    if index < len(segment) and segment[index] == "env":
        index += 1
        while index < len(segment):
            argument = segment[index]
            if argument == "--":
                index += 1
                break
            if assignment.fullmatch(argument):
                index += 1
                continue
            if argument in _ENV_FLAGS:
                index += 1
                continue
            if argument in _ENV_OPTIONS_WITH_VALUE:
                index += 2
                continue
            if any(
                argument.startswith(name + "=")
                or (len(name) == 2 and argument.startswith(name) and len(argument) > 2)
                for name in _ENV_OPTIONS_WITH_VALUE
            ):
                index += 1
                continue
            if argument.startswith("-"):
                return "__unverifiable_env__", segment[index:]
            break
    while index < len(segment) and assignment.fullmatch(segment[index]):
        index += 1
    while index < len(segment):
        wrapper = PurePath(segment[index]).name
        if wrapper == "command":
            index += 1
            while index < len(segment) and segment[index] in {"--", "-p"}:
                index += 1
            if index < len(segment) and segment[index] in {"-v", "-V"}:
                return None, []
            continue
        if wrapper == "exec":
            index += 1
            while index < len(segment):
                argument = segment[index]
                if argument == "-a":
                    index += 2
                elif argument in {"--", "-c", "-l"}:
                    index += 1
                elif argument.startswith("-"):
                    return "__unverifiable_wrapper__", segment[index:]
                else:
                    break
            continue
        if wrapper in {"sudo", "doas", "nice", "nohup"}:
            wrapped_command = " ".join(segment[index + 1:])
            if re.search(
                r"(?<![A-Za-z0-9_-])(?:git-push|git|gh)(?:\.exe)?(?=$|[\s;&|])",
                wrapped_command,
            ):
                return "__unverifiable_wrapper__", segment[index:]
        break
    if index >= len(segment):
        return None, []
    program = PurePath(segment[index]).name.removesuffix(".exe")
    return program, segment[index + 1:]


def _option_value(arguments: list[str], *names: str) -> Optional[str]:
    for index, argument in enumerate(arguments):
        for name in names:
            if argument == name:
                return arguments[index + 1] if index + 1 < len(arguments) else None
            if argument.startswith(name + "="):
                return argument[len(name) + 1:]
            if len(name) == 2 and name.startswith("-") and argument.startswith(name) and len(argument) > 2:
                return argument[2:].removeprefix("=")
    return None


def _option_values(arguments: list[str], *names: str) -> list[str]:
    values: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        matched = False
        for name in names:
            if argument == name:
                if index + 1 < len(arguments):
                    values.append(arguments[index + 1])
                index += 2
                matched = True
                break
            if argument.startswith(name + "="):
                values.append(argument[len(name) + 1:])
                index += 1
                matched = True
                break
            if len(name) == 2 and name.startswith("-") and argument.startswith(name) and len(argument) > 2:
                values.append(argument[2:].removeprefix("="))
                index += 1
                matched = True
                break
        if not matched:
            index += 1
    return values


def _gh_command_pair(arguments: list[str]) -> tuple[str, str]:
    """Return the gh command/subcommand with value options removed."""
    positional: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in _GH_OPTIONS_WITH_VALUE:
            index += 2
            continue
        if any(
            len(name) == 2 and argument.startswith(name) and len(argument) > 2
            for name in _GH_OPTIONS_WITH_VALUE
        ):
            index += 1
            continue
        if argument.startswith("-"):
            index += 1
            continue
        positional.append(argument)
        index += 1
        if len(positional) == 2:
            break
    return (
        positional[0] if positional else "",
        positional[1] if len(positional) > 1 else "",
    )


def _authorize(target: Optional[str], operation: str, reason: str) -> Optional[str]:
    try:
        invariant, require_repository, _ = _policy()
        from hermes_cli.publication_policy import canonical_repository_target
    except Exception:
        return _blocked("The checked publication policy could not be loaded; refusing recognized write.")
    if not target:
        return _blocked(f"{reason} has no explicit --repo target; refusing ambiguous recognized write.", invariant)
    try:
        require_repository(canonical_repository_target(target), operation)
    except Exception as exc:
        return _blocked(f"{reason} targets {target!r}; {exc}", invariant)
    return None


def _repository_from_url(url: str) -> Optional[str]:
    patterns = (
        r"https://github\.com/([^/\s]+/[^/\s]+?)(?:\.git)?",
        r"git@[A-Za-z0-9._-]+:([^/\s]+/[^/\s]+?)(?:\.git)?",
        r"ssh://git@[A-Za-z0-9._-]+/([^/\s]+/[^/\s]+?)(?:\.git)?",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, url)
        if match:
            return match.group(1)
    return None


def _authorize_push_url(target: Optional[str]) -> Optional[str]:
    try:
        invariant, _, require_push_url = _policy()
    except Exception:
        return _blocked("The checked publication policy could not be loaded; refusing recognized write.")
    if not target:
        return _blocked("Direct git push has no explicit URL; refusing ambiguous recognized write.", invariant)
    repository = _repository_from_url(target)
    if not repository:
        return _blocked("Direct git push target is not an explicit, verifiable GitHub URL.", invariant)
    return _blocked(
        f"Direct git push to {repository!r} is not authorized; use the checked publisher.",
        invariant,
    )


def _gh_block(arguments: list[str]) -> Optional[str]:
    pair = _gh_command_pair(arguments)
    if pair not in _GH_WRITES:
        if pair[0] != "api":
            return None
        method = _option_value(arguments, "--method", "-X")
        body = _option_values(arguments, *_GH_API_BODY_OPTIONS)
        effective_method = method or ("POST" if body else "GET")
        if effective_method.upper() == "GET":
            return None
    repository_options = _option_values(arguments, "--repo", "-R")
    if len(repository_options) > 1:
        try:
            invariant, _, _ = _policy()
        except Exception:
            invariant = None
        return _blocked("Repeated GitHub repository options are not authorized.", invariant)
    target = _option_value(arguments, "--repo", "-R")
    if pair == ("pr", "create") and target:
        try:
            from hermes_cli.publication_policy import canonical_repository_target

            if canonical_repository_target(target) == "PPiquemal/rsip":
                invariant, _, _ = _policy()
                return _blocked(
                    "Direct RSIP PR creation is not authorized; use the checked publisher.",
                    invariant,
                )
        except Exception as exc:
            try:
                invariant, _, _ = _policy()
            except Exception:
                invariant = None
            return _blocked(f"Direct RSIP PR target is unverifiable: {exc}", invariant)
    operation = _GH_OPERATIONS.get(pair, "direct_github_write")
    return _authorize(
        target, operation, "Direct gh publication"
    )


def _git_config_mutates(arguments: list[str]) -> bool:
    if any(flag in arguments for flag in _GIT_CONFIG_READ_FLAGS):
        return False
    return any(arg.startswith(("remote.", "user.", "url.")) for arg in arguments)


def _git_subcommand(arguments: list[str]) -> tuple[Optional[str], list[str]]:
    """Skip direct-git global flags so ``git -c key=value push`` stays visible."""
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in _GIT_GLOBAL_OPTIONS_WITH_VALUE:
            index += 2
        elif argument.startswith(("-c", "--config-env=", "--exec-path=", "--git-dir=", "--namespace=", "--super-prefix=", "--work-tree=")):
            index += 1
        elif argument.startswith("-"):
            index += 1
        else:
            return argument, arguments[index + 1:]
    return None, []


def _git_block(arguments: list[str]) -> Optional[str]:
    subcommand, arguments = _git_subcommand(arguments)
    if not subcommand:
        return None
    if subcommand == "push":
        if any(
            argument in {
                "-f", "--force", "--force-with-lease", "--all", "--mirror",
                "--tags", "--delete", "-d", "--prune",
            }
            or argument.startswith("--force=")
            or argument.startswith("--force-with-lease=")
            for argument in arguments
        ):
            try:
                invariant, _, _ = _policy()
            except Exception:
                invariant = None
            return _blocked("Force, bulk, tag or deleting push is not authorized.", invariant)
        positional = [argument for argument in arguments if not argument.startswith("-")]
        target = positional[0] if positional else None
        if len(positional) != 2 or not re.fullmatch(
            r"[0-9a-f]{40}|[0-9a-f]{64}", positional[1].partition(":")[0]
        ) or not re.fullmatch(
            r"[0-9a-f]{40,64}:refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]*",
            positional[1],
        ):
            try:
                invariant, _, _ = _policy()
            except Exception:
                invariant = None
            return _blocked(
                "Direct push requires one exact commit-to-branch refspec.", invariant
            )
        if positional[1].endswith(":refs/heads/main"):
            try:
                invariant, _, _ = _policy()
            except Exception:
                invariant = None
            return _blocked(
                "Direct push to the protected base branch is not authorized.", invariant
            )
        return _authorize_push_url(target)
    if subcommand == "remote" and arguments and arguments[0] in _GIT_REMOTE_MUTATIONS:
        try:
            invariant, _, _ = _policy()
        except Exception:
            invariant = None
        return _blocked("Changing a git remote is forbidden without new user authorization.", invariant)
    if subcommand == "config" and _git_config_mutates(arguments):
        try:
            invariant, _, _ = _policy()
        except Exception:
            invariant = None
        return _blocked("Changing git remote or identity configuration is forbidden without new user authorization.", invariant)
    return None


def _nested_shell_command(program: Optional[str], arguments: list[str]) -> Optional[str]:
    if program not in {"sh", "bash", "dash", "zsh", "ksh"}:
        return None
    for index, argument in enumerate(arguments):
        if argument.startswith("-") and "c" in argument[1:]:
            return arguments[index + 1] if index + 1 < len(arguments) else ""
    return None


def github_publication_block(command: str, *, _depth: int = 0) -> Optional[str]:
    """Return a fail-closed block message for a recognized direct GitHub write.

    ``None`` means this lexical guard found no prohibited direct ``git``/``gh``
    write.  It does not assert that other transports are safe.
    """
    if _depth > 4:
        return _blocked("Nested shell depth is unverifiable; refusing possible GitHub write.")
    segments = _command_segments(command)
    if segments is None:
        return _blocked("Unable to parse command; refusing ambiguous recognized GitHub write.") if "gh" in command or "git" in command else None
    for segment in segments:
        program, arguments = _direct_program(segment)
        if program == "gh":
            blocked = _gh_block(arguments)
        elif program in {"git", "git-push"}:
            blocked = _git_block(
                ["push", *arguments] if program == "git-push" else arguments
            )
        elif program == "__unverifiable_env__":
            blocked = _blocked(
                "Unrecognized env wrapper options make a possible GitHub write unverifiable."
            )
        elif program == "__unverifiable_wrapper__":
            blocked = _blocked(
                "A shell wrapper makes a possible GitHub write unverifiable."
            )
        else:
            nested = _nested_shell_command(program, arguments)
            blocked = github_publication_block(nested, _depth=_depth + 1) if nested is not None else None
        if blocked:
            return blocked
    return None


def publication_worker_policy_guidance() -> str:
    """Immutable-at-session-creation prompt guidance shared by every agent path."""
    try:
        invariant, _, _ = _policy()
    except Exception:
        invariant = "Publication policy unavailable: treat GitHub publication as BLOCKED."
    return (
        "# GitHub publication policy\n"
        f"{invariant}\n"
        "This policy is immutable for this session and applies to desktop, control-plane, resumed, and delegated workers. "
        "For direct terminal GitHub writes, use the checked publisher or an explicit checked `gh --repo` target. "
        "The terminal guard only lexically covers recognized direct git/gh writes; arbitrary Python, curl, and MCP "
        "clients remain outside that boundary and must not be treated as authorized publication paths."
    )
