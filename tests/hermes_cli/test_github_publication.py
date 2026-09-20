"""No network writes: exercise publication against real Git config and intercepted transports."""
import subprocess

import pytest

from hermes_cli import web_git


@pytest.fixture
def publication_repo(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "no-global-config"))
    root = tmp_path / "repo"
    root.mkdir()
    def git(*args):
        return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
    git("init", "-q", "-b", "feature/test")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.invalid")
    git("commit", "--allow-empty", "-qm", "test")
    git("remote", "add", "origin", "https://github.com/NousResearch/hermes-agent.git")
    git("remote", "add", "fork", "https://github.com/PPiquemal/hermes-agent.git")
    return root, git


def test_failed_push_is_blocked_and_never_creates_pr(publication_repo, monkeypatch):
    root, _ = publication_repo
    commands = []
    run = web_git._run
    def intercepted(argv, cwd, timeout, env):
        if "push" in argv:
            commands.append(argv)
            return subprocess.CompletedProcess(argv, 1, "", "remote: permission denied")
        if argv[0] == "gh":
            pytest.fail("PR creation attempted after failed push")
        return run(argv, cwd, timeout, env)
    monkeypatch.setattr(web_git, "_run", intercepted)
    monkeypatch.setattr(web_git.shutil, "which", lambda name: "/intercepted/gh")
    with pytest.raises(RuntimeError, match="BLOCKED"):
        web_git.review_create_pr(str(root))
    assert len(commands) == 1


@pytest.mark.parametrize("action", ["push", "commit", "pr"])
def test_explicit_fork_ignores_upstream_and_gh_defaults(publication_repo, monkeypatch, action):
    root, git = publication_repo
    git("update-ref", "refs/remotes/origin/main", "HEAD")
    git("branch", "--set-upstream-to=origin/main")
    monkeypatch.setenv("GH_REPO", "NousResearch/hermes-agent")
    monkeypatch.setenv("GH_HOST", "untrusted.invalid")
    if action == "commit":
        (root / "change.txt").write_text("change")
    calls = []
    run = web_git._run
    def intercepted(argv, cwd, timeout, env):
        if "push" in argv or argv[0] == "gh":
            calls.append(argv)
            output = "https://github.com/PPiquemal/hermes-agent/pull/7\n" if argv[0] == "gh" else ""
            return subprocess.CompletedProcess(argv, 0, output, "")
        return run(argv, cwd, timeout, env)
    monkeypatch.setattr(web_git, "_run", intercepted)
    monkeypatch.setattr(web_git.shutil, "which", lambda name: "/intercepted/gh")
    if action == "commit":
        web_git.review_commit(str(root), "change", True)
    elif action == "push":
        web_git.review_push(str(root))
    else:
        web_git.review_create_pr(str(root))
    assert calls[0][-2:] == ["https://github.com/PPiquemal/hermes-agent.git", f"{git('rev-parse', 'HEAD')}:refs/heads/feature/test"]
    if action == "pr":
        assert calls[1][calls[1].index("--repo") + 1] == "github.com/PPiquemal/hermes-agent"
        assert calls[1][calls[1].index("--head") + 1] == "PPiquemal:feature/test"
        assert calls[1][calls[1].index("--base") + 1] == "main"


@pytest.mark.parametrize("configuration", ["missing", "wrong", "multiple", "rewrite", "detached"])
def test_unverifiable_push_target_blocked_before_network(publication_repo, monkeypatch, configuration):
    root, git = publication_repo
    if configuration == "missing":
        git("remote", "remove", "fork")
    elif configuration == "wrong":
        git("config", "remote.fork.pushurl", "https://github.com/NousResearch/hermes-agent.git")
    elif configuration == "multiple":
        git("config", "--add", "remote.fork.pushurl", "https://github.com/PPiquemal/hermes-agent.git")
        git("config", "--add", "remote.fork.pushurl", "https://github.com/NousResearch/hermes-agent.git")
    elif configuration == "rewrite":
        git("config", "url.https://github.com/NousResearch/.pushInsteadOf", "https://github.com/PPiquemal/")
    else:
        git("checkout", "--detach")
    run = web_git._run
    def intercepted(argv, cwd, timeout, env):
        if "push" in argv or argv[0] == "gh":
            pytest.fail(f"network mutation attempted: {argv}")
        return run(argv, cwd, timeout, env)
    monkeypatch.setattr(web_git, "_run", intercepted)
    with pytest.raises(RuntimeError, match="BLOCKED"):
        web_git.review_create_pr(str(root))


@pytest.mark.parametrize("authorized,fail_push", [(False, False), (True, False), (True, True)])
def test_updater_sync_uses_same_policy(publication_repo, monkeypatch, authorized, fail_push):
    from hermes_cli import update_cmd, update_cmd_git
    root, git = publication_repo
    git("branch", "main")
    if authorized:
        git("remote", "set-url", "origin", "https://github.com/PPiquemal/hermes-agent.git")
    calls = []
    def run(command, args, cwd, **kwargs):
        if "push" in args:
            calls.append(args)
            return subprocess.CompletedProcess(args, int(fail_push), "", "")
        return subprocess.run(command + args, cwd=cwd, capture_output=True, text=True)
    monkeypatch.setattr(update_cmd, "_git_run", run)
    if not authorized or fail_push:
        with pytest.raises(RuntimeError, match="BLOCKED"):
            update_cmd_git._sync_fork_with_upstream(["git"], root)
    else:
        assert update_cmd_git._sync_fork_with_upstream(["git"], root)
        assert calls[0][-2:] == ["https://github.com/PPiquemal/hermes-agent.git", f"{git('rev-parse', 'HEAD')}:refs/heads/main"]
    assert len(calls) == int(authorized)
