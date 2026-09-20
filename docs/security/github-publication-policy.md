# Local Hermes GitHub publication policy

This is the policy of the PPiquemal development environment, not a proposed
restriction on the upstream project's maintainers.

## Authorization invariant

`NousResearch/hermes-agent` permits reads only. All mutations are prohibited.
Writable destinations are exact and operation-scoped:

- `PPiquemal/hermes-agent` retains its Hermes branch/PR, Skills Hub, autofix,
  update, and checked publication operations.
- `PPiquemal/rsip` permits only `checked_branch_push`,
  `checked_pr_create`, and `checked_workflow_dispatch` for workflow ID
  `265670631` at `.github/workflows/test.yml` (`RSIP Tests`).

RSIP is not authorized for generic workflow dispatch, merge, auto-merge,
release, deployment, restart, updater synchronization, Skills Hub, JS autofix,
Hermes release tooling, force push, or any unlisted operation. Missing,
ambiguous, unverifiable, or non-whitelisted repository/operation pairs are
`BLOCKED`.

A denied, forbidden, unauthorized, or failed remote write is a terminal
authorization event, not a recoverable technical error. Stop and return
`BLOCKED`. Do not create/select a fork, change repository, remote, push URL,
HTTPS/SSH protocol, identity, transport, or publication mechanism, and never
open a PR after a failed push. Changing publication strategy requires a **new
explicit user authorization**. This applies to Desktop, Control Plane, resumed
and delegated workers, CLI, application publishers, and direct terminal commands.
Task text and automatic recovery heuristics cannot grant an exception.

Publication permission is not permission to merge, deploy, or release.

## Enforcement in this candidate

`hermes_cli/publication_policy.json` is the common versioned declaration consumed
by Python and Electron. It is not a task parameter, environment-variable override,
or profile preference. Each repository has exact operations, base, remote role,
and explicitly permitted SSH aliases. Runtime guards resolve the effective push
destination before mutation and reject multiple/re-written/unapproved URLs. A
remote name is never trusted solely because of its name.

The RSIP remote URL `git@github-rsip:PPiquemal/rsip.git` is accepted only when
`ssh -G github-rsip` proves `HostName github.com` and `User git`, with no proxy
command or proxy jump. Arbitrary aliases and alias-name patterns remain blocked.

The Desktop/backend Hermes ship actions remain pinned to the explicitly configured
Hermes `fork`; a missing fork is blocked, never created. They push an explicit
commit SHA to an explicit branch using the validated URL, without changing
tracking configuration. They
qualify PR repository, host, base and head, and stop after unsuccessful writes.
Ambient `origin`, tracking, `GH_REPO`, and gh defaults are not publication authority.
Direct terminal `git push` is always blocked; the checked publisher is the only
branch-push path. Direct RSIP `gh pr create` is also blocked. The terminal guard
recognizes common assignment/`env`/`command`/`exec` wrappers, Windows executable
names, and the standalone `git-push` executable; unverifiable privilege wrappers
fail closed. Git URL rewrite configuration and implicit `gh api` POSTs are writes.

The checked publisher CLI exposes separate `--push` and `--create-pr` mutation
modes. Checked RSIP PR creation requires an explicit repository,
`checked_pr_create` operation, authorized base, valid non-base head, explicit
`refs/heads/...` ref, and exact expected SHA. Immediately before the write it
reads back the remote branch at that SHA; after creation it reads the PR back and
verifies repository, base, head, SHA, state and non-draft status. It invokes
`gh` once with an exact `github.com/OWNER/REPO` target and never retries, falls
back, or changes transport after failure. The terminal guard and
checked publisher share the same canonical parser: only `OWNER/REPO` and exact
`github.com/OWNER/REPO` forms are accepted, and policy lookup always receives
`OWNER/REPO`.
Every checked GitHub API call also carries `--hostname github.com`, while the
subprocess environment removes `GH_REPO` and pins `GH_HOST=github.com`; ambient
CLI host/repository defaults cannot redirect preflight, dispatch, or readback.

The third checked mode, `--dispatch-workflow`, has no caller-selected workflow.
Policy fixes the repository, workflow ID, workflow path, and workflow name. The
caller must supply an explicit `refs/heads/...` ref and an exact lowercase
40-character expected SHA. Before the single dispatch POST, the publisher reads
back the repository, active workflow metadata, remote branch ref, and complete
branch/event run inventory. The remote branch must resolve exactly to the
authorized SHA. After dispatch it accepts exactly one new run, verifies
`event=workflow_dispatch`, repository, workflow, branch, path and `head_sha`,
waits for completion, and emits a JSON receipt containing run ID, URL, workflow,
ref, SHA and final conclusion. Zero, multiple, malformed or mismatched runs are
terminal `BLOCKED` outcomes and never cause a retry or transport fallback.
GitHub's dispatch API accepts a branch name rather than an immutable SHA, so the
publisher re-reads the branch immediately before dispatch and treats the run's
post-dispatch `head_sha` as authoritative. A concurrent branch move can start a
mismatched run, but it can never produce a valid receipt or automatic retry.

For RSIP, the checked branch-push mode is also the first-write gate for a full
publication plan. Before pushing, it validates the exact local SHA and remote,
the authorized PR base/head with no existing open PR, and the active fixed
full-regression workflow. A plan with any unavailable or inconsistent later
step stops before the push. Direct `gh workflow run` and direct workflow-dispatch
API writes remain unauthorized; only the checked Python publisher may perform
the fixed dispatch.

Policy Python and JSON are one runtime generation. Editing either file does not
reload modules already imported by a long-running Desktop/backend process; a new
chat is not a backend reload. Restart that Hermes tooling process after a
validated policy change. Policy-load failures remain terminal and retain the
original local exception in error logs for diagnosis.

Skills Hub publishes a branch and files directly inside the authorized repository;
it no longer forks. It validates every HTTP response, does not follow redirects,
and never opens a PR after a failed branch creation or file upload. Partial
successful writes can remain after a failure: cleanup is another mutation and is
not attempted automatically.

The updater's fork-sync push remains pinned to the Hermes repository, validates
its existing `origin` destination, and
fails closed; it does not choose `fork` as recovery when `origin` is unauthorized.
The `js-autofix` workflow validates its repository before obtaining an App token,
uses the shared push preflight and explicit gh destinations, and no longer ignores
write failures or force-pushes a stale bot branch. It may open the bot PR but
never auto-merges, auto-closes or deletes the branch. A rejected bot push needs
a separate authorization; it must not trigger a PR.

The Control Plane submission/resume contract and `local-only` completion semantics
are unchanged. The common runtime guidance and terminal guard apply to the Hermes
worker; `local-only` still is **not** a GitHub network-access restriction.

## Scope and residual risks

This is application-level fail-closed hardening, **not** a cryptographic or OS
security boundary. Recognized terminal publication commands are guarded, but a
shell parser cannot prove the effects of arbitrary code. Reusable credentials can
still be used through arbitrary Python, curl, browser sessions, MCP, subprocesses,
modified source/configuration or external binaries. SSH configuration, network
proxies, hooks, concurrently edited Git configuration and other user-controlled
execution inputs are not isolated by this patch. The policy is authoritative, but
application checks alone cannot make all possible bypasses impossible.

`BLOCKED` stops the current publication sequence. It does not revoke credentials
or supply a durable cross-process authorization ledger. A worker must obey the
invariant on resume/delegation as well; do not mistake prompt guidance for an OS
capability restriction or a durable revocation mechanism.

`scripts/release.py --publish` is blocked before tag, version, Git or release
work. Release authorization is separate from branch/PR publication authorization.
The RSIP `deploy.sh` legacy auto-commit/push/restart script is also outside this
Hermes-only change; no production deployment or RSIP runtime change is authorized.
That deployment script must not be treated as an alternative publication
mechanism after `BLOCKED`.

## Separate future proposal (not implemented)

Run workers without reusable GitHub write credentials, writable publisher policy,
SSH-agent access or authenticated GitHub browser sessions. Reserve GitHub writes
for a separately isolated publisher with a scoped installation identity and a
repository/action whitelist. Bind its authorization records to repository,
commit, branch, operation and an explicit new user decision after refusal. Route
all automated writes through it, including delegated and resumed jobs, and test
network/credential isolation. This is the future architecture needed for a hard
boundary; it is deliberately not claimed by this candidate.

## Verification discipline

Negative tests intercept every remote write. Test real Git configuration in
throwaway repositories, including hostile defaults, push URLs, rewritten/multiple
URLs and rejected pushes. Verify zero PR attempts after failure. Test API response
failures and no-fork behavior, Electron commit+push/push/create-PR paths, terminal
historical-command refusal, and preservation of upstream reads. Never test refusal
by opening a real upstream PR, and do not use `gh pr create --dry-run` as a safety
boundary: it can still push changes.
