import { execFile } from 'node:child_process'

import publicationPolicyJson from '../../../hermes_cli/publication_policy.json'

export interface PublicationPolicy {
  repository: string
  read_only_repository: string
  remote: string
  base: string
}

interface PublicationRepositoryPolicy {
  remote: string
  base: string
  operations: string[]
  operation_remotes: Record<string, string>
  allow_github_com_urls: boolean
  workflows: Record<string, { id: number; name: string; path: string }>
  ssh_aliases: Record<string, { hostname: string; user: string }>
}

interface PublicationPolicyFile {
  repositories: Record<string, PublicationRepositoryPolicy>
  read_only_repositories: string[]
}

export interface PublicationCommandResult {
  exitCode: number
  stderr: string
  stdout: string
}

export type PublicationCommandRunner = (
  command: string,
  args: string[],
  cwd: string,
  env?: NodeJS.ProcessEnv
) => Promise<PublicationCommandResult>

export class PublicationBlockedError extends Error {
  constructor(reason: string) {
    super(`Publication BLOCKED: ${reason}`)
    this.name = 'PublicationBlockedError'
  }
}

function exactKeys(value: object, expected: string[]) {
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort())
}

function exactStrings(value: unknown, expected: string[]) {
  return (
    Array.isArray(value) &&
    value.every(entry => typeof entry === 'string') &&
    JSON.stringify([...value].sort()) === JSON.stringify([...expected].sort())
  )
}

export function policyFromJson(value: unknown): PublicationPolicy {
  const candidate = value as Partial<PublicationPolicyFile>
  const repository = 'PPiquemal/hermes-agent'
  const selected = candidate?.repositories?.[repository]
  const rsip = candidate?.repositories?.['PPiquemal/rsip']
  const rsipWorkflow = rsip?.workflows?.checked_workflow_dispatch

  if (
    !candidate ||
    !selected ||
    !rsip ||
    !candidate.repositories ||
    !exactKeys(candidate, ['repositories', 'read_only_repositories']) ||
    !exactKeys(candidate.repositories, [repository, 'PPiquemal/rsip']) ||
    !Array.isArray(candidate.read_only_repositories) ||
    !exactStrings(candidate.read_only_repositories, ['NousResearch/hermes-agent']) ||
    !exactKeys(selected, [
      'remote', 'base', 'operations', 'operation_remotes',
      'allow_github_com_urls', 'workflows', 'ssh_aliases'
    ]) ||
    selected.remote !== 'fork' ||
    selected.base !== 'main' ||
    selected.allow_github_com_urls !== true ||
    !exactStrings(selected.operations, [
      'hermes_branch', 'hermes_pr', 'skills', 'autofix', 'update',
      'checked_branch_push', 'checked_pr_create'
    ]) ||
    !exactKeys(selected.operation_remotes, ['autofix', 'update']) ||
    selected.operation_remotes.autofix !== 'origin' ||
    selected.operation_remotes.update !== 'origin' ||
    !exactKeys(selected.workflows, []) ||
    !exactKeys(selected.ssh_aliases, []) ||
    !exactKeys(rsip, [
      'remote', 'base', 'operations', 'operation_remotes',
      'allow_github_com_urls', 'workflows', 'ssh_aliases'
    ]) ||
    rsip.remote !== 'origin' ||
    rsip.base !== 'main' ||
    rsip.allow_github_com_urls !== false ||
    !exactStrings(rsip.operations, [
      'checked_branch_push', 'checked_pr_create', 'checked_workflow_dispatch'
    ]) ||
    !exactKeys(rsip.operation_remotes, []) ||
    !exactKeys(rsip.workflows, ['checked_workflow_dispatch']) ||
    !rsipWorkflow ||
    !exactKeys(rsipWorkflow, ['id', 'name', 'path']) ||
    rsipWorkflow.id !== 265670631 ||
    rsipWorkflow.name !== 'RSIP Tests' ||
    rsipWorkflow.path !== '.github/workflows/test.yml' ||
    !exactKeys(rsip.ssh_aliases, ['github-rsip']) ||
    !exactKeys(rsip.ssh_aliases['github-rsip'], ['hostname', 'user']) ||
    rsip.ssh_aliases['github-rsip'].hostname !== 'github.com' ||
    rsip.ssh_aliases['github-rsip'].user !== 'git'
  ) {
    throw new PublicationBlockedError('publication policy is incomplete')
  }

  return {
    repository,
    read_only_repository: 'NousResearch/hermes-agent',
    remote: selected.remote,
    base: selected.base
  }
}

export const publicationPolicy = policyFromJson(publicationPolicyJson)

export function processPublicationCommandRunner(): PublicationCommandRunner {
  return (command, args, cwd, env) =>
    new Promise(resolve => {
      execFile(
        command,
        args,
        { cwd, env, windowsHide: true, timeout: 30_000, maxBuffer: 8 * 1024 * 1024 },
        (error, stdout, stderr) =>
          resolve({
            exitCode: typeof error?.code === 'number' ? error.code : error ? 1 : 0,
            stderr: String(stderr || ''),
            stdout: String(stdout || '')
          })
      )
    })
}

function blocked(reason: string): never {
  throw new PublicationBlockedError(reason)
}

function lines(value: string) {
  return String(value || '')
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
}

function commandFailure(label: string, result: PublicationCommandResult): never {
  const detail = lines(result.stderr)[0] || lines(result.stdout)[0]

  blocked(`${label}${detail ? `: ${detail}` : ''}`)
}

async function requiredCommand(
  runner: PublicationCommandRunner,
  command: string,
  args: string[],
  cwd: string,
  env?: NodeJS.ProcessEnv
) {
  const result = await runner(command, args, cwd, env)

  if (result.exitCode !== 0) {
    commandFailure(`${command} ${args[0]} failed`, result)
  }

  return result.stdout
}

async function optionalConfig(runner: PublicationCommandRunner, gitBin: string, cwd: string, key: string) {
  const result = await runner(gitBin, ['config', '--get-all', key], cwd)

  if (result.exitCode === 0) {
    return lines(result.stdout)
  }

  if (result.exitCode === 1) {
    return []
  }

  commandFailure(`git config ${key} failed`, result)
}

async function applicableUrlRewrites(runner: PublicationCommandRunner, gitBin: string, cwd: string, rawUrl: string) {
  const result = await runner(gitBin, ['config', '--get-regexp', '^url\\..*\\.(insteadOf|pushInsteadOf)$'], cwd)

  if (result.exitCode === 1) {
    return []
  }

  if (result.exitCode !== 0) {
    commandFailure('git config URL rewrite lookup failed', result)
  }

  return lines(result.stdout).filter(line => {
    const value = line.replace(/^\S+\s+/, '')

    return value && rawUrl.startsWith(value)
  })
}

function isTruthyGitConfig(value: string) {
  return ['true', 'yes', 'on', '1'].includes(value.trim().toLowerCase())
}

function requireApprovedRemoteUrl(url: string) {
  const repositoryPath = `${publicationPolicy.repository}.git`
  const sshScp = /^git@github\.com:([^\s]+)$/
  const sshUrl = /^ssh:\/\/git@github\.com\/([^\s]+)$/
  const httpsUrl = /^https:\/\/github\.com\/([^\s]+)$/
  const match = sshScp.exec(url) || sshUrl.exec(url) || httpsUrl.exec(url)

  if (!match || match[1] !== repositoryPath) {
    blocked(`remote ${publicationPolicy.remote} does not target the approved GitHub repository`)
  }
}

async function validateRemote(cwd: string, runner: PublicationCommandRunner, gitBin: string) {
  const rawUrls = await optionalConfig(runner, gitBin, cwd, `remote.${publicationPolicy.remote}.url`)
  const pushUrls = await optionalConfig(runner, gitBin, cwd, `remote.${publicationPolicy.remote}.pushurl`)

  const effectiveUrls = lines(
    await requiredCommand(runner, gitBin, ['remote', 'get-url', '--push', '--all', publicationPolicy.remote], cwd)
  )

  if (rawUrls.length !== 1 || pushUrls.length > 0 || effectiveUrls.length !== 1) {
    blocked(`remote ${publicationPolicy.remote} must have exactly one configured and effective push URL`)
  }

  if (rawUrls[0] !== effectiveUrls[0]) {
    blocked(`remote ${publicationPolicy.remote} push URL rewrite is not permitted`)
  }

  requireApprovedRemoteUrl(effectiveUrls[0])

  const [mirror, refspecs, followTags, rewrites] = await Promise.all([
    optionalConfig(runner, gitBin, cwd, `remote.${publicationPolicy.remote}.mirror`),
    optionalConfig(runner, gitBin, cwd, `remote.${publicationPolicy.remote}.push`),
    optionalConfig(runner, gitBin, cwd, 'push.followTags'),
    applicableUrlRewrites(runner, gitBin, cwd, rawUrls[0])
  ])

  if (mirror.some(isTruthyGitConfig)) {
    blocked(`remote ${publicationPolicy.remote} mirror publishing is not permitted`)
  }

  if (refspecs.length > 0) {
    blocked(`remote ${publicationPolicy.remote} configured push refspecs are not permitted`)
  }

  if (followTags.some(isTruthyGitConfig)) {
    blocked('push.followTags must not be enabled')
  }

  if (rewrites.length > 0) {
    blocked('applicable Git URL rewrite configuration is not permitted')
  }

  return effectiveUrls[0]
}

async function validateBranch(cwd: string, runner: PublicationCommandRunner, gitBin: string) {
  const branch = (await requiredCommand(runner, gitBin, ['symbolic-ref', '--quiet', '--short', 'HEAD'], cwd)).trim()

  if (!branch || branch === publicationPolicy.base) {
    blocked('a non-base checked-out branch is required')
  }

  await requiredCommand(runner, gitBin, ['check-ref-format', '--branch', branch], cwd)

  const head = (await requiredCommand(runner, gitBin, ['rev-parse', '--verify', 'HEAD^{commit}'], cwd)).trim()

  const branchHead = (
    await requiredCommand(runner, gitBin, ['rev-parse', '--verify', `refs/heads/${branch}^{commit}`], cwd)
  ).trim()

  if (!/^[0-9a-f]{40,64}$/i.test(head) || branchHead !== head) {
    blocked('checked-out branch does not resolve to one concrete HEAD commit')
  }

  return { branch, head }
}

async function asBlocked<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation()
  } catch (error) {
    if (error instanceof PublicationBlockedError) {
      throw error
    }

    blocked(error instanceof Error && error.message ? error.message : String(error))
  }
}

export async function validatePublication(cwd: string, runner: PublicationCommandRunner, gitBin = 'git') {
  return asBlocked(async () => {
    const remoteUrl = await validateRemote(cwd, runner, gitBin)
    const branch = await validateBranch(cwd, runner, gitBin)

    return { ...branch, remoteUrl }
  })
}

export async function publishBranch(cwd: string, runner: PublicationCommandRunner, gitBin = 'git') {
  return asBlocked(async () => {
    const publication = await validatePublication(cwd, runner, gitBin)
    const refspec = `${publication.head}:refs/heads/${publication.branch}`

    await requiredCommand(
      runner,
      gitBin,
      [
        '-c',
        'push.followTags=false',
        '-c',
        'push.recurseSubmodules=no',
        '-c',
        'http.followRedirects=false',
        'push',
        '--porcelain',
        '--',
        publication.remoteUrl,
        refspec
      ],
      cwd
    )

    return publication
  })
}

export async function createPullRequestForPublishedBranch(
  cwd: string,
  gitRunner: PublicationCommandRunner,
  ghRunner: PublicationCommandRunner,
  environment: NodeJS.ProcessEnv = process.env,
  gitBin = 'git',
  ghBin = 'gh'
) {
  return asBlocked(async () => {
    const branch = await publishBranch(cwd, gitRunner, gitBin)
    const ghEnvironment: NodeJS.ProcessEnv = { ...environment, GH_HOST: 'github.com' }

    delete ghEnvironment.GH_REPO

    const owner = publicationPolicy.repository.split('/')[0]

    const stdout = await requiredCommand(
      ghRunner,
      ghBin,
      [
        'pr',
        'create',
        '--repo',
        `github.com/${publicationPolicy.repository}`,
        '--head',
        `${owner}:${branch.branch}`,
        '--base',
        publicationPolicy.base,
        '--fill'
      ],
      cwd,
      ghEnvironment
    )

    const url = lines(stdout).pop() || ''
    const expectedUrlPrefix = `https://github.com/${publicationPolicy.repository}/pull/`

    if (!url.startsWith(expectedUrlPrefix) || !/^https:\/\/github\.com\/[^/\s]+\/[^/\s]+\/pull\/\d+$/.test(url)) {
      blocked('gh pr create did not return a GitHub pull request URL')
    }

    return { ...branch, url }
  })
}
