import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { afterEach, test } from 'vitest'

import publicationPolicyJson from '../../../hermes_cli/publication_policy.json'

import {
  createPullRequestForPublishedBranch,
  policyFromJson,
  type PublicationCommandRunner,
  publicationPolicy,
  publishBranch
} from './github-publication'

const tempDirs: string[] = []

test('desktop policy parser fails closed on workflow or repository drift', () => {
  const mutations: Array<(value: typeof publicationPolicyJson) => void> = [
    value => { value.repositories['PPiquemal/rsip'].workflows.checked_workflow_dispatch.id = 1 },
    value => { value.repositories['PPiquemal/rsip'].operations.push('workflow_dispatch') },
    value => { value.repositories['PPiquemal/hermes-agent'].remote = 'origin' }
  ]

  for (const mutate of mutations) {
    const changed = structuredClone(publicationPolicyJson)

    mutate(changed)
    assert.throws(() => policyFromJson(changed), /Publication BLOCKED/)
  }
})

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { force: true, recursive: true })
  }
})

function makeRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-desktop-publication-'))

  tempDirs.push(dir)
  execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: dir })
  execFileSync('git', ['config', 'user.email', 'hermes-test@example.com'], { cwd: dir })
  execFileSync('git', ['config', 'user.name', 'Hermes Test'], { cwd: dir })
  fs.writeFileSync(path.join(dir, 'tracked.txt'), 'tracked\n')
  execFileSync('git', ['add', 'tracked.txt'], { cwd: dir })
  execFileSync('git', ['commit', '-qm', 'initial'], { cwd: dir })
  execFileSync('git', ['switch', '-qc', 'feature/publish-safe'], { cwd: dir })
  execFileSync('git', ['remote', 'add', publicationPolicy.remote, `https://github.com/${publicationPolicy.repository}.git`], {
    cwd: dir
  })

  return dir
}

function realGitRunner(onPush: (args: string[]) => void): PublicationCommandRunner {
  return async (command, args, cwd, env) => {
    if (command === 'git' && args.includes('push')) {
      onPush(args)

      return { exitCode: 0, stderr: '', stdout: '' }
    }

    try {
      return {
        exitCode: 0,
        stderr: '',
        stdout: execFileSync(command, args, { cwd, env: env as NodeJS.ProcessEnv, encoding: 'utf8' })
      }
    } catch (error) {
      const failed = error as { status?: number; stderr?: string; stdout?: string }

      return {
        exitCode: failed.status ?? 1,
        stderr: String(failed.stderr || ''),
        stdout: String(failed.stdout || '')
      }
    }
  }
}

test('publishBranch validates a real local repository before one explicit safe push', async () => {
  const repo = makeRepo()
  const pushes: string[][] = []

  const result = await publishBranch(repo, realGitRunner(args => pushes.push(args)))

  assert.equal(result.branch, 'feature/publish-safe')
  assert.equal(result.head.length, 40)
  assert.deepEqual(pushes, [
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
      `https://github.com/${publicationPolicy.repository}.git`,
      `${result.head}:refs/heads/feature/publish-safe`
    ]
  ])
})

test('publishBranch blocks URL rewrites before any push', async () => {
  const commands: string[][] = []

  const runner: PublicationCommandRunner = async (command, args) => {
    commands.push([command, ...args])

    if (args.join(' ') === `config --get-all remote.${publicationPolicy.remote}.pushurl`) {
      return { exitCode: 1, stderr: '', stdout: '' }
    }

    if (args.join(' ') === `config --get-all remote.${publicationPolicy.remote}.url`) {
      return { exitCode: 0, stderr: '', stdout: `https://github.com/${publicationPolicy.repository}.git\n` }
    }

    if (args.join(' ') === `remote get-url --push --all ${publicationPolicy.remote}`) {
      return { exitCode: 0, stderr: '', stdout: `git@github.com:${publicationPolicy.repository}.git\n` }
    }

    return { exitCode: 0, stderr: '', stdout: '' }
  }

  await assert.rejects(
    () => publishBranch('/tmp/not-used', runner),
    (error: unknown) => error instanceof Error && /^Publication BLOCKED: .*rewrite/.test(error.message)
  )
  assert.equal(commands.some(command => command.includes('push')), false)
})

test('publishBranch blocks configured extra push refspecs before any push', async () => {
  const repo = makeRepo()
  const pushes: string[][] = []
  const runner = realGitRunner(args => pushes.push(args))

  execFileSync('git', ['config', `remote.${publicationPolicy.remote}.push`, 'refs/heads/*:refs/heads/*'], { cwd: repo })

  await assert.rejects(
    () => publishBranch(repo, runner),
    (error: unknown) => error instanceof Error && /^Publication BLOCKED: .*push refspec/.test(error.message)
  )
  assert.deepEqual(pushes, [])
})

test('createPullRequestForPublishedBranch pins the GitHub target and ignores ambient gh repository selection', async () => {
  const repo = makeRepo()
  const pushes: string[][] = []
  const ghCalls: Array<{ args: string[]; env?: NodeJS.ProcessEnv }> = []
  const runner = realGitRunner(args => pushes.push(args))

  const ghRunner: PublicationCommandRunner = async (command, args, _cwd, env) => {
    ghCalls.push({ args: [command, ...args], env: env as NodeJS.ProcessEnv })

    return { exitCode: 0, stderr: '', stdout: 'https://github.com/PPiquemal/hermes-agent/pull/123\n' }
  }

  const result = await createPullRequestForPublishedBranch(repo, runner, ghRunner, {
    GH_HOST: 'example.invalid',
    GH_REPO: 'attacker/other'
  })

  assert.equal(result.url, 'https://github.com/PPiquemal/hermes-agent/pull/123')
  assert.equal(pushes.length, 1)
  assert.deepEqual(ghCalls.map(call => call.args), [
    [
      'gh',
      'pr',
      'create',
      '--repo',
      `github.com/${publicationPolicy.repository}`,
      '--head',
      `PPiquemal:${result.branch}`,
      '--base',
      publicationPolicy.base,
      '--fill'
    ]
  ])
  assert.equal(ghCalls[0].env?.GH_HOST, 'github.com')
  assert.equal(ghCalls[0].env?.GH_REPO, undefined)
})

test('createPullRequestForPublishedBranch never calls gh after a rejected push', async () => {
  const repo = makeRepo()
  let ghCalls = 0

  const gitRunner = realGitRunner(() => {
    throw new Error('permission denied')
  })

  const ghRunner: PublicationCommandRunner = async () => {
    ghCalls += 1

    return { exitCode: 0, stderr: '', stdout: 'https://github.com/PPiquemal/hermes-agent/pull/123\n' }
  }

  await assert.rejects(
    () => createPullRequestForPublishedBranch(repo, gitRunner, ghRunner),
    (error: unknown) => error instanceof Error && error.message.startsWith('Publication BLOCKED:')
  )
  assert.equal(ghCalls, 0)
})

test('createPullRequestForPublishedBranch blocks a mismatched PR result URL', async () => {
  const repo = makeRepo()
  const runner = realGitRunner(() => undefined)

  const ghRunner: PublicationCommandRunner = async () => ({
    exitCode: 0,
    stderr: '',
    stdout: 'https://github.com/NousResearch/hermes-agent/pull/111551\n'
  })

  await assert.rejects(
    () => createPullRequestForPublishedBranch(repo, runner, ghRunner),
    (error: unknown) => error instanceof Error && error.message.startsWith('Publication BLOCKED:')
  )
})
