import { Sandbox } from 'railway'

import type { ScanJob } from '../worker.js'

import { INVESTIGATOR_PROMPT, VERIFIER_PROMPT } from './prompts.js'
import {
  checkV2Template,
  destroyCheckV2Sandbox,
  discoverCandidates,
  type CheckV2Sandbox,
} from './sandbox.js'
import type {
  AgentConfig,
  AgentReport,
  Candidate,
  Evidence,
  Finding,
  CheckV2Result,
} from './types.js'

// Bump whenever V2's analysis protocol changes so cached results are not
// reused across materially different investigator/verifier behavior.
export const SCANNER_VERSION = 'v2-ripgrep-semgrep-investigate-verify-2'

const PROVIDER_KEY_ENV: Record<string, string> = {
  openrouter: 'OPENROUTER_API_KEY',
  openai: 'OPENAI_API_KEY',
  anthropic: 'ANTHROPIC_API_KEY',
  google: 'GEMINI_API_KEY',
  deepseek: 'DEEPSEEK_API_KEY',
  groq: 'GROQ_API_KEY',
  mistral: 'MISTRAL_API_KEY',
  xai: 'XAI_API_KEY',
}

function configuredAgent(): AgentConfig | null {
  const provider = (process.env.CODEVET_AI_PROVIDER ?? 'openrouter').toLowerCase()
  const piKeyEnv = PROVIDER_KEY_ENV[provider]
  const apiKey = process.env.CODEVET_AI_API_KEY ?? (piKeyEnv ? process.env[piKeyEnv] : undefined)
  const model = process.env.CODEVET_AI_MODEL?.trim()
  return piKeyEnv && apiKey && model ? { provider, model, apiKey, piKeyEnv } : null
}

function validatedCloneUrl(repoUrl: string, commitSha: string): string {
  if (!/^[0-9a-f]{40}$/i.test(commitSha)) throw new Error('CheckV2 requires a 40-character commit SHA')
  const url = new URL(repoUrl)
  if (
    url.protocol !== 'https:' || url.hostname !== 'github.com' || url.port ||
    url.username || url.password || url.search || url.hash ||
    !/^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git$/.test(url.pathname)
  ) {
    throw new Error('CheckV2 only permits canonical HTTPS github.com clone URLs')
  }
  return url.toString()
}

async function waitForSandbox(sandbox: CheckV2Sandbox): Promise<void> {
  // No application-level deadline: Railway remains the owner of its lifecycle.
  for (;;) {
    await sandbox.refresh()
    if (sandbox.status === 'RUNNING') return
    if (['FAILED', 'DESTROYED', 'DESTROYING'].includes(sandbox.status)) {
      throw new Error(`CheckV2 sandbox failed to start (${sandbox.status})`)
    }
    await new Promise((resolve) => setTimeout(resolve, 250))
  }
}

async function checkout(
  sandbox: CheckV2Sandbox,
  repoUrl: string,
  commitSha: string,
): Promise<void> {
  const result = await sandbox.exec(`
    runuser -u scanner -- env -i \\
      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \\
      HOME=/home/scanner \\
      REPO_URL='${repoUrl}' \\
      COMMIT_SHA='${commitSha}' \\
      GIT_CONFIG_NOSYSTEM=1 \\
      GIT_CONFIG_GLOBAL=/dev/null \\
      GIT_TERMINAL_PROMPT=0 \\
      bash --noprofile --norc -c '
        set -eu
        git init /workspace/repo
        cd /workspace/repo
        git -c core.hooksPath=/dev/null -c credential.helper= -c protocol.allow=never \\
          -c protocol.https.allow=always -c filter.lfs.smudge= -c filter.lfs.process= \\
          fetch --depth=1 --no-tags --no-recurse-submodules -- "$REPO_URL" "$COMMIT_SHA"
        git -c core.hooksPath=/dev/null checkout --detach FETCH_HEAD
        test "$(git rev-parse HEAD)" = "$COMMIT_SHA"
      '
  `)
  if (result.exitCode !== 0) throw new Error('CheckV2 could not fetch the requested commit')
}

function jsonObject(stdout: string): unknown {
  const start = stdout.indexOf('{')
  const end = stdout.lastIndexOf('}')
  if (start < 0 || end < start) throw new Error('Agent did not return JSON')
  return JSON.parse(stdout.slice(start, end + 1))
}

function text(value: unknown, field: string, max = 4_000): string {
  if (typeof value !== 'string' || !value.trim() || value.length > max) {
    throw new Error(`Invalid ${field}`)
  }
  return value
}

function relativePath(value: unknown): string {
  const path = text(value, 'path', 1_000)
  if (path.startsWith('/') || path.split('/').some((part) => !part || part === '.' || part === '..') || /[\x00-\x1f\x7f]/.test(path)) {
    throw new Error('Invalid repository path')
  }
  return path
}

function line(value: unknown): number {
  if (!Number.isInteger(value) || (value as number) < 1) throw new Error('Invalid source line')
  return value as number
}

function parseEvidence(value: unknown): Evidence {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid evidence')
  const item = value as Record<string, unknown>
  const file = relativePath(item.file)
  const startLine = line(item.startLine)
  const endLine = line(item.endLine)
  if (endLine < startLine || endLine - startLine > 50) throw new Error('Invalid evidence range')
  return { file, startLine, endLine, note: text(item.note, 'evidence note') }
}

function parseFlow(value: unknown): Finding['flow'] | undefined {
  if (value == null) return undefined
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid flow')
  const flow = value as Record<string, unknown>
  const result: NonNullable<Finding['flow']> = {}
  if (flow.source != null) result.source = parseEvidence(flow.source)
  if (flow.sink != null) result.sink = parseEvidence(flow.sink)
  if (flow.transformations != null) {
    if (!Array.isArray(flow.transformations) || flow.transformations.length > 20) throw new Error('Invalid flow transformations')
    result.transformations = flow.transformations.map(parseEvidence)
  }
  return result
}

function normalizedEnum(
  value: unknown,
  field: string,
  allowed: readonly string[],
  aliases: Readonly<Record<string, string>> = {},
): string {
  if (typeof value !== 'string') throw new Error(`Invalid ${field}`)
  const normalized = value.trim().toLowerCase().replace(/[\s_-]+/g, '_')
  const canonical = aliases[normalized] ?? normalized
  if (!allowed.includes(canonical)) throw new Error(`Invalid ${field}`)
  return canonical
}

/** Parse one model finding into the canonical persisted schema. */
export function parseFinding(value: unknown): Finding {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid finding')
  const item = value as Record<string, unknown>
  // Accept the two equivalent camel-case spellings used by the older scanner
  // protocol, but retain one canonical persisted schema.
  const kind = item.kind === 'suspiciousBehavior' ? 'suspicious_behavior'
    : item.kind === 'securityIssue' ? 'security_issue'
    : item.kind
  if (kind !== 'suspicious_behavior' && kind !== 'security_issue') throw new Error('Invalid finding kind')
  // Models commonly use presentation case ("High") and occasionally the
  // equivalent labels below. Canonicalize those values at the protocol edge
  // rather than failing an otherwise fully source-verified scan.
  const severity = normalizedEnum(item.severity, 'severity', ['low', 'medium', 'high', 'critical'], {
    info: 'low', informational: 'low', moderate: 'medium', severe: 'high',
  }) as Finding['severity']
  const confidence = normalizedEnum(item.confidence, 'confidence', ['low', 'medium', 'high'], {
    certain: 'high', strong: 'high', moderate: 'medium',
  }) as Finding['confidence']
  if (!Array.isArray(item.evidence) || item.evidence.length === 0 || item.evidence.length > 10) throw new Error('A finding needs evidence')
  return {
    kind,
    title: text(item.title, 'finding title', 500),
    severity,
    confidence,
    description: text(item.description, 'finding description'),
    evidence: item.evidence.map(parseEvidence),
    ...(item.flow == null ? {} : { flow: parseFlow(item.flow) }),
  }
}

/** Verify all model citations against checkout text before retaining them. */
async function verifyLocations(sandbox: CheckV2Sandbox, report: AgentReport): Promise<AgentReport> {
  const locations = report.findings.flatMap((finding) => [
    ...finding.evidence,
    ...(finding.flow?.source ? [finding.flow.source] : []),
    ...(finding.flow?.transformations ?? []),
    ...(finding.flow?.sink ? [finding.flow.sink] : []),
  ])
  const lengths = new Map<string, number>()
  for (const location of locations) {
    let count = lengths.get(location.file)
    if (count == null) {
      try {
        count = (await sandbox.files.read(`/workspace/repo/${location.file}`)).split(/\r?\n/).length
      } catch {
        throw new Error(`Agent cited unreadable file: ${location.file}`)
      }
      lengths.set(location.file, count)
    }
    if (location.endLine > count) throw new Error(`Agent cited invalid line: ${location.file}`)
  }
  return report
}

async function parseReport(sandbox: CheckV2Sandbox, stdout: string): Promise<AgentReport> {
  const raw = jsonObject(stdout)
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Invalid agent report')
  const report = raw as Record<string, unknown>
  if (!Array.isArray(report.findings) || !Array.isArray(report.inspectedFiles) || report.findings.length > 50 || report.inspectedFiles.length > 500) {
    throw new Error('Invalid report arrays')
  }
  const parsed: AgentReport = {
    summary: text(report.summary, 'summary'),
    findings: report.findings.map(parseFinding),
    inspectedFiles: [...new Set(report.inspectedFiles.map(relativePath))],
  }
  return verifyLocations(sandbox, parsed)
}

async function runAgent(
  sandbox: CheckV2Sandbox,
  agent: AgentConfig,
  systemPrompt: string,
  request: unknown,
): Promise<AgentReport> {
  await sandbox.files.write('/tmp/checkv2-agent-input.json', JSON.stringify(request))
  const command = `
    chown root:root /tmp/checkv2-agent-input.json
    chmod 600 /tmp/checkv2-agent-input.json
    cat /tmp/checkv2-agent-input.json | runuser -u scanner -- env -i \\
      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \\
      HOME=/home/scanner \\
      PI_TELEMETRY=0 \\
      CODEVET_AI_PROVIDER="$CODEVET_AI_PROVIDER" \\
      CODEVET_AI_MODEL="$CODEVET_AI_MODEL" \\
      CODEVET_AGENT_SYSTEM_PROMPT="$CODEVET_AGENT_SYSTEM_PROMPT" \\
      CODEVET_AGENT_API_KEY="$CODEVET_AGENT_API_KEY" \\
      ${agent.piKeyEnv}="$CODEVET_AGENT_API_KEY" \\
      bash --noprofile --norc -c '
        cd /workspace/repo
        # Use the template's absolute launcher. The fallback supports template
        # images created before that launcher was added.
        PI_COMMAND=/opt/checkv2/pi
        if [ ! -x "$PI_COMMAND" ]; then
          PI_COMMAND="$(npm prefix -g)/bin/pi"
        fi
        if [ ! -x "$PI_COMMAND" ]; then
          echo "Pi executable is unavailable" >&2
          exit 127
        fi
        exec "$PI_COMMAND" --print --no-session --provider "$CODEVET_AI_PROVIDER" --model "$CODEVET_AI_MODEL" --api-key "$CODEVET_AGENT_API_KEY" \\
          --tools read,grep,find,ls --no-context-files --no-extensions -e /opt/checkv2/repository-tools.js \\
          --no-skills --no-prompt-templates --no-approve --system-prompt "$CODEVET_AGENT_SYSTEM_PROMPT" \\
          -p "Analyze the repository using the JSON data supplied on stdin."
      '
  `
  const result = await sandbox.exec(command, {
    env: {
      CODEVET_AGENT_API_KEY: agent.apiKey,
      CODEVET_AI_PROVIDER: agent.provider,
      CODEVET_AI_MODEL: agent.model,
      CODEVET_AGENT_SYSTEM_PROMPT: systemPrompt,
    },
  })
  if (result.exitCode !== 0) {
    // Do not include stdout: it may contain model output derived from the
    // untrusted checkout. Pi reports startup/provider failures on stderr.
    const stderr = result.stderr.trim().slice(-4_000)
    const status = [
      `exit code ${result.exitCode ?? 'unknown'}`,
      ...(result.timedOut ? ['timed out'] : []),
      ...(result.truncated ? ['output truncated'] : []),
    ].join(', ')
    throw new Error(`Repository agent failed (${status})${stderr ? `: ${stderr}` : ''}`)
  }
  return parseReport(sandbox, result.stdout)
}

/**
 * V2 entrypoint. It has the same job input as the current orchestrator, so a
 * caller can switch imports when it is ready to adopt CheckV2Result.
 */
export async function runScannerContainer(
  job: ScanJob & { commitSha: string },
): Promise<CheckV2Result> {
  const commitSha = job.commitSha.toLowerCase()
  const repoUrl = validatedCloneUrl(job.repoUrl, commitSha)
  const sandbox = await Sandbox.create(checkV2Template, {
    networkIsolation: 'ISOLATED',
  })

  try {
    await waitForSandbox(sandbox)
    await checkout(sandbox, repoUrl, commitSha)
    const candidates = await discoverCandidates(sandbox)
    const agent = configuredAgent()
    if (!agent) {
      return {
        commitSha,
        candidates,
        investigation: null,
        findings: [],
        summary: 'Static candidate discovery completed; AI investigation is not configured.',
      }
    }

    const investigation = await runAgent(sandbox, agent, INVESTIGATOR_PROMPT, {
      role: 'investigator', candidates,
    })
    const verification = await runAgent(sandbox, agent, VERIFIER_PROMPT, {
      role: 'verifier', candidates, investigatorReport: investigation,
    })
    return {
      commitSha,
      candidates,
      investigation,
      findings: verification.findings,
      summary: verification.summary,
    }
  } finally {
    await destroyCheckV2Sandbox(sandbox)
  }
}

export type { CheckV2Result } from './types.js'
