import type { Channel, ConsumeMessage } from 'amqplib'
import type { Pool } from 'pg'
import { Sandbox } from 'railway'

export type ScanJob = {
  uid: string
  repoUrl: string
}

type ScannerFinding = {
  ruleId: string
  title: string
  severity: 'low' | 'medium' | 'high'
  file: string
  line: number
  column: number
  snippet: string
  match: string
}

type ScannerResult = {
  commitSha: string | null
  findings: ScannerFinding[]
}

type ScanRule = {
  id: string
  title: string
  severity: ScannerFinding['severity']
  pattern: RegExp
}

const SCAN_RULES: ScanRule[] = [
  {
    id: 'input-monitoring',
    title: 'Potential keylogging or input monitoring',
    severity: 'high',
    pattern:
      /keylog(?:ger|ging)?|keystroke|keypress|keydown|keyup|globalShortcut|RegisterHotKey/i,
  },
  {
    id: 'clipboard-access',
    title: 'Potential clipboard access',
    severity: 'medium',
    pattern:
      /clipboard|navigator\.clipboard|pasteboard|xclip|pbcopy|GetClipboardData/i,
  },
  {
    id: 'credential-collection',
    title: 'Potential credential, token, or secret handling',
    severity: 'high',
    pattern:
      /password|passwd|credential|token|api[_-]?key|secret|private[_-]?key/i,
  },
  {
    id: 'network-activity',
    title: 'Potential network activity or exfiltration path',
    severity: 'medium',
    pattern:
      /https?:\/\/|fetch\(|XMLHttpRequest|WebSocket|axios\.|request\(|\bcurl\b|\bwget\b|net\.connect|socket/i,
  },
  {
    id: 'tracking-fingerprinting',
    title: 'Potential tracking, telemetry, or fingerprinting',
    severity: 'medium',
    pattern:
      /analytics|telemetry|fingerprint|deviceId|machineId|tracking/i,
  },
  {
    id: 'dynamic-execution',
    title: 'Potential dynamic code execution or shelling out',
    severity: 'medium',
    pattern:
      /child_process|exec\(|spawn\(|eval\(|Function\(|powershell|osascript/i,
  },
]

const MAX_FINDINGS = 200

export function validateRepoUrl(repoUrl: string): URL {
  const url = new URL(repoUrl)

  if (url.protocol !== 'https:') {
    throw new Error('Only HTTPS repositories are allowed')
  }

  if (url.hostname !== 'github.com') {
    throw new Error('Only github.com repositories are allowed')
  }

  const parts = url.pathname
    .replace(/\\.git$/, '')
    .split('/')
    .filter(Boolean)

  if (parts.length !== 2) {
    throw new Error('Invalid GitHub repository URL')
  }

  const [owner, repo] = parts

  const validPart = /^[A-Za-z0-9_.-]+$/

  if (!validPart.test(owner) || !validPart.test(repo)) {
    throw new Error('Invalid GitHub repository URL')
  }

  return new URL(
    `https://github.com/${owner}/${repo}.git`
  )
}

function repoIdentifierFromUrl(repoUrl: URL): string {
  return repoUrl.pathname.replace(/^\//, '').replace(/\.git$/, '')
}

export const scannerTemplate = Sandbox.template()
  .withPackages(
    'git',
    'ripgrep',
    'ca-certificates',
    'util-linux',
    'passwd'
  )
  .run(`
    set -eux

    command -v git
    command -v rg
    command -v useradd
    command -v runuser

    mkdir -p /workspace
  `)
  .workdir('/workspace')

export async function processRequest(
  pool: Pool,
  channel: Channel,
  msg: ConsumeMessage,
  job: ScanJob
) {
  const { uid, repoUrl } = job

  try {
    console.log(`[${uid}] Starting ${repoUrl}`)

    const result = await pool.query(
      `
        UPDATE requests
        SET status = 'processing'
        WHERE uid = $1
        RETURNING uid
      `,
      [uid]
    )

    if (result.rowCount === 0) {
      console.error(`[${uid}] Request does not exist in database`)

      channel.ack(msg)
      return
    }

    let validatedRepoUrl: URL

    try {
      validatedRepoUrl = validateRepoUrl(repoUrl)
    } catch (error) {
      console.error(`[${uid}] Invalid repository URL:`, error)

      await pool.query(
        `
          UPDATE requests
          SET status = 'invalid'
          WHERE uid = $1
        `,
        [uid]
      )

      channel.ack(msg)
      return
    }

    const repoIdentifier = repoIdentifierFromUrl(validatedRepoUrl)
    const scannerResult = await runScannerContainer({
      ...job,
      repoUrl: validatedRepoUrl.toString(),
    })

    await pool.query(
      `
        INSERT INTO repo_results (
          uid,
          repo_identifier,
          repo_url,
          commit_sha,
          summary,
          findings,
          scanned_at
        )
        VALUES ($1, $2, $3, $4, $5, $6::jsonb, NOW())
        ON CONFLICT (uid, repo_identifier)
        DO UPDATE SET
          repo_url = EXCLUDED.repo_url,
          commit_sha = EXCLUDED.commit_sha,
          summary = EXCLUDED.summary,
          findings = EXCLUDED.findings,
          scanned_at = NOW()
      `,
      [
        uid,
        repoIdentifier,
        validatedRepoUrl.toString(),
        scannerResult.commitSha,
        '',
        JSON.stringify(scannerResult.findings),
      ]
    )

    console.log(
      `[${uid}] Stored ${scannerResult.findings.length} finding(s)`
    )

    await pool.query(
      `
        UPDATE requests
        SET status = 'completed'
        WHERE uid = $1
      `,
      [uid]
    )

    channel.ack(msg)

    console.log(`[${uid}] Completed`)
  } catch (error) {
    console.error(`[${uid}] Worker failed:`, error)

    try {
      await pool.query(
        `
          UPDATE requests
          SET status = 'failed'
          WHERE uid = $1
        `,
        [uid]
      )
    } catch (dbError) {
      console.error(
        `[${uid}] Failed to update database status:`,
        dbError
      )
    }

    channel.nack(msg, false, false)
  }
}

async function runScannerContainer(
  job: ScanJob
): Promise<ScannerResult> {
  const { uid, repoUrl } = job

  console.log(`[${uid}] Creating Railway sandbox`)

  let sandbox: Awaited<ReturnType<typeof Sandbox.create>>

  try {
    sandbox = await Sandbox.create(scannerTemplate, {
      // Destroy it fairly quickly if your worker crashes before cleanup.
      idleTimeoutMinutes: 5,

      // Default is already ISOLATED:
      // public internet is available, but it cannot access your
      // Railway project's private network.
      networkIsolation: 'ISOLATED',

      env: {
        JOB_UID: uid,
        REPO_URL: repoUrl,
      },
    })
  } catch (error) {
    console.error(`[${uid}] Failed to create Railway sandbox:`, error)
    throw error
  }

  console.log(`[${uid}] Sandbox created: ${sandbox.id}`)

  try {
    const result = await sandbox.exec(
      `
        runuser -u scanner -- env \
          HOME=/home/scanner \
          JOB_UID="$JOB_UID" \
          REPO_URL="$REPO_URL" \
          GIT_TERMINAL_PROMPT=0 \
          bash --noprofile --norc <<'SCAN_SCRIPT'
            set -euo pipefail

            cd /workspace

            echo "Sandbox started"
            echo "Job: $JOB_UID"

            git \
              -c core.hooksPath=/dev/null \
              -c protocol.file.allow=never \
              -c protocol.ext.allow=never \
              -c filter.lfs.smudge= \
              -c filter.lfs.process= \
              clone \
              --depth=1 \
              --single-branch \
              --no-tags \
              --no-recurse-submodules \
              "$REPO_URL" \
              repo

            unset REPO_URL
            cd repo

            echo "Repository cloned"
            echo "CODEVET_COMMIT:$(git rev-parse HEAD)"
            echo "CODEVET_RG_BEGIN"

            set +e
            set +o pipefail
            rg \
              --json \
              --hidden \
              --ignore-case \
              --line-number \
              --column \
              --max-filesize 1M \
              --max-count 50 \
              --glob '!**/.git/**' \
              --glob '!**/node_modules/**' \
              --glob '!**/vendor/**' \
              --glob '!**/dist/**' \
              --glob '!**/build/**' \
              --glob '!**/target/**' \
              --glob '!**/*.lock' \
              -e 'keylog(ger|ging)?|keystroke|keypress|keydown|keyup|globalShortcut|RegisterHotKey' \
              -e 'clipboard|navigator\.clipboard|pasteboard|xclip|pbcopy|GetClipboardData' \
              -e 'password|passwd|credential|token|api[_-]?key|secret|private[_-]?key' \
              -e 'https?://|fetch\(|XMLHttpRequest|WebSocket|axios\.|request\(|\bcurl\b|\bwget\b|net\.connect|socket' \
              -e 'analytics|telemetry|fingerprint|deviceId|machineId|tracking' \
              -e 'child_process|exec\(|spawn\(|eval\(|Function\(|powershell|osascript' \
              . | head -n 1000
            rg_status=\${PIPESTATUS[0]}
            set -o pipefail
            set -e

            if [ "$rg_status" -ne 0 ] && [ "$rg_status" -ne 1 ] && [ "$rg_status" -ne 141 ]; then
              exit "$rg_status"
            fi

            echo "CODEVET_RG_END"
SCAN_SCRIPT
      `,
      {
        timeoutSec: 120,
      }
    )

    console.log(`[${uid}] Sandbox stdout:`)
    console.log(result.stdout)

    if (result.stderr) {
      console.error(`[${uid}] Sandbox stderr:`)
      console.error(result.stderr)
    }

    if (result.exitCode !== 0) {
      throw new Error(
        `Sandbox command exited with code ${result.exitCode}`
      )
    }

    return parseScannerOutput(result.stdout)
  } finally {
    console.log(`[${uid}] Destroying sandbox`)

    try {
      await sandbox.destroy()
      console.log(`[${uid}] Sandbox destroyed`)
    } catch (error) {
      console.error(`[${uid}] Failed to destroy sandbox:`, error)
    }
  }
}

function parseScannerOutput(stdout: string): ScannerResult {
  const commitMatch = stdout.match(/^CODEVET_COMMIT:([0-9a-f]{40})$/m)
  const findings: ScannerFinding[] = []
  let inRgOutput = false

  for (const line of stdout.split('\n')) {
    if (line === 'CODEVET_RG_BEGIN') {
      inRgOutput = true
      continue
    }

    if (line === 'CODEVET_RG_END') {
      inRgOutput = false
      continue
    }

    if (!inRgOutput || findings.length >= MAX_FINDINGS) {
      continue
    }

    try {
      const event = JSON.parse(line)

      if (event.type !== 'match') {
        continue
      }

      const snippet = String(event.data?.lines?.text ?? '').trim()
      const rule = SCAN_RULES.find((candidate) =>
        candidate.pattern.test(snippet)
      )

      if (!rule) {
        continue
      }

      findings.push({
        ruleId: rule.id,
        title: rule.title,
        severity: rule.severity,
        file: String(event.data?.path?.text ?? ''),
        line: Number(event.data?.line_number ?? 0),
        column: Number(event.data?.submatches?.[0]?.start ?? 0) + 1,
        snippet: snippet.slice(0, 500),
        match: String(event.data?.submatches?.[0]?.match?.text ?? '').slice(
          0,
          200
        ),
      })
    } catch {
      // Ignore non-JSON progress/log lines emitted by the sandbox command.
    }
  }

  return {
    commitSha: commitMatch?.[1] ?? null,
    findings,
  }
}
