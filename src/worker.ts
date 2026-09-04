import type { Channel, ConsumeMessage } from 'amqplib'
import type { Pool } from 'pg'
import { Sandbox } from 'railway'

export type ScanJob = {
  uid: string
  repoUrl: string
  // When supplied by the producer, this lets the worker avoid scanning a
  // commit that has already been scanned.
  commitSha?: string
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
      /\b(?:password|passwd|credential|token|api[_-]?key|secret|private[_-]?key)s?\b/i,
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
  {
    id: 'sensitive-system-access',
    title: 'Potential sensitive device, system, or data access',
    severity: 'high',
    pattern:
      /getUserMedia|mediaDevices|MediaRecorder|microphone|micPermission|AVAudioRecorder|AVAudioEngine|AVCapture(?:Device|Session)|AudioRecord|RECORD_AUDIO|pyaudio|sounddevice|getDisplayMedia|camera|CAMERA|screenCapture|desktopCapturer|mouse(?:move|down|up|click)?|screencapture|clipboard|pasteboard|GetClipboardData|cookies?|browser[_ -]?(?:history|profile|profiles)|saved[_ -]?passwords?|home(?:dir|directory)?|Documents|\.env\b|config(?:uration)?[_ -]?files?|\.ssh|ssh[_ -]?keys?|private[_ -]?keys?|certificates?|keychains?|hostname|username|mac[_ -]?address|hardware[_ -]?id|device[_ -]?id|gps|geo(?:location)?|ip[_ -]?based[_ -]?location|process(?:es)?|running[_ -]?(?:processes|applications)|exec\(|spawn\(|PowerShell|osascript|startup[_ -]?items?|launch[_ -]?agents?|registry[_ -]?Run|cron|systemd|sudo|administrator[_ -]?elevation|setuid|UAC|https?:\/\/|fetch\(|XMLHttpRequest|WebSocket|raw[_ -]?sockets?|uploads?|exfiltrat(?:e|ion)|analytics|telemetry|fingerprint(?:ing)?|usage[_ -]?collection|eval\(|dynamically[_ -]?downloaded|Function\(|FFI|Win32|syscalls?|\/proc|\/dev/i,
  },
]

const MAX_FINDINGS = 1000
const MAX_RG_LINES = 1000

const LOW_CONFIDENCE_PATH_PATTERN =
  /(^|\/)(?:test|tests|__tests__|fixtures?|mocks?|docs?|examples?)\/|(?:^|\/)(?:README|CHANGELOG|LICENSE)(?:\.|$)|(?:_test\.go|\.(?:test|spec)\.[jt]sx?|\.md|\.lock|min\.js)$|(?:^|\/)node_modules\//i

function isLowConfidencePath(file: string): boolean {
  return LOW_CONFIDENCE_PATH_PATTERN.test(file.replace(/^\.\//, ''))
}

function isCommentOnlySnippet(snippet: string): boolean {
  const trimmed = snippet.trim()
  return /^(?:\/\/|#|\*|\/\*|<!--)/.test(trimmed)
}

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

    useradd \
      --create-home \
      --uid 10001 \
      --shell /bin/bash \
      scanner

    mkdir -p /workspace
    chown scanner:scanner /workspace

    id scanner
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

        run_rg() {
          rg \
            --vimgrep \
            --hidden \
            --ignore-case \
            --line-number \
            --column \
            --max-filesize 1M \
            --max-columns 500 \
            --max-count 50 \
            --glob '!**/.git/**' \
            --glob '!**/node_modules/**' \
            --glob '!**/vendor/**' \
            --glob '!**/dist/**' \
            --glob '!**/build/**' \
            --glob '!**/target/**' \
            --glob '!**/coverage/**' \
            --glob '!**/test/**' \
            --glob '!**/tests/**' \
            --glob '!**/__tests__/**' \
            --glob '!**/fixtures/**' \
            --glob '!**/mocks/**' \
            --glob '!**/docs/**' \
            --glob '!**/examples/**' \
            --glob '!**/*_test.go' \
            --glob '!**/*.test.*' \
            --glob '!**/*.spec.*' \
            --glob '!**/*.md' \
            --glob '!**/*.lock' \
            --glob '!**/*.min.js' \
            "$@" \
            . | head -n ${MAX_RG_LINES}

          rg_status=\${PIPESTATUS[0]}

          if [ "$rg_status" -ne 0 ] && \
             [ "$rg_status" -ne 1 ] && \
             [ "$rg_status" -ne 141 ]; then
            exit "$rg_status"
          fi
        }

        # Emit high-severity rules first so medium-severity noise can never
        # consume the parser/storage cap before high findings are seen.
        run_rg \
          -e 'keylog(ger|ging)?|keystroke|keypress|keydown|keyup|globalShortcut|RegisterHotKey' \
          -e '\\b(password|passwd|credential|token|api[_-]?key|secret|private[_-]?key)s?\\b' \
          -e 'getUserMedia|mediaDevices|MediaRecorder|microphone|micPermission|AVAudioRecorder|AVAudioEngine|AVCaptureDevice|AudioRecord|MediaRecorder|RECORD_AUDIO|pyaudio|sounddevice' \
          -e 'getDisplayMedia|getUserMedia|camera|AVCaptureSession|AVCaptureDevice|CAMERA|screenCapture|desktopCapturer' \
          -e 'mouse(move|down|up|click)?|screencapture|clipboard|pasteboard|GetClipboardData|cookies?|browser[_ -]?(history|profile|profiles)|saved[_ -]?passwords?|home(dir|directory)?|Documents|\\.env\\b|config(uration)?[_ -]?files?|\\.ssh|ssh[_ -]?keys?|private[_ -]?keys?|certificates?|keychains?|hostname|username|mac[_ -]?address|hardware[_ -]?id|device[_ -]?id|gps|geo(location)?|ip[_ -]?based[_ -]?location|process(es)?|running[_ -]?(processes|applications)|PowerShell|startup[_ -]?items?|launch[_ -]?agents?|registry[_ -]?Run|cron|systemd|sudo|administrator[_ -]?elevation|setuid|UAC|raw[_ -]?sockets?|uploads?|exfiltrat(e|ion)|usage[_ -]?collection|dynamically[_ -]?downloaded|FFI|Win32|syscalls?|/proc|/dev'

        run_rg \
          -e 'clipboard|navigator\\.clipboard|pasteboard|xclip|pbcopy|GetClipboardData' \
          -e 'https?://|fetch\\(|XMLHttpRequest|WebSocket|axios\\.|request\\(|\\bcurl\\b|\\bwget\\b|net\\.connect|socket' \
          -e 'analytics|telemetry|fingerprint|deviceId|machineId|tracking' \
          -e 'child_process|exec\\(|spawn\\(|eval\\(|Function\\(|powershell|osascript'

        set -o pipefail
        set -e

        echo "CODEVET_RG_END"
SCAN_SCRIPT
  `,
  {
    timeoutSec: 120,
  }
)

    console.log(
      `[${uid}] Sandbox completed: ${result.stdout.length} bytes of output`
    )

    if (result.stderr) {
      const stderr = result.stderr.trim()
      console.error(
        `[${uid}] Sandbox stderr (${stderr.length} bytes): ${stderr.slice(0, 2000)}`
      )
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

type RawFinding = {
  file: string
  line: number
  column: number
  snippet: string
  match: string
}

function addFinding(findings: ScannerFinding[], raw: RawFinding) {
  if (findings.length >= MAX_FINDINGS) {
    return
  }

  if (isLowConfidencePath(raw.file) || isCommentOnlySnippet(raw.snippet)) {
    return
  }

  const rule = SCAN_RULES.find((candidate) =>
    candidate.pattern.test(raw.snippet)
  )

  if (!rule) {
    return
  }

  const matchedText = raw.match || raw.snippet.match(rule.pattern)?.[0] || ''

  if (
    findings.some(
      (finding) =>
        finding.ruleId === rule.id &&
        finding.file === raw.file &&
        finding.line === raw.line &&
        finding.snippet === raw.snippet.slice(0, 500)
    )
  ) {
    return
  }

  findings.push({
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    file: raw.file,
    line: raw.line,
    column: raw.column,
    snippet: raw.snippet.slice(0, 500),
    match: matchedText.slice(0, 200),
  })
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

    if (!inRgOutput || findings.length >= MAX_FINDINGS || !line) {
      continue
    }

    try {
      if (line.startsWith('{')) {
        const event = JSON.parse(line)

        if (event.type !== 'match') {
          continue
        }

        addFinding(findings, {
          file: String(event.data?.path?.text ?? ''),
          line: Number(event.data?.line_number ?? 0),
          column: Number(event.data?.submatches?.[0]?.start ?? 0) + 1,
          snippet: String(event.data?.lines?.text ?? '').trim(),
          match: String(event.data?.submatches?.[0]?.match?.text ?? ''),
        })
        continue
      }

      const vimgrepMatch = line.match(/^(.+?):(\d+):(\d+):(.*)$/)
      if (vimgrepMatch) {
        addFinding(findings, {
          file: vimgrepMatch[1],
          line: Number(vimgrepMatch[2]),
          column: Number(vimgrepMatch[3]),
          snippet: vimgrepMatch[4].trim(),
          match: '',
        })
      }
    } catch {
      // Ignore malformed scanner output lines.
    }
  }

  return {
    commitSha: commitMatch?.[1] ?? null,
    findings,
  }
}
