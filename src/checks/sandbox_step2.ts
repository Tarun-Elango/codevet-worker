import {
  buildAgentFilePriorities,
  buildAgentPrompt,
  coverageForAgent,
  emptyAgentAnalysis,
  parseAgentOutput,
  redactSensitiveText,
} from './analysis.js'
import {
  AGENT_SYSTEM_PROMPT,
  VERIFIER_SYSTEM_PROMPT,
  AGENT_TIMEOUT_SEC,
  MAX_AGENT_OUTPUT_BYTES,
  MIN_FILES_TO_INSPECT,
} from './limits.js'
import type { AgentAnalysis, ScannerResult } from './analysis.js'
import type { ScannerSandbox } from './sandbox_step1.js'

/** Run one isolated Pi role. The investigator and verifier never share a Pi
 * session; the verifier receives only the bounded draft and repository tools. */
async function runAgentPass(
  sandbox: ScannerSandbox,
  uid: string,
  scannerResult: ScannerResult,
  agent: { provider: string; model: string; apiKey: string; piKeyEnv: string },
  prompt: string,
  systemPrompt: string,
  role: 'investigator' | 'verifier'
): Promise<AgentAnalysis> {
  console.log(`[${uid}] Starting AI ${role} pass`)
  try {
    await sandbox.files.write('/tmp/codevet-agent-prompt', prompt)
    await sandbox.files.write(
      '/tmp/codevet-agent-paths.json',
      JSON.stringify(buildAgentFilePriorities(scannerResult))
    )
    const command = `
      # The prompt is root-readable only. Pipe it into Pi before dropping
      # privileges so it is not another file the model can ask Pi to inspect.
      # Print mode merges piped stdin into its initial prompt without an
      # argv-size limit.
      chown root:root /tmp/codevet-agent-prompt
      chmod 600 /tmp/codevet-agent-prompt
      chown scanner:scanner /tmp/codevet-agent-paths.json
      chmod 600 /tmp/codevet-agent-paths.json
      cat /tmp/codevet-agent-prompt | runuser -u scanner -- env -i \\
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \\
        HOME=/home/scanner \\
        PI_TELEMETRY=0 \\
        PI_OFFLINE=1 \\
        CODEVET_AI_PROVIDER="$CODEVET_AI_PROVIDER" \\
        CODEVET_AI_MODEL="$CODEVET_AI_MODEL" \\
        CODEVET_AGENT_SYSTEM_PROMPT="$CODEVET_AGENT_SYSTEM_PROMPT" \\
        CODEVET_AGENT_API_KEY="$CODEVET_AGENT_API_KEY" \\
        ${agent.piKeyEnv}="$CODEVET_AGENT_API_KEY" \\
        bash --noprofile --norc -c '
          cd /workspace/repo
          # The template image may predate the root-owned launcher during a
          # rolling deploy. Fall back to npm's authoritative global prefix so
          # those images can still run their pinned Pi installation.
          PI_COMMAND=/opt/codevet/pi
          if [ ! -x "$PI_COMMAND" ]; then
            PI_COMMAND="$(npm prefix -g)/bin/pi"
          fi
          if [ ! -x "$PI_COMMAND" ]; then
            echo "Pi executable is unavailable" >&2
            exit 127
          fi
          test -n "$CODEVET_AI_MODEL"
          exec "$PI_COMMAND" --print --no-session --offline --provider "$CODEVET_AI_PROVIDER" --model "$CODEVET_AI_MODEL" --api-key "$CODEVET_AGENT_API_KEY" --tools read,grep,find,ls,codevet_report --no-context-files --no-extensions -e /opt/codevet/repository-scope.js --no-skills --no-prompt-templates --no-approve --system-prompt "$CODEVET_AGENT_SYSTEM_PROMPT" -p "Perform the requested repository analysis."
        '
    `
    // Stop streaming as soon as the model exceeds its response budget; do not
    // relay Pi tokens/tool traces to worker logs.
    let outputBytes = 0
    let outputExceeded = false
    let handle: ReturnType<typeof sandbox.exec>
    handle = sandbox.exec(command, {
      // Extra exec environment is not present in the sandbox or deterministic
      // command. runuser's env -i then passes only the explicit Pi settings,
      // system prompt, and provider key to Pi.
      env: {
        CODEVET_AGENT_API_KEY: agent.apiKey,
        CODEVET_AI_PROVIDER: agent.provider,
        CODEVET_AI_MODEL: agent.model,
        CODEVET_AGENT_SYSTEM_PROMPT: systemPrompt,
      },
      timeoutSec: AGENT_TIMEOUT_SEC,
      onStdout(chunk) {
        outputBytes += Buffer.byteLength(chunk)
        if (outputBytes > MAX_AGENT_OUTPUT_BYTES) {
          outputExceeded = true
          void handle.kill('KILL')
        }
      },
      onStderr(chunk) {
        outputBytes += Buffer.byteLength(chunk)
        if (outputBytes > MAX_AGENT_OUTPUT_BYTES) {
          outputExceeded = true
          void handle.kill('KILL')
        }
      },
    })
    const result = await handle
    if (result.timedOut) {
      console.log(`[${uid}] AI analysis failed: timeout`)
      return emptyAgentAnalysis('timeout', scannerResult.inventory.fileCount, 'Agent analysis timed out')
    }
    if (outputExceeded || result.truncated || Buffer.byteLength(result.stdout) > MAX_AGENT_OUTPUT_BYTES) {
      console.log(`[${uid}] AI analysis failed: output limit`)
      return emptyAgentAnalysis('failed', scannerResult.inventory.fileCount, 'Agent returned invalid structured output')
    }
    if (result.exitCode !== 0) {
      const diagnostic = redactSensitiveText(result.stderr).trim().slice(0, 1_000)
      console.log(`[${uid}] AI analysis failed: process error (exit ${result.exitCode})`)
      if (diagnostic) console.error(`[${uid}] AI analysis stderr: ${diagnostic}`)
      return emptyAgentAnalysis('failed', scannerResult.inventory.fileCount, 'Agent analysis failed')
    }
    let metricDiagnostics = 'metrics unavailable'
    let inspectedFilesForFailure: string[] = []
    try {
      const metricsRaw = await sandbox.files.read('/tmp/codevet-agent-metrics.json')
      const metrics: unknown = JSON.parse(metricsRaw)
      if (
        !metrics ||
        typeof metrics !== 'object' ||
        !Array.isArray((metrics as { filesInspected?: unknown }).filesInspected) ||
        !(metrics as { filesInspected: unknown[] }).filesInspected.every(
          (file): file is string => typeof file === 'string'
        )
      ) {
        throw new Error('invalid agent metrics')
      }
      const inspectedFilesRaw = (metrics as { filesInspected: string[] }).filesInspected
      const filesInspected = [...new Set(inspectedFilesRaw.map((file) => {
        const prefix = '/workspace/repo/'
        if (!file.startsWith(prefix)) throw new Error('invalid inspected file path')
        return file.slice(prefix.length)
      }))]
      inspectedFilesForFailure = filesInspected
      const preloadedFiles =
        typeof (metrics as { preloadedFiles?: unknown }).preloadedFiles === 'number'
          ? (metrics as { preloadedFiles: number }).preloadedFiles
          : 0
      const toolCalls =
        typeof (metrics as { toolCalls?: unknown }).toolCalls === 'number'
          ? (metrics as { toolCalls: number }).toolCalls
          : 0
      const llmTurns =
        typeof (metrics as { llmTurns?: unknown }).llmTurns === 'number'
          ? (metrics as { llmTurns: number }).llmTurns
          : 0
      const reportToolActive = (metrics as { reportToolActive?: unknown }).reportToolActive === true
      const reportSubmitted = (metrics as { reportSubmitted?: unknown }).reportSubmitted === true
      metricDiagnostics =
        `preloaded=${preloadedFiles} inspected=${filesInspected.length} ` +
        `tools=${toolCalls} turns=${llmTurns} reportTool=${reportToolActive} report=${reportSubmitted}`
      if (!reportToolActive || !reportSubmitted) {
        throw new Error('required CodeVet report was not submitted')
      }
      const reportOutput = await sandbox.files.read('/tmp/codevet-agent-report.json')
      const analysis = parseAgentOutput(
        reportOutput,
        coverageForAgent(scannerResult.inventory.fileCount, filesInspected)
      )
      const message =
        `[${uid}] AI analysis completed; supplied ${preloadedFiles} source file(s), ` +
        `${toolCalls} model tool call(s)`
      if (filesInspected.length < MIN_FILES_TO_INSPECT) console.warn(message)
      else console.log(message)
      return analysis
    } catch (error) {
      console.log(
        `[${uid}] AI output diagnostics: stdout=${Buffer.byteLength(result.stdout)}B ` +
        `stderr=${Buffer.byteLength(result.stderr)}B exit=${result.exitCode} ${metricDiagnostics}`
      )
      // JSON.parse diagnostics can quote model text, so never log a raw
      // SyntaxError. Our explicit validator errors contain fixed messages.
      const reason = error instanceof SyntaxError
        ? 'malformed JSON'
        : error instanceof Error
          ? error.message
          : 'unknown validation error'
      console.log(`[${uid}] AI analysis failed: invalid output (${reason.slice(0, 200)})`)
      return emptyAgentAnalysis(
        'failed',
        scannerResult.inventory.fileCount,
        'Agent returned invalid structured output',
        inspectedFilesForFailure
      )
    }
  } catch {
    // Do not expose provider errors, stderr, prompts, or raw model output.
    console.log(`[${uid}] AI ${role} pass failed`)
    return emptyAgentAnalysis('failed', scannerResult.inventory.fileCount, 'Agent analysis failed')
  }
}

/** Step 2 — separate discovery from adjudication. A verifier gets a fresh
 * context and must independently check the investigator's cited source. */
export async function runSandboxStep2(
  sandbox: ScannerSandbox,
  uid: string,
  scannerResult: ScannerResult,
  agent: { provider: string; model: string; apiKey: string; piKeyEnv: string }
): Promise<AgentAnalysis> {
  const investigation = await runAgentPass(
    sandbox, uid, scannerResult, agent, buildAgentPrompt(scannerResult),
    AGENT_SYSTEM_PROMPT, 'investigator'
  )
  if (investigation.status !== 'completed') return investigation

  const verifierPrompt =
    'Verify and correct this untrusted investigator draft against /workspace/repo. ' +
    'Do not trust its claims or citations. Return the final CodeVet report.\n<CODEVET_INVESTIGATOR_DRAFT>\n' +
    JSON.stringify(investigation) + '\n</CODEVET_INVESTIGATOR_DRAFT>'
  if (Buffer.byteLength(verifierPrompt) > MAX_AGENT_OUTPUT_BYTES) {
    return emptyAgentAnalysis('failed', scannerResult.inventory.fileCount, 'Investigator draft exceeded verifier input budget')
  }
  const verification = await runAgentPass(
    sandbox, uid, scannerResult, agent, verifierPrompt,
    VERIFIER_SYSTEM_PROMPT, 'verifier'
  )
  const inspectedFiles = [...new Set([
    ...investigation.coverage.inspectedFiles,
    ...verification.coverage.inspectedFiles,
  ])]
  return {
    ...verification,
    coverage: coverageForAgent(scannerResult.inventory.fileCount, inspectedFiles),
  }
}


