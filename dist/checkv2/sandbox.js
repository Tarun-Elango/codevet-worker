import { Sandbox } from 'railway';
const PI_VERSION = '0.85.1';
/**
 * This extension is deliberately small: Pi is given only the four repository
 * inspection tools and every explicit path is resolved under the checkout.
 * The trusted host still runs Pi and static analyzers; the model cannot run
 * shell commands or repository code.
 */
const REPOSITORY_TOOLS_EXTENSION = String.raw `
import { realpath } from "node:fs/promises"
import { relative, resolve, sep } from "node:path"

const ROOT = "/workspace/repo"
const TOOLS = new Set(["read", "grep", "find", "ls"])
const SENSITIVE = /(?:^|\/)\.env(?:\.|$)|(?:^|\/)(?:secret|secrets|credential|credentials)\b|\.(?:pem|key|p8|p12|pfx|jks)$/i

export default async function (pi) {
  const root = await realpath(ROOT)
  pi.on("session_start", () => pi.setActiveTools([...TOOLS]))
  pi.on("tool_call", async (event) => {
    if (!TOOLS.has(event.toolName)) return { block: true, reason: "Only read, grep, find, and ls are available." }
    const requested = event.input?.path
    // grep/find/ls may search the checkout by default. read always needs a path.
    if (requested === undefined && event.toolName !== "read") return undefined
    if (typeof requested !== "string" || requested.length === 0) return { block: true, reason: "A repository path is required." }
    try {
      const target = await realpath(resolve(root, requested))
      const inside = target === root || target.startsWith(root + sep)
      const repoPath = relative(root, target).split(sep).join("/")
      if (!inside || SENSITIVE.test(repoPath) || repoPath === ".git" || repoPath.startsWith(".git/")) {
        return { block: true, reason: "That path is outside the readable repository scope." }
      }
      event.input.path = target
      return undefined
    } catch {
      return { block: true, reason: "That repository path does not exist or resolves outside the checkout." }
    }
  })
}
`;
/** Runs trusted static-search code only. It never executes repository files. */
export const discoveryScript = String.raw `
import { writeFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'

const LIMIT = 250
const patterns = {
  keyboard: "addEventListener\\s*\\(\\s*['\"](?:key(?:down|up|press)|keypress)|onkey(?:down|up|press)|globalShortcut|keylog(?:ger|ging)?",
  clipboard: "navigator\\.clipboard|clipboard\\.(?:read|write)|pasteboard|GetClipboardData",
  microphone: "getUserMedia|MediaRecorder|microphone|AudioRecord|RECORD_AUDIO",
  credentials: "(?:password|credential|token|api[_-]?key|secret)[^\\n]{0,120}(?:fetch|axios|request|send|log|write)",
  network: "\\b(?:fetch|axios|got|request|http|https|grpc|sendBeacon|WebSocket|XMLHttpRequest|curl|wget)\\b",
  process: "\\b(?:exec|execFile|spawn|fork|subprocess\\.(?:run|Popen)|os\\.system)\\s*\\(",
  filesystem: "\\b(?:readFile|writeFile|createReadStream|createWriteStream|readdir|unlink|rm|sendFile)\\s*\\(",
  dynamic_code: "\\b(?:eval|Function|vm\\.runIn|pickle\\.loads|yaml\\.load|unserialize)\\s*\\(",
  persistence: "(?:crontab|systemctl\\s+enable|launchctl|schtasks|CurrentVersion\\\\Run|LaunchAgents)",
  obfuscation: "(?:atob|fromCharCode|b64decode|FromBase64String).{0,120}(?:eval|exec|Function)|(?:eval|exec|Function).{0,120}(?:atob|base64)",
  security: "(?:innerHTML\\s*=|dangerouslySetInnerHTML|pull_request_target|permissions\\s*:\\s*write-all|curl.+\\|\\s*(?:sh|bash))",
}
const ignored = [
  '--glob', '!**/.git/**', '--glob', '!**/node_modules/**', '--glob', '!**/vendor/**',
  '--glob', '!**/dist/**', '--glob', '!**/build/**', '--glob', '!**/coverage/**',
  '--glob', '!**/*.min.js', '--glob', '!**/.env', '--glob', '!**/.env.*',
]
const candidates = []
const seen = new Set()
function add(candidate) {
  if (candidates.length >= LIMIT || !candidate.file || !Number.isInteger(candidate.line)) return
  const file = candidate.file.replace(/^\.\//, '').replace(/\\\\/g, '/')
  if (file.startsWith('../') || file.startsWith('/') || seen.has(candidate.kind + ':' + file + ':' + candidate.line)) return
  seen.add(candidate.kind + ':' + file + ':' + candidate.line)
  candidates.push({ ...candidate, file, text: String(candidate.text ?? '').replace(/[\\r\\n]+/g, ' ').slice(0, 500) })
}
for (const [kind, pattern] of Object.entries(patterns)) {
  const run = spawnSync('rg', ['--json', '--hidden', '--no-ignore', '--max-count', '8', ...ignored, '-e', pattern, '.'], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 })
  for (const line of run.stdout.split('\\n')) {
    try {
      const event = JSON.parse(line)
      if (event.type !== 'match') continue
      add({ kind, file: event.data.path.text, line: event.data.line_number, text: event.data.lines.text })
    } catch { /* Ignore malformed ripgrep events. */ }
  }
}
// Semgrep supplies an independent set of rule-based anchors. Failure (for
// example an unavailable community ruleset) must not discard ripgrep leads.
const semgrep = spawnSync('semgrep', ['--config', 'auto', '--json', '--quiet', '.'], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 })
try {
  const report = JSON.parse(semgrep.stdout)
  for (const result of report.results ?? []) {
    add({
      kind: 'semgrep', file: result.path, line: result.start?.line,
      text: result.extra?.lines ?? result.extra?.message ?? '', rule: result.check_id,
    })
  }
} catch { /* Semgrep is advisory discovery, not a required scanner protocol. */ }
await writeFile('/tmp/checkv2-candidates.json', JSON.stringify(candidates), { mode: 0o600 })
`;
export const checkV2Template = Sandbox.template()
    .withPackages('git', 'ripgrep', 'semgrep', 'nodejs', 'npm', 'ca-certificates', 'util-linux', 'passwd')
    .run(`
    set -eu
    useradd --create-home --uid 10001 --shell /bin/sh scanner
    mkdir -p /workspace /opt/checkv2
    chown scanner:scanner /workspace
    npm install -g --ignore-scripts @earendil-works/pi-coding-agent@${PI_VERSION}
  `)
    .run(`
    cat > /opt/checkv2/repository-tools.js <<'EOF'
${REPOSITORY_TOOLS_EXTENSION}
EOF
    chown root:root /opt/checkv2/repository-tools.js
    chmod 0644 /opt/checkv2/repository-tools.js
  `);
export async function discoverCandidates(sandbox) {
    await sandbox.files.write('/tmp/checkv2-discover.mjs', discoveryScript);
    const result = await sandbox.exec('chown scanner:scanner /tmp/checkv2-discover.mjs && runuser -u scanner -- env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/home/scanner node /tmp/checkv2-discover.mjs');
    if (result.exitCode !== 0) {
        throw new Error('Ripgrep/Semgrep candidate discovery failed');
    }
    const raw = JSON.parse(await sandbox.files.read('/tmp/checkv2-candidates.json'));
    if (!Array.isArray(raw))
        throw new Error('Invalid candidate discovery output');
    return raw.filter((item) => {
        if (!item || typeof item !== 'object')
            return false;
        const candidate = item;
        return typeof candidate.kind === 'string' && typeof candidate.file === 'string' &&
            Number.isInteger(candidate.line) && typeof candidate.text === 'string';
    });
}
export async function destroyCheckV2Sandbox(sandbox) {
    await sandbox.destroy();
}
