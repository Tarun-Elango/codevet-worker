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
  // Capability and collection anchors from the existing scanner taxonomy.
  keyboard: "addEventListener\\s*\\(\\s*['\"\\x60](?:key(?:down|up|press)|keypress)|onkey(?:down|up|press)\\s*=|globalShortcut|RegisterHotKey|keylog(?:ger|ging)?|keystroke",
  clipboard: "navigator\\.clipboard|clipboard\\.(?:read|write)|pasteboard|xclip|pbcopy|GetClipboardData",
  microphone: "getUserMedia|mediaDevices|MediaRecorder|microphone|micPermission|AVAudioRecorder|AVAudioEngine|AVCapture(?:Device|Session)|AudioRecord|RECORD_AUDIO|pyaudio|sounddevice",
  credentials: "navigator\\.credentials|(?:browser|chrome)\\.(?:cookies|passwords)|keytar\\.(?:getPassword|findCredentials)|CredentialManager|\\.ssh|id_(?:rsa|dsa|ecdsa|ed25519)|keychain|Keychains|(?:querySelector|getElementById|FormData|localStorage|sessionStorage|\\.value\\b)[^\\n]{0,100}\\b(?:password|passwd|credential|token|api[_-]?key|secret)\\b|\\b(?:password|passwd|credential|token|api[_-]?key|secret|private[_-]?key)\\b",
  credential_logging: "(?:console|logger|log)\\s*\\.\\s*(?:log|info|debug|warn|error)\\s*\\([^\\n]{0,300}\\b(?:password|passwd|credential|token|api[_-]?key|secret|private[_-]?key)s?\\b",
  tracking: "(?:analytics|telemetry|tracking)\\s*(?:\\.|\\(|\\[)|(?:track|identify|capture|fingerprint)\\s*\\(|(?:deviceId|machineId|usage[_ -]?collection)",
  system_access: "getDisplayMedia|camera|CAMERA|screenCapture|desktopCapturer|mouse(?:move|down|up|click)?|screencapture|navigator\\.mediaDevices\\.getUserMedia\\s*\\([^)]*video|AVCapture(?:Device|Session)|document\\.cookie|cookies?|(?:browser|chrome)[_ -]?(?:history|profile|profiles)|saved[_ -]?passwords?|(?:os\\.|process\\.)?(?:homedir|hostname|platform|arch)\\s*\\(|Documents|\\.env\\b|\\.ssh|ssh[_ -]?keys?|private[_ -]?keys?|certificates?|keychains?|hostname|mac[_ -]?address|hardware[_ -]?id|device[_ -]?id|gps|geo(?:location)?|process(?:es)?|running[_ -]?(?:processes|applications)|startup[_ -]?items?|launch[_ -]?agents?|registry[_ -]?Run|cron|systemd|sudo|administrator[_ -]?elevation|setuid|UAC|FFI|Win32|syscalls?|/proc|/dev|readdir(?:Sync)?\\s*\\([^)]*(?:Library/Keychains|AppData|Documents)",
  network: "\\b(?:fetch|axios|got|request|http|https|grpc|requests?|httpx|aiohttp|urllib|reqwest)\\s*(?:\\.|\\()|sendBeacon\\s*\\(|new\\s+WebSocket\\s*\\(|XMLHttpRequest|\\b(?:curl|wget)\\b|\\b(?:net\\.)?connect\\s*\\(|\\bsocket\\s*\\(|\\b(?:HttpClient|OkHttp|Net::HTTP)\\b",
  process: "\\b(?:exec|execFile|spawn|fork)\\s*\\(|\\bchild_process\\s*\\.|\\bsubprocess\\.(?:run|Popen|call)\\s*\\(|\\bos\\.system\\s*\\(|\\beval\\s*\\(|new\\s+Function\\s*\\(|powershell|osascript",
  filesystem: "\\b(?:readFile|writeFile|createReadStream|createWriteStream|open|readdir|unlink|rm|rmdir|sendFile|download)\\s*\\(|\\b(?:fs|path)\\.(?:read|write|open|resolve|join|unlink|rm)",
  dynamic_code: "\\b(?:eval|Function|vm\\.runIn|pickle\\.loads?|yaml\\.load|unserialize|ObjectInputStream|BinaryFormatter|Marshal\\.load)\\s*\\(",
  // Supply-chain/host-abuse anchors include download-and-execute, persistence,
  // reverse shells, obfuscation, cryptomining, destructive commands, and CI.
  supply_chain: "(?:preinstall|install|postinstall|prepare)[^\\n]{0,180}(?:curl|wget|Invoke-WebRequest|fetch|b64decode|FromBase64String|eval|exec|spawn)|(?:fetch|curl|wget)[^\\n]{0,180}(?:exec|spawn|bash|sh|chmod\\s+\\+x)|(?:curl|wget|Invoke-WebRequest)[^\\n]{0,300}(?:\\|\\s*(?:sh|bash)|powershell)|/dev/tcp|nc\\s+[^\\n]*\\s-e\\s|bash\\s+-i|TcpClient|DownloadString|stratum\\+tcp|xmrig|cryptonight|monero|coinhive",
  persistence: "crontab|/etc/cron|systemctl\\s+enable|launchctl\\s+load|LaunchAgents|CurrentVersion\\\\Run|schtasks\\s+/create",
  obfuscation: "(?:eval|Function|exec|powershell)\\s*\\([^\\n]{0,100}(?:atob|fromCharCode|base64|b64decode|FromBase64String)|(?:atob|b64decode|FromBase64String)\\s*\\([^\\n]{0,100}\\)(?:[^\\n]{0,80})(?:eval|exec)",
  destructive: "rm\\s+-rf\\s+(?:/|~|\\$HOME)|del\\s+/s\\s+/q|Remove-Item[^\\n]*-Recurse[^\\n]*-Force|mkfs\\.|dd\\s+if=.*\\s+of=/dev/",
  security: "(?:\\b(?:eval|exec|execFile|spawn|os\\.system|subprocess\\.(?:run|Popen|call))\\s*\\([^\\n]*(?:req(?:uest)?\\.|ctx\\.|params|query|body|argv)|new\\s+Function\\s*\\([^\\n]*(?:req(?:uest)?\\.|ctx\\.|params|query|body)|(?:pickle\\.loads?|yaml\\.load|unserialize|ObjectInputStream|BinaryFormatter)\\s*\\([^\\n]*(?:req(?:uest)?\\.|ctx\\.|params|query|body)|(?:jwt\\.(?:verify|decode)|verify_signature|algorithms?)\\b[^\\n]*(?:none|false|0)|(?:isAdmin|admin|root|privileged)\\b[^\\n]*(?:true|allow|bypass)|pull_request_target|permissions\\s*:\\s*write-all|(?:req(?:uest)?\\.|ctx\\.|params|query|body)[^\\n]{0,180}(?:\\.(?:query|execute|raw)|readFile|sendFile|createReadStream)\\s*\\(|(?:\\.innerHTML\\s*=|outerHTML\\s*=|document\\.write\\s*\\(|dangerouslySetInnerHTML|v-html\\s*=)|\\b(?:query|execute|raw|execSQL|createQuery)\\s*\\(|\\b(?:readFile|writeFile|createReadStream|createWriteStream|open|sendFile|download|unlink|rm|rmdir)\\s*\\(|\\b(?:fs|path)\\.(?:read|write|open|resolve|join|unlink|rm)|\\bopen\\s*\\(|\\b(?:md5|sha1)\\s*\\([^\\n]*(?:password|passwd|credential|token)|createHash\\s*\\(\\s*['\"](?:md5|sha1)['\"]|\\bECB\\b|DES/ECB|origin\\s*:\\s*['\"]\\*['\"][^\\n]{0,200}credentials\\s*:\\s*true|Access-Control-Allow-Origin[^\\n]*\\*|(?:\\x60[^\\x60]*\\$\\{|\\+\\s*(?:req|request|ctx|params|query|body|user|input))))",
}
const ignored = [
  '--glob', '!**/.git/**', '--glob', '!**/node_modules/**', '--glob', '!**/vendor/**',
  '--glob', '!**/dist/**', '--glob', '!**/build/**', '--glob', '!**/coverage/**',
  '--glob', '!**/*.min.js', '--glob', '!**/.env', '--glob', '!**/.env.*',
]
const PER_KIND_LIMIT = 40
const candidatesByKind = new Map()
const seen = new Set()
function add(candidate) {
  if (!candidate.file || !Number.isInteger(candidate.line)) return
  const file = candidate.file.replace(/^\.\//, '').replace(/\\\\/g, '/')
  const key = candidate.kind + ':' + file + ':' + candidate.line
  if (file.startsWith('../') || file.startsWith('/') || seen.has(key)) return
  const bucket = candidatesByKind.get(candidate.kind) ?? []
  if (bucket.length >= PER_KIND_LIMIT) return
  seen.add(key)
  bucket.push({ ...candidate, file, text: String(candidate.text ?? '').replace(/[\r\n]+/g, ' ').slice(0, 500) })
  candidatesByKind.set(candidate.kind, bucket)
}
for (const [kind, pattern] of Object.entries(patterns)) {
  const run = spawnSync('rg', ['--json', '--hidden', '--no-ignore', '--max-count', '8', ...ignored, '-e', pattern, '.'], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 })
  for (const line of run.stdout.split('\n')) {
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
// Round-robin selection preserves a useful lead from every category instead
// of letting noisy early patterns consume the complete candidate budget.
const candidates = []
for (let index = 0; candidates.length < LIMIT; index += 1) {
  let added = false
  for (const bucket of candidatesByKind.values()) {
    const candidate = bucket[index]
    if (candidate && candidates.length < LIMIT) {
      candidates.push(candidate)
      added = true
    }
  }
  if (!added) break
}
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
