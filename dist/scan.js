import { Sandbox } from 'railway';
const MAX_FINDINGS = 1000;
const MAX_CANDIDATES = 1000;
const MAX_SNIPPETS = 250;
const MAX_FLOWS = 100;
const MAX_RG_LINES = 2500;
const MAX_RG_MATCHES_PER_CATEGORY = 40;
const MAX_INVENTORY_FILES = 5000;
const MAX_MANIFESTS = 100;
const MAX_SANDBOX_OUTPUT_BYTES = 32 * 1024 * 1024;
const SANDBOX_START_TIMEOUT_MS = 60_000;
const SANDBOX_STATUS_POLL_MS = 250;
export const SCANNER_VERSION = 'v2';
const LOW_CONFIDENCE_PATH_PATTERN = /(^|\/)(?:test|tests|__tests__|fixtures?|mocks?|docs?|examples?)\/|(?:^|\/)(?:README|CHANGELOG|LICENSE)(?:\.|$)|(?:_test\.go|\.(?:test|spec)\.[jt]sx?|\.md|\.lock|min\.js|\.map)$|(?:^|\/)node_modules\//i;
const SOURCE_FILE_PATTERN = /\.(?:ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|kt|kts|rb|php|c|h|cc|cpp|cxx|cs|swift|dart|lua|sh|bash|zsh|html?|vue|svelte)$/i;
const KEYBOARD_BEHAVIOR_PATTERN = /(?:addEventListener\s*\(\s*['"`](?:key(?:down|up|press)|keypress)|onkey(?:down|up|press)\s*=|globalShortcut|RegisterHotKey|keylog(?:ger|ging)?|keystroke)/i;
const MICROPHONE_BEHAVIOR_PATTERN = /getUserMedia|mediaDevices|MediaRecorder|microphone|micPermission|AVAudioRecorder|AVAudioEngine|AVCapture(?:Device|Session)|AudioRecord|RECORD_AUDIO|pyaudio|sounddevice/i;
const CLIPBOARD_BEHAVIOR_PATTERN = /clipboard|navigator\.clipboard|pasteboard|xclip|pbcopy|GetClipboardData/i;
const NETWORK_CALL_PATTERN = /\b(?:fetch|axios|got|request|http|https|grpc|requests?|httpx|aiohttp|urllib|reqwest)\s*(?:\.|\()|sendBeacon\s*\(|new\s+WebSocket\s*\(|XMLHttpRequest|\b(?:curl|wget)\b|\b(?:net\.)?connect\s*\(|\bsocket\s*\(|\b(?:HttpClient|OkHttp|Net::HTTP)\b/i;
const PROCESS_EXECUTION_PATTERN = /\b(?:exec|execFile|spawn|fork)\s*\(|\bchild_process\s*\.|\bsubprocess\.(?:run|Popen|call)\s*\(|\bos\.system\s*\(|\beval\s*\(|new\s+Function\s*\(/i;
const SENSITIVE_LOGGING_PATTERN = /(?:console|logger|log)\s*\.\s*(?:log|info|debug|warn|error)\s*\([^)]*\b(?:password|passwd|credential|token|api[_-]?key|secret|private[_-]?key)s?\b/i;
const CREDENTIAL_COLLECTION_PATTERN = /\b(?:password|passwd|credential)s?\b[^\n]{0,100}(?:\.value\b|querySelector|FormData|request|body|params|localStorage|sessionStorage)|(?:querySelector|input|form)[^\n]{0,80}(?:password|passwd|credential)/i;
const TRACKING_BEHAVIOR_PATTERN = /(?:analytics|telemetry|tracking)\s*(?:\.|\(|\[)|(?:track|identify|capture|fingerprint)\s*\(|(?:deviceId|machineId|usage[_ -]?collection)/i;
const SYSTEM_ACCESS_BEHAVIOR_PATTERN = /getDisplayMedia|camera|CAMERA|screenCapture|desktopCapturer|mouse(?:move|down|up|click)?|screencapture|cookies?|browser[_ -]?(?:history|profile|profiles)|saved[_ -]?passwords?|home(?:dir|directory)?|Documents|\.env\b|\.ssh|ssh[_ -]?keys?|private[_ -]?keys?|certificates?|keychains?|hostname|mac[_ -]?address|hardware[_ -]?id|device[_ -]?id|gps|geo(?:location)?|process(?:es)?|running[_ -]?(?:processes|applications)|startup[_ -]?items?|launch[_ -]?agents?|registry[_ -]?Run|cron|systemd|sudo|administrator[_ -]?elevation|setuid|UAC|FFI|Win32|syscalls?|\/proc|\/dev/i;
const SENSITIVE_FLOW_SOURCES = [
    'keyboard_input',
    'microphone_access',
    'clipboard_access',
    'credential_handling',
    'sensitive_system_access',
];
function normalizePath(file) {
    return file.replace(/^\.\//, '').replace(/\\/g, '/');
}
/** Validate again at the execution boundary; this function is exported and
 * must not rely on the queue worker having normalized its inputs. */
function validatedCloneUrl(repoUrl, commitSha) {
    if (!/^[0-9a-f]{40}$/i.test(commitSha)) {
        throw new Error('Scanner requires a 40-character commit SHA');
    }
    let url;
    try {
        url = new URL(repoUrl);
    }
    catch {
        throw new Error('Scanner requires a valid repository URL');
    }
    if (url.protocol !== 'https:' ||
        url.hostname !== 'github.com' ||
        url.port ||
        url.username ||
        url.password ||
        url.search ||
        url.hash ||
        !/^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git$/.test(url.pathname)) {
        throw new Error('Scanner only permits canonical HTTPS github.com clone URLs');
    }
    return url.toString();
}
function isLowConfidencePath(file) {
    return LOW_CONFIDENCE_PATH_PATTERN.test(normalizePath(file));
}
function isCommentOnlySnippet(snippet) {
    const trimmed = snippet.trim();
    return /^(?:\/\/|#|\*|\/\*|<!--)/.test(trimmed);
}
function isAnalyzableSource(file) {
    const normalized = normalizePath(file);
    if (isLowConfidencePath(normalized)) {
        return false;
    }
    if (SOURCE_FILE_PATTERN.test(normalized) ||
        /(?:^|\/)(?:Dockerfile(?:\..*)?|Makefile|docker-compose[^/]*\.ya?ml)$/i.test(normalized)) {
        return true;
    }
    return /(?:^|\/)(?:main|index|app|server|cli)$/.test(normalized);
}
/**
 * STEP C — Build the disposable scanner environment.
 *
 * The sandbox only receives tools needed to clone and inspect source. It does
 * not receive the repository worker's private network, and the scan script
 * below never invokes a repository command, package manager, or build tool.
 */
export const scannerTemplate = Sandbox.template()
    .withPackages('git', 'ripgrep', 'ca-certificates', 'util-linux', 'passwd')
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
    .workdir('/workspace');
/**
 * STEP D — Enter a disposable sandbox for one immutable revision, inspect it,
 * and always destroy it. Repository content is treated as data throughout.
 */
async function waitForSandboxRunning(sandbox) {
    const deadline = Date.now() + SANDBOX_START_TIMEOUT_MS;
    while (Date.now() < deadline) {
        await sandbox.refresh();
        if (sandbox.status === 'RUNNING') {
            return;
        }
        if (sandbox.status === 'FAILED' ||
            sandbox.status === 'DESTROYED' ||
            sandbox.status === 'DESTROYING') {
            throw new Error(`Sandbox failed to start (status: ${sandbox.status})`);
        }
        await new Promise((resolve) => {
            setTimeout(resolve, SANDBOX_STATUS_POLL_MS);
        });
    }
    throw new Error(`Sandbox did not start within ${SANDBOX_START_TIMEOUT_MS}ms`);
}
export async function runScannerContainer(job) {
    const { uid } = job;
    const commitSha = job.commitSha.toLowerCase();
    const repoUrl = validatedCloneUrl(job.repoUrl, commitSha);
    console.log(`[${uid}] Creating Railway sandbox`);
    let sandbox;
    try {
        sandbox = await Sandbox.create(scannerTemplate, {
            // Destroy it fairly quickly if your worker crashes before cleanup.
            idleTimeoutMinutes: 5,
            // Railway's ISOLATED mode has public egress but cannot access this
            // environment's private network. Git itself is restricted to HTTPS.
            networkIsolation: 'ISOLATED',
            env: {
                JOB_UID: uid,
                REPO_URL: repoUrl,
                COMMIT_SHA: commitSha,
            },
        });
    }
    catch (error) {
        console.error(`[${uid}] Failed to create Railway sandbox:`, error);
        throw error;
    }
    console.log(`[${uid}] Sandbox created: ${sandbox.id}`);
    try {
        await waitForSandboxRunning(sandbox);
        console.log(`[${uid}] Sandbox running`);
        const result = await sandbox.exec(`
    # Start with an allowlisted environment so inherited Git, shell, proxy,
    # loader, and credential settings cannot affect the scan.
    runuser -u scanner -- env -i \
      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      HOME=/home/scanner \
      JOB_UID="$JOB_UID" \
      REPO_URL="$REPO_URL" \
      COMMIT_SHA="$COMMIT_SHA" \
      GIT_CONFIG_NOSYSTEM=1 \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_ATTR_NOSYSTEM=1 \
      GIT_TERMINAL_PROMPT=0 \
      GIT_ASKPASS=/bin/false \
      bash --noprofile --norc <<'SCAN_SCRIPT'
        set -euo pipefail
        umask 077

        cd /workspace

        # STEP E — Clone only the requested commit. No repository lifecycle
        # scripts, hooks, submodules, dependencies, or binaries are run.
        echo "Sandbox started"
        echo "Job: $JOB_UID"

        git init repo
        cd repo
        git \
          -c core.hooksPath=/dev/null \
          -c credential.helper= \
          -c protocol.allow=never \
          -c protocol.https.allow=always \
          -c filter.lfs.smudge= \
          -c filter.lfs.process= \
          -c filter.lfs.required=false \
          fetch \
          --depth=1 \
          --no-tags \
          --no-recurse-submodules \
          -- "$REPO_URL" "$COMMIT_SHA"
        git \
          -c core.hooksPath=/dev/null \
          -c filter.lfs.smudge= \
          -c filter.lfs.process= \
          -c filter.lfs.required=false \
          checkout --detach FETCH_HEAD

        actual_commit=$(git rev-parse HEAD)
        if [ "$actual_commit" != "$COMMIT_SHA" ]; then
          echo 'Fetched revision does not match the requested commit' >&2
          exit 1
        fi

        # Do not leave request-controlled values in the environment while
        # inspecting repository files.
        unset REPO_URL COMMIT_SHA

        echo "Repository cloned"
        echo "CODEVET_COMMIT:$actual_commit"

        # STEP F — Inventory files and manifests. The file list is bounded for
        # transport, but fileCount is computed across the whole checkout.
        echo "CODEVET_INVENTORY_BEGIN"
        file_count=$(find . -type f ! -path './.git/*' -printf 'x' | wc -c)
        printf 'CODEVET_INVENTORY_COUNT:%s\\n' "$file_count"

        emitted_files=0
        find . -type f ! -path './.git/*' -print0 |
        while IFS= read -r -d '' file; do
          if [ "$emitted_files" -ge ${MAX_INVENTORY_FILES} ]; then
            break
          fi

          path=$(printf '%s' "$file" | sed 's#^\\./##')
          encoded_path=$(printf '%s' "$path" | base64 | tr -d '\\n')
          printf 'CODEVET_FILE:%s\\n' "$encoded_path"
          emitted_files=$((emitted_files + 1))
        done

        emitted_manifests=0
        find . -type f ! -path './.git/*' \
          \\( \
            -name 'package.json' -o \
            -name 'package-lock.json' -o \
            -name 'yarn.lock' -o \
            -name 'pnpm-lock.yaml' -o \
            -name 'requirements.txt' -o \
            -name 'pyproject.toml' -o \
            -name 'setup.py' -o \
            -name 'Pipfile' -o \
            -name 'Pipfile.lock' -o \
            -name 'poetry.lock' -o \
            -name 'uv.lock' -o \
            -name 'go.mod' -o \
            -name 'Cargo.toml' -o \
            -name 'pom.xml' -o \
            -name 'build.gradle' -o \
            -name 'build.gradle.kts' -o \
            -name 'Gemfile' -o \
            -name 'composer.json' -o \
            -name 'mix.exs' -o \
            -name 'Dockerfile' \
          \\) -print0 |
        while IFS= read -r -d '' file; do
          if [ "$emitted_manifests" -ge ${MAX_MANIFESTS} ]; then
            break
          fi

          path=$(printf '%s' "$file" | sed 's#^\\./##')
          encoded_path=$(printf '%s' "$path" | base64 | tr -d '\\n')
          content=$(head -c 20000 -- "$file" | base64 | tr -d '\\n')
          printf 'CODEVET_MANIFEST:%s:%s\\n' "$encoded_path" "$content"
          emitted_manifests=$((emitted_manifests + 1))
        done
        echo "CODEVET_INVENTORY_END"

        # STEP G — Broad candidate discovery. These searches are deliberately
        # inexpensive hints; they are not reported as vulnerabilities yet.
        echo "CODEVET_DISCOVERY_BEGIN"

        run_rg() {
          set +e
          rg \
            --json \
            --context 30 \
            --hidden \
            --no-ignore \
            --ignore-case \
            --max-filesize 1M \
            --max-columns 500 \
            --max-count ${MAX_RG_MATCHES_PER_CATEGORY} \
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
            --glob '!**/*.map' \
            --glob '!**/.env' \
            --glob '!**/.env.*' \
            --glob '!**/*.{pem,key,p12,pfx}' \
            "$@" \
            . | head -n ${MAX_RG_LINES}

          rg_status=\${PIPESTATUS[0]}
          set -e

          # rg returns 1 for no matches and 141 if head closed the pipe. Both
          # are expected; all other statuses indicate a scanner failure.
          if [ "$rg_status" -ne 0 ] && \
             [ "$rg_status" -ne 1 ] && \
             [ "$rg_status" -ne 141 ]; then
            return "$rg_status"
          fi
          return 0
        }

        echo "CODEVET_CATEGORY_BEGIN:keyboard_input"
        run_rg \
          -e 'keylog(ger|ging)?|keystroke|keypress|keydown|keyup|globalShortcut|RegisterHotKey'
        echo "CODEVET_CATEGORY_END:keyboard_input"

        echo "CODEVET_CATEGORY_BEGIN:microphone_access"
        run_rg \
          -e 'microphone|getUserMedia|mediaDevices|MediaRecorder|micPermission|AVAudioRecorder|AVAudioEngine|AVCapture(Device|Session)|AudioRecord|RECORD_AUDIO|pyaudio|sounddevice'
        echo "CODEVET_CATEGORY_END:microphone_access"

        echo "CODEVET_CATEGORY_BEGIN:sensitive_system_access"
        run_rg \
          -e 'getDisplayMedia|camera|CAMERA|screenCapture|desktopCapturer|mouse(move|down|up|click)?|screencapture|cookies?|browser[_ -]?(history|profile|profiles)|saved[_ -]?passwords?|home(dir|directory)?|Documents|\\.env\\b|\\.ssh|ssh[_ -]?keys?|private[_ -]?keys?|certificates?|keychains?|hostname|mac[_ -]?address|hardware[_ -]?id|device[_ -]?id|gps|geo(location)?|process(es)?|running[_ -]?(processes|applications)|startup[_ -]?items?|launch[_ -]?agents?|registry[_ -]?Run|cron|systemd|sudo|administrator[_ -]?elevation|setuid|UAC|FFI|Win32|syscalls?|/proc|/dev'
        echo "CODEVET_CATEGORY_END:sensitive_system_access"

        echo "CODEVET_CATEGORY_BEGIN:external_http"
        run_rg \
          -e 'fetch\\(|axios\\.|XMLHttpRequest|WebSocket|sendBeacon\\(|grpc|http(s)?\\.request|request\\(|requests?\\.(get|post|put|delete|request)|httpx|aiohttp|urllib|reqwest|HttpClient|OkHttp|Net::HTTP|https?://|\\bcurl\\b|\\bwget\\b|net\\.connect|socket'
        echo "CODEVET_CATEGORY_END:external_http"

        echo "CODEVET_CATEGORY_BEGIN:process_execution"
        run_rg \
          -e 'child_process|exec\\(|execFile\\(|spawn\\(|fork\\(|subprocess\\.(run|Popen|call)|os\\.system|eval\\(|Function\\(|powershell|osascript'
        echo "CODEVET_CATEGORY_END:process_execution"

        echo "CODEVET_CATEGORY_BEGIN:clipboard_access"
        run_rg \
          -e 'clipboard|navigator\\.clipboard|pasteboard|xclip|pbcopy|GetClipboardData'
        echo "CODEVET_CATEGORY_END:clipboard_access"

        echo "CODEVET_CATEGORY_BEGIN:credential_handling"
        run_rg \
          -e '\\b(password|passwd|credential|token|api[_-]?key|secret|private[_-]?key)s?\\b'
        echo "CODEVET_CATEGORY_END:credential_handling"

        echo "CODEVET_CATEGORY_BEGIN:tracking_telemetry"
        run_rg \
          -e 'analytics|telemetry|fingerprint|deviceId|machineId|tracking|usage[_ -]?collection'
        echo "CODEVET_CATEGORY_END:tracking_telemetry"

        echo "CODEVET_DISCOVERY_END"
SCAN_SCRIPT
  `, {
            timeoutSec: 120,
        });
        if (result.timedOut || result.truncated) {
            throw new Error(result.timedOut
                ? 'Sandbox command timed out'
                : 'Sandbox output was truncated');
        }
        if (result.stdout.length > MAX_SANDBOX_OUTPUT_BYTES) {
            throw new Error('Sandbox output exceeded the scanner limit');
        }
        console.log(`[${uid}] Sandbox completed: ${result.stdout.length} bytes of output`);
        if (result.stderr) {
            const stderr = result.stderr.trim();
            console.error(`[${uid}] Sandbox stderr (${stderr.length} bytes): ${stderr.slice(0, 2000)}`);
        }
        if (result.exitCode !== 0) {
            throw new Error(`Sandbox command exited with code ${result.exitCode}`);
        }
        // STEP J — Parse and run deterministic analysis on the structured sandbox
        // output. The worker receives evidence, never a live repository handle.
        return parseScannerOutput(result.stdout);
    }
    finally {
        // STEP K — Destroy the per-request sandbox on success, failure, or
        // cancellation so repositories cannot accumulate between scans.
        console.log(`[${uid}] Destroying sandbox`);
        try {
            await sandbox.destroy();
            console.log(`[${uid}] Sandbox destroyed`);
        }
        catch (error) {
            console.error(`[${uid}] Failed to destroy sandbox:`, error);
        }
    }
}
function redactSensitiveText(value) {
    return value
        .replace(/(\b(?:password|passwd|credential|token|api[_-]?key|secret|private[_-]?key)s?\b\s*[:=]\s*)(["'`])[^"'`]*\2/gi, '$1[REDACTED]')
        .replace(/([?&](?:password|passwd|credential|token|api[_-]?key|secret)=)[^&\\s]+/gi, '$1[REDACTED]');
}
function isSensitivePath(file) {
    return /(?:^|\/)\.env(?:\.|$)|(?:^|\/)(?:secrets?|credentials?)\.(?:ya?ml|json|ini|conf)$|\.(?:pem|key|p12|pfx)$/i.test(normalizePath(file));
}
function safeText(file, value, maxLength) {
    // Do not return contents from files conventionally used for secrets. A
    // pattern match is useful inventory evidence, but its value is not needed.
    if (isSensitivePath(file)) {
        return '[REDACTED: sensitive file]';
    }
    const withoutNewline = value.replace(/\r?\n$/, '');
    return redactSensitiveText(withoutNewline).slice(0, maxLength);
}
function addCandidate(candidates, raw, category) {
    if (candidates.length >= MAX_CANDIDATES ||
        !raw.file ||
        !Number.isInteger(raw.line) ||
        raw.line < 1 ||
        !raw.text) {
        return;
    }
    const file = normalizePath(raw.file);
    const code = safeText(file, raw.text, 500);
    const match = safeText(file, raw.match, 200);
    if (candidates.some((candidate) => candidate.category === category &&
        candidate.file === file &&
        candidate.line === raw.line)) {
        return;
    }
    candidates.push({
        category,
        file,
        line: raw.line,
        column: Math.max(1, raw.column),
        code,
        match,
    });
}
function addFinding(findings, candidate, rule) {
    if (findings.length >= MAX_FINDINGS) {
        return;
    }
    if (findings.some((finding) => finding.ruleId === rule.ruleId &&
        finding.file === candidate.file &&
        finding.line === candidate.line)) {
        return;
    }
    findings.push({
        ...rule,
        file: candidate.file,
        line: candidate.line,
        column: candidate.column,
        snippet: candidate.code,
        match: candidate.match,
    });
}
function addBehavior(behaviors, candidate) {
    if (behaviors.some((behavior) => behavior.category === candidate.category &&
        behavior.file === candidate.file &&
        behavior.line === candidate.line)) {
        return;
    }
    behaviors.push({
        category: candidate.category,
        file: candidate.file,
        line: candidate.line,
        column: candidate.column,
        code: candidate.code,
        match: candidate.match,
    });
}
function extractDestination(code) {
    const destination = code.match(/https?:\/\/[^\s'"`<>),;]+/i)?.[0];
    return destination ? destination.replace(/[.!?]+$/, '') : null;
}
function addNetworkCall(networkCalls, candidate, analysisCode = candidate.code) {
    if (networkCalls.some((call) => call.file === candidate.file && call.line === candidate.line)) {
        return;
    }
    networkCalls.push({
        category: 'external_http',
        file: candidate.file,
        line: candidate.line,
        column: candidate.column,
        code: candidate.code,
        match: candidate.match,
        destination: extractDestination(analysisCode),
    });
}
function nearbyCode(candidate, linesByFile) {
    const fileLines = linesByFile.get(candidate.file);
    if (!fileLines) {
        return candidate.code;
    }
    const codeLines = [];
    const startLine = Math.max(1, candidate.line - 3);
    const endLine = candidate.line + 3;
    for (let line = startLine; line <= endLine; line += 1) {
        const text = fileLines.get(line);
        if (text !== undefined) {
            codeLines.push(text);
        }
    }
    return codeLines.length > 0 ? codeLines.join('\n') : candidate.code;
}
/**
 * STEP H — Apply custom static rules to candidate lines.
 *
 * This is intentionally conservative: broad terms such as "token" or
 * "request" become evidence, but only a source-like file and an actionable
 * expression become a behavior or security finding.
 */
function analyzeCandidates(candidates, linesByFile) {
    const securityFindings = [];
    const behaviors = [];
    const networkCalls = [];
    for (const candidate of candidates) {
        if (!isAnalyzableSource(candidate.file) ||
            isCommentOnlySnippet(candidate.code)) {
            continue;
        }
        const codeForAnalysis = nearbyCode(candidate, linesByFile);
        switch (candidate.category) {
            case 'keyboard_input':
                if (KEYBOARD_BEHAVIOR_PATTERN.test(codeForAnalysis)) {
                    addBehavior(behaviors, candidate);
                }
                break;
            case 'microphone_access':
                if (MICROPHONE_BEHAVIOR_PATTERN.test(codeForAnalysis)) {
                    addBehavior(behaviors, candidate);
                }
                break;
            case 'clipboard_access':
                if (CLIPBOARD_BEHAVIOR_PATTERN.test(codeForAnalysis)) {
                    addBehavior(behaviors, candidate);
                }
                break;
            case 'tracking_telemetry':
                if (TRACKING_BEHAVIOR_PATTERN.test(codeForAnalysis)) {
                    addBehavior(behaviors, candidate);
                }
                break;
            case 'sensitive_system_access':
                if (SYSTEM_ACCESS_BEHAVIOR_PATTERN.test(codeForAnalysis)) {
                    addBehavior(behaviors, candidate);
                }
                break;
            case 'external_http':
                if (NETWORK_CALL_PATTERN.test(codeForAnalysis)) {
                    addNetworkCall(networkCalls, candidate, codeForAnalysis);
                }
                break;
            case 'process_execution':
                if (PROCESS_EXECUTION_PATTERN.test(codeForAnalysis)) {
                    addBehavior(behaviors, candidate);
                    addFinding(securityFindings, candidate, {
                        ruleId: 'dynamic-execution',
                        category: 'process_execution',
                        title: 'Potential dynamic code execution or shelling out',
                        severity: 'high',
                        confidence: 'high',
                        reason: 'The source contains an executable shell, subprocess, or dynamic-evaluation expression.',
                    });
                }
                break;
            case 'credential_handling':
                // Handling is useful behavior evidence, but a credential mention by
                // itself is not a vulnerability.
                addBehavior(behaviors, candidate);
                if (SENSITIVE_LOGGING_PATTERN.test(codeForAnalysis)) {
                    addFinding(securityFindings, candidate, {
                        ruleId: 'sensitive-logging',
                        category: 'sensitive_logging',
                        title: 'Potential sensitive data logged',
                        severity: 'high',
                        confidence: 'high',
                        reason: 'A logging call appears to include a password, token, secret, or credential value.',
                    });
                }
                else if (CREDENTIAL_COLLECTION_PATTERN.test(codeForAnalysis)) {
                    addFinding(securityFindings, candidate, {
                        ruleId: 'credential-collection',
                        category: 'credential_collection',
                        title: 'Potential credential collection',
                        severity: 'high',
                        confidence: 'medium',
                        reason: 'A credential-like value appears to be read from an input, request, form, or storage API.',
                    });
                }
                break;
        }
    }
    return { securityFindings, behaviors, networkCalls };
}
function directoryOf(file) {
    const separator = file.lastIndexOf('/');
    return separator < 0 ? '' : file.slice(0, separator);
}
function topLevelOf(file) {
    return file.split('/')[0] ?? file;
}
function areRelatedModules(sourceFile, sinkFile) {
    return (directoryOf(sourceFile) === directoryOf(sinkFile) ||
        topLevelOf(sourceFile) === topLevelOf(sinkFile));
}
/**
 * STEP I — Correlate related evidence without claiming a proven data flow.
 * A same-module (or same top-level module) relationship is enough to give the
 * future AI a useful lead, while the wording remains explicitly tentative.
 */
function correlateFindings(behaviors, networkCalls) {
    const flows = [];
    const sources = behaviors.filter((behavior) => SENSITIVE_FLOW_SOURCES.includes(behavior.category));
    const seen = new Set();
    for (const source of sources) {
        for (const sink of networkCalls) {
            if (!areRelatedModules(source.file, sink.file)) {
                continue;
            }
            const key = `${source.category}:${source.file}:${source.line}->${sink.file}:${sink.line}`;
            if (seen.has(key)) {
                continue;
            }
            seen.add(key);
            flows.push({
                type: 'possible_sensitive_flow',
                source: source.category,
                sink: 'external_http',
                files: [...new Set([source.file, sink.file])],
                reason: 'Sensitive input handling and outbound network activity occur in related modules; verify whether data reaches the destination.',
                evidence: {
                    source: {
                        file: source.file,
                        line: source.line,
                        code: source.code,
                    },
                    sink: {
                        file: sink.file,
                        line: sink.line,
                        code: sink.code,
                        destination: sink.destination,
                    },
                },
            });
            if (flows.length >= MAX_FLOWS) {
                return flows;
            }
        }
    }
    return flows;
}
function addContextSnippet(snippets, evidence, linesByFile) {
    if (snippets.length >= MAX_SNIPPETS) {
        return;
    }
    if (snippets.some((snippet) => snippet.file === evidence.file &&
        snippet.findingLine === evidence.line)) {
        return;
    }
    const startLine = Math.max(1, evidence.line - 30);
    const endLine = evidence.line + 30;
    const fileLines = linesByFile.get(evidence.file) ?? new Map();
    const contextLines = [];
    for (let line = startLine; line <= endLine; line += 1) {
        const text = fileLines.get(line);
        if (text !== undefined) {
            contextLines.push(`${line}: ${text}`);
        }
    }
    snippets.push({
        file: evidence.file,
        findingLine: evidence.line,
        startLine,
        endLine,
        code: contextLines.join('\n'),
    });
}
/**
 * STEP J — Collect bounded source context around meaningful evidence. The
 * scanner returns snippets rather than sending an entire untrusted checkout
 * to the worker or to a later model.
 */
function collectSnippets(findings, behaviors, networkCalls, linesByFile) {
    const snippets = [];
    for (const finding of findings) {
        addContextSnippet(snippets, finding, linesByFile);
    }
    for (const behavior of behaviors) {
        addContextSnippet(snippets, behavior, linesByFile);
    }
    for (const networkCall of networkCalls) {
        addContextSnippet(snippets, networkCall, linesByFile);
    }
    return snippets;
}
function languageForPath(file) {
    const extension = file.match(/\.([^.\/]+)$/)?.[1]?.toLowerCase();
    if (!extension) {
        return null;
    }
    const languages = {
        ts: 'typescript',
        tsx: 'typescript',
        js: 'javascript',
        jsx: 'javascript',
        mjs: 'javascript',
        cjs: 'javascript',
        py: 'python',
        go: 'go',
        rs: 'rust',
        java: 'java',
        kt: 'kotlin',
        kts: 'kotlin',
        rb: 'ruby',
        php: 'php',
        c: 'c',
        h: 'c',
        cc: 'cpp',
        cpp: 'cpp',
        cxx: 'cpp',
        cs: 'csharp',
        swift: 'swift',
        dart: 'dart',
        lua: 'lua',
        sh: 'shell',
        bash: 'shell',
        zsh: 'shell',
        html: 'html',
        htm: 'html',
        vue: 'vue',
        svelte: 'svelte',
    };
    return languages[extension] ?? null;
}
function addPackageManager(packageManagers, path) {
    const name = path.split('/').pop()?.toLowerCase() ?? '';
    if (name === 'package.json' || name === 'package-lock.json') {
        packageManagers.add('npm');
    }
    if (name === 'yarn.lock') {
        packageManagers.add('yarn');
    }
    if (name === 'pnpm-lock.yaml') {
        packageManagers.add('pnpm');
    }
    if (name === 'requirements.txt' ||
        name === 'pyproject.toml' ||
        name === 'setup.py' ||
        name === 'pipfile' ||
        name === 'pipfile.lock' ||
        name === 'poetry.lock' ||
        name === 'uv.lock') {
        packageManagers.add('pip');
    }
    if (name === 'go.mod') {
        packageManagers.add('go modules');
    }
    if (name === 'cargo.toml') {
        packageManagers.add('cargo');
    }
    if (name === 'pom.xml') {
        packageManagers.add('maven');
    }
    if (name === 'build.gradle' || name === 'build.gradle.kts') {
        packageManagers.add('gradle');
    }
    if (name === 'gemfile') {
        packageManagers.add('bundler');
    }
    if (name === 'composer.json') {
        packageManagers.add('composer');
    }
    if (name === 'mix.exs') {
        packageManagers.add('mix');
    }
}
function addFrameworks(frameworks, manifests) {
    const checks = [
        ['electron', /\belectron\b/i],
        ['react', /\breact\b/i],
        ['next.js', /\bnext(?:\.js)?\b/i],
        ['vue', /\bvue(?:\.js)?\b/i],
        ['angular', /\b@angular\b|\bangular\b/i],
        ['svelte', /\bsvelte(?:kit)?\b/i],
        ['express', /\bexpress\b/i],
        ['hono', /\bhono\b/i],
        ['fastify', /\bfastify\b/i],
        ['nestjs', /\bnestjs\b|@nestjs\//i],
        ['django', /\bdjango\b/i],
        ['flask', /\bflask\b/i],
        ['fastapi', /\bfastapi\b/i],
        ['gin', /\bgin(?:-gonic)?\b/i],
        ['actix', /\bactix(?:-web)?\b/i],
        ['tauri', /\btauri\b/i],
    ];
    for (const manifest of manifests) {
        for (const [framework, pattern] of checks) {
            if (pattern.test(manifest.content)) {
                frameworks.add(framework);
            }
        }
    }
}
function addEntrypoint(entrypoints, path) {
    if (!path || isLowConfidencePath(path)) {
        return;
    }
    const normalized = path.replace(/^\.\//, '');
    if (normalized.length <= 300) {
        entrypoints.add(normalized);
    }
}
function packageEntrypoints(entrypoints, manifest) {
    if (!manifest.path.endsWith('package.json')) {
        return;
    }
    try {
        const packageJson = JSON.parse(manifest.content);
        const base = directoryOf(manifest.path);
        const addPackagePath = (value) => {
            if (typeof value !== 'string' || !value || value.startsWith('http')) {
                return;
            }
            addEntrypoint(entrypoints, `${base ? `${base}/` : ''}${value.replace(/^\.\//, '')}`);
        };
        addPackagePath(packageJson.main);
        addPackagePath(packageJson.module);
        if (typeof packageJson.bin === 'string') {
            addPackagePath(packageJson.bin);
        }
        else if (packageJson.bin && typeof packageJson.bin === 'object') {
            for (const value of Object.values(packageJson.bin)) {
                addPackagePath(value);
            }
        }
    }
    catch {
        // An invalid manifest is still inventory evidence, but is not executed.
    }
}
/**
 * STEP F — Turn the cheap file/manifests pass into a compact inventory. This
 * parses JSON as text only; it never installs or imports repository code.
 */
function buildInventory(fileCount, files, manifests) {
    const languages = new Set();
    const packageManagers = new Set();
    const frameworks = new Set();
    const entrypoints = new Set();
    for (const file of files) {
        const language = languageForPath(file);
        if (language) {
            languages.add(language);
        }
        addPackageManager(packageManagers, file);
        const normalized = normalizePath(file);
        if (/(?:^|\/)(?:main|index|app|server|cli)\.(?:ts|tsx|js|jsx|mjs|cjs|py|go|rs|rb|php)$/i.test(normalized) ||
            /(?:^|\/)cmd\/[^/]+\.(?:go|rs)$/i.test(normalized)) {
            addEntrypoint(entrypoints, normalized);
        }
    }
    for (const manifest of manifests) {
        addPackageManager(packageManagers, manifest.path);
        packageEntrypoints(entrypoints, manifest);
    }
    addFrameworks(frameworks, manifests);
    return {
        languages: [...languages].sort(),
        packageManagers: [...packageManagers].sort(),
        frameworks: [...frameworks].sort(),
        fileCount: Math.max(0, fileCount),
        entrypoints: [...entrypoints].sort().slice(0, 50),
    };
}
function parseDiscoveryEvent(line, category, candidates, linesByFile) {
    try {
        const event = JSON.parse(line);
        if (event.type !== 'match' && event.type !== 'context') {
            return;
        }
        const file = normalizePath(String(event.data?.path?.text ?? ''));
        const lineNumber = Number(event.data?.line_number ?? 0);
        const text = String(event.data?.lines?.text ?? '');
        if (!file || !Number.isInteger(lineNumber) || lineNumber < 1) {
            return;
        }
        const submatch = event.data?.submatches?.[0];
        const columnStart = Number(submatch?.start ?? 0);
        const raw = {
            type: event.type,
            file,
            line: lineNumber,
            column: Number.isFinite(columnStart) && columnStart >= 0
                ? columnStart + 1
                : 1,
            text,
            match: String(submatch?.match?.text ?? ''),
        };
        let fileLines = linesByFile.get(file);
        if (!fileLines) {
            fileLines = new Map();
            linesByFile.set(file, fileLines);
        }
        fileLines.set(lineNumber, safeText(file, text, 500));
        if (event.type === 'match') {
            addCandidate(candidates, raw, category);
        }
    }
    catch {
        // A truncated or malformed rg event must not discard the rest of a scan.
    }
}
/**
 * STEP J — Parse the sandbox protocol and produce the complete structured
 * evidence object consumed by the worker.
 */
export function parseScannerOutput(stdout) {
    const commitMatch = stdout.match(/^CODEVET_COMMIT:([0-9a-f]{40})$/m);
    let fileCount = 0;
    const files = [];
    const manifests = [];
    const linesByFile = new Map();
    const candidates = [];
    let inInventory = false;
    let inDiscovery = false;
    let category = null;
    for (const line of stdout.split('\n')) {
        if (line === 'CODEVET_INVENTORY_BEGIN') {
            inInventory = true;
            continue;
        }
        if (line === 'CODEVET_INVENTORY_END') {
            inInventory = false;
            continue;
        }
        if (inInventory && line.startsWith('CODEVET_INVENTORY_COUNT:')) {
            const count = Number(line.slice('CODEVET_INVENTORY_COUNT:'.length));
            if (Number.isFinite(count)) {
                fileCount = count;
            }
            continue;
        }
        if (inInventory && line.startsWith('CODEVET_FILE:')) {
            const encodedPath = line.slice('CODEVET_FILE:'.length);
            const path = normalizePath(Buffer.from(encodedPath, 'base64').toString('utf8'));
            if (path && files.length < MAX_INVENTORY_FILES) {
                files.push(path);
            }
            continue;
        }
        if (inInventory && line.startsWith('CODEVET_MANIFEST:')) {
            const encoded = line.slice('CODEVET_MANIFEST:'.length);
            const separator = encoded.indexOf(':');
            if (separator > 0 && manifests.length < MAX_MANIFESTS) {
                const path = normalizePath(Buffer.from(encoded.slice(0, separator), 'base64').toString('utf8'));
                const content = Buffer.from(encoded.slice(separator + 1), 'base64').toString('utf8');
                if (path) {
                    manifests.push({ path, content });
                }
            }
            continue;
        }
        if (line === 'CODEVET_DISCOVERY_BEGIN') {
            inDiscovery = true;
            continue;
        }
        if (line === 'CODEVET_DISCOVERY_END') {
            inDiscovery = false;
            category = null;
            continue;
        }
        const categoryBegin = line.match(/^CODEVET_CATEGORY_BEGIN:(keyboard_input|microphone_access|sensitive_system_access|external_http|process_execution|clipboard_access|credential_handling|tracking_telemetry)$/);
        if (categoryBegin) {
            category = categoryBegin[1];
            continue;
        }
        if (line.startsWith('CODEVET_CATEGORY_END:')) {
            category = null;
            continue;
        }
        if (inDiscovery && category) {
            parseDiscoveryEvent(line, category, candidates, linesByFile);
        }
    }
    const inventory = buildInventory(fileCount || files.length, files, manifests);
    const analysis = analyzeCandidates(candidates, linesByFile);
    const candidateFlows = correlateFindings(analysis.behaviors, analysis.networkCalls);
    const snippets = collectSnippets(analysis.securityFindings, analysis.behaviors, analysis.networkCalls, linesByFile);
    return {
        commitSha: commitMatch?.[1] ?? null,
        inventory,
        candidates,
        securityFindings: analysis.securityFindings,
        behaviors: analysis.behaviors,
        networkCalls: analysis.networkCalls,
        candidateFlows,
        snippets,
        findings: analysis.securityFindings,
    };
}
