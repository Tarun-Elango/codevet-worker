// Backward-compatible public exports. Scan implementation lives in ./checks.
export * from './checks/analysis.js';
export { runScannerContainer } from './checks/orchestrator.js';
export { scannerTemplate } from './checks/sandbox.js';
