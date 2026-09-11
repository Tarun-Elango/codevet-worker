import { SCANNER_VERSION, configuredAgent, validatedCloneUrl } from './analysis.js';
import { runSandboxScan } from './sandbox.js';
/** Coordinate validated scan inputs with the isolated sandbox implementation. */
export async function runScannerContainer(job) {
    const commitSha = job.commitSha.toLowerCase();
    const repoUrl = validatedCloneUrl(job.repoUrl, commitSha);
    return runSandboxScan({ ...job, commitSha, repoUrl }, configuredAgent());
}
export { SCANNER_VERSION };
