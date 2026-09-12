import type { ScanJob } from '../worker.js'

import {
  SCANNER_VERSION,
  configuredAgent,
  validatedCloneUrl,
} from './analysis.js'
import {
  destroyScannerSandbox,
  runSandboxStep1,
} from './sandbox_step1.js'
import { runSandboxStep2 } from './sandbox_step2.js'
import type { ScannerResult } from './analysis.js'

/** Coordinate validated input, the deterministic scan, optional AI enrichment,
 * and the lifetime of the one shared isolated sandbox. */
export async function runScannerContainer(
  job: ScanJob & { commitSha: string }
): Promise<ScannerResult> {
  const commitSha = job.commitSha.toLowerCase()
  const repoUrl = validatedCloneUrl(job.repoUrl, commitSha)
  const agent = configuredAgent()
  const { sandbox, scannerResult } = await runSandboxStep1({ ...job, commitSha, repoUrl })

  try {
    if (!agent) {
      console.log(`[${job.uid}] AI analysis skipped: no configured API key`)
      return { ...scannerResult, agentAnalysis: null }
    }

    const agentAnalysis = await runSandboxStep2(sandbox, job.uid, scannerResult, agent)
    return { ...scannerResult, agentAnalysis }
  } finally {
    await destroyScannerSandbox(sandbox, job.uid)
  }
}

export { SCANNER_VERSION }
