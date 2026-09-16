import { runScannerContainer, SCANNER_VERSION } from './checksv2/orchestrator.js';
function parseRepoUrl(repoUrl) {
    const url = new URL(repoUrl);
    if (url.protocol !== 'https:' || url.hostname !== 'github.com') {
        throw new Error('Only HTTPS github.com repositories are allowed');
    }
    const parts = url.pathname.replace(/\.git$/, '').split('/').filter(Boolean);
    const [owner, repo, view, ...refParts] = parts;
    const validPart = /^[A-Za-z0-9_.-]+$/;
    if (!owner || !repo || !validPart.test(owner) || !validPart.test(repo)) {
        throw new Error('Invalid GitHub repository URL');
    }
    let ref;
    if (parts.length > 2) {
        if (view !== 'tree' || refParts.length === 0) {
            throw new Error('Use a repository URL or a GitHub /tree/BRANCH URL');
        }
        ref = refParts.map(decodeURIComponent).join('/');
        if (!ref || /[\x00-\x20~^:?*\\[\\]|]|\.\.|\/$|\.$/.test(ref)) {
            throw new Error('Invalid Git branch name');
        }
    }
    return {
        cloneUrl: new URL(`https://github.com/${owner}/${repo}.git`),
        ref,
    };
}
// Kept exported for callers that only need the safe clone URL.
export function validateRepoUrl(repoUrl) {
    return parseRepoUrl(repoUrl).cloneUrl;
}
function repoIdentifierFromUrl(repoUrl) {
    return repoUrl.pathname.replace(/^\//, '').replace(/\.git$/, '');
}
/** Provide a useful persisted summary when the optional AI summary is null. */
function summaryForResult(result) {
    const agentSummary = result.agentAnalysis?.summary?.trim();
    if (agentSummary)
        return agentSummary;
    const aiIssueCount = result.agentAnalysis?.securityIssues.length ?? 0;
    const behaviorCount = result.agentAnalysis?.suspiciousBehaviors.length ?? 0;
    const primaryFinding = result.agentAnalysis?.securityIssues[0]?.description ??
        result.securityFindings[0]?.title ??
        result.agentAnalysis?.suspiciousBehaviors[0]?.description;
    const risk = result.agentAnalysis?.overallRisk ?? 'unknown';
    return [
        `Risk: ${risk}. Found ${result.securityFindings.length} deterministic finding(s), ${aiIssueCount} AI security issue(s), and ${behaviorCount} suspicious behavior(s).`,
        ...(primaryFinding ? [`Primary finding: ${primaryFinding}`] : []),
    ].join(' ');
}
// Resolve either GitHub's default branch or a ref selected in a /tree/ URL.
/**
 * STEP B — Resolve a branch to an immutable commit before creating a sandbox.
 * The scanner always fetches this SHA rather than a moving branch name.
 */
async function resolveBranchCommit(repoUrl, ref) {
    const [owner, repo] = repoIdentifierFromUrl(repoUrl).split('/');
    const apiUrl = new URL(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/commits`);
    if (ref) {
        // Encode slashes too: the complete value is one Git ref, not URL path
        // components supplied by the requester.
        apiUrl.pathname += `/${encodeURIComponent(ref)}`;
    }
    else {
        apiUrl.searchParams.set('per_page', '1');
    }
    const headers = {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'codevet-scanner-worker',
        'X-GitHub-Api-Version': '2022-11-28',
    };
    if (process.env.GITHUB_TOKEN) {
        headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    }
    const response = await fetch(apiUrl, {
        headers,
        signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) {
        throw new Error(`GitHub returned ${response.status} while resolving the default branch commit`);
    }
    const body = (await response.json());
    const commitSha = Array.isArray(body) ? body[0]?.sha : body.sha;
    if (typeof commitSha !== 'string' ||
        !/^[0-9a-f]{40}$/i.test(commitSha)) {
        throw new Error('GitHub did not return a valid commit SHA');
    }
    return commitSha.toLowerCase();
}
/**
 * STEP C — Coordinate one scan in the trusted worker. Database state and the
 * advisory lock prevent duplicate work; all repository inspection remains in
 * runScannerContainer's isolated sandbox.
 */
export async function processRequest(pool, channel, msg, job) {
    const { uid, repoUrl } = job;
    let lockClient = null;
    let lockKey = null;
    try {
        console.log(`[${uid}] Starting ${repoUrl}`);
        const result = await pool.query(`
        UPDATE requests
        SET status = 'processing'
        WHERE uid = $1
        RETURNING uid
      `, [uid]);
        if (result.rowCount === 0) {
            console.error(`[${uid}] Request does not exist in database`);
            channel.ack(msg);
            return;
        }
        let validatedRepository;
        try {
            validatedRepository = parseRepoUrl(repoUrl);
        }
        catch (error) {
            console.error(`[${uid}] Invalid repository URL:`, error);
            await pool.query(`
          UPDATE requests
          SET status = 'invalid'
          WHERE uid = $1
        `, [uid]);
            channel.ack(msg);
            return;
        }
        const validatedRepoUrl = validatedRepository.cloneUrl;
        const repoIdentifier = repoIdentifierFromUrl(validatedRepoUrl);
        // A plain repository URL means the default branch; /tree/REF means that
        // exact branch/ref. In both cases cache by immutable commit SHA.
        const commitSha = job.commitSha ??
            (await resolveBranchCommit(validatedRepoUrl, validatedRepository.ref));
        // Serialize scans for a repository across all worker instances. Without
        // this lock, two deliveries can both miss the cache and create sandboxes
        // before either one stores its result.
        lockClient = await pool.connect();
        lockKey = repoIdentifier.toLowerCase();
        await lockClient.query('SELECT pg_advisory_lock(hashtextextended($1, 0))', [lockKey]);
        const cachedResult = await lockClient.query(`
        SELECT 1
        FROM repo_results
        WHERE lower(repo_identifier) = lower($1)
          AND commit_sha = $2
          AND scanner_version = $3
        LIMIT 1
      `, [repoIdentifier, commitSha, SCANNER_VERSION]);
        if (cachedResult.rowCount && cachedResult.rowCount > 0) {
            console.log(`[${uid}] Skipping already-scanned ${validatedRepoUrl.toString()}@${commitSha}`);
            await lockClient.query(`
          UPDATE requests
          SET status = 'completed'
          WHERE uid = $1
        `, [uid]);
            channel.ack(msg);
            return;
        }
        /**
         * STEP D — The sandbox returns structured inventory, candidates, static
         * findings, correlations, and bounded snippets. No repository access is
         * needed after this point.
         */
        const scannerResult = await runScannerContainer({
            ...job,
            repoUrl: validatedRepoUrl.toString(),
            commitSha,
        });
        const deterministicIssues = scannerResult.securityFindings;
        const aiIssues = scannerResult.agentAnalysis?.status === 'completed'
            ? scannerResult.agentAnalysis.securityIssues
            : [];
        console.log(`[${uid}] Analysis: ` +
            `${deterministicIssues.length} deterministic finding(s), ` +
            `${aiIssues.length} AI security issue(s)`);
        const storedFindings = {
            deterministic: scannerResult.securityFindings,
            aiSecurityIssues: scannerResult.agentAnalysis?.securityIssues ?? [],
            suspiciousBehaviors: scannerResult.agentAnalysis?.suspiciousBehaviors ?? [],
            externalServices: scannerResult.agentAnalysis?.externalServices ?? [],
            // Preserve the scoped AI verdict and trusted coverage alongside the
            // existing arrays so clients do not mistake a risk of "none" for a
            // repository-wide safety guarantee.
            agentAnalysis: scannerResult.agentAnalysis,
        };
        await lockClient.query(`
        INSERT INTO repo_results (
          uid,
          repo_identifier,
          repo_url,
          commit_sha,
          summary,
          findings,
          scanner_version,
          overall_risk,
          scanned_at
        )
        VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, NOW())
        ON CONFLICT (repo_identifier, commit_sha, scanner_version)
        DO UPDATE SET
          repo_url = EXCLUDED.repo_url,
          commit_sha = EXCLUDED.commit_sha,
          summary = EXCLUDED.summary,
          findings = EXCLUDED.findings,
          scanner_version = EXCLUDED.scanner_version,
          overall_risk = EXCLUDED.overall_risk,
          scanned_at = NOW()
      `, [
            uid,
            repoIdentifier,
            validatedRepoUrl.toString(),
            commitSha,
            summaryForResult(scannerResult),
            JSON.stringify(storedFindings),
            SCANNER_VERSION,
            scannerResult.agentAnalysis?.overallRisk ?? 'unknown',
        ]);
        console.log(`[${uid}] Stored analysis`);
        await pool.query(`
        UPDATE requests
        SET status = 'completed'
        WHERE uid = $1
      `, [uid]);
        channel.ack(msg);
        console.log(`[${uid}] Completed`);
    }
    catch (error) {
        console.error(`[${uid}] Worker failed:`, error);
        try {
            await pool.query(`
          UPDATE requests
          SET status = 'failed'
          WHERE uid = $1
        `, [uid]);
        }
        catch (dbError) {
            console.error(`[${uid}] Failed to update database status:`, dbError);
        }
        channel.nack(msg, false, false);
    }
    finally {
        if (lockClient) {
            try {
                if (lockKey) {
                    await lockClient.query('SELECT pg_advisory_unlock(hashtextextended($1, 0))', [lockKey]);
                }
            }
            catch (error) {
                console.error(`[${uid}] Failed to release scan lock:`, error);
            }
            finally {
                lockClient.release();
            }
        }
    }
}
