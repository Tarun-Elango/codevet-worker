import type { Channel, ConsumeMessage } from 'amqplib'
import type { Pool } from 'pg'
import { spawn } from 'node:child_process'
import { Sandbox } from 'railway'

export type ScanJob = {
  uid: string
  repoUrl: string
}

export function validateRepoUrl(repoUrl: string): URL {
  const url = new URL(repoUrl)

  if (url.protocol !== 'https:') {
    throw new Error('Only HTTPS repositories are allowed')
  }

  if (url.hostname !== 'github.com') {
    throw new Error('Only github.com repositories are allowed')
  }

  const parts = url.pathname
    .replace(/\\.git$/, '')
    .split('/')
    .filter(Boolean)

  if (parts.length !== 2) {
    throw new Error('Invalid GitHub repository URL')
  }

  const [owner, repo] = parts

  const validPart = /^[A-Za-z0-9_.-]+$/

  if (!validPart.test(owner) || !validPart.test(repo)) {
    throw new Error('Invalid GitHub repository URL')
  }

  return new URL(
    `https://github.com/${owner}/${repo}.git`
  )
}

export const scannerTemplate = Sandbox.template()
  .withPackages(
    'git',
    'ripgrep',
    'ca-certificates',
    'util-linux',
    'passwd'
  )
  .run(`
    set -eux

    # Dedicated non-root account for scanning
    useradd \
      --create-home \
      --uid 10001 \
      --shell /bin/bash \
      scanner

    mkdir -p /workspace
    chown scanner:scanner /workspace

    # Defense-in-depth Git configuration
    git config --system core.hooksPath /dev/null
    git config --system protocol.file.allow never
    git config --system protocol.ext.allow never
    git config --system submodule.recurse false
  `)
  .workdir('/workspace')

export async function processRequest(
  pool: Pool,
  channel: Channel,
  msg: ConsumeMessage,
  job: ScanJob
) {
  const { uid, repoUrl } = job

  try {
    console.log(`[${uid}] Starting ${repoUrl}`)

    const result = await pool.query(
      `
        UPDATE requests
        SET status = 'processing'
        WHERE uid = $1
        RETURNING uid
      `,
      [uid]
    )

    if (result.rowCount === 0) {
      console.error(`[${uid}] Request does not exist in database`)

      channel.ack(msg)
      return
    }

    let validatedRepoUrl: URL

    try {
      validatedRepoUrl = validateRepoUrl(repoUrl)
    } catch (error) {
      console.error(`[${uid}] Invalid repository URL:`, error)

      await pool.query(
        `
          UPDATE requests
          SET status = 'invalid'
          WHERE uid = $1
        `,
        [uid]
      )

      channel.ack(msg)
      return
    }

    await runScannerContainer({
      ...job,
      repoUrl: validatedRepoUrl.toString(),
    })

    console.log(`[${uid}] Work performed`)

    await pool.query(
      `
        UPDATE requests
        SET status = 'completed'
        WHERE uid = $1
      `,
      [uid]
    )

    channel.ack(msg)

    console.log(`[${uid}] Completed`)
  } catch (error) {
    console.error(`[${uid}] Worker failed:`, error)

    try {
      await pool.query(
        `
          UPDATE requests
          SET status = 'queued'
          WHERE uid = $1
        `,
        [uid]
      )
    } catch (dbError) {
      console.error(
        `[${uid}] Failed to reset database status:`,
        dbError
      )
    }

    channel.nack(msg, false, false)
  }
}

async function runScannerContainer(job: ScanJob): Promise<void> {
  const { uid, repoUrl } = job

  console.log(`[${uid}] Creating Railway sandbox`)

  const sandbox = await Sandbox.create(scannerTemplate, {
    // Destroy it fairly quickly if your worker crashes before cleanup.
    idleTimeoutMinutes: 5,

    // Default is already ISOLATED:
    // public internet is available, but it cannot access your
    // Railway project's private network.
    networkIsolation: 'ISOLATED',

    env: {
      JOB_UID: uid,
      REPO_URL: repoUrl,
    },
  })

  console.log(`[${uid}] Sandbox created: ${sandbox.id}`)

  try {
    const result = await sandbox.exec(
      `
        runuser -u scanner -- env \
          HOME=/home/scanner \
          JOB_UID="$JOB_UID" \
          REPO_URL="$REPO_URL" \
          GIT_TERMINAL_PROMPT=0 \
          bash --noprofile --norc -c '
            set -euo pipefail

            cd /workspace

            echo "Sandbox started"
            echo "Job: $JOB_UID"

            git \
              -c core.hooksPath=/dev/null \
              -c protocol.file.allow=never \
              -c protocol.ext.allow=never \
              clone \
              --depth=1 \
              --single-branch \
              --no-tags \
              "$REPO_URL" \
              repo

            unset REPO_URL
            cd repo

            echo "Repository cloned"

            rg --files | head -100
          '
      `,
      {
        timeoutSec: 60,
      }
    )

    console.log(`[${uid}] Sandbox stdout:`)
    console.log(result.stdout)

    if (result.stderr) {
      console.error(`[${uid}] Sandbox stderr:`)
      console.error(result.stderr)
    }

    if (result.exitCode !== 0) {
      throw new Error(
        `Sandbox command exited with code ${result.exitCode}`
      )
    }
  } finally {
    console.log(`[${uid}] Destroying sandbox`)

    await sandbox.destroy()

    console.log(`[${uid}] Sandbox destroyed`)
  }
}