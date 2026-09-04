import type { Channel, ConsumeMessage } from 'amqplib'
import type { Pool } from 'pg'
import { spawn } from 'node:child_process'
import { Sandbox } from 'railway'

export type ScanJob = {
  uid: string
  repoUrl: string
}

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

    await runScannerContainer(job)

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

    channel.nack(msg, false, true)
  }
}

async function runScannerContainer(job: ScanJob): Promise<void> {
  const { uid, repoUrl } = job

  console.log(`[${uid}] Creating Railway sandbox`)

  const sandbox = await Sandbox.create({
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
    `bash -lc '
      echo "Sandbox started"
      echo "Job: $JOB_UID"
      echo "Repo: $REPO_URL"

      echo "Doing fake scanner work..."

      mkdir -p /tmp/work
      echo "hello from isolated scanner" > /tmp/work/test.txt

      echo "Files:"
      ls -la /tmp/work

      echo "Contents:"
      cat /tmp/work/test.txt

      echo "System:"
      uname -a

      echo "Memory:"
      cat /proc/meminfo | head

      echo "Fake scan finished"
    '`,
    {
      timeoutSec: 30,
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