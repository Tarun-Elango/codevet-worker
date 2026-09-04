import type { Channel, ConsumeMessage } from 'amqplib'
import type { Pool } from 'pg'
import { spawn } from 'node:child_process'

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

  console.log(`[${uid}] Starting scanner container`)

  const args = [
    'run',

    // Delete container after command finishes
    '--rm',

    // No network access
    '--network=none',

    // Very small resource limits
    '--cpus=0.10',
    '--memory=32m',
    '--memory-swap=32m',
    '--pids-limit=16',

    // Filesystem / privilege restrictions
    '--read-only',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges',

    // Writable temporary directory
    '--tmpfs',
    '/tmp:rw,noexec,nosuid,size=256m',

    // Pass harmless metadata into container
    '--env',
    `JOB_UID=${uid}`,

    '--env',
    `REPO_URL=${repoUrl}`,

    // Simple image for testing
    'alpine:3.20',

    'sh',
    '-c',
    `
      echo "Container started"
      echo "Job: $JOB_UID"
      echo "Repo: $REPO_URL"

      echo "Doing fake scanner work..."

      mkdir -p /tmp/work

      echo "hello from isolated scanner" > /tmp/work/test.txt

      echo "Files:"
      ls -la /tmp/work

      echo "Contents:"
      cat /tmp/work/test.txt

      echo "Fake scan finished"
    `,
  ]

  await runCommand('docker', args)

  console.log(`[${uid}] Scanner container stopped`)
}

function runCommand(
  command: string,
  args: string[]
): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: 'inherit',
    })

    child.on('error', (error) => {
      reject(error)
    })

    child.on('exit', (code) => {
      if (code === 0) {
        resolve()
      } else {
        reject(
          new Error(
            `${command} exited with code ${code}`
          )
        )
      }
    })
  })
}