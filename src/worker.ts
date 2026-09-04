import type { Channel, ConsumeMessage } from 'amqplib'
import type { Pool } from 'pg'

export type ScanJob = {
  uid: string
  repoUrl: string
}


async function scanCheck(job: ScanJob) {
  /*
   * Placeholder for sandboxed scanner.
   *
   * Eventually:
   *
   * const container = await createSandboxContainer(job.uid)
   *
   * try {
   *   await container.start()
   *
   *   await runScan(container, job.repoUrl)
   *
   *   await saveResults(job.uid)
   * } finally {
   *   await container.remove({ force: true })
   * }
   */

  console.log(`[${job.uid}] Running scan for ${job.repoUrl}`)
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

    /*
     * Actual scanner logic goes here.
     */

    await scanCheck(job)
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