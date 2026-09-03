import 'dotenv/config'

import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import amqp from 'amqplib'
import type { Channel, ChannelModel, ConsumeMessage } from 'amqplib'
import pg from 'pg'
import 'dotenv/config'
const { Pool } = pg

const QUEUE_NAME = 'scan_requests'

const RABBITMQ_URL = process.env.RABBITMQ_URL
const DATABASE_URL = process.env.DATABASE_URL

const PORT = Number(process.env.PORT ?? 3000)
const WORKER_CONCURRENCY = Number(
  process.env.WORKER_CONCURRENCY ?? 5
)

if (!RABBITMQ_URL) {
  throw new Error('RABBITMQ_URL is not set')
}

if (!DATABASE_URL) {
  throw new Error('DATABASE_URL is not set')
}
const rabbitmqUrl: string = RABBITMQ_URL
const databaseUrl: string = DATABASE_URL
const pool = new Pool({
  connectionString: databaseUrl,
})

type ScanJob = {
  uid: string
  repoUrl: string
}

let rabbitConnection: ChannelModel | null = null
let rabbitChannel: Channel | null = null
let workerReady = false


const app = new Hono()

app.get('/', (c) => {
  return c.json({
    service: 'scanner-worker',
    status: 'running',
  })
})

app.get('/health', async (c) => {
  try {
    await pool.query('SELECT 1')

    return c.json({
      status: workerReady ? 'healthy' : 'starting',
      database: 'connected',
      rabbitmq: workerReady ? 'connected' : 'connecting',
    })
  } catch (error) {
    console.error('Health check failed:', error)

    return c.json(
      {
        status: 'unhealthy',
        database: 'disconnected',
        rabbitmq: workerReady ? 'connected' : 'unknown',
      },
      503
    )
  }
})

function parseJob(msg: ConsumeMessage): ScanJob | null {
  try {
    const body = JSON.parse(msg.content.toString())

    if (
      typeof body.uid !== 'string' ||
      typeof body.repoUrl !== 'string' ||
      !body.uid ||
      !body.repoUrl
    ) {
      return null
    }

    return {
      uid: body.uid,
      repoUrl: body.repoUrl,
    }
  } catch {
    return null
  }
}

async function processJob(
  channel: Channel,
  msg: ConsumeMessage
) {
  const job = parseJob(msg)

  if (!job) {
    console.error('Invalid job received:', msg.content.toString())

    // Bad message: discard it.
    // Don't requeue or it would loop forever.
    channel.nack(msg, false, false)

    return
  }

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

      // Nothing useful can be done with this job.
      channel.ack(msg)

      return
    }

    /*
     * ------------------------------------------------
     * Actual scanner logic will eventually go here.
     * ------------------------------------------------
     */

    console.log(`[${uid}] Work performed`)

    /*
     * ------------------------------------------------
     */

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

    // For now assume unexpected failures may be transient.
    // Put the message back onto RabbitMQ.
    channel.nack(msg, false, true)
  }
}

async function startWorker() {
  console.log('Connecting to RabbitMQ...')

  rabbitConnection = await amqp.connect(rabbitmqUrl)

  rabbitConnection.on('error', (error) => {
    console.error('RabbitMQ connection error:', error)
  })

  rabbitConnection.on('close', () => {
    console.error('RabbitMQ connection closed')
    workerReady = false
  })

  rabbitChannel = await rabbitConnection.createChannel()

  await rabbitChannel.assertQueue(QUEUE_NAME, {
    durable: true,
  })

  await rabbitChannel.prefetch(WORKER_CONCURRENCY)

  await rabbitChannel.consume(
    QUEUE_NAME,
    (msg) => {
      if (!msg || !rabbitChannel) {
        return
      }

      // Intentionally not awaited here.
      // RabbitMQ can deliver multiple messages,
      // controlled by prefetch().
      void processJob(rabbitChannel, msg)
    },
    {
      noAck: false,
    }
  )

  workerReady = true

  console.log(
    `Waiting for jobs from "${QUEUE_NAME}" with concurrency ${WORKER_CONCURRENCY}`
  )
}

const server = serve(
  {
    fetch: app.fetch,
    port: PORT,
  },
  (info) => {
    console.log(`Hono listening on port ${info.port}`)
  }
)

startWorker().catch((error) => {
  console.error('Failed to start RabbitMQ worker:', error)
  process.exit(1)
})

async function shutdown(signal: string) {
  console.log(`${signal} received, shutting down...`)

  workerReady = false

  server.close()

  try {
    await rabbitChannel?.close()
  } catch (error) {
    console.error('Failed to close RabbitMQ channel:', error)
  }

  try {
    await rabbitConnection?.close()
  } catch (error) {
    console.error('Failed to close RabbitMQ connection:', error)
  }

  await pool.end()

  process.exit(0)
}

process.on('SIGTERM', () => {
  void shutdown('SIGTERM')
})

process.on('SIGINT', () => {
  void shutdown('SIGINT')
})
