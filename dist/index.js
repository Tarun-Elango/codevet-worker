import 'dotenv/config';
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import amqp from 'amqplib';
import pg from 'pg';
import 'dotenv/config';
import { processRequest, } from './worker.js';
const { Pool } = pg;
const QUEUE_NAME = 'scan_requests';
const RABBITMQ_URL = process.env.RABBITMQ_URL;
const DATABASE_URL = process.env.DATABASE_URL;
const PORT = Number(process.env.PORT ?? 3000);
const WORKER_CONCURRENCY = Number(process.env.WORKER_CONCURRENCY ?? 5);
if (!RABBITMQ_URL) {
    throw new Error('RABBITMQ_URL is not set');
}
if (!DATABASE_URL) {
    throw new Error('DATABASE_URL is not set');
}
const rabbitmqUrl = RABBITMQ_URL;
const databaseUrl = DATABASE_URL;
const pool = new Pool({
    connectionString: databaseUrl,
});
let rabbitConnection = null;
let rabbitChannel = null;
let workerReady = false;
const app = new Hono();
app.get('/', (c) => {
    return c.json({
        service: 'scanner-worker',
        status: 'running',
    });
});
app.get('/health', async (c) => {
    try {
        await pool.query('SELECT 1');
        return c.json({
            status: workerReady ? 'healthy' : 'starting',
            database: 'connected',
            rabbitmq: workerReady ? 'connected' : 'connecting',
        });
    }
    catch (error) {
        console.error('Health check failed:', error);
        return c.json({
            status: 'unhealthy',
            database: 'disconnected',
            rabbitmq: workerReady ? 'connected' : 'unknown',
        }, 503);
    }
});
function parseJob(msg) {
    try {
        const body = JSON.parse(msg.content.toString());
        if (typeof body.uid !== 'string' ||
            typeof body.repoUrl !== 'string' ||
            !body.uid ||
            !body.repoUrl) {
            return null;
        }
        const commitSha = body.commitSha ?? body.commit_sha;
        // commitSha is optional for backwards compatibility with messages that
        // were published before commit-aware de-duplication was added.
        if (commitSha !== undefined &&
            (typeof commitSha !== 'string' ||
                !/^[0-9a-f]{40}$/i.test(commitSha))) {
            return null;
        }
        return {
            uid: body.uid,
            repoUrl: body.repoUrl,
            ...(commitSha
                ? { commitSha: commitSha.toLowerCase() }
                : {}),
        };
    }
    catch {
        return null;
    }
}
async function processJob(channel, msg) {
    const job = parseJob(msg);
    if (!job) {
        console.error('Invalid job received:', msg.content.toString());
        // Bad message: discard it.
        // Don't requeue or it would loop forever.
        channel.nack(msg, false, false);
        return;
    }
    await processRequest(pool, channel, msg, job);
}
async function startWorker() {
    console.log('Connecting to RabbitMQ...');
    rabbitConnection = await amqp.connect(rabbitmqUrl);
    rabbitConnection.on('error', (error) => {
        console.error('RabbitMQ connection error:', error);
    });
    rabbitConnection.on('close', () => {
        console.error('RabbitMQ connection closed');
        workerReady = false;
    });
    rabbitChannel = await rabbitConnection.createChannel();
    await rabbitChannel.assertQueue(QUEUE_NAME, {
        durable: true,
    });
    await rabbitChannel.prefetch(WORKER_CONCURRENCY);
    // tells mq, when message arrives call this callback
    await rabbitChannel.consume(QUEUE_NAME, (msg) => {
        if (!msg || !rabbitChannel) {
            return;
        }
        // Intentionally not awaited here.
        // RabbitMQ can deliver multiple messages,
        // controlled by prefetch().
        void processJob(rabbitChannel, msg);
    }, {
        noAck: false,
    });
    workerReady = true;
    console.log(`Waiting for jobs from "${QUEUE_NAME}" with concurrency ${WORKER_CONCURRENCY}`);
}
const server = serve({
    fetch: app.fetch,
    port: PORT,
}, (info) => {
    console.log(`Hono listening on port ${info.port}`);
});
startWorker().catch((error) => {
    console.error('Failed to start RabbitMQ worker:', error);
    process.exit(1);
});
async function shutdown(signal) {
    console.log(`${signal} received, shutting down...`);
    workerReady = false;
    server.close();
    try {
        await rabbitChannel?.close();
    }
    catch (error) {
        console.error('Failed to close RabbitMQ channel:', error);
    }
    try {
        await rabbitConnection?.close();
    }
    catch (error) {
        console.error('Failed to close RabbitMQ connection:', error);
    }
    await pool.end();
    process.exit(0);
}
process.on('SIGTERM', () => {
    void shutdown('SIGTERM');
});
process.on('SIGINT', () => {
    void shutdown('SIGINT');
});
/**
CREATE TABLE repo_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    uid UUID NOT NULL,
    repo_identifier TEXT NOT NULL,
    repo_url TEXT NOT NULL,

    commit_sha TEXT,

    summary TEXT,
    findings JSONB,

    scanner_version TEXT NOT NULL DEFAULT 'v1',
    overall_risk VARCHAR(32),

    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (repo_identifier, commit_sha)
);
 
CREATE TABLE requests (
    uid UUID PRIMARY KEY,
    repo_url TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address INET,
    status VARCHAR(32) NOT NULL DEFAULT 'queued'
);
 */ 
