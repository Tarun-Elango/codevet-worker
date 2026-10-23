# Codevet Worker

A background worker that scans GitHub repositories in isolated sandboxes to detect suspicious code behavior and potential security risks.

## Dependencies

- **RabbitMQ** — consumes scan jobs from the `scan_requests` queue (`RABBITMQ_URL`).
- **PostgreSQL** — tracks requests and stores scan results (`DATABASE_URL`).
- **Railway** — runs repository scans in isolated sandboxes.
- **AI provider** — enables AI analysis with `CODEVET_AI_API_KEY`, `CODEVET_AI_PROVIDER`, and `CODEVET_AI_MODEL`.

Jobs must be published to RabbitMQ by a separate producer.

## Run locally

```sh
npm install
npm run dev
```

Health check: `http://localhost:3000/health`.
