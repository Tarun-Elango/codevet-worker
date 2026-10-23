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

## How scanning works

1. **Deterministic code scan** — checks for exposed secrets and identifies code patterns that may indicate suspicious behavior or major security risks.
2. **Pi agent review** — investigates those leads and explores the repository in an isolated sandbox using read-only file tools, with no code execution or file editing. Sensitive files are excluded. It judges behavior in context, and a separate verifier checks the findings against the source before the final report.
