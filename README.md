# ContentCreatorHub (`v1.0.0`)

**ContentCreatorHub** is a hardened, UK/EU GDPR-compliant creator workflow engine and **Social Media Post Analyzer** built on Python 3.11+ and a zero-TypeScript vanilla HTML5, CSS3, and ES2023 JavaScript dashboard.

Every numeric threshold, scoring weight, platform character limit, and operational bound is declared in `config.yaml` and `content_hub/constants.py`, executing deterministically across immutable stage batches.

---

## 1. Tutorial: Quickstart

### Run Locally with `uv` (Offline Zero-Credential Mode)

1. Create an isolated environment and install the package alongside `ruff`:

   ```bash
   uv venv
   uv pip install -e . ruff
   ```

2. Verify PEP 8 formatting and execute the automated security, GDPR, and analyzer test suite:

   ```bash
   uv run ruff check content_hub tests
   uv run python -m unittest discover -s tests -v
   ```

3. Launch the multi-tab web dashboard on `http://127.0.0.1:8080`:

   ```bash
   uv run python -m content_hub.server --config config.yaml --serve
   ```

4. Open `http://127.0.0.1:8080` in any desktop or mobile browser to navigate across:
   - **Creator Overview**: Execute sample batches, monitor pipeline stage verification, and inspect recent post scores.
   - **Post Analyzer**: Draft posts for LinkedIn, X / Microblog, Instagram, or YouTube Community and inspect hook, readability, sentiment, hashtag/CTA, and platform-fit metrics.
   - **GDPR & Ops**: Execute Article 17 Right to Erasure, run TTL retention sweeps, test single-use 30-minute password reset tokens, stage or roll back Blue-Green slots, and verify the SHA-256 audit ledger.

### Run with Local Cloud Emulators (`Azurite` + `fake-gcs-server`)

```bash
docker compose -f docker-compose.sandbox.yml up --build
```

When the sandbox stack is active, `telemetry_persist_stage` automatically syncs derived JSON snapshots to local Azure Blob Storage or Google Cloud Storage emulators without external cloud credentials.

---

## 2. How-To Guides

### Score a Social Media Post via REST API

```bash
curl -X POST [http://127.0.0.1:8080/api/posts/analyze](http://127.0.0.1:8080/api/posts/analyze) \
  -H "Origin: [http://127.0.0.1:8080](http://127.0.0.1:8080)" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer content-hub-session-token" \
  -H "X-User-Id: creator-alpha" \
  -d '{
    "owner_id": "creator-alpha",
    "target_platform": "linkedin_pro",
    "raw_post": "How we cut API latency by 42% using a 3-step blueprint?\nFirst, index high-frequency keys.\nBookmark and share your thoughts! #Engineering #CleanCode"
  }'
```

### Execute a GDPR Article 17 Right to Erasure Request

Via CLI:

```bash
uv run python -m content_hub.server --config config.yaml --erase-subject creator-alpha
```

Via REST API:

```bash
curl -X POST [http://127.0.0.1:8080/api/gdpr/erase](http://127.0.0.1:8080/api/gdpr/erase) \
  -H "Origin: [http://127.0.0.1:8080](http://127.0.0.1:8080)" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer content-hub-session-token" \
  -H "X-User-Id: creator-alpha" \
  -d '{"owner_id": "creator-alpha", "subject_id": "creator-alpha"}'
```

Both methods recompute the subject's `HKDF-SHA256` pseudonym, purge matching files and JSON manifest entries on disk, delete matching rows from the SQLite WAL database, clear the in-memory batch snapshot, and append a tamper-evident audit entry to `workspace/audit/audit_log.jsonl`.

### Configure Production Secrets

Set the master GDPR key via environment variable prior to starting the server:

```bash
export CONTENT_HUB_GDPR_SECRET="replace-with-high-entropy-secret"
```

---

## 3. Explanation: Architecture, Security & Privacy by Design

### Declarative Data-Driven Pipeline

All post submissions flow sequentially through the stage registry declared under `hub.stages` in `config.yaml` using immutable `@dataclass(frozen=True)` `ContentBatch` instances:

1. **`pii_scrub_stage`**: Verifies UK/EU cloud regional residency, derives a domain-separated `HKDF-SHA256` (`RFC 5869`) creator pseudonym per rotation epoch, and scrubs emails, phone numbers, and IPv4 addresses via regular expressions.
2. **`post_analyzer_stage`**: Evaluates opening hook strength, sentence-length cadence, positive/critical lexicon polarity, spam-trigger penalties, hashtag/CTA balance, and character suitability across all configured social platforms.
3. **`telemetry_persist_stage`**: Stores parameterized records in SQLite (`WAL` mode), writes atomic JSON summaries via `os.replace`, syncs with cloud sandbox emulators (or offline local storage), and appends a SHA-256 hash-chained record to `audit_log.jsonl`.

### 10-Point Pre-Deployment & OWASP ASVS Controls

1. **Object-Level Authorization (BOLA)**: Constant-time `hmac.compare_digest` ensures authenticated callers only read or mutate their own `owner_id` resources (`HTTP 403` on mismatch).
2. **Input Hygiene (SQLi & XSS)**: Rejects SQLi and XSS patterns (`HTTP 400`), HTML-escapes text fields, and executes parameterized SQLite queries (`?`) exclusively.
3. **Strict CORS Allowlist**: Serves requests only from origins explicitly listed in `security.allowed_cors_origins`.
4. **Sliding-Window Rate Limiting**: Throttles excessive per-client requests (`HTTP 429`) to prevent abuse and unexpected compute bills.
5. **30-Minute Single-Use Password Reset Tokens**: Cryptographically signed tokens track `ISSUED`, `CONSUMED`, and `EXPIRED` states, returning `HTTP 410` after 1800 seconds or replay.
6. **Sanitized Frontend Error Boundaries**: Dedicated UI screens handle `400`, `403`, `404`, `410`, and `429` responses alongside a global `500` catch-all boundary that suppresses raw stack traces.
7. **Targeted Database Indexing**: Creates SQLite B-tree indexes strictly on `owner_id` and `batch_id` to accelerate primary queries without unnecessary write amplification.
8. **Cost-Capped Production Logging**: Bounds operational logs inside a fixed-capacity ring buffer (`deque`) with strict per-message character truncation.
9. **Immediate Breakage Alerts**: Automatically writes `ERROR` and `CRITICAL` events (including unhandled `500` exceptions) to `workspace/audit/alerts.jsonl`.
10. **Blue-Green Deployment & Instant Rollback**: Stages releases into the standby slot (`blue` or `green`), verifies health checks before promotion, and supports one-step traffic rollback.

---

## 4. Reference: API Endpoints, CLI Flags & Configuration

### REST API Reference

| Method | Endpoint | Purpose | Primary Status Codes |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/status` | Returns active slot, UK/EU region, stage state, latest report, and scoped history | `200`, `401`, `403`, `429` |
| `POST` | `/api/posts/analyze` | Scrubs PII, scores a post draft across platforms, and persists telemetry | `200`, `400`, `403`, `429` |
| `GET` | `/api/posts/history` | Fetches parameterized SQLite analysis history scoped to `X-User-Id` | `200`, `401`, `403`, `429` |
| `POST` | `/api/gdpr/erase` | Executes Article 17 erasure across disk manifests, SQLite rows, and RAM cache | `200`, `400`, `403`, `500` |
| `POST` | `/api/gdpr/purge` | Purges workspace artifacts exceeding `gdpr.retention_ttl_seconds` | `200`, `403`, `429` |
| `GET` | `/api/gdpr/audit` | Verifies SHA-256 hash chain integrity and returns recent zero-PII audit events | `200`, `403`, `500` |
| `POST` | `/api/auth/reset-issue` | Issues a single-use, 30-minute HMAC-signed password reset token | `200`, `400`, `403` |
| `POST` | `/api/auth/reset-consume` | Consumes a valid reset token once; rejects expired or replayed tokens | `200`, `400`, `403`, `410` |
| `POST` | `/api/deploy/stage` | Stages standby slot, verifies health probe, and promotes or rolls back | `200`, `400`, `403` |
| `POST` | `/api/deploy/rollback` | Immediately rolls active traffic back to the prior deployment slot | `200`, `403`, `429` |

### CLI Reference

| Flag | Description |
| :--- | :--- |
| `--config <path>` | Path to declarative YAML configuration (default: `config.yaml`). |
| `--run-once` | Seeds starter workspace assets, runs the three-stage pipeline once, prints JSON status, and exits. |
| `--erase-subject <id>` | Executes GDPR Article 17 Right to Erasure for `<id>` (raw ID or 64-character hex pseudonym) and exits. |
| `--serve` | Starts the ContentCreatorHub web dashboard server on `server.host:server.port`. |

---

## 5. Release Notes — `v1.0.0`

- Unified the hardened privacy-first pipeline with the **Social Media Post Analyzer** in a responsive three-tab vanilla HTML5, CSS3, and ES2023 JavaScript dashboard.
- Removed all TypeScript build dependencies, inline code comments, and magic numbers in favor of `config.yaml`, `content_hub/constants.py`, and CSS `:root` custom properties.
- Implemented RFC 5869 `HKDF-SHA256` domain-separated pseudonymization, regex PII redaction, clean-buffer EXIF stripping, SHA-256 hash-chained JSONL accountability logging, and cache-coherent GDPR Article 17 erasure.
- Enforced all 10 pre-deployment controls, bounded iteration contracts, non-root `Dockerfile` packaging, local `Azurite` / `fake-gcs-server` sandbox orchestration, and automated GitHub Actions CI verification.
