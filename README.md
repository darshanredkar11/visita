# VisitorPass

A visitor-management platform for gated communities, offices, and institutions — offline-capable, cryptographically signed guest passes, verified at the gate with zero network dependency.

## Design principles

- **Offline-first** — guest passes are signed (Ed25519) and verified entirely on-device; a gate scan never needs connectivity.
- **Security-first** — per-org key isolation, encrypted PII, tamper-evident audit log, replay-proof auth.
- **Privacy-first** — phone numbers are HMAC'd for lookup and ChaCha20-Poly1305 encrypted at rest; per-org configurable retention.
- **Mobile-first** — guards, residents, and admins operate primarily from a phone/tablet, not a desktop.
- **Extremely lightweight & low cost** — single Rust binary + Postgres + Caddy; runs on one small VPS.
- **Easy to maintain & deploy** — one `docker-compose up`, one migration set, no orchestration platform required.
- **Extremely fast** — Rust/Axum backend, indexed Postgres, no heavy runtime.
- **Scales to hundreds/thousands of organizations** — single shared schema, `org_id`-scoped everywhere, no per-tenant schema sprawl.
- **Org-type agnostic** — the same schema and APIs serve every vertical below with zero code branching on org type.

## Target organizations

Housing societies, offices, hospitals, warehouses, schools, colleges, factories, coworking spaces, apartments, hostels.

## Architecture

```
crates/domain          — entities, value objects, domain errors (no framework deps)
crates/application     — use cases, ports (repository/crypto/key-provider traits)
crates/infrastructure  — Postgres repositories, crypto (Ed25519/ChaCha20-Poly1305/Argon2), key provider
crates/api             — Axum HTTP API, routing, middleware, handlers
migrations/            — SQL schema (Postgres, time-partitioned audit/entry logs)
web/                   — React + TypeScript admin/resident web app
mobile/                — Kotlin Multiplatform app (Android; shared crypto/sync/db core)
docker/                — Dockerfile, docker-compose, Caddy reverse proxy config
```

**Core flow**: an admin/resident creates a visitor pass → backend signs a CBOR payload with the organization's Ed25519 key → QR code encodes `vp1.<base64url_cbor>` → a guard's device (online or offline) verifies the signature locally against the org's public key, no server round-trip required → entry events queue locally and sync to the server when connectivity returns.

## Tech stack

- **Backend**: Rust, Axum, SQLx/Postgres, PASETO v4 tokens, Ed25519 (pass signing), ChaCha20-Poly1305 (PII encryption), Argon2id (passwords)
- **Web**: React 19, TypeScript, Vite
- **Mobile**: Kotlin Multiplatform (shared crypto/sync/SQLDelight core, Android app)
- **Infra**: Docker, Caddy (TLS + reverse proxy), PostgreSQL 16

## Getting started

```bash
cp .env.example .env        # fill in DATABASE_URL, MASTER_KEY_HEX (openssl rand -hex 32), BASE_URL
docker compose -f docker/docker-compose.yml up
```

Migrations run automatically via `sqlx migrate` on API startup. See `.env.example` for all configuration options.

## Status

Actively hardening pre-launch. See project notes for the current audit/fix tracker.
