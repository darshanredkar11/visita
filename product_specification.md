# Visita VisitorPass: Full Product Specification

This document outlines the complete product specification for Visita, an enterprise-grade, offline-first visitor management SaaS platform.

---

## 1. System Architecture & Core Differentiator

Visita's architecture is built around **cryptographic offline resilience**.
* **Zero-Network Gate Operations**: Guard kiosk tablets can cryptographically verify visitor passes (QR codes) entirely offline using Ed25519 signatures and local public keys.
* **Asynchronous Sync**: Devices queue entry logs locally and synchronize them to the cloud backend incrementally when a network connection is available.
* **Technology Stack**:
  - Backend: Rust (Axum, SQLx), PostgreSQL, PASETO v4 tokens.
  - Guard Kiosk: Kotlin Multiplatform (KMP), SQLDelight, Native hardware cryptography.
  - Web Portals: React, Vite.

---

## 2. Product Components & User Interfaces

The Visita product suite consists of four distinct user interfaces targeting different operational layers.

### 2.1 The Platform Super-Admin Portal (SaaS Operations)
*The centralized control center for the Visita SaaS owner to manage all global tenants.*
* **Organization Provisioning**: Onboard new organizations (residential societies, corporate office parks) and provision their root administrator accounts.
* **Global Billing & Subscriptions**: Track SaaS subscription tiers per organization (e.g., limits on active locations or daily passes).
* **Cross-Tenant Analytics**: View platform-wide health metrics, total check-in volume, and average gate sync latencies.
* **Global Device Revocation**: Ability to instantly wipe or block rogue Guard Tablets at the platform level in case of severe physical security breaches.

### 2.2 The Organization Admin Portal (Building Management)
*The tenant-level portal for building owners or security managers.*
* **Location Management**: Create and configure physical entry points (e.g., "Main Gate", "Basement Parking").
* **Member Management**: Invite residents/tenants and assign units/apartments. Invite security guards.
* **Device Registration**: Register and pair Android/iOS tablets to specific locations. Revoke lost or stolen tablets.
* **Audit & Reporting**: View complete entry/exit logs for the organization. Configure data retention policies (e.g., auto-delete logs older than 90 days for GDPR compliance).

### 2.3 The Resident Portal / App (Tenants & Employees)
*The end-user application for pass generation and visitor management.*
* **Pre-Approved Pass Generation**: Create passes for expected visitors (Name, Phone, Date Range).
* **Pass Sharing**: Export and share secure, dynamic QR code passes directly via WhatsApp, SMS, or as branded PDF cards.
* **Real-Time Notifications**: Receive push notifications or SMS alerts when a guest arrives at the gate.
* **Ad-Hoc Approvals**: Receive actionable requests from the gate for unexpected visitors. One-tap "Approve" or "Deny".
* **Visitor History**: View a personal log of past visitors and active passes.

### 2.4 The Guard Kiosk App (Security Operations)
*The hardware-bound tablet application running at physical locations.*
* **Offline QR Verification**: Scan visitor QRs and instantly validate signatures and time-bounds without internet latency.
* **Check-In/Out Logging**: Record entry and exit events with timestamps.
* **Ad-Hoc Check-In**: Manually enter details for unexpected visitors and trigger approval requests to residents.
* **Denial Logging**: Log denied entries with specific reason codes (e.g., "Expired Pass", "Resident Denied").

---

## 3. Data & Security Specification

### 3.1 Multi-Tenant Database Isolation
* Every tenant-owned operational table (organizations, org_memberships,
  locations, devices, visitor_passes, entry_logs, org_keys,
  ad_hoc_approvals, sync.device_checkpoints) carries an `org_id` foreign
  key (or, for `organizations` itself, is keyed on its own `id`).
  `app.users` is the one exception: it is a global identity table by
  design (a single user can hold memberships in more than one org via
  `app.org_memberships`, which is what actually carries `org_id`).
* Isolation is enforced in two independent layers:
  1. **Application layer**: every repository method takes an explicit
     `org_id` (or an `OrgContext`/`PlatformContext` that carries one) and
     hand-adds `WHERE org_id = $N` -- enforced at the Rust type level (no
     repository method accepts a bare id without a caller-scoped context).
  2. **Postgres row-level security** (`ENABLE`/`FORCE ROW LEVEL SECURITY`
     + policies keyed on a per-transaction `app.current_org_id` GUC,
     `SET`/cleared via `SELECT set_config(..., true)` inside each request's
     transaction): a genuine second, independent layer -- a query that
     forgot its `WHERE org_id` clause is still restricted to the caller's
     org by Postgres itself, not just by convention. This requires the
     app's runtime database connection to use a non-superuser,
     non-BYPASSRLS role (`visitorpass_app`): Postgres superusers bypass
     RLS unconditionally, with no override, so the migration/schema-owner
     role (`visitorpass`) cannot be the one serving requests.
  A narrow, explicitly-audited set of code paths -- platform-admin
  cross-tenant queries, and pre-authentication lookups that DISCOVER an
  org_id (device pairing, the public pass-sharing page, slug-based org
  login) rather than already knowing it -- opt out of layer 2 via a
  separate `app.rls_bypass` GUC; layer 1's explicit scoping still applies
  wherever one of those paths has an org_id to scope by.
* PASETO token claim validation (the `org` claim, cross-checked against
  the URL's `org_id` path segment) is what establishes which `org_id` a
  request is authorized for before either layer above ever runs a query.

### 3.2 Cryptographic Signatures
* **Keys**: Every organization is assigned a unique Ed25519 keypair during creation.
* **Passes**: QRs are signed by the backend using the private key.
* **Tablets**: Tablets sync the organization's public key upon pairing. Signatures are verified locally on the tablet.

### 3.3 Identity & Authorization
* **Roles**: The system supports roles: `PlatformAdmin`, `OrgAdmin`, `Resident`, and `Guard`.
* **Tokens**: Short-lived (15-min) PASETO access tokens with strict Role-Based Access Control (RBAC) middleware limits.
* **Refresh**: Long-lived refresh tokens stored securely (HttpOnly cookies for web, secure enclaves for mobile) to maintain sessions without repetitive logins.

---

## 4. Key Workflows

### 4.1 The Pre-Approved Workflow
1. Resident generates pass -> Backend signs pass -> Resident shares pass.
2. Visitor arrives at gate -> Guard scans pass -> Tablet verifies offline.
3. Tablet logs entry -> Background syncs log to backend.

### 4.2 The Ad-Hoc Workflow (Unexpected Visitor)
1. Visitor arrives -> Guard inputs name/unit -> Tablet triggers "Ad-Hoc Request" over WebSocket.
2. Resident receives push notification -> Clicks "Approve".
3. Backend updates DB -> WebSocket pushes approval to Tablet -> Guard grants entry.

---

## 5. Compliance & Extensibility
* **PII Encryption**: Visitor phone numbers are encrypted at rest using AES-GCM (on both the backend and local SQLite databases).
* **Data Retention Engine**: Scheduled cron jobs permanently purge entry logs and expired passes beyond the configured organizational retention window.
* **Webhooks (Future)**: Support for triggering external webhooks (e.g., syncing visitor data to a corporate Active Directory or HR system) upon successful check-in.
