# Visita — Product Feature Phases

**Status:** Working roadmap  
**Planning baseline:** 9 October 2026  
**Development start:** 10 October 2026  
**Product:** Simple, offline-first visitor management for organizations of different types

## 1. Product vision

Visita helps an organization manage visitor entry and exit with minimal friction. Organizations such as housing societies, offices, hospitals, clinics, factories, warehouses, schools, colleges, coworking spaces and other premises can register themselves, establish their authority to manage a site, create visitor passes, and verify those passes at the gate—even when connectivity is unavailable.

Visita is **one product for many types of premises**, not a collection of industry-specific products.

### Product principles

1. **Simple first:** make the common visitor lifecycle easy to understand and operate.
2. **Offline-first:** pass verification must not require a live server request at the gate.
3. **Cryptographically verifiable:** signed passes must be validated locally using trusted public keys.
4. **Privacy by default:** collect only what is needed, restrict access, and enforce retention/deletion rules.
5. **Trustworthy onboarding:** make signup easy, but establish who controls the organization and premises before granting higher-trust capabilities.
6. **Small operational footprint:** keep deployment, upgrades, backups and recovery straightforward.
7. **One core workflow:** do not introduce separate clinic, factory, school or housing-society feature branches without evidence that the core model cannot support a real requirement.

## 2. Explicit non-goals

Do not build these as part of the core product:

- Patient management, medical records, billing or clinical workflows.
- Factory HR, contractor payroll, worker safety management or inventory/material movement.
- Appointment scheduling suites, queue management or general-purpose CRM/ERP.
- AI features without a clear, validated visitor-management use case.
- Unnecessary analytics, complex workflow builders, or industry-specific dashboards.
- Mandatory visitor identity-document scans, biometrics or phone numbers by default.
- Automated organization verification integrations before a reliable and lawful provider is identified.

These can be reconsidered only when real users demonstrate a clear need. They must not delay the core product.

## 3. Phase roadmap

Phases are ordered by dependency and risk, not by calendar promises. Start with Phase 0 on 10 October 2026. Before implementing a feature, inspect the current repository and tests; reuse sound existing code and fix gaps instead of rewriting working components.

### Phase 0 — Baseline audit and release criteria

**Goal:** establish what already works and what is unsafe or incomplete before adding features.

Scope:
- Map the existing API, web app, mobile app, database migrations, crypto implementation, offline storage and sync paths.
- Run available unit, integration, end-to-end, formatting, lint and build checks; record commands and actual outcomes.
- Trace the complete happy path: register organization → create location → register guard device → create pass → scan offline → record entry/exit → sync events.
- Audit tenant isolation, authorization, secret handling, key lifecycle, idempotency, replay handling, device revocation and error handling.
- Identify mismatches between README/specification and actual implementation.
- Create a short, prioritized issue list with reproducible evidence.

**Exit criteria:**
- A trustworthy baseline report exists.
- Critical defects are prioritized before feature work.
- Every later phase has testable acceptance criteria.
- No claim is made that a capability works until its implementation and tests are verified.

### Phase 1 — Reliable visitor lifecycle and offline gate

**Goal:** make the single core workflow reliable.

Scope:
- Create, view, list and revoke visitor passes.
- Keep pass fields minimal: visitor name, purpose, destination/location, validity window and only genuinely necessary optional details.
- Sign QR payloads and verify signatures locally on a registered guard device.
- Validate expiry, status, permitted action and use limits where configured.
- Record entry, exit and denied attempts with timestamps and reason codes.
- Store events safely on the device while offline and synchronize them when connectivity returns.
- Make sync idempotent so retries do not create duplicate events.
- Handle duplicate/replayed scans explicitly; document what can and cannot be guaranteed offline.
- Show understandable results to guards: valid, expired, revoked-known-to-device, invalid signature, already used or needs online confirmation.

**Important offline limitation:** a disconnected device cannot learn about a revocation or policy change that occurred after its last successful sync. The product must make the last-sync/revocation freshness visible and define a configurable, explicit policy for stale devices rather than implying that offline revocation is instantaneous.

**Exit criteria:**
- The end-to-end visitor lifecycle passes automated tests.
- Verification works without a network connection using previously synchronized trust material.
- Offline events survive app restart and sync safely after reconnecting.
- Expiry, invalid signatures, duplicate events and stale-device cases are tested.
- No cross-organization pass, event or key access is possible.

### Phase 2 — Self-service organization onboarding and premises verification

**Goal:** let different types of organizations sign up without making onboarding burdensome.

Scope:
- Create an organization owner account with verified email and secure authentication.
- Collect organization name, organization type, country, address, postal code and time zone.
- Support multiple sites/locations without creating industry-specific product variants.
- Capture the registering person's name, role/designation and declaration that they are authorized to register the organization.
- Add an onboarding/verification state separate from the organization's operational status. Suggested verification states: PENDING, IN_REVIEW, VERIFIED, REJECTED, with a reason and audit trail for review decisions.
- Allow suitable proof to be submitted based on organization type and jurisdiction. Examples may include a society registration/management document, applicable hospital/clinic establishment licence, or business/establishment/premises evidence for an office, factory or warehouse.
- Store proof privately with access restrictions, encryption, access logging and a defined deletion schedule.
- Provide a simple manual review path before investing in automated verification.
- Make onboarding progress and any missing information clear to the owner.
- Avoid asking for all possible documents from every organization; request only evidence appropriate to the entity, jurisdiction and level of trust required.

**Access policy:** account creation and guided setup may be available while verification is pending. Production pass issuance, broad invitations or other higher-trust actions may be limited until verification, according to a documented policy. Verification status must not be confused with the cryptographic validity of an already signed pass.

**Exit criteria:**
- A new organization can sign up and understand the next steps without support.
- Required fields and evidence rules are validated on the server.
- Proof files cannot be accessed through public URLs or by another tenant.
- Review, rejection, resubmission and approval are auditable.
- Existing organization registration and login flows remain covered by regression tests.

### Phase 3 — Privacy and DPDP-by-default foundation

**Goal:** make privacy part of the product's normal operation, not an optional add-on.

Scope:
- Document Visita's data inventory, purposes, roles, recipients, retention and deletion behavior.
- Show a clear, versioned privacy notice at the appropriate point in the flow; record the relevant notice version and acknowledgement where appropriate.
- Separate necessary service processing from consent-based optional processing. Do not treat a blanket checkbox as a substitute for a valid legal basis or required notice.
- Minimize visitor fields; keep phone number and identity-document collection optional unless a documented use case and applicable requirement justify them.
- Apply role- and tenant-scoped access to visitor data, organization proof and entry logs.
- Set conservative defaults for visitor-pass and entry-log retention, make permitted configuration explicit, and enforce automatic deletion.
- Define separate retention rules for visitor records, security/audit events, account data and organization verification documents.
- Provide an operational process for applicable data-subject requests, grievance handling, correction and deletion.
- Maintain security-event audit trails without unnecessarily copying sensitive visitor data into logs.
- Encrypt sensitive data at rest and in transit, protect encryption/signing keys, and restrict access to backups.
- Protect offline databases, minimize the amount of personal data retained on guard devices, and document lost-device handling.
- Prepare a practical incident and personal-data-breach response process.

**Compliance note:** product defaults should support compliance with India's Digital Personal Data Protection Act and applicable rules, including their effective dates and scope. Do not advertise Visita as automatically guaranteeing legal compliance. Confirm the current legal requirements with qualified counsel before launch and when requirements change.

**Exit criteria:**
- Each collected field has a documented purpose and retention rule.
- Deletion jobs are tested and failures are observable.
- A person can find the privacy notice and the relevant request/grievance route.
- Tenant isolation and role restrictions are covered by tests.
- Offline storage, backups, evidence files and logs are included in the privacy/security review.

### Phase 4 — Device trust, recovery and operational reliability

**Goal:** make the system dependable for real premises.

Scope:
- Register and pair guard devices securely to an organization and location.
- Support device revocation and a clear lost/stolen-device procedure.
- Define public-key distribution, key versioning, rotation and recovery behavior.
- Display device last-sync time and synchronization health.
- Handle clock skew, network interruption, repeated sync, partial sync and server restarts safely.
- Document database backup/restore, master-key backup/recovery, migrations and upgrades.
- Add health checks, useful operational logs, basic metrics and actionable error messages.
- Confirm that deployment follows least privilege and that production secrets are not committed to the repository.

**Exit criteria:**
- A revoked device is rejected when it next reaches a trusted online control point; limitations while fully offline are documented.
- Key rotation and recovery are tested with old and new passes/devices.
- Backup restoration is demonstrated in a clean environment.
- A small operator can deploy and upgrade Visita using documented steps.

### Phase 5 — Simple day-to-day administration

**Goal:** give an organization just enough visibility to operate visitor management.

Scope:
- Manage locations and gate devices.
- Invite and remove administrators/guards with clear roles.
- Search/filter visitor passes and entry/exit history within the user's authorized scope.
- Provide a basic export for authorized users, with privacy and retention controls applied.
- Show simple daily entry/exit counts and, only if reliable, current occupancy.
- Provide useful empty states, validation messages and a short setup guide.

**Exit criteria:**
- Common tasks can be completed without developer assistance.
- Exports do not bypass authorization or retention rules.
- Basic counts reconcile with recorded events and clearly communicate offline-sync freshness.

### Phase 6 — Pilot, hardening and public launch

**Goal:** release a small, trustworthy product rather than a feature-heavy product.

Scope:
- Pilot with a small mix of premises types using the same core workflow.
- Test poor connectivity, long offline periods, device loss, duplicate scans, revoked passes, key rotation, backups and restore.
- Review accessibility, mobile usability, onboarding completion and guard speed.
- Publish clear installation, configuration, privacy, security-contact, backup and upgrade documentation.
- Establish a supported deployment path and a process for security reports.
- Fix launch-blocking defects before adding convenience features.

**Exit criteria:**
- Pilot users can onboard and operate the product with minimal assistance.
- No known unresolved critical security or data-isolation defects remain.
- Core flows, recovery procedures and privacy controls have repeatable tests.
- Release notes and known limitations are documented.

## 4. Cross-phase non-negotiable acceptance criteria

Every phase must preserve these invariants:

- **Tenant isolation:** users and devices can access only authorized organizations, sites and records.
- **Authorization:** the server validates permissions; hiding a UI action is not security.
- **Offline honesty:** the UI must communicate stale synchronization and the limits of offline revocation.
- **Data minimization:** no field or data collection is added without a stated purpose.
- **Retention enforcement:** policy must be implemented and tested, not merely displayed in settings.
- **Cryptographic correctness:** verify signatures and trust/key versions; never trust QR contents merely because they decode.
- **Idempotent sync:** retries must not silently duplicate events or corrupt state.
- **Auditability:** security-sensitive changes, organization verification decisions and device/key actions are attributable.
- **Operational recovery:** backup and restore must include the secrets/keys required to recover safely.
- **Regression safety:** each change includes appropriate tests and does not break an existing flow.

## 5. Definition of done for each development task

A task is done only when:
1. The behavior and acceptance criteria are clear.
2. The smallest useful implementation is delivered.
3. Server-side validation and authorization are in place where relevant.
4. Tests cover normal, failure, boundary and authorization cases appropriate to the change.
5. Privacy, retention, offline behavior and tenant isolation have been considered.
6. Documentation and configuration examples are updated where needed.
7. Available checks have been run and their actual results recorded.
8. No unrelated feature expansion is bundled into the change.

## 6. Starting checklist for 10 October 2026

- [ ] Review the repository's current state and identify the real working baseline.
- [ ] Run existing checks and record failures without hiding pre-existing issues.
- [ ] Trace one complete visitor lifecycle through API, web/mobile, database and offline sync.
- [ ] Write the top critical/high-risk gaps with file paths and reproduction steps.
- [ ] Select the first small implementation task from Phase 1 or the highest-risk prerequisite.
- [ ] Keep onboarding and privacy requirements visible while implementing the core workflow.
- [ ] Do not start optional integrations or industry-specific features.

## 7. Change-control rule

This document is the working product boundary. A proposed feature should be accepted only if it:
- supports the core visitor lifecycle, organization onboarding, privacy/security, or reliable operation;
- is required to meet a demonstrated user need or legal obligation; and
- can be delivered without making the core product unnecessarily complex.

If it does not meet those tests, defer it. Revisit phase order as repository audits and pilot evidence reveal facts, but do not expand scope simply because a feature is technically possible.
