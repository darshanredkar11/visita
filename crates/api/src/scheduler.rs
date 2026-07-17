//! Background maintenance jobs: pass expiry, session/challenge cleanup,
//! partition creation, and per-org retention enforcement.
//!
//! # Retention design
//!
//! `app.entry_logs` and `audit.audit_events` are partitioned by
//! `created_at`, and partitions are SHARED across every org -- a single
//! partition can hold rows belonging to many orgs with DIFFERENT
//! `retention_days`. That means a partition can only be physically DROPPED
//! once the LONGEST retention window among ALL orgs has passed for that
//! partition's date range; dropping it earlier would delete still-required
//! data belonging to a longer-retention org sharing the same partition.
//!
//! We enforce retention in two tiers (approach "(ii)" from the audit):
//!   1. Row-level `DELETE`, scoped by `(org_id, created_at)`, for any org
//!      whose `retention_days` is SHORTER than the org-wide maximum. This
//!      makes each org's own retention promise take effect immediately and
//!      exactly, at the cost of a per-row delete instead of an O(1)
//!      partition drop.
//!   2. Whole-partition `DROP`, but only once a partition's upper date
//!      bound is older than `NOW() - MAX(retention_days across all orgs)`.
//!      By then every org's window has passed for that partition (any
//!      short-retention org's rows in it were already removed by tier 1),
//!      so the drop is safe for everyone who shares that partition.
//!
//! This never over-retains a short-retention org's data the way approach
//! "(i)" (only ever dropping once the org-wide *maximum* has passed, with
//! no row-level deletes) would; the cost is periodic per-row deletes for
//! orgs with a below-average retention window, which is cheap at V1's scale
//! (a handful of orgs, each with a handful of below-average-retention rows
//! per run).

use chrono::{Datelike, NaiveDate, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Marks overdue `ACTIVE` passes as `EXPIRED`. Returns rows affected.
/// Intended cadence: every 15 minutes.
///
/// RLS bypass: this is a background job touching every org, not a
/// per-request user action -- see rls.rs's `bypass_scoped_tx` doc comment.
/// Inlined (not calling that helper) because these functions use
/// `sqlx::Error`, not `DomainError`.
pub async fn expire_passes(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('app.rls_bypass', 'true', true)").execute(&mut *tx).await?;
    let count: i32 = sqlx::query_scalar("SELECT app.expire_passes()")
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(count as i64)
}

/// Purges expired sessions and device challenges.
/// Returns `(sessions_removed, challenges_removed)`. Intended cadence: daily.
pub async fn cleanup_sessions_and_challenges(pool: &PgPool) -> Result<(i64, i64), sqlx::Error> {
    let sessions: i32 = sqlx::query_scalar("SELECT app.cleanup_expired_sessions()")
        .fetch_one(pool)
        .await?;
    let challenges: i32 = sqlx::query_scalar("SELECT app.cleanup_expired_challenges()")
        .fetch_one(pool)
        .await?;
    Ok((sessions as i64, challenges as i64))
}

fn add_months(d: NaiveDate, months: i64) -> NaiveDate {
    let total = d.year() as i64 * 12 + (d.month() as i64 - 1) + months;
    let year = total.div_euclid(12) as i32;
    let month = (total.rem_euclid(12) + 1) as u32;
    NaiveDate::from_ymd_opt(year, month, 1).expect("computed year/month must be valid")
}

fn quarter_start(d: NaiveDate) -> NaiveDate {
    let q_month = ((d.month() - 1) / 3) * 3 + 1;
    NaiveDate::from_ymd_opt(d.year(), q_month, 1).expect("computed quarter start must be valid")
}

async fn table_exists(pool: &PgPool, schema: &str, name: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2)",
    )
    .bind(schema)
    .bind(name)
    .fetch_one(pool)
    .await
}

/// Ensures monthly `app.entry_logs_YYYY_MM` partitions exist for at least
/// `months_ahead` months beyond the current month. Returns the names of any
/// partitions actually created (idempotent: existing ones are left alone).
pub async fn ensure_entry_logs_partitions(
    pool: &PgPool,
    months_ahead: i64,
) -> Result<Vec<String>, sqlx::Error> {
    let today = Utc::now().date_naive();
    let mut created = Vec::new();

    for i in 0..=months_ahead {
        let from = add_months(NaiveDate::from_ymd_opt(today.year(), today.month(), 1).unwrap(), i);
        let to = add_months(from, 1);
        let name = format!("entry_logs_{:04}_{:02}", from.year(), from.month());

        if !table_exists(pool, "app", &name).await? {
            let sql = format!(
                "CREATE TABLE app.{name} PARTITION OF app.entry_logs FOR VALUES FROM ('{from}') TO ('{to}')",
            );
            sqlx::query(&sql).execute(pool).await?;
            created.push(name);
        }
    }

    Ok(created)
}

/// Ensures quarterly `audit.audit_events_YYYY_qN` partitions exist for at
/// least `months_ahead` months beyond the current quarter.
pub async fn ensure_audit_events_partitions(
    pool: &PgPool,
    months_ahead: i64,
) -> Result<Vec<String>, sqlx::Error> {
    let today = Utc::now().date_naive();
    let start_quarter = quarter_start(today);
    let quarters_ahead = months_ahead / 3 + 1;
    let mut created = Vec::new();

    for i in 0..=quarters_ahead {
        let from = add_months(start_quarter, i * 3);
        let to = add_months(from, 3);
        let q = (from.month() - 1) / 3 + 1;
        let name = format!("audit_events_{:04}_q{}", from.year(), q);

        if !table_exists(pool, "audit", &name).await? {
            let sql = format!(
                "CREATE TABLE audit.{name} PARTITION OF audit.audit_events FOR VALUES FROM ('{from}') TO ('{to}')",
            );
            sqlx::query(&sql).execute(pool).await?;
            created.push(name);
        }
    }

    Ok(created)
}

/// Result summary of one retention-enforcement pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetentionReport {
    /// Rows removed by the tier-1 per-org row-level delete.
    pub rows_deleted: i64,
    /// Whole partitions removed by the tier-2 partition drop.
    pub partitions_dropped: i64,
}

/// Extracts the exclusive upper-bound date of a partition from its
/// deterministic name (`entry_logs_YYYY_MM` or `audit_events_YYYY_qN`).
/// Returns `None` for anything that doesn't match (e.g. the parent table).
fn partition_upper_bound(name: &str, prefix: &str, quarterly: bool) -> Option<NaiveDate> {
    let suffix = name.strip_prefix(prefix)?;
    if quarterly {
        // "2026_q4"
        let (year_str, q_str) = suffix.split_once("_q")?;
        let year: i32 = year_str.parse().ok()?;
        let quarter: u32 = q_str.parse().ok()?;
        if !(1..=4).contains(&quarter) {
            return None;
        }
        let start = NaiveDate::from_ymd_opt(year, (quarter - 1) * 3 + 1, 1)?;
        Some(add_months(start, 3))
    } else {
        // "2026_07"
        let (year_str, month_str) = suffix.split_once('_')?;
        let year: i32 = year_str.parse().ok()?;
        let month: u32 = month_str.parse().ok()?;
        let start = NaiveDate::from_ymd_opt(year, month, 1)?;
        Some(add_months(start, 1))
    }
}

/// Enforces per-org `retention_days`. See module docs for the two-tier design.
/// RLS bypass: see `expire_passes`' doc comment above.
pub async fn enforce_retention(pool: &PgPool) -> Result<RetentionReport, sqlx::Error> {
    let mut report = RetentionReport::default();
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('app.rls_bypass', 'true', true)").execute(&mut *tx).await?;

    let max_retention: i32 =
        sqlx::query_scalar("SELECT COALESCE(MAX(retention_days), 90) FROM app.organizations")
            .fetch_one(&mut *tx)
            .await?;

    // Tier 1: row-level delete for orgs whose window is shorter than the
    // org-wide maximum (see module docs).
    let short_orgs: Vec<(Uuid, i32)> = sqlx::query_as(
        "SELECT id, retention_days FROM app.organizations WHERE retention_days < $1",
    )
    .bind(max_retention)
    .fetch_all(&mut *tx)
    .await?;

    for (org_id, retention_days) in short_orgs {
        let r1 = sqlx::query(
            "DELETE FROM app.entry_logs WHERE org_id = $1 AND created_at < NOW() - make_interval(days => $2)",
        )
        .bind(org_id)
        .bind(retention_days)
        .execute(&mut *tx)
        .await?;

        let r2 = sqlx::query(
            "DELETE FROM audit.audit_events WHERE org_id = $1 AND created_at < NOW() - make_interval(days => $2)",
        )
        .bind(org_id)
        .bind(retention_days)
        .execute(&mut *tx)
        .await?;

        report.rows_deleted += r1.rows_affected() as i64 + r2.rows_affected() as i64;
    }

    // Tier 2: drop whole partitions once older than the org-wide MAXIMUM
    // retention window. Safe because every org's window has passed by then,
    // and shorter-retention orgs' rows were already removed in tier 1.
    let cutoff = Utc::now().date_naive() - chrono::Duration::days(max_retention as i64);

    let entry_log_partitions: Vec<String> = sqlx::query_scalar(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'app' AND table_name ~ '^entry_logs_[0-9]{4}_[0-9]{2}$'",
    )
    .fetch_all(&mut *tx)
    .await?;
    for name in entry_log_partitions {
        if let Some(upper) = partition_upper_bound(&name, "entry_logs_", false) {
            if upper <= cutoff {
                sqlx::query("SELECT app.cleanup_entry_logs_partition($1)")
                    .bind(&name)
                    .execute(&mut *tx)
                    .await?;
                report.partitions_dropped += 1;
            }
        }
    }

    let audit_partitions: Vec<String> = sqlx::query_scalar(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'audit' AND table_name ~ '^audit_events_[0-9]{4}_q[1-4]$'",
    )
    .fetch_all(&mut *tx)
    .await?;
    for name in audit_partitions {
        if let Some(upper) = partition_upper_bound(&name, "audit_events_", true) {
            if upper <= cutoff {
                let sql = format!("DROP TABLE IF EXISTS audit.{name}");
                sqlx::query(&sql).execute(&mut *tx).await?;
                report.partitions_dropped += 1;
            }
        }
    }

    tx.commit().await?;
    Ok(report)
}

/// Spawns the background maintenance loop. Fire-and-forget: logs errors but
/// never panics the process, since a maintenance-job failure should never
/// take down request serving.
///
/// `pool` is the runtime (least-privilege, RLS-enforced) connection --
/// sufficient for everything except partition creation, which is DDL
/// (`CREATE TABLE ... PARTITION OF`) and needs `privileged_pool` (the
/// migration/owner role, which unlike `pool` has DDL rights; see
/// AppConfig::migration_database_url and main.rs).
pub fn spawn_background_jobs(pool: PgPool, privileged_pool: PgPool) {
    // Pass expiry: every 15 minutes, matching app.expire_passes()'s doc comment.
    let expiry_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15 * 60));
        loop {
            interval.tick().await;
            match expire_passes(&expiry_pool).await {
                Ok(n) if n > 0 => tracing::info!(expired = n, "pass expiry job ran"),
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "pass expiry job failed"),
            }
        }
    });

    // Session/challenge cleanup + partition maintenance + retention: daily.
    // months_ahead=3 (~90 days) comfortably covers the "at least 60 days
    // into the future" requirement with margin, given the daily cadence.
    const PARTITION_LOOKAHEAD_MONTHS: i64 = 3;
    let daily_pool = pool;
    let daily_privileged_pool = privileged_pool;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 60 * 60));
        loop {
            interval.tick().await;

            match cleanup_sessions_and_challenges(&daily_pool).await {
                Ok((s, c)) => tracing::info!(sessions = s, challenges = c, "session/challenge cleanup ran"),
                Err(e) => tracing::error!(error = %e, "session/challenge cleanup failed"),
            }

            match ensure_entry_logs_partitions(&daily_privileged_pool, PARTITION_LOOKAHEAD_MONTHS).await {
                Ok(created) if !created.is_empty() => {
                    tracing::info!(partitions = ?created, "created entry_logs partitions")
                }
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "entry_logs partition maintenance failed"),
            }

            match ensure_audit_events_partitions(&daily_privileged_pool, PARTITION_LOOKAHEAD_MONTHS).await {
                Ok(created) if !created.is_empty() => {
                    tracing::info!(partitions = ?created, "created audit_events partitions")
                }
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "audit_events partition maintenance failed"),
            }

            match enforce_retention(&daily_pool).await {
                Ok(report) if report.rows_deleted > 0 || report.partitions_dropped > 0 => {
                    tracing::info!(?report, "retention enforcement ran")
                }
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "retention enforcement failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    async fn test_pool() -> Option<PgPool> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://visitorpass:CHANGEME@localhost:5432/visitorpass".to_string());
        PgPool::connect(&database_url).await.ok()
    }

    #[tokio::test]
    async fn test_expire_passes_flips_active_to_expired() {
        let pool = match test_pool().await {
            Some(p) => p,
            None => return,
        };

        let org_id = Uuid::now_v7();
        let location_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let pass_id = Uuid::now_v7();

        sqlx::query("INSERT INTO app.organizations (id, name, org_type, slug) VALUES ($1, 'Scheduler Test Org', 'OFFICE', $2)")
            .bind(org_id).bind(format!("sched-test-{}", Uuid::new_v4())).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO app.locations (id, org_id, name, status) VALUES ($1, $2, 'Loc', 'ACTIVE')")
            .bind(location_id).bind(org_id).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO app.users (id, email, password_hash, full_name) VALUES ($1, $2, 'x', 'User')")
            .bind(user_id).bind(format!("sched-{}@test.local", Uuid::new_v4())).execute(&pool).await.unwrap();

        // ACTIVE pass whose valid_until is already in the past -- exactly the
        // condition expire_passes() must flip to EXPIRED.
        sqlx::query(
            "INSERT INTO app.visitor_passes (id, org_id, location_id, created_by, pass_number, visitor_name, visitor_phone_hmac, purpose, valid_from, valid_until, qr_payload, qr_nonce, key_version, status)
             VALUES ($1, $2, $3, $4, $5, 'Guest', 'hmac', 'test', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', 'vp1.x', $6, 1, 'ACTIVE')"
        )
            .bind(pass_id).bind(org_id).bind(location_id).bind(user_id)
            .bind(format!("VP-{}", &Uuid::new_v4().simple().to_string()[..8].to_uppercase()))
            .bind(vec![0u8; 12])
            .execute(&pool).await.unwrap();

        let expired = expire_passes(&pool).await.unwrap();
        assert!(expired >= 1, "expire_passes should report at least the one overdue pass it just flipped");

        let status: String = sqlx::query_scalar("SELECT status::text FROM app.visitor_passes WHERE id = $1")
            .bind(pass_id).fetch_one(&pool).await.unwrap();
        assert_eq!(status, "EXPIRED");

        sqlx::query("DELETE FROM app.visitor_passes WHERE id = $1").bind(pass_id).execute(&pool).await.ok();
        sqlx::query("DELETE FROM app.users WHERE id = $1").bind(user_id).execute(&pool).await.ok();
        sqlx::query("DELETE FROM app.locations WHERE id = $1").bind(location_id).execute(&pool).await.ok();
        sqlx::query("DELETE FROM app.organizations WHERE id = $1").bind(org_id).execute(&pool).await.ok();
    }

    #[tokio::test]
    async fn test_ensure_entry_logs_partitions_creates_missing() {
        let pool = match test_pool().await {
            Some(p) => p,
            None => return,
        };

        // Migrations only bootstrap through 2026-12; 8 months ahead reaches
        // into 2027 regardless of what "today" is when this test runs, so
        // this reliably exercises real partition CREATION, not a no-op.
        ensure_entry_logs_partitions(&pool, 8).await.unwrap();

        let today = Utc::now().date_naive();
        let far_future = add_months(NaiveDate::from_ymd_opt(today.year(), today.month(), 1).unwrap(), 8);
        let name = format!("entry_logs_{:04}_{:02}", far_future.year(), far_future.month());
        let exists = table_exists(&pool, "app", &name).await.unwrap();
        assert!(exists, "partition {name} should exist after ensure_entry_logs_partitions");

        // Idempotent: calling again creates nothing new for that same month.
        let created_again = ensure_entry_logs_partitions(&pool, 8).await.unwrap();
        assert!(!created_again.contains(&name), "re-running must not recreate an existing partition");
    }

    #[tokio::test]
    async fn test_ensure_audit_events_partitions_creates_missing() {
        let pool = match test_pool().await {
            Some(p) => p,
            None => return,
        };

        ensure_audit_events_partitions(&pool, 8).await.unwrap();

        let today = Utc::now().date_naive();
        let far_future = add_months(quarter_start(today), 9);
        let q = (far_future.month() - 1) / 3 + 1;
        let name = format!("audit_events_{:04}_q{}", far_future.year(), q);
        let exists = table_exists(&pool, "audit", &name).await.unwrap();
        assert!(exists, "partition {name} should exist after ensure_audit_events_partitions");
    }

    #[tokio::test]
    async fn test_enforce_retention_purges_short_org_not_long_org() {
        let pool = match test_pool().await {
            Some(p) => p,
            None => return,
        };

        // retention_days=1 must be far below the org-wide max computed at
        // enforcement time; retention_days=999 must be at/above it (it will
        // typically BECOME the max) -- see module docs for why the deletion
        // decision is relative to that max.
        let org_short = Uuid::now_v7();
        let org_long = Uuid::now_v7();
        let location_short = Uuid::now_v7();
        let location_long = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let pass_short = Uuid::now_v7();
        let pass_long = Uuid::now_v7();

        for (org_id, retention) in [(org_short, 1i32), (org_long, 999i32)] {
            sqlx::query("INSERT INTO app.organizations (id, name, org_type, slug, retention_days) VALUES ($1, 'Retention Test', 'OFFICE', $2, $3)")
                .bind(org_id).bind(format!("ret-test-{}", Uuid::new_v4())).bind(retention)
                .execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO app.locations (id, org_id, name, status) VALUES ($1, $2, 'Loc', 'ACTIVE')")
            .bind(location_short).bind(org_short).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO app.locations (id, org_id, name, status) VALUES ($1, $2, 'Loc', 'ACTIVE')")
            .bind(location_long).bind(org_long).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO app.users (id, email, password_hash, full_name) VALUES ($1, $2, 'x', 'User')")
            .bind(user_id).bind(format!("ret-{}@test.local", Uuid::new_v4())).execute(&pool).await.unwrap();

        for (pid, org_id, loc_id) in [(pass_short, org_short, location_short), (pass_long, org_long, location_long)] {
            sqlx::query(
                "INSERT INTO app.visitor_passes (id, org_id, location_id, created_by, pass_number, visitor_name, visitor_phone_hmac, purpose, valid_from, valid_until, qr_payload, qr_nonce, key_version)
                 VALUES ($1, $2, $3, $4, $5, 'Guest', 'hmac', 'test', NOW(), NOW() + interval '1 hour', 'vp1.x', $6, 1)"
            )
                .bind(pid).bind(org_id).bind(loc_id).bind(user_id)
                .bind(format!("VP-{}", &Uuid::new_v4().simple().to_string()[..8].to_uppercase()))
                .bind(vec![0u8; 12])
                .execute(&pool).await.unwrap();
        }

        // Both orgs get an entry_log row dated ~6 months (well within an
        // already-bootstrapped partition) in the past: older than the
        // short-retention org's 1-day window, nowhere near the long-retention
        // org's 999-day window.
        let old_ts = chrono::Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
        let entry_short = Uuid::now_v7();
        let entry_long = Uuid::now_v7();
        for (eid, org_id, loc_id, pid) in [
            (entry_short, org_short, location_short, pass_short),
            (entry_long, org_long, location_long, pass_long),
        ] {
            sqlx::query(
                "INSERT INTO app.entry_logs (id, org_id, location_id, pass_id, action, occurred_at, client_event_id, created_at)
                 VALUES ($1, $2, $3, $4, 'ENTRY', $5, $6, $5)"
            )
                .bind(eid).bind(org_id).bind(loc_id).bind(pid)
                .bind(old_ts).bind(Uuid::now_v7())
                .execute(&pool).await.unwrap();
        }

        let report = enforce_retention(&pool).await.unwrap();
        assert!(report.rows_deleted >= 1, "at least the short-retention org's row should have been purged");

        let short_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app.entry_logs WHERE id = $1")
            .bind(entry_short).fetch_one(&pool).await.unwrap();
        assert_eq!(short_count, 0, "short-retention org's old row must be purged");

        let long_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app.entry_logs WHERE id = $1")
            .bind(entry_long).fetch_one(&pool).await.unwrap();
        assert_eq!(long_count, 1, "long-retention org's old row must be retained");

        sqlx::query("DELETE FROM app.entry_logs WHERE id = $1").bind(entry_long).execute(&pool).await.ok();
        sqlx::query("DELETE FROM app.visitor_passes WHERE id = $1").bind(pass_short).execute(&pool).await.ok();
        sqlx::query("DELETE FROM app.visitor_passes WHERE id = $1").bind(pass_long).execute(&pool).await.ok();
        sqlx::query("DELETE FROM app.users WHERE id = $1").bind(user_id).execute(&pool).await.ok();
        sqlx::query("DELETE FROM app.locations WHERE id = $1").bind(location_short).execute(&pool).await.ok();
        sqlx::query("DELETE FROM app.locations WHERE id = $1").bind(location_long).execute(&pool).await.ok();
        sqlx::query("DELETE FROM app.organizations WHERE id = $1").bind(org_short).execute(&pool).await.ok();
        sqlx::query("DELETE FROM app.organizations WHERE id = $1").bind(org_long).execute(&pool).await.ok();
    }
}
