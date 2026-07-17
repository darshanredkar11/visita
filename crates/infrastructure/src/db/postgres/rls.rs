use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;
use visitorpass_domain::DomainError;

/// Begins a transaction and sets the `app.current_org_id` GUC that migration
/// 023's row-level-security policies key on. Every query issued through the
/// returned transaction is restricted by Postgres itself to rows belonging
/// to `org_id`, in addition to whatever `WHERE org_id = $N` the query
/// already has by hand -- this is the whole point: RLS is a second,
/// independent layer, not a replacement for the app-layer scoping.
///
/// `SELECT set_config(name, value, true)` (the `true` = "is_local") is used
/// instead of the `SET LOCAL` statement because `SET` cannot take a bound
/// parameter -- `set_config` is an ordinary function call and can.
/// "is_local = true" scopes the setting to this transaction only; it is
/// automatically cleared on COMMIT or ROLLBACK, so it can never leak onto
/// another request that later reuses this same pooled physical connection.
pub async fn org_scoped_tx(pool: &PgPool, org_id: Uuid) -> Result<Transaction<'static, Postgres>, DomainError> {
    let mut tx = pool.begin().await.map_err(|_| DomainError::CryptoError)?;
    sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;
    Ok(tx)
}

/// Begins a transaction that is exempt from org scoping. Two distinct kinds
/// of caller need this, and both are narrow and intentional -- this is NOT
/// a general escape hatch:
///
///   1. Platform-admin cross-tenant queries (see `PlatformContext`) --
///      legitimately need to see every org.
///   2. A handful of pre-authentication lookups that DISCOVER an org_id
///      from the query itself rather than already knowing it: device
///      pairing (`DeviceRepository::find_by_public_key`), the public share
///      page (`PassRepository::find_by_pass_number_public`), and
///      slug-based org lookup during password login
///      (`OrgRepository::find_by_slug`). There is no `current_org_id` to
///      set until AFTER these queries return.
///
/// Every call site using this MUST have a comment explaining which of the
/// two it is; see the call sites themselves.
pub async fn bypass_scoped_tx(pool: &PgPool) -> Result<Transaction<'static, Postgres>, DomainError> {
    let mut tx = pool.begin().await.map_err(|_| DomainError::CryptoError)?;
    sqlx::query("SELECT set_config('app.rls_bypass', 'true', true)")
        .execute(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;
    Ok(tx)
}
