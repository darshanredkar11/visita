use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use visitorpass_domain::{
    entities::{User, UserStatus},
    value_objects::Role,
    DomainError,
};
use visitorpass_application::ports::repositories::{CreateUserInput, UserRepository};

pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn create(&self, input: CreateUserInput) -> Result<User, DomainError> {
        let user_id = Uuid::now_v7();
        sqlx::query(
            r#"
            INSERT INTO app.users (id, email, phone_hmac, password_hash, full_name, status, email_verified_at, last_login_at, failed_login_attempts, locked_until, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, 'ACTIVE'::app.user_status, NULL, NULL, 0, NULL, NOW(), NOW())
            "#,
        )
        .bind(user_id)
        .bind(&input.email)
        .bind(&input.phone_hmac)
        .bind(&input.password_hash)
        .bind(&input.full_name)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let Some(db_err) = e.as_database_error() {
                if db_err.is_unique_violation() {
                    return DomainError::EmailAlreadyExists;
                }
            }
            DomainError::CryptoError
        })?;

        self.find_by_id(user_id).await
    }

    async fn find_by_id(&self, id: Uuid) -> Result<User, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT id, email, phone_hmac, password_hash, full_name, status::text, email_verified_at, last_login_at, failed_login_attempts, locked_until, created_at, updated_at
            FROM app.users
            WHERE id = $1 AND status != 'DELETED'
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::UserNotFound(id))?;

        let status_str: String = row.get("status");

        Ok(User {
            id: row.get("id"),
            email: row.get("email"),
            phone_hmac: row.get("phone_hmac"),
            password_hash: row.get("password_hash"),
            full_name: row.get("full_name"),
            status: match status_str.as_str() {
                "SUSPENDED" => UserStatus::Suspended,
                _ => UserStatus::Active,
            },
            email_verified_at: row.get("email_verified_at"),
            last_login_at: row.get("last_login_at"),
            failed_login_attempts: row.get("failed_login_attempts"),
            locked_until: row.get("locked_until"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn find_by_email(&self, email: &str) -> Result<User, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT id, email, phone_hmac, password_hash, full_name, status::text, email_verified_at, last_login_at, failed_login_attempts, locked_until, created_at, updated_at
            FROM app.users
            WHERE LOWER(email) = LOWER($1) AND status != 'DELETED'
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::InvalidCredentials)?; // map to general credentials mismatch

        let status_str: String = row.get("status");

        Ok(User {
            id: row.get("id"),
            email: row.get("email"),
            phone_hmac: row.get("phone_hmac"),
            password_hash: row.get("password_hash"),
            full_name: row.get("full_name"),
            status: match status_str.as_str() {
                "SUSPENDED" => UserStatus::Suspended,
                _ => UserStatus::Active,
            },
            email_verified_at: row.get("email_verified_at"),
            last_login_at: row.get("last_login_at"),
            failed_login_attempts: row.get("failed_login_attempts"),
            locked_until: row.get("locked_until"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn record_login_success(&self, user_id: Uuid) -> Result<(), DomainError> {
        sqlx::query(
            r#"
            UPDATE app.users
            SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW(), updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        Ok(())
    }

    async fn record_login_failure(&self, user_id: Uuid) -> Result<(), DomainError> {
        // Increment attempts
        sqlx::query(
            r#"
            UPDATE app.users
            SET failed_login_attempts = failed_login_attempts + 1, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        Ok(())
    }

    async fn set_lock(&self, user_id: Uuid, until: Option<DateTime<Utc>>) -> Result<(), DomainError> {
        sqlx::query(
            r#"
            UPDATE app.users
            SET locked_until = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(until)
        .execute(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        Ok(())
    }

    async fn verify_email(&self, user_id: Uuid) -> Result<(), DomainError> {
        sqlx::query(
            r#"
            UPDATE app.users
            SET email_verified_at = NOW(), updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        Ok(())
    }

    async fn find_membership_role(&self, user_id: Uuid, org_id: Uuid) -> Result<Role, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT role::text
            FROM app.org_memberships
            WHERE user_id = $1 AND org_id = $2 AND status = 'ACTIVE'::app.member_status
            "#,
        )
        .bind(user_id)
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::InsufficientRole {
            required: "Active membership".into(),
            actual:   "None".into(),
        })?;

        let role_str: String = row.get("role");
        Role::try_from(role_str.as_str())
    }

    async fn list_memberships(&self, user_id: Uuid) -> Result<Vec<(Uuid, String, Role, Option<String>)>, DomainError> {
        let rows = sqlx::query(
            r#"
            SELECT m.org_id, o.name as org_name, m.role::text, m.unit_identifier
            FROM app.org_memberships m
            JOIN app.organizations o ON m.org_id = o.id
            WHERE m.user_id = $1 AND m.status = 'ACTIVE'::app.member_status
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to query user memberships");
            DomainError::CryptoError
        })?;

        let mut results = Vec::new();
        for r in rows {
            let org_id: Uuid = r.get("org_id");
            let org_name: String = r.get("org_name");
            let role_str: String = r.get("role");
            let role = Role::try_from(role_str.as_str())?;
            let unit_identifier: Option<String> = r.get("unit_identifier");
            results.push((org_id, org_name, role, unit_identifier));
        }

        Ok(results)
    }
}
