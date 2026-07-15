use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;
use visitorpass_domain::{
    entities::{OrgKey, OrgStatus, OrgType, Organization},
    value_objects::OrgContext,
    DomainError,
};
use visitorpass_application::ports::repositories::OrgRepository;

pub struct PgOrgRepository {
    pool: PgPool,
}

impl PgOrgRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OrgRepository for PgOrgRepository {
    async fn create(&self, org: &Organization, initial_key: &OrgKey, owner_id: Uuid) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(|_| DomainError::CryptoError)?;

        sqlx::query(
            r#"
            INSERT INTO app.organizations (id, name, org_type, slug, status, retention_days, current_key_version, sync_seq, timezone, created_at, updated_at)
            VALUES ($1, $2, $3::app.org_type, $4, $5::app.org_status, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(org.id)
        .bind(&org.name)
        .bind(org.org_type.as_str())
        .bind(&org.slug)
        .bind("ACTIVE") // Default org status is ACTIVE
        .bind(org.retention_days)
        .bind(org.current_key_version)
        .bind(org.sync_seq)
        .bind(&org.timezone)
        .bind(org.created_at)
        .bind(org.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if let Some(db_err) = e.as_database_error() {
                if db_err.is_unique_violation() {
                    return DomainError::SlugAlreadyExists(org.slug.clone());
                }
            }
            DomainError::CryptoError
        })?;

        sqlx::query(
            r#"
            INSERT INTO app.org_keys (id, org_id, version, signing_public_key, signing_private_key_enc, key_derivation_nonce, enc_algorithm, activated_at, retired_at, rotated_by, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(initial_key.id)
        .bind(initial_key.org_id)
        .bind(initial_key.version)
        .bind(&initial_key.signing_public_key)
        .bind(&initial_key.signing_private_key_enc)
        .bind(&initial_key.key_derivation_nonce)
        .bind(&initial_key.enc_algorithm)
        .bind(initial_key.activated_at)
        .bind(initial_key.retired_at)
        .bind(initial_key.rotated_by)
        .bind(initial_key.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        // Insert Org Membership for the Owner
        sqlx::query(
            r#"
            INSERT INTO app.org_memberships (id, org_id, user_id, role, status, joined_at, created_at, updated_at)
            VALUES ($1, $2, $3, 'OWNER'::app.member_role, 'ACTIVE'::app.member_status, NOW(), NOW(), NOW())
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(org.id)
        .bind(owner_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create initial owner membership");
            DomainError::CryptoError
        })?;

        tx.commit().await.map_err(|_| DomainError::CryptoError)?;
        Ok(())
    }

    async fn find_by_id(&self, _ctx: &OrgContext, id: Uuid) -> Result<Organization, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT id, name, org_type::text, slug, status::text, retention_days, current_key_version, sync_seq, timezone, created_at, updated_at
            FROM app.organizations
            WHERE id = $1 AND status != 'DELETED'
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::OrganizationNotFound(id))?;

        let org_type_str: String = row.get("org_type");
        let status_str: String = row.get("status");

        Ok(Organization {
            id: row.get("id"),
            name: row.get("name"),
            org_type: OrgType::try_from(org_type_str.as_str())?,
            slug: row.get("slug"),
            status: match status_str.as_str() {
                "SUSPENDED" => OrgStatus::Suspended,
                _ => OrgStatus::Active,
            },
            retention_days: row.get("retention_days"),
            current_key_version: row.get("current_key_version"),
            sync_seq: row.get("sync_seq"),
            timezone: row.get("timezone"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Organization, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT id, name, org_type::text, slug, status::text, retention_days, current_key_version, sync_seq, timezone, created_at, updated_at
            FROM app.organizations
            WHERE slug = $1 AND status != 'DELETED'
            "#,
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::InvitationNotFound)?; // standard mapping

        let org_type_str: String = row.get("org_type");
        let status_str: String = row.get("status");

        Ok(Organization {
            id: row.get("id"),
            name: row.get("name"),
            org_type: OrgType::try_from(org_type_str.as_str())?,
            slug: row.get("slug"),
            status: match status_str.as_str() {
                "SUSPENDED" => OrgStatus::Suspended,
                _ => OrgStatus::Active,
            },
            retention_days: row.get("retention_days"),
            current_key_version: row.get("current_key_version"),
            sync_seq: row.get("sync_seq"),
            timezone: row.get("timezone"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn update(&self, _ctx: &OrgContext, org: &Organization) -> Result<Organization, DomainError> {
        sqlx::query(
            r#"
            UPDATE app.organizations
            SET name = $2, org_type = $3::app.org_type, retention_days = $4, timezone = $5, updated_at = NOW()
            WHERE id = $1 AND status != 'DELETED'
            "#,
        )
        .bind(org.id)
        .bind(&org.name)
        .bind(org.org_type.as_str())
        .bind(org.retention_days)
        .bind(&org.timezone)
        .execute(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        self.find_by_id(_ctx, org.id).await
    }

    async fn increment_sync_seq(&self, org_id: Uuid) -> Result<i64, DomainError> {
        let row = sqlx::query(
            r#"
            UPDATE app.organizations
            SET sync_seq = sync_seq + 1, updated_at = NOW()
            WHERE id = $1
            RETURNING sync_seq
            "#,
        )
        .bind(org_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        Ok(row.get("sync_seq"))
    }

    async fn find_active_key(&self, org_id: Uuid) -> Result<OrgKey, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT id, org_id, version, signing_public_key, signing_private_key_enc, key_derivation_nonce, enc_algorithm, activated_at, retired_at, rotated_by, created_at
            FROM app.org_keys
            WHERE org_id = $1 AND retired_at IS NULL
            "#,
        )
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::UnknownKeyVersion(0))?;

        Ok(OrgKey {
            id: row.get("id"),
            org_id: row.get("org_id"),
            version: row.get("version"),
            signing_public_key: row.get("signing_public_key"),
            signing_private_key_enc: row.get("signing_private_key_enc"),
            key_derivation_nonce: row.get("key_derivation_nonce"),
            enc_algorithm: row.get("enc_algorithm"),
            activated_at: row.get("activated_at"),
            retired_at: row.get("retired_at"),
            rotated_by: row.get("rotated_by"),
            created_at: row.get("created_at"),
        })
    }

    async fn find_key_version(&self, org_id: Uuid, version: i32) -> Result<OrgKey, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT id, org_id, version, signing_public_key, signing_private_key_enc, key_derivation_nonce, enc_algorithm, activated_at, retired_at, rotated_by, created_at
            FROM app.org_keys
            WHERE org_id = $1 AND version = $2
            "#,
        )
        .bind(org_id)
        .bind(version)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::UnknownKeyVersion(version))?;

        Ok(OrgKey {
            id: row.get("id"),
            org_id: row.get("org_id"),
            version: row.get("version"),
            signing_public_key: row.get("signing_public_key"),
            signing_private_key_enc: row.get("signing_private_key_enc"),
            key_derivation_nonce: row.get("key_derivation_nonce"),
            enc_algorithm: row.get("enc_algorithm"),
            activated_at: row.get("activated_at"),
            retired_at: row.get("retired_at"),
            rotated_by: row.get("rotated_by"),
            created_at: row.get("created_at"),
        })
    }

    async fn list_keys(&self, ctx: &OrgContext) -> Result<Vec<OrgKey>, DomainError> {
        let rows = sqlx::query(
            r#"
            SELECT id, org_id, version, signing_public_key, signing_private_key_enc, key_derivation_nonce, enc_algorithm, activated_at, retired_at, rotated_by, created_at
            FROM app.org_keys
            WHERE org_id = $1
            ORDER BY version DESC
            "#,
        )
        .bind(ctx.org_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        Ok(rows
            .into_iter()
            .map(|row| OrgKey {
                id: row.get("id"),
                org_id: row.get("org_id"),
                version: row.get("version"),
                signing_public_key: row.get("signing_public_key"),
                signing_private_key_enc: row.get("signing_private_key_enc"),
                key_derivation_nonce: row.get("key_derivation_nonce"),
                enc_algorithm: row.get("enc_algorithm"),
                activated_at: row.get("activated_at"),
                retired_at: row.get("retired_at"),
                rotated_by: row.get("rotated_by"),
                created_at: row.get("created_at"),
            })
            .collect())
    }

    async fn store_key(&self, key: &OrgKey) -> Result<(), DomainError> {
        sqlx::query(
            r#"
            INSERT INTO app.org_keys (id, org_id, version, signing_public_key, signing_private_key_enc, key_derivation_nonce, enc_algorithm, activated_at, retired_at, rotated_by, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(key.id)
        .bind(key.org_id)
        .bind(key.version)
        .bind(&key.signing_public_key)
        .bind(&key.signing_private_key_enc)
        .bind(&key.key_derivation_nonce)
        .bind(&key.enc_algorithm)
        .bind(key.activated_at)
        .bind(key.retired_at)
        .bind(key.rotated_by)
        .bind(key.created_at)
        .execute(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        // Also update organization's current key version
        sqlx::query(
            r#"
            UPDATE app.organizations
            SET current_key_version = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(key.org_id)
        .bind(key.version)
        .execute(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        Ok(())
    }

    async fn retire_key(&self, ctx: &OrgContext, version: i32) -> Result<(), DomainError> {
        sqlx::query(
            r#"
            UPDATE app.org_keys
            SET retired_at = NOW(), rotated_by = $3
            WHERE org_id = $1 AND version = $2 AND retired_at IS NULL
            "#,
        )
        .bind(ctx.org_id)
        .bind(version)
        .bind(ctx.user_id)
        .execute(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        Ok(())
    }

    async fn generate_join_token(&self, org_id: Uuid, user_id: Uuid) -> Result<String, DomainError> {
        use rand::Rng;
        use sha2::Digest;
        use base64::Engine;
        
        // Generate 16 random bytes (128 bits) from a CSPRNG
        let mut rng = rand::rngs::OsRng;
        let random_bytes: [u8; 16] = rng.gen();
        
        // Base64-encode for human readability and shareability
        let raw_token = format!("INV-{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&random_bytes));
        
        // Hash the token with SHA-256 for storage
        let mut hasher = sha2::Sha256::new();
        hasher.update(raw_token.as_bytes());
        let token_hash = format!("{:x}", hasher.finalize());
        
        let mut tx = self.pool.begin().await.map_err(|_| DomainError::CryptoError)?;

        sqlx::query("DELETE FROM app.org_join_tokens WHERE org_id = $1")
            .bind(org_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| DomainError::CryptoError)?;

        sqlx::query(
            r#"
            INSERT INTO app.org_join_tokens (id, org_id, token_hash, expires_at, created_at, created_by)
            VALUES ($1, $2, $3, NOW() + INTERVAL '30 days', NOW(), $4)
            "#
        )
        .bind(Uuid::now_v7())
        .bind(org_id)
        .bind(&token_hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        tx.commit().await.map_err(|_| DomainError::CryptoError)?;
        Ok(raw_token)
    }

    async fn get_active_join_token(&self, org_id: Uuid) -> Result<Option<String>, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT token_hash
            FROM app.org_join_tokens
            WHERE org_id = $1 AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at DESC
            LIMIT 1
            "#
        )
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        Ok(row.map(|r| r.get("token_hash")))
    }

    async fn verify_join_token(&self, token: &str) -> Result<Uuid, DomainError> {
        use sha2::Digest;
        
        // Hash the token with SHA-256 for comparison
        let mut hasher = sha2::Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = format!("{:x}", hasher.finalize());
        
        let row = sqlx::query(
            r#"
            SELECT org_id
            FROM app.org_join_tokens
            WHERE token_hash = $1 AND (expires_at IS NULL OR expires_at > NOW())
            "#
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        match row {
            Some(r) => Ok(r.get("org_id")),
            None => Err(DomainError::InsufficientRole {
                required: "Valid join invitation token".into(),
                actual: "Expired or invalid token".into(),
            })
        }
    }

    async fn add_membership_direct(&self, org_id: Uuid, user_id: Uuid, role: visitorpass_domain::value_objects::Role, unit_identifier: String) -> Result<(), DomainError> {
        sqlx::query(
            r#"
            INSERT INTO app.org_memberships (id, org_id, user_id, role, status, unit_identifier, joined_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4::app.member_role, 'ACTIVE'::app.member_status, $5, NOW(), NOW(), NOW())
            ON CONFLICT (org_id, user_id) DO UPDATE
            SET role = EXCLUDED.role, status = EXCLUDED.status, unit_identifier = EXCLUDED.unit_identifier, updated_at = NOW()
            "#
        )
        .bind(Uuid::now_v7())
        .bind(org_id)
        .bind(user_id)
        .bind(role.as_str())
        .bind(unit_identifier)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to direct insert membership");
            DomainError::CryptoError
        })?;

        Ok(())
    }
}
