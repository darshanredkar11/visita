use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;
use visitorpass_domain::{
    entities::{OrgKey, OrgStatus, OrgType, Organization, SubscriptionTier},
    value_objects::{Email, PlatformContext, Role},
    DomainError,
};

use crate::ports::{
    crypto_service::CryptoService,
    repositories::{AuditEventInput, AuditRepository, CreateUserInput, OrgRepository, UserRepository},
};

pub struct ProvisionOrgInput {
    pub name:        String,
    pub org_type:    String,
    pub slug:        String,
    pub timezone:    String,
    pub admin_email: String,
    pub admin_name:  String,
}

pub struct ProvisionOrgOutput {
    pub organization:  Organization,
    pub admin_user_id: Uuid,
}

/// Platform Super-Admin Portal -- "Organization Provisioning"
/// (product_specification.md section 2.1).
///
/// Distinct from `RegisterOrganizationUseCase` (anonymous, self-service
/// `/api/v1/organizations`, requires the caller to set an initial
/// password): this is platform-admin-only and JIT-creates the new org's
/// root OrgAdmin with no usable password, exactly like a first-time
/// `/api/v1/auth/google` login (see `google_auth` handler's "new user
/// registration" branch) -- they authenticate exclusively via Google
/// afterward. If `admin_email` already belongs to an existing user, that
/// user is granted an OrgAdmin membership on the new org instead of
/// erroring, so a platform admin can add a second org to someone who
/// already has an account.
pub struct ProvisionOrganizationUseCase {
    orgs:   Arc<dyn OrgRepository>,
    users:  Arc<dyn UserRepository>,
    crypto: Arc<dyn CryptoService>,
    audit:  Arc<dyn AuditRepository>,
}

impl ProvisionOrganizationUseCase {
    pub fn new(
        orgs:   Arc<dyn OrgRepository>,
        users:  Arc<dyn UserRepository>,
        crypto: Arc<dyn CryptoService>,
        audit:  Arc<dyn AuditRepository>,
    ) -> Self {
        Self { orgs, users, crypto, audit }
    }

    pub async fn execute(&self, ctx: &PlatformContext, input: ProvisionOrgInput) -> Result<ProvisionOrgOutput, DomainError> {
        if input.name.trim().is_empty() {
            return Err(DomainError::ValidationFailed {
                field:   "name".into(),
                message: "organization name is required".into(),
            });
        }
        if input.slug.trim().is_empty() || !input.slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(DomainError::ValidationFailed {
                field:   "slug".into(),
                message: "slug must contain only alphanumeric characters or hyphens".into(),
            });
        }

        let email = Email::parse(&input.admin_email)?;

        if self.orgs.find_by_slug(&input.slug).await.is_ok() {
            return Err(DomainError::SlugAlreadyExists(input.slug));
        }

        let org_id = Uuid::now_v7();
        let key_version = 1;

        // (a) Create org + Ed25519 signing key, mirroring
        // `PgOrgRepository::create`'s multi-insert transaction pattern
        // (same as `RegisterOrganizationUseCase`).
        let keypair = self.crypto.generate_org_keypair(org_id, key_version)?;
        let initial_key = OrgKey {
            id:                      Uuid::now_v7(),
            org_id,
            version:                 key_version,
            signing_public_key:      keypair.public_key_bytes,
            signing_private_key_enc: keypair.encrypted_private_key,
            key_derivation_nonce:    keypair.nonce,
            enc_algorithm:           "CHACHA20_POLY1305".into(),
            activated_at:            Utc::now(),
            retired_at:              None,
            rotated_by:              None,
            created_at:              Utc::now(),
        };

        let organization = Organization {
            id:                  org_id,
            name:                input.name.trim().to_string(),
            org_type:            OrgType::try_from(input.org_type.as_str())?,
            slug:                input.slug.trim().to_lowercase(),
            status:              OrgStatus::Active,
            retention_days:      90, // default V1 free tier retention
            current_key_version: key_version,
            sync_seq:            0,
            timezone:            input.timezone.trim().to_string(),
            subscription_tier:   SubscriptionTier::default(), // platform admin upgrades via set_subscription_tier afterward
            max_locations:       1,
            max_daily_passes:    100,
            created_at:          Utc::now(),
            updated_at:          Utc::now(),
        };

        // (b) JIT-find-or-create the admin user by email -- they must NOT
        // be required to have logged in via Google first. Uses the same
        // random, never-communicated password hash as `google_auth`'s
        // first-login branch, since the intended auth path is Google
        // OAuth.
        let admin = match self.users.find_by_email(email.as_str()).await {
            Ok(u) => u,
            Err(_) => {
                let dummy_password_hash = self.crypto.hash_password(&Uuid::new_v4().to_string()).await?;
                self.users.create(CreateUserInput {
                    email:         email.as_str().to_string(),
                    password_hash: dummy_password_hash,
                    phone_hmac:    None,
                    full_name:     input.admin_name.trim().to_string(),
                }).await?
            }
        };

        self.orgs.create(&organization, &initial_key, admin.id).await?;

        // (c) `create`'s built-in owner-membership insert uses the
        // legacy 'ADMIN' role string (read-compat, see `Role::TryFrom`);
        // this explicit call normalizes it to the canonical `OrgAdmin`
        // and is also what makes an *existing* user's membership on this
        // new org correct if they already had some other role elsewhere
        // (ON CONFLICT (org_id, user_id) DO UPDATE).
        self.orgs.add_membership_direct(org_id, admin.id, Role::OrgAdmin, String::new()).await?;

        // Fire-and-forget per `AuditRepository::append`'s contract.
        let _ = self.audit.append(AuditEventInput {
            org_id,
            event_type:         "ORG_PROVISIONED_BY_PLATFORM_ADMIN".into(),
            actor_user_id:      Some(ctx.user_id),
            actor_device_id:    None,
            target_entity_type: Some("organization".into()),
            target_entity_id:   Some(org_id),
            metadata:           serde_json::json!({ "admin_email": email.as_str() }),
            ip_address:         None,
        }).await;

        Ok(ProvisionOrgOutput { organization, admin_user_id: admin.id })
    }
}
