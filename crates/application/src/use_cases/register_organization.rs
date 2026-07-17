use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;
use visitorpass_domain::{
    entities::{OrgKey, OrgStatus, OrgType, Organization},
    value_objects::Role,
    DomainError,
};

use crate::ports::{
    crypto_service::CryptoService,
    repositories::{
        AuditEventInput, AuditRepository, CreateUserInput, OrgRepository, UserRepository,
    },
};

pub struct RegisterOrgInput {
    pub name:            String,
    pub org_type:        String,
    pub slug:            String,
    pub timezone:        String,
    pub owner_email:     String,
    pub owner_password:  String,
    pub owner_name:      String,
}

pub struct RegisterOrgOutput {
    pub organization: Organization,
    pub owner_id:     Uuid,
}

pub struct RegisterOrganizationUseCase {
    orgs:   Arc<dyn OrgRepository>,
    users:  Arc<dyn UserRepository>,
    crypto: Arc<dyn CryptoService>,
    audit:  Arc<dyn AuditRepository>,
}

impl RegisterOrganizationUseCase {
    pub fn new(
        orgs:   Arc<dyn OrgRepository>,
        users:  Arc<dyn UserRepository>,
        crypto: Arc<dyn CryptoService>,
        audit:  Arc<dyn AuditRepository>,
    ) -> Self {
        Self { orgs, users, crypto, audit }
    }

    pub async fn execute(&self, input: RegisterOrgInput) -> Result<RegisterOrgOutput, DomainError> {
        // Validate slug (must be URL safe)
        if input.slug.trim().is_empty() || !input.slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(DomainError::ValidationFailed {
                field:   "slug".into(),
                message: "slug must contain only alphanumeric characters or hyphens".into(),
            });
        }

        // Validate email
        let email = visitorpass_domain::value_objects::Email::parse(&input.owner_email)?;

        // Check if slug already exists
        if self.orgs.find_by_slug(&input.slug).await.is_ok() {
            return Err(DomainError::SlugAlreadyExists(input.slug));
        }

        // Check if email already exists
        if self.users.find_by_email(email.as_str()).await.is_ok() {
            return Err(DomainError::EmailAlreadyExists);
        }

        let org_id = Uuid::now_v7();
        let key_version = 1;

        // Generate organization key material
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

        // Create Organization entity
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
            subscription_tier:   visitorpass_domain::entities::SubscriptionTier::default(), // self-service signups start on Free
            max_locations:       1,
            max_daily_passes:    100,
            created_at:          Utc::now(),
            updated_at:          Utc::now(),
        };

        // Hash owner password
        let password_hash = self.crypto.hash_password(&input.owner_password).await?;
        let phone_hmac = None; // V1: default to no phone for root owner (managed via profile later)

        // Create owner user
        let owner = self.users.create(CreateUserInput {
            email:         email.as_str().to_string(),
            password_hash,
            phone_hmac,
            full_name:     input.owner_name.trim().to_string(),
        }).await?;

        // Save org, initial key, and OWNER membership atomically in a transaction inside repository
        self.orgs.create(&organization, &initial_key, owner.id).await?;
        
        Ok(RegisterOrgOutput { organization, owner_id: owner.id })
    }
}
