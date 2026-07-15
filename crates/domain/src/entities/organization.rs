use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrgType {
    HousingSociety,
    Office,
    Hospital,
    Warehouse,
    School,
    College,
    Factory,
    Coworking,
    Apartment,
    Hostel,
    Other,
}

impl OrgType {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrgType::HousingSociety => "HOUSING_SOCIETY",
            OrgType::Office         => "OFFICE",
            OrgType::Hospital       => "HOSPITAL",
            OrgType::Warehouse      => "WAREHOUSE",
            OrgType::School         => "SCHOOL",
            OrgType::College        => "COLLEGE",
            OrgType::Factory        => "FACTORY",
            OrgType::Coworking      => "COWORKING",
            OrgType::Apartment      => "APARTMENT",
            OrgType::Hostel         => "HOSTEL",
            OrgType::Other          => "OTHER",
        }
    }
}

impl TryFrom<&str> for OrgType {
    type Error = crate::DomainError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "HOUSING_SOCIETY" => Ok(OrgType::HousingSociety),
            "OFFICE"          => Ok(OrgType::Office),
            "HOSPITAL"        => Ok(OrgType::Hospital),
            "WAREHOUSE"       => Ok(OrgType::Warehouse),
            "SCHOOL"          => Ok(OrgType::School),
            "COLLEGE"         => Ok(OrgType::College),
            "FACTORY"         => Ok(OrgType::Factory),
            "COWORKING"       => Ok(OrgType::Coworking),
            "APARTMENT"       => Ok(OrgType::Apartment),
            "HOSTEL"          => Ok(OrgType::Hostel),
            "OTHER"           => Ok(OrgType::Other),
            _ => Err(crate::DomainError::ValidationFailed {
                field:   "org_type".into(),
                message: format!("unknown org type: {s}"),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrgStatus {
    Active,
    Suspended,
    Deleted,
}

/// Organization entity. Root aggregate of all org-scoped data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id:                  Uuid,
    pub name:                String,
    pub org_type:            OrgType,
    pub slug:                String,
    pub status:              OrgStatus,
    pub retention_days:      i32,
    pub current_key_version: i32,
    /// Monotonic counter. Incremented on every server-side org event.
    /// Used by mobile devices for incremental sync.
    pub sync_seq:            i64,
    pub timezone:            String,
    pub created_at:          DateTime<Utc>,
    pub updated_at:          DateTime<Utc>,
}

impl Organization {
    pub fn is_active(&self) -> bool {
        self.status == OrgStatus::Active
    }

    /// Validate that this org can process requests.
    pub fn assert_active(&self) -> Result<(), crate::DomainError> {
        if self.status == OrgStatus::Suspended {
            Err(crate::DomainError::OrganizationSuspended)
        } else {
            Ok(())
        }
    }
}
