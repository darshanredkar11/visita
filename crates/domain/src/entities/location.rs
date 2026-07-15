use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LocationStatus { Active, Inactive, Deleted }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub id:           Uuid,
    pub org_id:       Uuid,
    pub name:         String,
    pub description:  Option<String>,
    pub timezone:     String,
    pub address_line: Option<String>,
    pub status:       LocationStatus,
    pub created_at:   DateTime<Utc>,
    pub updated_at:   DateTime<Utc>,
}
