//! # VisitorPass Domain
//!
//! Pure domain layer. Contains:
//! - Entities (Organization, VisitorPass, EntryLog, …)
//! - Value objects (OrgContext, Role, PassNumber, Email, …)
//! - Domain errors
//!
//! ## Rules
//! - Zero framework dependencies (no Axum, no SQLx, no Tokio)
//! - Every public type must enforce its invariants in constructors
//! - No panics in production paths; all errors are typed

pub mod entities;
pub mod errors;
pub mod value_objects;

pub use errors::DomainError;
