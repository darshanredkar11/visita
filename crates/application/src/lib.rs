//! # Application Layer
//!
//! Contains:
//! - **Ports** (traits): contracts that the infrastructure layer must implement
//! - **Use Cases**: pure business logic, no framework or DB dependencies
//!
//! Every use case takes an `OrgContext` as its first argument.
//! Every port method takes an `OrgContext` as its first argument.
//! No bare ID lookups anywhere in this crate.

pub mod ports;
pub mod use_cases;
