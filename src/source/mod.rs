//! Upstream source access.
//!
//! The metadata model lives here already so hash verification can depend on it
//! without pulling in the network layer. Task 5 adds the HTTPS index and
//! metadata client to this module.

pub mod metadata;
