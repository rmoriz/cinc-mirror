//! Shared integration-test fixtures.
//!
//! The module is compiled into several test binaries, and not every binary uses
//! every helper, so dead-code warnings are expected and suppressed here rather
//! than repeated at each item.

#![allow(dead_code)]

pub mod registry;
