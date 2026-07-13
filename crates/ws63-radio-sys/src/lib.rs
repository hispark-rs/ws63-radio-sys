#![no_std]

//! Raw WS63 radio blob integration contract.
//!
//! The Cargo `links = "ws63_radio_sys"` build script exports the checked-out
//! payload paths and the machine-owned archive profile. This crate contains no
//! safe radio API, scheduler policy, or duplicate archive inventory.

/// Marker type for the Cargo links contract.
pub struct RadioAbi;
