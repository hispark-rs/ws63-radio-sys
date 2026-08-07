#![no_std]

//! Raw WS63 radio blob integration contract.
//!
//! The Cargo `links = "ws63_radio_sys"` build script exports the normalized
//! archive directory supplied by `ws63-radio-blob` and the machine-owned link
//! profile. Upstream-supplicant features select a Cargo-delivered target
//! archive; they never compile C or discover a cross compiler on the consumer
//! machine. This crate contains no safe radio API, scheduler policy, or
//! duplicate archive inventory.

#[cfg(all(
    any(feature = "wpa2-personal", feature = "wpa3-personal"),
    feature = "upstream-supplicant-port"
))]
compile_error!("select either legacy vendor supplicant archives or the upstream hostap profile");

#[cfg(all(
    any(
        feature = "upstream-authenticator-wpa2",
        feature = "upstream-authenticator-wpa3"
    ),
    feature = "upstream-supplicant-port"
))]
compile_error!("select either the AP authenticator or STA supplicant target archive");

#[cfg(all(
    feature = "upstream-authenticator-wpa2",
    feature = "upstream-authenticator-wpa3"
))]
compile_error!("select exactly one AP authenticator security profile");

#[cfg(any(
    feature = "upstream-authenticator-wpa2",
    feature = "upstream-authenticator-wpa3"
))]
pub mod authenticator;
#[cfg(feature = "sle")]
pub mod sle;
pub mod supplicant;

/// Marker type for the Cargo links contract.
pub struct RadioAbi;
