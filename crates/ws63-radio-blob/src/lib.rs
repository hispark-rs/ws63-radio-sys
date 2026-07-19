#![no_std]

//! Redistributable normalized WS63 Wi-Fi target archives.
//!
//! The build script expands the Cargo-delivered payload into this package's
//! private `OUT_DIR`, verifies every archive against the normalization
//! manifest, and exports the directory through `DEP_WS63_RADIO_BLOB_LIB_DIR`.

/// Normalization provenance and hashes for every delivered target archive.
pub const NORMALIZATION_MANIFEST: &str = include_str!("../artifacts/manifest.json");
