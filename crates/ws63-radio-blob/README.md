# ws63-radio-blob

Cargo-delivered, redistributable WS63 Wi-Fi target archives normalized by
`hisi-rf-link` for stock `rust-lld`.

The package stores each deterministic archive as a Zstandard payload to stay
within registry limits. Its pure Rust build script expands the archives only
into Cargo's package-specific `OUT_DIR`, validates their size and SHA-256 from
`artifacts/manifest.json`, and publishes the resulting directory as Cargo
`links` metadata. It performs no network access and invokes no host tools.

These are target artifacts, not host executables. Image headers and firmware
hashing remain the responsibility of `hisi-fwpkg`.
