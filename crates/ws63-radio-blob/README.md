# ws63-radio-blob

Cargo-delivered, redistributable WS63 Wi-Fi target archives normalized by
`hisi-rf-link` for stock `rust-lld`. It also carries reproducible target
archives for the pinned upstream hostap 2.11 WPA2/WPA3 Personal profiles.

The package stores each deterministic archive as a Zstandard payload to stay
within registry limits. Its pure Rust build script expands the archives only
into Cargo's package-specific `OUT_DIR`, validates their size and SHA-256 from
`artifacts/manifest.json`, and publishes the resulting directory as Cargo
`links` metadata. It performs no network access and invokes no host tools.

The manifest binds every archive to a size and SHA-256. Native supplicant
entries additionally record the upstream tag, commit, release tarball hash,
target, compiler, and source-profile revision. Rebuilding those entries is a
maintainer/release operation; consumer builds only expand and link them.

These are target artifacts, not host executables. Image headers and firmware
hashing remain the responsibility of `hisi-fwpkg`.
