# ws63-radio-blob

Cargo-delivered, redistributable WS63 radio target archives normalized by
`hisi-rf-link` for stock `rust-lld`. It also carries reproducible target
archives for the pinned upstream hostap 2.11 WPA2/WPA3 Personal STA profiles,
the separately selected WPA2-Personal and WPA3-SAE AP authenticators, and the official
2026-1, 2026-2, and 2026-3 security backports.

The BLE B0 payload contains normalized `libbt_host.a`, `libbt_app.a`, and
`libbth_sdk.a` artifacts plus the shared `libbg_common.a`. Its hash-bound profile
and generated external-symbol ownership report are versioned with the payload.
The B1 initialization contract additionally carries normalized `libbgtp.a` and
`libbgtp_rom_data.a`, a rooted object closure, and the four-task/stack resource
inventory. The SLE/GLE archive is deliberately excluded. Packaging the
controller is a prerequisite, not evidence that controller/host initialization
has run on silicon.

The package stores each deterministic archive as a Zstandard payload to stay
within registry limits. Its pure Rust build script expands the archives only
into Cargo's package-specific `OUT_DIR`, validates their size and SHA-256 from
`artifacts/manifest.json`, and publishes the resulting directory as Cargo
`links` metadata. It performs no network access and invokes no host tools.

The manifest binds every archive to a size and SHA-256. Native supplicant and
authenticator entries additionally record the upstream tag/base commit, patched commit,
security advisory set, release tarball hash,
target, compiler, archiver, exact `cc-rs` version, canonical builder source, and
source-profile revision. CI rebuilds every native archive with that contract
and compares its bytes with this package. Rebuilding is a maintainer/release
operation; consumer builds only expand and link them.

These are target artifacts, not host executables. Image headers and firmware
hashing remain the responsibility of `hisi-fwpkg`.
