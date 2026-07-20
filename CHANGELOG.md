# Changelog

## [Unreleased]

## [0.1.0-alpha.4] - 2026-07-20

### Security

- Backported the official hostap 2026-1, 2026-2, and 2026-3 fixes onto the
  pinned 2.11 release. This closes MLO bounds validation, PMKSA network/AKMP
  context validation, and the SAE H2E anti-clogging token NULL dereference.
- Added an executable SAE H2E regression that parses a token-container commit
  through the same NULL output-parameter shape used by SME/PASN callers.

### Changed

- Rebuilt both redistributable WPA2/WPA3 target archives from the hash-bound
  security maintenance commit and advanced their profile revisions.
- Moved the nested source pin to the public `hispark-rs/hostap` mirror while
  retaining the official 2.11 tag, release tarball hash, advisory URLs, and
  exact seven-commit backport inventory as provenance.

## [0.1.0-alpha.3] - 2026-07-19

### Added

- Added a pure Rust `hisi-rf-link rebuild-native-supplicant` maintainer command
  that reconstructs the pinned WPA2 and WPA3 hostap target archives and rejects
  compiler, archiver, source, manifest, size, hash, or byte drift.
- Added canonical macOS release CI that pins GCC 15.1.0, GNU binutils 2.45 and
  `cc-rs 1.2.67`, rebuilds both target archives, and gates publication on an
  exact byte-for-byte match with the Cargo payload.

## [0.1.0-alpha.2] - 2026-07-19

### Added

- Initial `ws63-radio-sys` archive-profile and Cargo metadata contract.
- Initial `hisi-rf-link` host CLI shell.
- Explicit WPA2-Personal and WPA3-Personal archive profiles; only the WPA3
  candidate selects the vendor mbedTLS and hardened crypto oracle archives
  required by SAE/P-256.
- Hash-bound WPA task classification now selects the WPA2 or WPA3 artifact row
  explicitly instead of attributing both archives to the WPA2 evidence source.
- Pinned upstream hostap 2.11 and added the first versioned C/Rust supplicant ABI
  for a runner-owned, LiteOS-free native runtime port.
- Added native `os_hisi_rtos`/`eloop_hisi_rtos`, an EAPOL-only L2 path, and the
  first upstream `wpa_driver_ops` subset for MAC, management TX, and key
  install/remove, with host/RV32 and object-symbol drift gates.
- Versioned the WS63 driver hook table and exposed its raw install lifecycle so
  the Rust integration can own registration without relying on private C state.
- Release CI now rebuilds every normalized vendor archive from the pinned
  `ws63-RF` input and compares its bytes, hashes, sizes, and relocation counts
  with the Cargo-delivered payload before packaging or publishing the unit.
