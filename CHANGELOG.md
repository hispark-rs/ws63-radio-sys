# Changelog

## [Unreleased]

## [0.1.0-alpha.10] - 2026-08-03

### Added

- Added a separate upstream hostapd WPA2-Personal authenticator archive,
  in-memory AP lifecycle ABI, Rust raw bindings, and Cargo feature/metadata.
  Consumer builds remain free of C compilers, configuration files, and host
  scripts.
- Added Ubuntu, macOS, and Windows consumer checks for the AP target archive.

### Fixed

- Extended the versioned authenticator input ABI with associated and
  disassociated station events so the native hostapd state machine receives
  the WS63 driver's `NEW_STA`/`DEL_STA` notifications.
- Rebuilt the WPA2/WPA3 STA archives after the freestanding portability layer
  changed, advanced their profile revisions, and restored byte-for-byte source
  and Cargo-payload parity.

## [0.1.0-alpha.9] - 2026-08-03

### Fixed

- Preserve association-response diagnostics across the upstream hostap driver
  event boundary, including raw/status codes and bounded response IE metadata.
- Accept the transition-compatible WPA2 group-cipher set while retaining CCMP
  as the required pairwise cipher.

### Tests

- Link the complete pinned WPA2 hostap source profile into a native lifecycle
  test and prove that an installed pairwise key is removed through
  `hisi_wpa_disconnect` and upstream `wpa_clear_keys`. Repeated disconnect is
  idempotent, while the existing WPA2/WPA3 driver and RV32 ABI gates remain in
  the same executable contract.

## [0.1.0-alpha.8] - 2026-07-28

### Fixed

- Normalize vendor association status `8030` to IEEE status 30 and schedule a
  bounded cached-BSS retry through the native event loop. The retry diagnostics
  are exported through the versioned C/Rust ABI so the WS63 backend can
  distinguish temporary association rejection from authentication and EAPOL
  failures.

## [0.1.0-alpha.7] - 2026-07-23

### Changed

- Advanced the native supplicant ABI to v9 and split bounded poll accounting
  into an exact completed-work count plus an independent output-event-ready
  flag. This removes the ambiguous `work_pending` value before the WS63
  incremental backend starts enforcing per-poll work budgets.
- Rebuilt the redistributable WPA2/WPA3 target archives with the pinned release
  toolchain and advanced both artifact profile revisions to v3.

## [0.1.0-alpha.6] - 2026-07-20

### Changed

- Export the runtime-compatibility and upstream-supplicant root-symbol sets as
  versioned Cargo metadata so the selected chip backend can own final native
  link closure without a consumer `build.rs`.
- Stop linking the native hostap archive directly from the raw sys crate; the
  chip backend now composes it with the normalized Wi-Fi archive closure.
- Record the pinned upstream hostap roots in the supplicant boundary profile,
  keeping the final-link and drift validators on one fact source.

## [0.1.0-alpha.5] - 2026-07-20

### Fixed

- Updated the exact WS63 ROM backend dependency to
  `hisi-rom-sys-ws63 0.1.0-alpha.2`, so radio and PKE crypto consumers resolve
  one compatible crates.io backend without relying on a parent workspace patch.

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
