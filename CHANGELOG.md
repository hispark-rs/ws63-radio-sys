# Changelog

## [Unreleased]

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
