# Changelog

## [Unreleased]

### Added

- Initial `ws63-radio-sys` archive-profile and Cargo metadata contract.
- Initial `hisi-rf-link` host CLI shell.
- Explicit WPA2-Personal and WPA3-Personal archive profiles; only the WPA3
  candidate selects the vendor mbedTLS oracle required by SAE/P-256.
- Hash-bound WPA task classification now selects the WPA2 or WPA3 artifact row
  explicitly instead of attributing both archives to the WPA2 evidence source.
- Pinned upstream hostap 2.11 and added the first versioned C/Rust supplicant ABI
  for a runner-owned, LiteOS-free native runtime port.
