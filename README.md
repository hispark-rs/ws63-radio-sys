# ws63-radio-sys

Low-level WS63 radio blob integration contracts.

This repository owns two release units:

- `ws63-radio-sys`: a `no_std` crate that identifies the vendor archive ABI and
  exports blob paths to dependent Cargo build scripts through `links` metadata.
- `hisi-rf-link`: the host-side linker/post-link tool for vendor relocations and
  mask-ROM patch generation.

The language-neutral vendor payload remains the nested `ws63-RF` submodule. It is
not packaged on crates.io; consult the original SDK license before redistribution.

`crates/hisi-rf-link/profiles/ws63-scheduling.toml` binds observed RF task entry
symbols and vendor priorities to exact archive or ROM hashes. It records
classification evidence, not runtime policy: unmatched entries remain `unknown`,
and a consuming firmware must verify an external archive before using its rows.

The WPA archive profile is explicit. `wpa2-personal` preserves the verified
supplicant/security/libc closure; `wpa3-personal` additionally selects the vendor
mbedTLS 3.6.0 oracle required by the current SAE/P-256 implementation. The latter
is a link candidate until its controlled-AP HIL gate passes.

The replacement path is pinned upstream hostap 2.11, not the SDK's LiteOS-derived
2.10 fork. `include/hisi_wpa_supplicant.h` and `ws63_radio_sys::supplicant`
define the same narrow, versioned ABI for a single runner-owned context. The
vendor archive remains a behavior and silicon-parity oracle while the upstream
port is brought up; it is not the long-term runtime architecture.

The optional `upstream-supplicant-port` feature compiles the first native port
layer:

- `os_hisi_rtos.c` delegates allocation, clocks, sleeping, entropy and runner
  wakeups through the versioned OS hook table;
- `eloop_hisi_rtos.c` provides a bounded single-runner timeout loop without
  POSIX sockets, threads or LiteOS symbols;
- `hisi_wpa_port.c` owns hook installation and rejects ABI drift or conflicting
  runtime registrations;
- `l2_packet_ws63.c` implements the EAPOL-only hostap L2 boundary. RX is
  delivered only when `RadioRunner` drains a bounded vendor-event queue, and
  the driver registration cannot be removed while an RX endpoint is alive;
- `hisi_wpa_driver_port.c` owns the narrow WS63 driver hook lifetime without
  exposing hostap internal structures to Rust.

This closes the W2C runtime seam and the EAPOL subpart of W2D, not a complete
supplicant build. The full hostap object closure, production formatting support,
and WS63 scan/auth/assoc/management/key-install driver bridge remain W2D work.
Host behavior tests and freestanding RV32 compilation are enforced by
`scripts/check-native-supplicant-port.py` so this partial boundary cannot be
mistaken for a silicon parity claim.
