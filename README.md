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
  exposing hostap internal structures to Rust; its public raw install contract
  validates the same ABI version prefix as the OS hook table;
- `driver_ws63.c` now consumes upstream hostap 2.11's real `wpa_driver_ops` and
  implements the first fail-closed subset: init/deinit, MAC address, management
  TX, and key install/remove. The key ABI preserves peer presence, RX/TX and
  pairwise/group flags, and a bounded replay sequence instead of exposing
  hostap's internal key structure.
- `supplicant_ws63.c` owns the opaque single-context lifecycle and bounded
  state-event queue exposed through the versioned C ABI. Queue overflow is an
  explicit failure event rather than a silent loss.
- `personal.toml` is the complete source profile for the current WPA2-Personal
  STA closure: 42 upstream/port RV32 objects, 15 compile definitions, and the
  exact external compiler/crypto/memory ABI in `native.required-symbols`.
- `freestanding_hisi.c` supplies the small formatter/string/sort contract still
  used directly by that pinned source set. It is intentionally not a general
  libc or POSIX compatibility layer.

This closes the W2C source/libc/formatter build closure and the EAPOL subpart of
W2D, not silicon parity. The WS63 scan/auth/assoc operations, management/EAPOL RX
event bridge, Rust context owner, and `RadioRunner` integration remain W2D work.
Host behavior tests, all-source freestanding RV32 compilation, ABI size/offset
assertions, restricted-format checks, and an exact external symbol manifest are
enforced by `scripts/check-native-supplicant-port.py` so a successful archive
build cannot be mistaken for a working connection.
