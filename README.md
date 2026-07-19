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

`crates/hisi-rf-link/profiles/ws63-runtime-compat.toml` is the machine-readable
boundary for the delivered Wi-Fi archives' LiteOS/architecture namespace. It
distinguishes the seven symbols supplied by the bounded native-runtime adapter
from eight archive-only symbols that are not reachable in the upstream
supplicant firmware. `scripts/check-runtime-compat-profile.py` compares the
manifest with `nm -u` output, while the parent integration verifies both the
Rust provider and final ELF. This is a compatibility profile, not a LiteOS
backend.

`crates/hisi-rf-link/profiles/ws63-supplicant-boundary.toml` owns the exact
legacy WPA archive closure, the native hostap archive name, and the bounded
native object markers and legacy-provider symbol set. Cargo merges the cc-rs
archive into the `ws63-radio-sys` rlib, so the object markers preserve its
provenance in the final rust-lld map. Parent final-link checks consume this
profile so an upstream-supplicant image cannot silently pull the vendor
supplicant, vendor mbedTLS, or its LiteOS compatibility provider back into the
firmware.

The WPA archive profile is explicit. `wpa2-personal` preserves the verified
supplicant/security/libc closure; `wpa3-personal` additionally selects the vendor
mbedTLS 3.6.0 oracle used for migration parity. The upstream profiles select
neither vendor supplicant archive. The vendor profiles remain explicit oracle
features during the migration window and are not the default architecture.

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

W2C and W2D are closed: the single native `RadioRunner` now drives scan,
authentication, association, management/EAPOL RX/TX and key installation, and
the upstream WPA2 and transition-mode WPA3 paths have on-silicon parity evidence.
Host behavior tests, all-source freestanding RV32 compilation, ABI size/offset
assertions, restricted-format checks, and exact external symbol manifests remain
mandatory in `scripts/check-native-supplicant-port.py`; they complement rather
than replace the parent repository's HIL gates.
