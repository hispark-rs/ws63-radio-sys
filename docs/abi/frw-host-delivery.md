# WS63 FRW Host-Delivery ABI

Status: narrow unsafe binding; no native producer-fence or HIL claim.

The canonical declarations are in the matching `fbb_ws63` SDK, relative to
its root (the consumer build never reads an SDK checkout):

- `src/protocol/wifi/rom_code/ws63/source/device/frw/romable/frw_rom_cb_rom.h`:
  `FRW_ROM_CB_RX_NETBUF`, `frw_rom_cb_register`, and `frw_get_rom_cb`.
- `src/protocol/wifi/rom_code/ws63/source/device/inc/romable/frw_dmac_rom.h`:
  `frw_rx_netbuf_cb(oal_dmac_netbuf_stru *, osal_u32) -> osal_u32`.

The historical `ws63-RF/include/port/port_frw.h` one-argument declaration is
not the binding source. No complete vendor struct is reproduced here.

## Cross-Checks

- The final SDK assembly registers `frw_rx_netbuf` in callback 261 at
  `0x2a4704..0x2a470e`, in `dmac_main_rom_cb_base_init_before_frw_init`.
- SDK `frw_rx_netbuf` at `0x264166` preserves both arguments, copies the
  original payload to a newly allocated host netbuf, frees the original,
  then invokes `frw_hmac_rcv_netbuf`.
- Read-only WS63 ROM capture confirms that `hcc_slave_tx` at `0x128cea`
  looks up slot 261 and forwards the two arguments. The register/get entries
  at `0x128d4a`/`0x128d60` are already in the ROM symbol owner. No addresses
  are duplicated in the Rust ABI.
- On the fixed NET0 STA ELF SHA-256
  `35fbdf1ceed30d1b82c105892ff953dd813e23717885e290516bdfdaaea6df5e`,
  slot 261 read `0x29792e`, which the ELF resolves to `frw_rx_netbuf`.

Source/capture SHA-256:

| Input | SHA-256 |
| --- | --- |
| SDK `frw_rom_cb_rom.h` | `081d9473acf6c3b941633f993debb80ea17765fbc694947547f1f06d5b080ba1` |
| SDK `frw_dmac_rom.h` | `f5d7744d5d7aa9cfcb7e310045046aad13bce3513e5851ab9efca638d465e48f` |
| SDK `ws63-liteos-app.asm` | `5aedd0fb8e916efc27325fc5190822e05a0cf84f0b4d602e12c6fa06b242bf2e` |
| ROM `[0x128cb0, 0x128d60)` | `1fe52a0df4819124524e38944bb39e58a9583740b0c1a518290cb3f351e37d68` |

These addresses identify the observed profile, not a portable firmware layout.
Runtime registration must compare function pointers from the actual image,
reject an unexpected owner, and preserve opaque netbuf ownership exactly once.

## Unproven Boundaries

`frw_rx_netbuf` returns zero even on some allocation/copy failures. Optional
host RX MSG595 processing may outlive the callback; earlier device work may
not yet have entered it. A zero return, zero observed calls in flight, or an
empty host queue is therefore not sufficient to reopen a connection epoch.
An observer must forward management/EAPOL traffic even while the Ethernet L2
route is closed. It must not treat the callback's opaque netbuf as an Ethernet
frame or silently drop/free it based on the L2 admission state.
