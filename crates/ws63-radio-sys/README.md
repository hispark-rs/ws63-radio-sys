# ws63-radio-sys

Low-level, `no_std` ABI and link contract for the HiSilicon WS63 radio payload.

Normal consumer builds receive normalized target archives from
`ws63-radio-blob`, ROM facts from `hisi-rom-sys-ws63`, and pure Rust link-profile
facts from `hisi-rf-link`. The build script performs no network access and does
not invoke Python, a shell, GCC, GNU binutils, or an SDK toolchain.

This crate is an implementation dependency of the WS63 radio backend. Applications
should use the safe `hisi-rf` facade once the chip backend is released rather than
calling raw symbols or reading Cargo metadata directly.
