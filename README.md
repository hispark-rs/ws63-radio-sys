# ws63-radio-sys

Low-level WS63 radio blob integration contracts.

This repository owns two release units:

- `ws63-radio-sys`: a `no_std` crate that identifies the vendor archive ABI and
  exports blob paths to dependent Cargo build scripts through `links` metadata.
- `hisi-rf-link`: the host-side linker/post-link tool for vendor relocations and
  mask-ROM patch generation.

The language-neutral vendor payload remains the nested `ws63-RF` submodule. It is
not packaged on crates.io; consult the original SDK license before redistribution.

