# hisi-rf-link

Versioned host-side link transforms for WS63 vendor radio archives.

```text
hisi-rf-link inspect [--summary] <archive>...
hisi-rf-link normalize --profile-revision <revision> --out-dir <dir> \
  --manifest <manifest.json> <archive>...
hisi-rf-link verify-normalized --manifest <manifest.json> --archive-dir <dir>
hisi-rf-link verify-guarded-sites --manifest <guarded.jsonl> \
  --final-elf <elf> --archive-dir <original-archive-dir>
hisi-rf-link patch-reloc ...
hisi-rf-link verify-layout ...
hisi-rf-link generate-rom-patch ...
hisi-rf-link patch-from-oracle ...
hisi-rf-link task-profile --elf <final-elf> --log <uart-log>
```

`normalize` is implemented entirely in Rust. It rewrites the declared WS63
vendor relocations to standard ELF semantics, fails closed on unknown forms,
and emits a deterministic hash manifest. The resulting archives can be linked
by stock `rust-lld`; no final addresses are encoded in the distributed archive.

The post-link commands remain migration-oracle tools. They embed the reviewed
legacy Python implementations and execute them through `uv`; they are not part
of the target plain-Cargo build path. Image header/hash semantics remain owned
by `hisi-fwpkg` and are intentionally outside this tool.

`task-profile` emits a versioned JSON report that joins exact task entry
addresses from `RFDBG_TASK`/`RFDBG_TASK_METRIC` UART records with the final ELF
symbol table and the hash-bound `profiles/ws63-scheduling.toml`. It never uses a
nearest-symbol guess: unmatched addresses remain `unknown`, and the report does
not change runtime scheduling policy.
