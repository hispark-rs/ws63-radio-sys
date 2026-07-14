# hisi-rf-link

Versioned host-side post-link transforms for WS63 vendor radio archives.

```text
hisi-rf-link patch-reloc ...
hisi-rf-link verify-layout ...
hisi-rf-link generate-rom-patch ...
hisi-rf-link patch-from-oracle ...
hisi-rf-link task-profile --elf <final-elf> --log <uart-log>
```

The command embeds the reviewed Python implementations, so callers do not reach
into a parent checkout for scripts. Image header/hash semantics remain owned by
`hisi-fwpkg` and are intentionally outside this tool.

`task-profile` emits a versioned JSON report that joins exact task entry
addresses from `RFDBG_TASK`/`RFDBG_TASK_METRIC` UART records with the final ELF
symbol table and the hash-bound `profiles/ws63-scheduling.toml`. It never uses a
nearest-symbol guess: unmatched addresses remain `unknown`, and the report does
not change runtime scheduling policy.
