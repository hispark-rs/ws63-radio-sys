# hisi-rf-link

Versioned host-side post-link transforms for WS63 vendor radio archives.

```text
hisi-rf-link patch-reloc ...
hisi-rf-link verify-layout ...
hisi-rf-link generate-rom-patch ...
hisi-rf-link patch-from-oracle ...
```

The command embeds the reviewed Python implementations, so callers do not reach
into a parent checkout for scripts. Image header/hash semantics remain owned by
`hisi-fwpkg` and are intentionally outside this tool.

