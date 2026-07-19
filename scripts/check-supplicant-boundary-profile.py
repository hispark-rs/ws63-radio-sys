#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["tomli>=2.0.1; python_version < '3.11'"]
# ///
"""Check the machine-owned upstream/vendor supplicant boundary profile."""

from __future__ import annotations

import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9/3.10 through the uv single-script contract.
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_PROFILE = ROOT / "crates/hisi-rf-link/profiles/ws63.toml"
BOUNDARY_PROFILE = ROOT / "crates/hisi-rf-link/profiles/ws63-supplicant-boundary.toml"
BUILD_RS = ROOT / "crates/ws63-radio-sys/build.rs"


def fail(message: str) -> None:
    print(f"supplicant boundary profile: {message}", file=sys.stderr)
    raise SystemExit(1)


archive_profile = tomllib.loads(ARCHIVE_PROFILE.read_text())
boundary = tomllib.loads(BOUNDARY_PROFILE.read_text())
if boundary["archive_profile_revision"] != archive_profile["revision"]:
    fail("archive profile revision drift")

legacy_archives = boundary["legacy_archives"]
if len(legacy_archives) != len(set(legacy_archives)):
    fail("duplicate legacy archive")
expected_archives = {
    f"lib{entry['name']}.a" for entry in archive_profile["wpa_archives"]
}
if set(legacy_archives) != expected_archives:
    fail(
        "legacy archive inventory drift: "
        f"missing={sorted(expected_archives - set(legacy_archives))}, "
        f"unexpected={sorted(set(legacy_archives) - expected_archives)}"
    )

symbols = boundary["legacy_provider_symbols"]
if len(symbols) != len(set(symbols)):
    fail("duplicate legacy provider symbol")
for symbol in symbols:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol):
        fail(f"invalid provider symbol: {symbol}")

native_archive = boundary["native_archive"]
if not re.fullmatch(r"lib[A-Za-z0-9_]+\.a", native_archive):
    fail(f"invalid native archive: {native_archive}")
compile_name = native_archive.removeprefix("lib").removesuffix(".a")
if f'build.compile("{compile_name}")' not in BUILD_RS.read_text():
    fail(f"cc-rs output drift: expected build.compile(\"{compile_name}\")")
native_object_markers = boundary["native_object_markers"]
if len(native_object_markers) != len(set(native_object_markers)):
    fail("duplicate native object marker")
native_port = ROOT / "port/hostap"
for marker in native_object_markers:
    if not re.fullmatch(r"[A-Za-z0-9_]+\.o", marker):
        fail(f"invalid native object marker: {marker}")
    source = native_port / f"{marker.removesuffix('.o')}.c"
    if not source.is_file():
        fail(f"native object marker has no port source: {source.relative_to(ROOT)}")

print(
    "supplicant boundary profile OK: "
    f"native={native_archive}, legacy_archives={len(legacy_archives)}, "
    f"native_markers={len(native_object_markers)}, legacy_symbols={len(symbols)}"
)
