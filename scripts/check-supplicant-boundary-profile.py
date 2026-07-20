#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["tomli>=2.0.1; python_version < '3.11'"]
# ///
"""Check the machine-owned upstream/vendor supplicant boundary profile."""

from __future__ import annotations

import json
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
ARTIFACT_MANIFEST = ROOT / "crates/ws63-radio-blob/artifacts/manifest.json"


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

native_roots = boundary["native_root_symbols"]
if len(native_roots) != len(set(native_roots)):
    fail("duplicate native root symbol")
for symbol in native_roots:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol):
        fail(f"invalid native root symbol: {symbol}")

native_archives = boundary["native_archives"]
artifact_manifest = json.loads(ARTIFACT_MANIFEST.read_text())
artifact_profiles = {
    profile["id"]: (profile["archive"], profile["revision"])
    for profile in artifact_manifest["native_supplicant"]["profiles"]
}
expected_profiles: dict[str, tuple[str, str]] = {}
for entry in native_archives:
    profile = entry["profile"]
    archive = entry["archive"]
    revision = entry["revision"]
    if profile in expected_profiles:
        fail(f"duplicate native profile: {profile}")
    if not re.fullmatch(r"lib[A-Za-z0-9_]+\.a", archive):
        fail(f"invalid native archive: {archive}")
    expected_profiles[profile] = (archive, revision)
if expected_profiles != artifact_profiles:
    fail(
        "Cargo artifact profile drift: "
        f"boundary={expected_profiles}, artifact={artifact_profiles}"
    )

build_rs = BUILD_RS.read_text()
for forbidden in ("cc::Build", "build.compile(", "riscv64-unknown-elf-gcc", "riscv64-unknown-elf-ar"):
    if forbidden in build_rs:
        fail(f"consumer build reintroduced host tool: {forbidden}")
for required in (
    "DEP_WS63_RADIO_BLOB_NATIVE_SUPPLICANT_WPA2_ARCHIVE",
    "DEP_WS63_RADIO_BLOB_NATIVE_SUPPLICANT_WPA3_ARCHIVE",
    "native supplicant artifact/profile revision mismatch",
    "cargo:native_supplicant_archive={}",
    "cargo:native_supplicant_root_symbols={}",
):
    if required not in build_rs:
        fail(f"Cargo-delivered native link contract drift: {required}")
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
    f"native_profiles={len(native_archives)}, legacy_archives={len(legacy_archives)}, "
    f"native_markers={len(native_object_markers)}, native_roots={len(native_roots)}, "
    f"legacy_symbols={len(symbols)}"
)
