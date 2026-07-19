#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["tomli>=2.0.1; python_version < '3.11'"]
# ///
"""Check the bounded WS63 kernel/architecture compatibility namespace."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9/3.10 through the uv single-script contract.
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_PROFILE = ROOT / "crates/hisi-rf-link/profiles/ws63.toml"
COMPAT_PROFILE = ROOT / "crates/hisi-rf-link/profiles/ws63-runtime-compat.toml"
PAYLOAD_LIB = ROOT / "ws63-RF/lib"


def fail(message: str) -> None:
    print(f"runtime compatibility profile: {message}", file=sys.stderr)
    raise SystemExit(1)


archive_profile = tomllib.loads(ARCHIVE_PROFILE.read_text())
compat_profile = tomllib.loads(COMPAT_PROFILE.read_text())
if compat_profile["archive_profile_revision"] != archive_profile["revision"]:
    fail("archive profile revision drift")

patterns = [re.compile(pattern) for pattern in compat_profile["namespace_patterns"]]
entries = compat_profile["symbols"]
names = [entry["name"] for entry in entries]
if len(names) != len(set(names)):
    fail("duplicate symbol")

for entry in entries:
    classification = entry["classification"]
    if classification not in {"provided", "off-path"}:
        fail(f"invalid classification for {entry['name']}: {classification}")
    if classification == "provided" and not entry.get("provider"):
        fail(f"provided symbol has no owner: {entry['name']}")
    if not any(pattern.search(entry["name"]) for pattern in patterns):
        fail(f"symbol is outside the declared namespace: {entry['name']}")

nm = os.environ.get("NM") or shutil.which("riscv64-unknown-elf-nm") or shutil.which("llvm-nm")
if not nm:
    fail("no RISC-V-capable nm found (set NM or install riscv64-unknown-elf-nm)")

archives = [
    PAYLOAD_LIB / f"lib{entry['name']}.a" for entry in archive_profile["wifi_archives"]
]
missing = [str(path) for path in archives if not path.is_file()]
if missing:
    fail(f"missing Wi-Fi archives: {', '.join(missing)}")

result = subprocess.run(
    [nm, "--undefined-only", "--format=posix", *map(str, archives)],
    check=True,
    text=True,
    capture_output=True,
)
actual = {
    line.split()[0]
    for line in result.stdout.splitlines()
    if line.split() and any(pattern.search(line.split()[0]) for pattern in patterns)
}
expected = set(names)
if actual != expected:
    fail(
        "archive namespace drift: "
        f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}"
    )

provided = sum(entry["classification"] == "provided" for entry in entries)
off_path = len(entries) - provided
print(
    f"runtime compatibility profile OK: {len(entries)} archive symbols "
    f"({provided} provided, {off_path} off-path)"
)
