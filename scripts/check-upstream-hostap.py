#!/usr/bin/env python3
"""Verify the pinned upstream hostap source and supplicant ABI contract."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "upstream/hostap-2.11.json"


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", ROOT / "third-party/hostap", *args], text=True
    ).strip()


def main() -> int:
    metadata = json.loads(MANIFEST.read_text())
    actual = git("rev-parse", "HEAD")
    expected = metadata["commit"]
    if actual != expected:
        raise SystemExit(f"hostap submodule drift: expected {expected}, got {actual}")

    tags = git("tag", "--points-at", "HEAD").splitlines()
    if metadata["tag"] not in tags:
        raise SystemExit(f"hostap commit is not tagged {metadata['tag']}")

    version_header = (
        ROOT / "third-party/hostap/src/common/version.h"
    ).read_text()
    match = re.search(r'#define VERSION_STR "([^"]+)"', version_header)
    if not match or match.group(1) != metadata["version"]:
        raise SystemExit("hostap VERSION_STR does not match the source manifest")

    digest = metadata["release_archive"]["sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit("invalid release archive SHA-256")
    print(f"hostap {metadata['version']} pinned at {actual}; release sha256={digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
