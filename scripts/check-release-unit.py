#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""Validate the packages that form the ws63-radio-sys release unit."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = {
    "hisi-rf-link": ROOT / "crates/hisi-rf-link/Cargo.toml",
    "ws63-radio-blob": ROOT / "crates/ws63-radio-blob/Cargo.toml",
    "ws63-radio-sys": ROOT / "crates/ws63-radio-sys/Cargo.toml",
}


def load_manifest(path: Path) -> dict:
    with path.open("rb") as manifest:
        return tomllib.load(manifest)


def dependency_version(manifest: dict, section: str, name: str) -> str | None:
    dependency = manifest.get(section, {}).get(name)
    if isinstance(dependency, str):
        return dependency
    if isinstance(dependency, dict):
        version = dependency.get("version")
        return version if isinstance(version, str) else None
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", default="", help="release tag to validate")
    parser.add_argument("--print-version", action="store_true")
    args = parser.parse_args()

    manifests = {name: load_manifest(path) for name, path in PACKAGES.items()}
    versions = {
        name: manifest["package"]["version"]
        for name, manifest in manifests.items()
    }
    unique_versions = set(versions.values())
    if len(unique_versions) != 1:
        print(f"release-unit versions differ: {versions}", file=sys.stderr)
        return 1

    version = unique_versions.pop()
    sys_manifest = manifests["ws63-radio-sys"]
    exact = f"={version}"
    internal_dependencies = {
        "hisi-rf-link": dependency_version(
            sys_manifest, "build-dependencies", "hisi-rf-link"
        ),
        "ws63-radio-blob": dependency_version(
            sys_manifest, "dependencies", "ws63-radio-blob"
        ),
    }
    invalid = {
        name: requirement
        for name, requirement in internal_dependencies.items()
        if requirement != exact
    }
    if invalid:
        print(
            f"ws63-radio-sys must pin release-unit dependencies to {exact}: {invalid}",
            file=sys.stderr,
        )
        return 1

    if args.tag and args.tag != f"v{version}":
        print(
            f"tag {args.tag!r} does not match release-unit version v{version}",
            file=sys.stderr,
        )
        return 1

    if args.print_version:
        print(version)
    else:
        print(f"release unit {version}: {', '.join(PACKAGES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
