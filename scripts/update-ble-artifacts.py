#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["zstandard==0.23.0"]
# ///
"""Normalize and package the hash-bound WS63 BLE host/controller archives."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import tomllib

import zstandard


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE = ROOT / "crates" / "hisi-rf-link" / "profiles" / "ws63-ble-b0.toml"
INIT_PROFILE = ROOT / "crates" / "hisi-rf-link" / "profiles" / "ws63-ble-b1.toml"
PAYLOAD = ROOT / "crates" / "ws63-radio-blob" / "artifacts"
ORACLE = ROOT / "ws63-RF" / "lib"
MANIFEST = PAYLOAD / "manifest.json"


def host_target() -> str:
    output = subprocess.run(
        ["rustc", "-vV"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout
    for line in output.splitlines():
        if line.startswith("host: "):
            return line.removeprefix("host: ")
    raise RuntimeError("rustc -vV did not report a host target")


def main() -> None:
    profile = tomllib.loads(PROFILE.read_text())
    init_profile = tomllib.loads(INIT_PROFILE.read_text())
    names = [entry["archive"] for entry in profile["archives"]]
    controller_names = [
        entry["archive"] for entry in init_profile["controller_archives"]
    ]
    normalized = [name for name in names if name != "libbg_common.a"] + controller_names

    with tempfile.TemporaryDirectory(prefix="ws63-ble-b0-") as directory:
        output = pathlib.Path(directory)
        generated_manifest = output / "manifest.json"
        subprocess.run(
            [
                "cargo",
                "run",
                "--quiet",
                "-p",
                "hisi-rf-link",
                "--target",
                host_target(),
                "--locked",
                "--",
                "normalize",
                "--profile-revision",
                "ws63-ble-b1-normalized-v1",
                "--out-dir",
                str(output),
                "--manifest",
                str(generated_manifest),
                *(str(ORACLE / name) for name in normalized),
            ],
            cwd=ROOT,
            check=True,
        )
        generated = json.loads(generated_manifest.read_text())
        compressor = zstandard.ZstdCompressor(level=19)
        for artifact in generated["artifacts"]:
            name = artifact["archive"]
            (PAYLOAD / f"{name}.zst").write_bytes(
                compressor.compress((output / name).read_bytes())
            )

    manifest = json.loads(MANIFEST.read_text())
    by_name = {artifact["archive"]: artifact for artifact in manifest["artifacts"]}
    for artifact in generated["artifacts"]:
        by_name[artifact["archive"]] = artifact
    existing_order = [artifact["archive"] for artifact in manifest["artifacts"]]
    for name in normalized:
        if name not in existing_order:
            existing_order.append(name)
    manifest["artifacts"] = [by_name[name] for name in existing_order]
    manifest["ble_profile"] = {
        "revision": profile["revision"],
        "normalization_revision": "ws63-ble-b0-normalized-v1",
        "archives": names,
        "required_symbol_report": "hisi-rf-link/profiles/ws63-ble-b0-report.json",
        "init_revision": init_profile["revision"],
        "init_normalization_revision": "ws63-ble-b1-normalized-v1",
        "controller_archives": controller_names,
        "init_required_symbol_report": "hisi-rf-link/profiles/ws63-ble-b1-report.json",
    }
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
