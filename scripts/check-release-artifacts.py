#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["zstandard==0.23.0"]
# ///

import hashlib
import json
import pathlib
import subprocess
import tempfile
import tomllib

import zstandard


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE = ROOT / "crates" / "hisi-rf-link" / "profiles" / "ws63.toml"
PAYLOAD = ROOT / "crates" / "ws63-radio-blob" / "artifacts"
ORACLE = ROOT / "ws63-RF" / "lib"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def host_target() -> str:
    output = subprocess.run(
        ["rustc", "-vV"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for line in output.splitlines():
        if line.startswith("host: "):
            return line.removeprefix("host: ")
    raise RuntimeError("rustc -vV did not report a host target")


def unpack(name: str) -> bytes:
    source = PAYLOAD / f"{name}.zst"
    if not source.is_file():
        raise RuntimeError(f"missing packaged release artifact: {source}")
    return zstandard.ZstdDecompressor().decompress(source.read_bytes())


def main() -> None:
    profile = tomllib.loads(PROFILE.read_text())
    committed = json.loads((PAYLOAD / "manifest.json").read_text())
    committed_by_name = {
        artifact["archive"]: artifact for artifact in committed["artifacts"]
    }
    archive_names = [f"lib{entry['name']}.a" for entry in profile["wifi_archives"]]
    inputs = [ORACLE / name for name in archive_names]
    missing = [str(path) for path in inputs if not path.is_file()]
    if missing:
        raise RuntimeError(f"missing ws63-RF release inputs: {missing}")

    with tempfile.TemporaryDirectory(prefix="ws63-radio-release-") as directory:
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
                profile["normalized_artifact_revision"],
                "--out-dir",
                str(output),
                "--manifest",
                str(generated_manifest),
                *(str(path) for path in inputs),
            ],
            cwd=ROOT,
            check=True,
        )
        generated = json.loads(generated_manifest.read_text())

        if generated["profile_revision"] != committed["profile_revision"]:
            raise RuntimeError("normalization profile revision drift")

        for artifact in generated["artifacts"]:
            name = artifact["archive"]
            expected = committed_by_name.get(name)
            if expected is None:
                raise RuntimeError(f"generated unlisted release artifact: {name}")
            for field in (
                "input_sha256",
                "output_sha256",
                "input_size",
                "output_size",
                "transformations",
            ):
                if artifact[field] != expected[field]:
                    raise RuntimeError(
                        f"{name} {field} drift: "
                        f"generated={artifact[field]!r}, committed={expected[field]!r}"
                    )
            generated_bytes = (output / name).read_bytes()
            packaged_bytes = unpack(name)
            if generated_bytes != packaged_bytes:
                raise RuntimeError(f"{name} packaged bytes are not reproducible")
            if sha256(packaged_bytes) != expected["output_sha256"]:
                raise RuntimeError(f"{name} packaged SHA-256 drift")
            print(f"{name}: reproducible ({len(packaged_bytes)} bytes)")

    callback_name = "librom_callback.a"
    callback = ORACLE / callback_name
    callback_expected = committed_by_name[callback_name]
    callback_bytes = callback.read_bytes()
    if callback_bytes != unpack(callback_name):
        raise RuntimeError("ROM callback archive differs from pinned ws63-RF input")
    if sha256(callback_bytes) != callback_expected["output_sha256"]:
        raise RuntimeError("ROM callback archive SHA-256 drift")
    print(f"{callback_name}: reproducible ({len(callback_bytes)} bytes)")


if __name__ == "__main__":
    main()
