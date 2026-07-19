#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

import os
import pathlib
import re
import shlex
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
HOSTAP = ROOT / "third-party" / "hostap"
SAE_FUZZ = HOSTAP / "tests" / "fuzzing" / "sae"
SAE_BUILD = HOSTAP / "build" / "tests" / "fuzzing" / "sae"
VECTOR_SOURCE = ROOT / "tests" / "upstream_personal_vectors.c"

EXPECTED_SAE_CORPUS = {
    "sae-commit-h2e-rejected-groups.dat": (0, 1),
    "sae-commit-h2e-token.dat": (0, 0),
    "sae-commit-pw-id.dat": (0, 0),
    "sae-commit-token.dat": (0, 1),
    "sae-commit-valid.dat": (0, 0),
}


def capture(command: list[str], **kwargs: object) -> str:
    return subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
        **kwargs,
    ).stdout


def pkg_config(*arguments: str) -> list[str]:
    return shlex.split(capture(["pkg-config", *arguments, "openssl"]).strip())


def build_sae_oracle() -> None:
    shutil.rmtree(SAE_BUILD, ignore_errors=True)
    environment = os.environ.copy()
    openssl_cflags = " ".join(pkg_config("--cflags"))
    openssl_library_dirs = " ".join(pkg_config("--libs-only-L"))
    environment["CFLAGS"] = f"-MMD -O2 -Wall -g {openssl_cflags}".strip()
    environment["LDFLAGS"] = openssl_library_dirs
    subprocess.run(
        ["make", "-C", str(SAE_FUZZ), "clean", "all"],
        cwd=ROOT,
        check=True,
        env=environment,
    )


def replay_sae_corpus() -> None:
    executable = SAE_FUZZ / "sae"
    corpus = SAE_FUZZ / "corpus"
    environment = os.environ.copy()
    environment["WPADEBUG"] = "0"
    seen = {path.name for path in corpus.glob("*.dat")}
    if seen != set(EXPECTED_SAE_CORPUS):
        raise RuntimeError(
            "SAE corpus drift: "
            f"missing={sorted(set(EXPECTED_SAE_CORPUS) - seen)}, "
            f"extra={sorted(seen - set(EXPECTED_SAE_CORPUS))}"
        )
    for name, expected in sorted(EXPECTED_SAE_CORPUS.items()):
        result = subprocess.run(
            [str(executable), str(corpus / name)],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
            env=environment,
        )
        output = result.stdout + result.stderr
        statuses = tuple(
            int(value)
            for value in re.findall(r"sae_parse_commit\([01]\): (\d+)", output)
        )
        if statuses != expected:
            raise RuntimeError(
                f"SAE corpus result drift for {name}: "
                f"expected={expected}, actual={statuses}"
            )


def build_and_run_personal_vectors() -> None:
    compiler = os.environ.get("CC", "cc")
    include_flags = [
        f"-I{HOSTAP / 'src'}",
        f"-I{HOSTAP / 'src' / 'utils'}",
        f"-I{HOSTAP / 'wpa_supplicant'}",
    ]
    objects = [
        SAE_BUILD / "src" / "crypto" / "crypto_openssl.o",
        SAE_BUILD / "src" / "crypto" / "dh_groups.o",
        SAE_BUILD / "src" / "crypto" / "sha1-prf.o",
        SAE_BUILD / "src" / "crypto" / "sha256-prf.o",
        SAE_BUILD / "src" / "crypto" / "sha256-kdf.o",
        SAE_BUILD / "src" / "common" / "dragonfly.o",
        SAE_BUILD / "src" / "common" / "libcommon.a",
        SAE_BUILD / "src" / "utils" / "libutils.a",
    ]
    missing = [str(path) for path in objects if not path.is_file()]
    if missing:
        raise RuntimeError(f"missing upstream SAE build artifacts: {missing}")
    with tempfile.TemporaryDirectory(prefix="hisi-wpa-vectors-") as directory:
        executable = pathlib.Path(directory) / "upstream-personal-vectors"
        subprocess.run(
            [
                compiler,
                "-std=gnu11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-unused-parameter",
                "-DCONFIG_SHA256",
                "-DCONFIG_ECC",
                "-DCONFIG_SAE",
                *include_flags,
                *pkg_config("--cflags"),
                str(VECTOR_SOURCE),
                *map(str, objects),
                *pkg_config("--libs"),
                "-o",
                str(executable),
            ],
            cwd=ROOT,
            check=True,
        )
        subprocess.run([str(executable)], cwd=ROOT, check=True)


def main() -> None:
    build_sae_oracle()
    replay_sae_corpus()
    build_and_run_personal_vectors()
    print(
        "upstream personal vectors: WPA2 PTK/MIC, RSNE/PMF, "
        "SAE HnP/H2E roundtrips, 5 SAE corpus fixtures"
    )


if __name__ == "__main__":
    main()
