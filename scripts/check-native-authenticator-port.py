#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

import os
import pathlib
import tomllib
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
PORT = ROOT / "port" / "hostap"
INCLUDE = ROOT / "include"
SOURCE = PORT / "hisi_wpa_ap_driver_port.c"
DRIVER_SOURCE = PORT / "driver_ws63_ap.c"
TEST = ROOT / "tests" / "native_authenticator_port.c"
MANIFEST = PORT / "ap-driver.required-symbols"
DRIVER_MANIFEST = PORT / "driver-ws63-ap.required-symbols"
HOSTAP = ROOT / "third-party" / "hostap"
PROFILES = (
    (PORT / "ap-personal.toml", PORT / "ap-personal.required-symbols"),
    (PORT / "ap-personal-wpa3.toml", PORT / "ap-personal-wpa3.required-symbols"),
)


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, cwd=ROOT, check=False, capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {command[0]}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def riscv_clang() -> str:
    for candidate in (
        os.environ.get("CLANG"),
        "/opt/homebrew/opt/llvm/bin/clang",
        "/usr/local/opt/llvm/bin/clang",
        shutil.which("clang"),
    ):
        resolved = shutil.which(candidate) if candidate else None
        if not resolved:
            continue
        targets = run([resolved, "--print-targets"])
        if "riscv32" in targets.stdout:
            return resolved
    raise RuntimeError("no clang with a RISC-V backend; set CLANG explicitly")


def llvm_nm(clang: str) -> str:
    for candidate in (
        pathlib.Path(clang).with_name("llvm-nm"),
        shutil.which("llvm-nm"),
        shutil.which("nm"),
    ):
        if candidate and pathlib.Path(candidate).is_file():
            return str(candidate)
    raise RuntimeError("llvm-nm is required for the AP ABI drift gate")


def expected_symbols(manifest: pathlib.Path) -> set[tuple[str, str]]:
    result = set()
    for line in manifest.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            result.add(tuple(line.split()))
    return result


def actual_symbols(nm: str, object_path: pathlib.Path) -> set[tuple[str, str]]:
    result = set()
    for line in run([nm, "-g", str(object_path)]).stdout.splitlines():
        columns = line.split()
        if len(columns) == 2 and columns[0] == "U":
            result.add(("undefined", columns[1]))
        elif len(columns) == 3:
            result.add(("defined", columns[2]))
    return result


def external_symbols(nm: str, objects: list[pathlib.Path]) -> set[str]:
    defined = set()
    undefined = set()
    for object_path in objects:
        for kind, symbol in actual_symbols(nm, object_path):
            (defined if kind == "defined" else undefined).add(symbol)
    return undefined - defined


def source_profile(path: pathlib.Path) -> dict[str, object]:
    profile = tomllib.loads(path.read_text())
    base_name = profile.get("extends")
    if base_name is None:
        return profile
    base = source_profile(PORT / str(base_name))
    return {
        "revision": profile["revision"],
        "upstream_sources": [
            *base.get("upstream_sources", []),
            *profile.get("upstream_sources", []),
        ],
        "port_sources": [
            *base.get("port_sources", []),
            *profile.get("port_sources", []),
        ],
        "defines": [*base.get("defines", []), *profile.get("defines", [])],
    }


def main() -> None:
    clang = riscv_clang()
    with tempfile.TemporaryDirectory(prefix="hisi-wpa-ap-port-") as directory:
        output = pathlib.Path(directory)
        executable = output / "native-authenticator-port"
        run([
            os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
            "-Werror", f"-I{INCLUDE}", f"-I{PORT}", str(SOURCE), str(TEST),
            "-o", str(executable),
        ])
        run([str(executable)])

        object_path = output / "hisi_wpa_ap_driver_port.o"
        run([
            clang, "--target=riscv32-unknown-none-elf", "-ffreestanding",
            "-fno-builtin", "-march=rv32imfc", "-mabi=ilp32f",
            f"-I{INCLUDE}", f"-I{PORT}", "-c", str(SOURCE),
            "-o", str(object_path),
        ])
        nm = llvm_nm(clang)
        actual = actual_symbols(nm, object_path)
        expected = expected_symbols(MANIFEST)
        if actual != expected:
            raise RuntimeError(
                "AP driver symbol drift: "
                f"missing={sorted(expected - actual)}, "
                f"extra={sorted(actual - expected)}"
            )

        for profile_path, profile_manifest in PROFILES:
            profile = source_profile(profile_path)
            profile_sources = [
                HOSTAP / source for source in profile["upstream_sources"]
            ] + [PORT / source for source in profile["port_sources"]]
            missing = [str(source) for source in profile_sources if not source.is_file()]
            if missing:
                raise RuntimeError(f"missing authenticator profile sources: {missing}")
            profile_flags = [f"-D{definition}" for definition in profile["defines"]]
            profile_objects = []
            for index, source in enumerate(profile_sources):
                profile_object = output / f"{profile_path.stem}-{index:02d}-{source.stem}.o"
                run([
                    clang, "--target=riscv32-unknown-none-elf", "-ffreestanding",
                    "-fno-builtin", "-march=rv32imfc", "-mabi=ilp32f",
                    "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-Wno-zero-length-array", "-Wno-flexible-array-extensions",
                    "-Wno-unused-parameter", "-Wno-unused-but-set-variable",
                    "-Wno-unused-variable", f"-I{INCLUDE}", f"-I{PORT}",
                    f"-I{HOSTAP / 'hostapd'}", f"-I{HOSTAP / 'src' / 'utils'}",
                    f"-I{HOSTAP / 'src'}", "-include",
                    str(PORT / "hisi_wpa_hostap_compat.h"), *profile_flags,
                    "-c", str(source), "-o", str(profile_object),
                ])
                profile_objects.append(profile_object)
            actual_external = external_symbols(nm, profile_objects)
            expected_external = {
                line.strip()
                for line in profile_manifest.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            }
            if actual_external != expected_external:
                raise RuntimeError(
                    f"AP profile {profile_path.stem} external symbol drift: "
                    f"missing={sorted(expected_external - actual_external)}, "
                    f"extra={sorted(actual_external - expected_external)}"
                )
            print(
                f"native authenticator profile {profile_path.stem}: "
                f"{len(profile_sources)} RV32 objects compiled"
            )

        driver_object = output / "driver_ws63_ap.o"
        run([
            clang, "--target=riscv32-unknown-none-elf", "-ffreestanding",
            "-fno-builtin", "-march=rv32imfc", "-mabi=ilp32f",
            "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-Wno-zero-length-array", "-Wno-flexible-array-extensions",
            "-Wno-unused-parameter",
            "-DOS_NO_C_LIB_DEFINES", f"-I{INCLUDE}", f"-I{PORT}",
            f"-I{HOSTAP / 'wpa_supplicant'}",
            f"-I{HOSTAP / 'src' / 'utils'}", f"-I{HOSTAP / 'src'}",
            "-include", str(PORT / "hisi_wpa_hostap_compat.h"),
            "-c", str(DRIVER_SOURCE), "-o", str(driver_object),
        ])
        actual = actual_symbols(nm, driver_object)
        expected = expected_symbols(DRIVER_MANIFEST)
        if actual != expected:
            raise RuntimeError(
                "WS63 AP driver symbol drift: "
                f"missing={sorted(expected - actual)}, "
                f"extra={sorted(actual - expected)}"
            )
    print("native authenticator AP driver ABI: host lifecycle and RV32 symbols OK")


if __name__ == "__main__":
    main()
