#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

import os
import pathlib
import re
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
PORT = ROOT / "port" / "hostap"
PROFILE_SPECS = [
    (PORT / "personal.toml", PORT / "native.required-symbols"),
    (PORT / "personal-wpa3.toml", PORT / "native-wpa3.required-symbols"),
]
HOSTAP = ROOT / "third-party" / "hostap"
HOSTAP_SUPPLICANT = HOSTAP / "wpa_supplicant"
HOSTAP_UTILS = ROOT / "third-party" / "hostap" / "src" / "utils"
HOSTAP_SRC = ROOT / "third-party" / "hostap" / "src"
INCLUDE = ROOT / "include"
SOURCES = [
    PORT / "hisi_wpa_port.c",
    PORT / "freestanding_hisi.c",
    PORT / "os_hisi_rtos.c",
    PORT / "eloop_hisi_rtos.c",
    PORT / "hisi_wpa_driver_port.c",
    PORT / "l2_packet_ws63.c",
    PORT / "driver_ws63.c",
]
COMMON = [
    "-std=c11",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wno-unused-parameter",
    "-Wno-variadic-macros",
    "-DOS_NO_C_LIB_DEFINES",
    f"-I{INCLUDE}",
    f"-I{PORT}",
    f"-I{HOSTAP_SUPPLICANT}",
    f"-I{HOSTAP_UTILS}",
    f"-I{HOSTAP_SRC}",
]


def profile_array(profile: pathlib.Path, name: str) -> list[str]:
    text = profile.read_text()
    match = re.search(rf"(?ms)^{re.escape(name)}\s*=\s*\[(.*?)\]", text)
    if not match:
        raise RuntimeError(f"missing {name} in {profile}")
    return re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', match.group(1))


def profile_sources(profile: pathlib.Path) -> list[pathlib.Path]:
    sources = [
        HOSTAP / source for source in profile_array(profile, "upstream_sources")
    ]
    sources.extend(PORT / source for source in profile_array(profile, "port_sources"))
    missing = [str(source) for source in sources if not source.is_file()]
    if missing:
        raise RuntimeError(f"missing native profile sources: {missing}")
    if len(sources) != len(set(sources)):
        raise RuntimeError("duplicate native profile source")
    return sources


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def riscv_clang() -> str:
    candidates = [
        os.environ.get("CLANG"),
        "/opt/homebrew/opt/llvm/bin/clang",
        "/usr/local/opt/llvm/bin/clang",
        shutil.which("clang"),
    ]
    for candidate in candidates:
        resolved = shutil.which(candidate) if candidate else None
        if not resolved:
            continue
        targets = subprocess.run(
            [resolved, "--print-targets"],
            check=False,
            capture_output=True,
            text=True,
        )
        if targets.returncode == 0 and "riscv32" in targets.stdout:
            return resolved
    raise RuntimeError("no clang with a RISC-V backend; set CLANG explicitly")


def llvm_nm(clang: str) -> str:
    candidates = [
        pathlib.Path(clang).with_name("llvm-nm"),
        shutil.which("llvm-nm"),
        *(shutil.which(f"llvm-nm-{version}") for version in range(21, 13, -1)),
        shutil.which("nm"),
    ]
    for candidate in candidates:
        if candidate and pathlib.Path(candidate).is_file():
            return str(candidate)
    raise RuntimeError("llvm-nm is required for the driver symbol drift gate")


def check_driver_symbols(nm: str, driver_object: pathlib.Path) -> None:
    result = subprocess.run(
        [nm, "-g", str(driver_object)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    actual: set[tuple[str, str]] = set()
    for line in result.stdout.splitlines():
        columns = line.split()
        if len(columns) == 2 and columns[0] == "U":
            actual.add(("undefined", columns[1]))
        elif len(columns) == 3:
            actual.add(("defined", columns[2]))

    expected: set[tuple[str, str]] = set()
    manifest = PORT / "driver_ws63.required-symbols"
    for line in manifest.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        kind, symbol = line.split()
        expected.add((kind, symbol))
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise RuntimeError(
            f"driver_ws63 symbol drift: missing={missing}, extra={extra}"
        )


def object_symbols(nm: str, object_path: pathlib.Path) -> tuple[set[str], set[str]]:
    result = subprocess.run(
        [nm, "-g", str(object_path)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    defined: set[str] = set()
    undefined: set[str] = set()
    for line in result.stdout.splitlines():
        columns = line.split()
        if len(columns) == 2 and columns[0] == "U":
            undefined.add(columns[1])
        elif len(columns) >= 3 and columns[-2] != "U":
            defined.add(columns[-1])
    return defined, undefined


def check_native_external_symbols(
    nm: str, objects: list[pathlib.Path], manifest: pathlib.Path
) -> None:
    defined: set[str] = set()
    undefined: set[str] = set()
    for object_path in objects:
        object_defined, object_undefined = object_symbols(nm, object_path)
        defined.update(object_defined)
        undefined.update(object_undefined)
    actual = undefined - defined
    expected = {
        line.strip()
        for line in manifest.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }
    if actual != expected:
        raise RuntimeError(
            "native supplicant external symbol drift: "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )


def check_restricted_scan_formats(
    profile: pathlib.Path, sources: list[pathlib.Path]
) -> None:
    actual: set[str] = set()
    pattern = re.compile(r'\bsscanf\s*\(\s*[^,\n]+,\s*"([^"]*)"')
    for source in sources:
        actual.update(pattern.findall(source.read_text(errors="replace")))
    expected = set(profile_array(profile, "sscanf_formats"))
    if actual != expected:
        raise RuntimeError(
            f"restricted sscanf format drift: expected={sorted(expected)}, "
            f"actual={sorted(actual)}"
        )


def main() -> None:
    host_cc = os.environ.get("CC", "cc")
    clang = riscv_clang()
    nm = llvm_nm(clang)
    with tempfile.TemporaryDirectory(prefix="hisi-wpa-port-") as directory:
        output = pathlib.Path(directory)
        for name, extra_defines in (
            ("personal", []),
            ("personal-wpa3", ["-DCONFIG_SAE"]),
        ):
            executable = output / f"native-port-test-{name}"
            run(
                [host_cc, *COMMON, *extra_defines, *map(str, SOURCES),
                 str(ROOT / "tests" / "native_supplicant_port.c"),
                 "-o", str(executable)]
            )
            run([str(executable)])

        for profile_index, (profile, manifest) in enumerate(PROFILE_SPECS):
            native_sources = profile_sources(profile)
            profile_defines = [
                f"-D{definition}" for definition in profile_array(profile, "defines")
            ]
            objects: dict[str, pathlib.Path] = {}
            all_objects: list[pathlib.Path] = []
            cross_flags = [
                flag for flag in COMMON if flag != "-DOS_NO_C_LIB_DEFINES"
            ]
            cross_flags.extend([
                "-Wno-zero-length-array",
                "-Wno-flexible-array-extensions",
                "-Wno-unused-but-set-variable",
                "-Wno-unused-variable",
                "-include",
                str(PORT / "hisi_wpa_hostap_compat.h"),
                *profile_defines,
            ])
            for index, source in enumerate(native_sources):
                object_path = output / f"{profile_index}-{index:02d}-{source.stem}.o"
                run(
                    [clang, "--target=riscv32-unknown-none-elf", "-ffreestanding",
                     "-fno-builtin", "-march=rv32imfc", "-mabi=ilp32f",
                     *cross_flags, "-c", str(source),
                     "-o", str(object_path)]
                )
                objects[source.name] = object_path
                all_objects.append(object_path)
            if len(all_objects) != len(native_sources):
                raise RuntimeError("native profile object count drift")
            check_driver_symbols(nm, objects["driver_ws63.c"])
            check_native_external_symbols(nm, all_objects, manifest)
            check_restricted_scan_formats(profile, native_sources)
            print(
                f"native supplicant profile {profile.stem}: "
                f"{len(all_objects)} RV32 objects, "
                f"{len(profile_array(profile, 'defines'))} defines, "
                "external ABI locked"
            )


if __name__ == "__main__":
    main()
