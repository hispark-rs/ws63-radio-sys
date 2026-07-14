#!/usr/bin/env python3

import os
import pathlib
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
PORT = ROOT / "port" / "hostap"
HOSTAP_UTILS = ROOT / "third-party" / "hostap" / "src" / "utils"
HOSTAP_SRC = ROOT / "third-party" / "hostap" / "src"
INCLUDE = ROOT / "include"
SOURCES = [
    PORT / "hisi_wpa_port.c",
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
    "-Wpedantic",
    "-Wno-unused-parameter",
    "-Wno-variadic-macros",
    "-Wno-zero-length-array",
    "-Wno-flexible-array-extensions",
    f"-I{INCLUDE}",
    f"-I{PORT}",
    f"-I{HOSTAP_UTILS}",
    f"-I{HOSTAP_SRC}",
]


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


def main() -> None:
    host_cc = os.environ.get("CC", "cc")
    clang = riscv_clang()
    nm = llvm_nm(clang)
    with tempfile.TemporaryDirectory(prefix="hisi-wpa-port-") as directory:
        output = pathlib.Path(directory)
        executable = output / "native-port-test"
        run(
            [host_cc, *COMMON, *map(str, SOURCES),
             str(ROOT / "tests" / "native_supplicant_port.c"),
             "-o", str(executable)]
        )
        run([str(executable)])

        objects: dict[str, pathlib.Path] = {}
        for source in SOURCES:
            object_path = output / f"{source.stem}.o"
            run(
                [clang, "--target=riscv32-unknown-none-elf", "-ffreestanding",
                 "-fno-builtin", *COMMON, "-c", str(source),
                 "-o", str(object_path)]
            )
            objects[source.name] = object_path
        check_driver_symbols(nm, objects["driver_ws63.c"])


if __name__ == "__main__":
    main()
