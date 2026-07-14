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
]
COMMON = [
    "-std=c11",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wpedantic",
    "-Wno-unused-parameter",
    "-Wno-variadic-macros",
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


def main() -> None:
    host_cc = os.environ.get("CC", "cc")
    clang = riscv_clang()
    with tempfile.TemporaryDirectory(prefix="hisi-wpa-port-") as directory:
        output = pathlib.Path(directory)
        executable = output / "native-port-test"
        run(
            [host_cc, *COMMON, *map(str, SOURCES),
             str(ROOT / "tests" / "native_supplicant_port.c"),
             "-o", str(executable)]
        )
        run([str(executable)])

        for source in SOURCES:
            run(
                [clang, "--target=riscv32-unknown-none-elf", "-ffreestanding",
                 "-fno-builtin", *COMMON, "-c", str(source),
                 "-o", str(output / f"{source.stem}.o")]
            )


if __name__ == "__main__":
    main()
