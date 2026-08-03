#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

import os
import pathlib
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
PORT = ROOT / "port" / "hostap"
INCLUDE = ROOT / "include"
SOURCE = PORT / "hisi_wpa_ap_driver_port.c"
TEST = ROOT / "tests" / "native_authenticator_port.c"
MANIFEST = PORT / "ap-driver.required-symbols"


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, cwd=ROOT, check=True, capture_output=True, text=True
    )


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


def expected_symbols() -> set[tuple[str, str]]:
    result = set()
    for line in MANIFEST.read_text().splitlines():
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
        actual = actual_symbols(llvm_nm(clang), object_path)
        expected = expected_symbols()
        if actual != expected:
            raise RuntimeError(
                "AP driver symbol drift: "
                f"missing={sorted(expected - actual)}, "
                f"extra={sorted(actual - expected)}"
            )
    print("native authenticator AP driver ABI: host lifecycle and RV32 symbols OK")


if __name__ == "__main__":
    main()
