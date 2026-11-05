"""Automatically compile CryptVault for the current OS: python compul.py."""

import argparse
import platform
import struct
import subprocess
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
SUPPORTED_SYSTEMS = {"Windows", "Darwin", "Linux"}


def build_command(system):
    """Choose a native executable, or an app bundle on macOS."""
    if system not in SUPPORTED_SYSTEMS:
        raise ValueError(f"Unsupported operating system: {system}")
    command = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--noupx", "--name", "CryptVault",
        "--onedir" if system == "Darwin" else "--onefile",
        "--distpath", str(PROJECT_DIR / "dist"),
        "--workpath", str(PROJECT_DIR / "build"),
        "--specpath", str(PROJECT_DIR / "build"),
    ]
    if system in {"Windows", "Darwin"}:
        command.append("--windowed")
    for package in ("PySide6", "shiboken6", "cryptography"):
        command.extend(["--collect-all", package])
    command.append(str(PROJECT_DIR / "cryptvault.py"))
    return command


def output_path(system):
    name = {"Windows": "CryptVault.exe", "Darwin": "CryptVault.app",
            "Linux": "CryptVault"}[system]
    return PROJECT_DIR / "dist" / name


def build(*, check_only=False):
    """Check the host, install dependencies, and compile with this Python."""
    try:
        if getattr(sys, "frozen", False):
            raise RuntimeError("Run compul.py with Python from the source folder.")
        if sys.version_info < (3, 10) or struct.calcsize("P") != 8:
            raise RuntimeError("Install 64-bit Python 3.10 or newer to compile the app.")
        system = platform.system()
        command = build_command(system)
        for name in ("cryptvault.py", "app.py", "crypto_engine.py", "requirements.txt"):
            if not (PROJECT_DIR / name).is_file():
                raise FileNotFoundError(f"Missing source file: {PROJECT_DIR / name}")

        print(f"Detected OS: {system} ({platform.machine()})", flush=True)
        print(f"Python: {sys.executable}", flush=True)
        print(f"Output: {output_path(system)}", flush=True)
        if check_only:
            print("Build plan is ready. No downloads or compilation were performed.")
            return 0

        print("\n1/3 Checking pip...", flush=True)
        pip = subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if pip.returncode:
            subprocess.run([sys.executable, "-m", "ensurepip", "--upgrade"], check=True)

        print("\n2/3 Installing runtime libraries and PyInstaller...", flush=True)
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade",
             "-r", str(PROJECT_DIR / "requirements.txt"), "pyinstaller>=6.22.3"],
            cwd=PROJECT_DIR, check=True,
        )
        print("\n3/3 Compiling CryptVault...", flush=True)
        subprocess.run(command, cwd=PROJECT_DIR, check=True)
        result = output_path(system)
        if not result.exists():
            raise RuntimeError(f"The builder finished but its output is missing: {result}")
        print(f"\nDone! Your compiled app is at:\n{result}", flush=True)
        return 0
    except KeyboardInterrupt:
        print("\nCompilation cancelled.", file=sys.stderr)
        return 130
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"\nCould not compile CryptVault: {exc}", file=sys.stderr)
        print("See the messages above for the failing step.", file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="Show the detected OS and output path without building.")
    return build(check_only=parser.parse_args().check)


if __name__ == "__main__":
    raise SystemExit(main())
