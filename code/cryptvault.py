"""CryptVault launcher: run, install, check, or build without a venv."""

import argparse
import faulthandler
import importlib
import os
import subprocess
import sys
import traceback
from pathlib import Path

_fault_log = None


def log_path():
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "CryptVault"
    base.mkdir(parents=True, exist_ok=True)
    return base / "startup.log"


def report_error(exc, *, popup=True):
    requirements = PROJECT_DIR / "requirements.txt"
    command = f'"{sys.executable}" -m pip install --upgrade -r "{requirements}"'
    message = (
        "CryptVault could not start or encountered an error.\n\n"
        f"{type(exc).__name__}: {exc}\n\n"
        f"Python: {sys.executable}\n\n"
        "Install the libraries with the SAME Python, from the source folder:\n"
        f"{command}\n\n"
        "Or run: python cryptvault.py install"
    )
    try:
        path = log_path()
        if path.exists() and path.stat().st_size > 1024 * 1024:
            path.write_text("", encoding="utf-8")
        with path.open("a", encoding="utf-8") as output:
            output.write("\n" + message + "\n")
            output.write(
                "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            )
        message += f"\n\nDetails: {path}"
    except OSError:
        pass
    if sys.stderr is not None:
        print(message, file=sys.stderr)
    if popup and sys.platform == "win32":
        import ctypes

        ctypes.windll.user32.MessageBoxW(
            None, message, "CryptVault — startup problem", 0x10
        )
    return message


def install_diagnostics():
    global _fault_log
    try:
        path = log_path()
        if path.exists() and path.stat().st_size > 1024 * 1024:
            path.write_text("", encoding="utf-8")
        _fault_log = path.open("a", encoding="utf-8")
        faulthandler.enable(file=_fault_log)
    except (OSError, RuntimeError):
        pass

    def exception_hook(kind, error, tb):
        report_error(error.with_traceback(tb))

    sys.excepthook = exception_hook


PROJECT_DIR = Path(__file__).resolve().parent


def dependency_check():
    from cryptography import __version__ as crypto_version
    from PySide6 import __version__ as qt_version

    importlib.import_module("app")

    print(
        f"Ready: {sys.executable}\nPySide6 {qt_version}\ncryptography {crypto_version}"
    )
    return 0


def install_dependencies(*, build=False):
    packages = ["-r", str(PROJECT_DIR / "requirements.txt")]
    if build:
        packages.append("pyinstaller>=6.22.3")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--upgrade", *packages],
        cwd=PROJECT_DIR,
        check=True,
    )


def build_executable():
    install_dependencies(build=True)
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--clean",
        "--noupx",
        "--name",
        "CryptVault",
    ]
    for package in ("PySide6", "shiboken6", "cryptography"):
        command.extend(["--collect-all", package])
    command.append(str(PROJECT_DIR / "cryptvault.py"))
    subprocess.run(command, cwd=PROJECT_DIR, check=True)
    print(f"Build saved to {PROJECT_DIR / 'dist'}")
    return 0


def run(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        nargs="?",
        default="run",
        choices=("run", "install", "check", "build"),
    )
    args = parser.parse_args(argv)
    command = args.command
    install_diagnostics()
    try:
        if sys.version_info < (3, 10):
            raise RuntimeError("Please install 64-bit Python 3.10 or newer.")
        if command == "install":
            install_dependencies()
            return dependency_check()
        if command == "check":
            return dependency_check()
        if command == "build":
            return build_executable()
        import app

        return app.main()
    except Exception as exc:
        report_error(exc, popup=command == "run")
        return 1


if __name__ == "__main__":
    raise SystemExit(run())
