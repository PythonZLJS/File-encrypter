"""
CryptVault - Fast, secure, streaming file/folder encryption with a
liquid-glass GUI and a choice of authenticated encryption algorithms.
Cross-platform: Windows / macOS / Linux (compile separately on each OS -
see README.md, or use build_windows.bat / build_unix.sh).

Run:   python main.py
Build: pyinstaller --onefile --windowed --name CryptVault main.py
"""

import sys
import os
import struct
import secrets
import string
import re
import time
import zipfile
import tempfile
import threading
import subprocess
import hashlib
from pathlib import Path
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM, ChaCha20Poly1305, AESGCMSIV, AESOCB3, AESCCM
)
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QFileDialog, QProgressBar, QCheckBox, QFrame, QMessageBox,
    QGraphicsDropShadowEffect, QListWidget, QListWidgetItem, QTextEdit,
    QAbstractItemView, QComboBox, QScrollArea, QSizePolicy, QLayout, QMenu,
    QTabWidget, QDialog, QTableWidget, QTableWidgetItem, QHeaderView
)
from PySide6.QtCore import (
    Qt, QObject, Signal, QRunnable, QThreadPool, QSettings, QRect, QPoint, QSize, QTimer
)
from PySide6.QtGui import (
    QColor, QFont, QPainter, QLinearGradient, QRadialGradient, QBrush,
    QDragEnterEvent, QDropEvent, QAction
)

# ========================================================================
# CRYPTO ENGINE  (streaming - constant memory use regardless of file size)
# ========================================================================
# On-disk format (version 3):
#   MAGIC(4)="CVL3" | VERSION(1) | LAYERS(1) | IS_FOLDER(1) | KDF_PRESET(8, padded)
#   for each layer: CIPHER_ID(1) | SALT(16) | NONCE_PREFIX(4)
#   then a sequence of chunks until EOF:
#       LEN(4, big-endian) | CIPHERTEXT (includes AEAD authentication tag)
#
# Because each layer's CIPHER_ID is stored right in the file, decrypting
# NEVER requires knowing which "Encryption Type" was used to encrypt -
# the app reads it straight out of the header and picks the right
# algorithm(s) automatically, every time.
#
# Each chunk is authenticated with associated data binding its index and
# whether it's the final chunk, so chunks can't be reordered, dropped, or
# the file truncated without decryption failing. Nonces are never reused:
# built from a random 4-byte prefix (per layer, per file) + an 8-byte
# big-endian counter. Key derivation uses scrypt (memory-hard).

MAGIC = b"CVL3"
VERSION = 3
KEY_LEN = 32
CHUNK_SIZE = 1024 * 1024  # 1 MB chunks - keeps memory flat & progress smooth
SHRED_PASSES = 3

SCRYPT_PRESETS = {
    "fast":     dict(n=2 ** 14, r=8, p=1),
    "balanced": dict(n=2 ** 15, r=8, p=1),
    "paranoid": dict(n=2 ** 17, r=8, p=1),
}

# ---- Individual cipher algorithms available to build an Encryption Type from ----
CIPHER_REGISTRY = {
    0: AESGCM,
    1: ChaCha20Poly1305,
    2: AESGCMSIV,
    3: AESOCB3,
    4: AESCCM,
}
CIPHER_NAMES = {
    0: "AES-256-GCM",
    1: "ChaCha20-Poly1305",
    2: "AES-256-GCM-SIV",
    3: "AES-256-OCB3",
    4: "AES-256-CCM",
}

# ---- Named "Encryption Type" presets offered in the GUI ----
# Each is an ordered list of cipher IDs (innermost layer first). All of
# these are strong, modern, authenticated ciphers - none is "weak"; the
# differences are about speed, hardware support, and defense-in-depth.
ENCRYPTION_TYPES = [
    {
        "name": "AES-256-GCM (Standard)",
        "ciphers": [0],
        "summary": "The industry-standard choice - what TLS and most disk encryption uses.",
        "pros": "Extremely fast on virtually all modern CPUs thanks to hardware AES "
                "acceleration (AES-NI). The most widely used, audited, and battle-tested "
                "authenticated cipher in the world today.",
        "cons": "None significant for personal use. In general, GCM's security depends on "
                "nonces never repeating - this app already guarantees that automatically, "
                "so this isn't something you need to worry about.",
    },
    {
        "name": "ChaCha20-Poly1305 (Software-Friendly)",
        "ciphers": [1],
        "summary": "A modern cipher designed to run fast even without special CPU hardware.",
        "pros": "Consistently fast on CPUs that lack AES hardware acceleration (some older "
                "PCs, budget devices, certain ARM chips). Its software implementation runs "
                "in constant time by design, which gives strong resistance to timing-based "
                "side-channel attacks.",
        "cons": "On a modern desktop/laptop with AES-NI, it's usually a little slower than "
                "plain AES-256-GCM.",
    },
    {
        "name": "AES-256-GCM-SIV (Misuse-Resistant)",
        "ciphers": [2],
        "summary": "AES-GCM's more forgiving sibling - safer if a nonce were ever reused.",
        "pros": "Provides the same strong security as AES-GCM, but is specifically designed "
                "to stay safe even in the unlikely event a nonce gets reused - a property "
                "called 'nonce-misuse resistance'. Good extra peace of mind.",
        "cons": "Slightly slower than plain AES-GCM, and less commonly deployed in the wild, "
                "so it has had less real-world scrutiny than GCM (though it's well-studied "
                "academically).",
    },
    {
        "name": "AES-256-OCB3 (High Performance)",
        "ciphers": [3],
        "summary": "One of the fastest authenticated ciphers available, fully parallelizable.",
        "pros": "Very high throughput with minimal computational overhead - often the "
                "fastest option on capable hardware. Good choice when raw speed on huge "
                "files/folders matters most.",
        "cons": "Was patent-encumbered for many years (patents expired in 2021), so it's "
                "less universally adopted than GCM and isn't FIPS-approved, meaning it "
                "shows up less often in compliance-driven software.",
    },
    {
        "name": "AES-256-CCM (Compact / IoT Standard)",
        "ciphers": [4],
        "summary": "A well-established cipher used in Bluetooth, Zigbee, and WPA2.",
        "pros": "Extremely widely deployed in constrained and embedded devices, meaning it's "
                "been scrutinized heavily in practice over many years.",
        "cons": "Structurally slower than GCM/OCB3 because it processes data in two internal "
                "passes rather than one. For huge files this app's chunking keeps that cost "
                "manageable, but it's still the slowest single-layer option here.",
    },
    {
        "name": "Double Shield (AES-GCM + ChaCha20)",
        "ciphers": [0, 1],
        "summary": "Two independent cipher families, layered - defense in depth.",
        "pros": "Your data stays protected even in the (extremely unlikely) event that a "
                "serious flaw were ever found in one of the two algorithms alone, since "
                "they come from entirely different cryptographic designs.",
        "cons": "Roughly double the CPU time and battery/power cost of a single-layer "
                "option, since every byte is encrypted twice.",
    },
    {
        "name": "Fort Knox (Triple Layer: AES-GCM + ChaCha20 + AES-GCM-SIV)",
        "ciphers": [0, 1, 2],
        "summary": "Maximum layered paranoia - three independent algorithms in sequence.",
        "pros": "The strongest defense-in-depth option offered here. Would require a "
                "practical break in all three independent algorithms to fail.",
        "cons": "Meaningfully slower - roughly triple the processing time and output "
                "read/write cost. Overkill for almost all personal use cases; mainly useful "
                "if you specifically want maximum peace of mind and don't mind the wait.",
    },
]


class CryptoError(Exception):
    pass


class Cancelled(Exception):
    pass


def derive_key(secret: bytes, salt: bytes, preset: str) -> bytes:
    params = SCRYPT_PRESETS[preset]
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=params["n"], r=params["r"], p=params["p"])
    return kdf.derive(secret)


def build_secret(password: str, keyfile_bytes: bytes = None) -> bytes:
    """Combine a password with an optional keyfile into the raw key-derivation
    input. Using a keyfile means BOTH the password and the exact keyfile are
    required to decrypt - a "something you know + something you have" scheme.
    Only the keyfile's hash is mixed in, never the raw bytes, so a very large
    keyfile doesn't get embedded anywhere."""
    secret = password.encode("utf-8")
    if keyfile_bytes:
        secret += b"|keyfile|" + hashlib.sha256(keyfile_bytes).digest()
    return secret


def sha256_of_file(path: Path, progress_cb=None) -> str:
    """Streams the file to compute its SHA-256 - lets you independently
    verify two files are byte-identical (e.g. before/after transfer)."""
    total = max(path.stat().st_size, 1)
    h = hashlib.sha256()
    read = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
            read += len(chunk)
            if progress_cb:
                progress_cb(min(99, int(read / total * 100)))
    if progress_cb:
        progress_cb(100)
    return h.hexdigest()


def _cipher_by_id(cipher_id: int, key: bytes):
    return CIPHER_REGISTRY[cipher_id](key)


def _nonce_for_chunk(prefix4: bytes, index: int) -> bytes:
    return prefix4 + struct.pack(">Q", index)


def encrypt_stream(src_path: Path, dst_path: Path, secret: bytes, cipher_ids: list,
                    is_folder: bool, preset: str, progress_cb=None, cancel_check=None):
    total_size = max(src_path.stat().st_size, 1)
    layers = len(cipher_ids)
    salts = [secrets.token_bytes(16) for _ in range(layers)]
    prefixes = [secrets.token_bytes(4) for _ in range(layers)]
    keys = [derive_key(secret + f"|layer{i}".encode(), salts[i], preset) for i in range(layers)]
    ciphers = [_cipher_by_id(cipher_ids[i], keys[i]) for i in range(layers)]

    try:
        with open(src_path, "rb") as fin, open(dst_path, "wb") as fout:
            fout.write(MAGIC)
            fout.write(bytes([VERSION]))
            fout.write(bytes([layers]))
            fout.write(bytes([1 if is_folder else 0]))
            fout.write(preset.encode("ascii").ljust(8, b"\x00"))
            for i in range(layers):
                fout.write(bytes([cipher_ids[i]]))
                fout.write(salts[i])
                fout.write(prefixes[i])

            index = 0
            read_total = 0
            buf = fin.read(CHUNK_SIZE)
            while True:
                if cancel_check and cancel_check():
                    raise Cancelled()
                nxt = fin.read(CHUNK_SIZE)
                is_last = len(nxt) == 0
                aad = struct.pack(">QB", index, 1 if is_last else 0)

                current = buf
                for i in range(layers):
                    nonce = _nonce_for_chunk(prefixes[i], index)
                    current = ciphers[i].encrypt(nonce, current, aad)

                fout.write(struct.pack(">I", len(current)))
                fout.write(current)

                read_total += len(buf)
                if progress_cb:
                    progress_cb(min(99, int(read_total / total_size * 100)))

                if is_last:
                    break
                buf = nxt
                index += 1
        if progress_cb:
            progress_cb(100)
    except Cancelled:
        try:
            dst_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise


def _read_header(fin):
    magic = fin.read(4)
    if magic != MAGIC:
        raise CryptoError(
            "Not a CryptVault v3 file (bad magic header). If this file was made with an "
            "older version of this app, decrypt it with that version first."
        )
    _version = fin.read(1)[0]
    layers = fin.read(1)[0]
    is_folder = fin.read(1)[0] == 1
    preset = fin.read(8).rstrip(b"\x00").decode("ascii")
    cipher_ids, salts, prefixes = [], [], []
    for _ in range(layers):
        cipher_ids.append(fin.read(1)[0])
        salts.append(fin.read(16))
        prefixes.append(fin.read(4))
    return layers, is_folder, preset, cipher_ids, salts, prefixes


def decrypt_stream(src_path: Path, dst_path: Path, secret: bytes, progress_cb=None, cancel_check=None) -> bool:
    """Returns True if the original was a folder. The cipher(s) used are
    read automatically from the file's own header - the caller never needs
    to know or specify which Encryption Type was used to encrypt it."""
    total_size = max(src_path.stat().st_size, 1)
    try:
        with open(src_path, "rb") as fin:
            layers, is_folder, preset, cipher_ids, salts, prefixes = _read_header(fin)
            keys = [derive_key(secret + f"|layer{i}".encode(), salts[i], preset) for i in range(layers)]
            ciphers = [_cipher_by_id(cipher_ids[i], keys[i]) for i in range(layers)]

            with open(dst_path, "wb") as fout:
                index = 0
                while True:
                    if cancel_check and cancel_check():
                        raise Cancelled()
                    len_bytes = fin.read(4)
                    if len(len_bytes) < 4:
                        break
                    (clen,) = struct.unpack(">I", len_bytes)
                    ciphertext = fin.read(clen)
                    pos = fin.tell()
                    is_last = pos >= total_size

                    aad = struct.pack(">QB", index, 1 if is_last else 0)
                    current = ciphertext
                    try:
                        for i in reversed(range(layers)):
                            nonce = _nonce_for_chunk(prefixes[i], index)
                            current = ciphers[i].decrypt(nonce, current, aad)
                    except Exception:
                        raise CryptoError("Wrong password (or wrong keyfile), or the file is corrupted/tampered.")

                    fout.write(current)
                    index += 1
                    if progress_cb:
                        progress_cb(min(99, int(pos / total_size * 100)))
                    if is_last:
                        break
        if progress_cb:
            progress_cb(100)
        return is_folder
    except Cancelled:
        try:
            dst_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise


def verify_password_quick(src_path: Path, secret: bytes) -> bool:
    """Decrypts only the first chunk to confirm a password (and keyfile, if
    any) - instant feedback even on huge files. Cipher(s) auto-detected."""
    with open(src_path, "rb") as fin:
        layers, is_folder, preset, cipher_ids, salts, prefixes = _read_header(fin)
        keys = [derive_key(secret + f"|layer{i}".encode(), salts[i], preset) for i in range(layers)]
        ciphers = [_cipher_by_id(cipher_ids[i], keys[i]) for i in range(layers)]

        len_bytes = fin.read(4)
        if len(len_bytes) < 4:
            return False
        (clen,) = struct.unpack(">I", len_bytes)
        ciphertext = fin.read(clen)
        pos = fin.tell()
        total_size = src_path.stat().st_size
        is_last = pos >= total_size
        aad = struct.pack(">QB", 0, 1 if is_last else 0)
        current = ciphertext
        try:
            for i in reversed(range(layers)):
                nonce = _nonce_for_chunk(prefixes[i], 0)
                current = ciphers[i].decrypt(nonce, current, aad)
            return True
        except Exception:
            return False


def describe_encryption_type(src_path: Path) -> str:
    """Reads just the header to report which Encryption Type a .cvlt file
    uses, without needing any password."""
    with open(src_path, "rb") as fin:
        layers, is_folder, preset, cipher_ids, salts, prefixes = _read_header(fin)
    names = " + ".join(CIPHER_NAMES.get(c, f"unknown({c})") for c in cipher_ids)
    return f"{names} ({layers} layer{'s' if layers != 1 else ''}, {preset} preset)"


def zip_folder_to_file(folder_path: Path, dst_zip: Path, compress=True, progress_cb=None, cancel_check=None):
    all_files = [p for p in folder_path.rglob("*") if p.is_file()]
    total = max(len(all_files), 1)
    method = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    with zipfile.ZipFile(dst_zip, "w", method) as zf:
        for idx, file_path in enumerate(all_files):
            if cancel_check and cancel_check():
                raise Cancelled()
            arcname = file_path.relative_to(folder_path.parent)
            zf.write(file_path, arcname)
            if progress_cb:
                progress_cb(int((idx + 1) / total * 100))


def unzip_file_to_folder(src_zip: Path, dest_dir: Path):
    with zipfile.ZipFile(src_zip, "r") as zf:
        zf.extractall(dest_dir)


def shred_file(path: Path, passes: int = SHRED_PASSES):
    try:
        length = path.stat().st_size
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(length))
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
    except Exception:
        try:
            path.unlink()
        except Exception:
            pass


def shred_path(path: Path, passes: int = SHRED_PASSES):
    if path.is_dir():
        for f in path.rglob("*"):
            if f.is_file():
                shred_file(f, passes)
        for d in sorted(path.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            if d.is_dir():
                try:
                    d.rmdir()
                except Exception:
                    pass
        try:
            path.rmdir()
        except Exception:
            pass
    else:
        shred_file(path, passes)


def password_strength(pw: str):
    if not pw:
        return 0, "", "#888888"
    score = 0
    if len(pw) >= 8:
        score += 1
    if len(pw) >= 14:
        score += 1
    if re.search(r"[A-Z]", pw) and re.search(r"[a-z]", pw):
        score += 1
    if re.search(r"\d", pw):
        score += 1
    if re.search(r"[^\w]", pw):
        score += 1
    score = min(score, 4)
    labels = {0: ("Very weak", "#ff5b5b"), 1: ("Weak", "#ff8a5b"),
              2: ("Fair", "#ffd15b"), 3: ("Strong", "#8bd85b"),
              4: ("Very strong", "#4be0a0")}
    label, color = labels[score]
    return score, label, color


def generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def human_size(num_bytes: float) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.1f}{unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f}PB"


def open_in_file_manager(path: Path):
    path = str(path)
    try:
        if sys.platform == "win32":
            os.startfile(path)  # noqa
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass


# ========================================================================
# BACKGROUND TASKS (QThreadPool - processes several files in parallel,
# using multiple CPU cores at once instead of one file at a time)
# ========================================================================
class TaskSignals(QObject):
    progress = Signal(str, int)
    done = Signal(str, str, float, int)
    failed = Signal(str, str)
    cancelled = Signal(str)


class CryptoTask(QRunnable):
    def __init__(self, mode, path, secret, cipher_ids, preset, shred, output_dir, cancel_event,
                 compress_folders=True):
        super().__init__()
        self.mode = mode
        self.path = Path(path)
        self.secret = secret
        self.cipher_ids = cipher_ids  # only used for encrypt; decrypt auto-detects
        self.preset = preset
        self.shred = shred
        self.output_dir = Path(output_dir) if output_dir else None
        self.cancel_event = cancel_event
        self.compress_folders = compress_folders
        self.signals = TaskSignals()

    def _cancel_check(self):
        return self.cancel_event.is_set()

    def run(self):
        start = time.time()
        try:
            if self._cancel_check():
                self.signals.cancelled.emit(str(self.path))
                return
            if self.mode == "encrypt":
                output = self._encrypt()
            else:
                output = self._decrypt()
            size = Path(output).stat().st_size if Path(output).is_file() else 0
            self.signals.done.emit(str(self.path), str(output), time.time() - start, size)
        except Cancelled:
            self.signals.cancelled.emit(str(self.path))
        except Exception as e:
            self.signals.failed.emit(str(self.path), str(e))

    def _dest_dir_for(self, original: Path) -> Path:
        return self.output_dir if self.output_dir else original.parent

    def _encrypt(self):
        is_folder = self.path.is_dir()
        dest_dir = self._dest_dir_for(self.path)
        dest_dir.mkdir(parents=True, exist_ok=True)
        out_name = dest_dir / (self.path.name + ".cvlt")

        if is_folder:
            tmp_zip = Path(tempfile.mkstemp(suffix=".zip")[1])
            try:
                zip_folder_to_file(self.path, tmp_zip, compress=self.compress_folders,
                                    progress_cb=lambda p: self.signals.progress.emit(str(self.path), int(p * 0.3)),
                                    cancel_check=self._cancel_check)
                encrypt_stream(tmp_zip, out_name, self.secret, self.cipher_ids, True, self.preset,
                                progress_cb=lambda p: self.signals.progress.emit(str(self.path), 30 + int(p * 0.7)),
                                cancel_check=self._cancel_check)
            finally:
                tmp_zip.unlink(missing_ok=True)
        else:
            encrypt_stream(self.path, out_name, self.secret, self.cipher_ids, False, self.preset,
                            progress_cb=lambda p: self.signals.progress.emit(str(self.path), p),
                            cancel_check=self._cancel_check)

        if self.shred:
            shred_path(self.path)
        return out_name

    def _decrypt(self):
        dest_dir = self._dest_dir_for(self.path)
        dest_dir.mkdir(parents=True, exist_ok=True)
        if self.path.suffix == ".cvlt":
            target = dest_dir / self.path.stem
        else:
            target = dest_dir / (self.path.name + ".decrypted")

        tmp_out = Path(tempfile.mkstemp()[1])
        try:
            # No cipher_ids passed in here - decrypt_stream reads them from
            # the file's own header automatically.
            is_folder = decrypt_stream(self.path, tmp_out, self.secret,
                                        progress_cb=lambda p: self.signals.progress.emit(str(self.path), int(p * 0.8)),
                                        cancel_check=self._cancel_check)
            if is_folder:
                out_dir = dest_dir / (target.name + "_decrypted")
                out_dir.mkdir(exist_ok=True, parents=True)
                unzip_file_to_folder(tmp_out, out_dir)
                result = out_dir
            else:
                target.write_bytes(tmp_out.read_bytes())
                result = target
        finally:
            tmp_out.unlink(missing_ok=True)

        if self.shred:
            shred_path(self.path)
        return result


# ========================================================================
# FLOW LAYOUT — used inside each tab so button rows wrap onto a new line
# instead of ever clipping or overflowing, at any window width.
# ========================================================================
class FlowLayout(QLayout):
    def __init__(self, parent=None, margin=0, spacing=8):
        super().__init__(parent)
        self.setContentsMargins(margin, margin, margin, margin)
        self.setSpacing(spacing)
        self._items = []

    def addItem(self, item):
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, index):
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index):
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self):
        return Qt.Orientations(Qt.Orientation(0))

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self._do_layout(QRect(0, 0, width, 0), test_only=True)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._do_layout(rect, test_only=False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        m = self.contentsMargins()
        size += QSize(m.left() + m.right(), m.top() + m.bottom())
        return size

    def _do_layout(self, rect, test_only):
        x, y = rect.x(), rect.y()
        line_height = 0
        spacing = self.spacing()

        for item in self._items:
            hint = item.sizeHint()
            next_x = x + hint.width() + spacing
            if next_x - spacing > rect.right() and line_height > 0:
                x = rect.x()
                y = y + line_height + spacing
                next_x = x + hint.width() + spacing
                line_height = 0

            if not test_only:
                item.setGeometry(QRect(QPoint(x, y), hint))

            x = next_x
            line_height = max(line_height, hint.height())

        return y + line_height - rect.y()


# ========================================================================
# LIQUID-GLASS STYLING (dark + light variants)
# ========================================================================
_QSS_TEMPLATE = """
QWidget#GlassPanel {
    background-color: §PANEL_BG§;
    border-radius: 26px;
    border: 1px solid §PANEL_BORDER§;
}
QWidget#Card {
    background-color: §CARD_BG§;
    border-radius: 16px;
    border: 1px solid §PANEL_BORDER§;
}
QLabel#Title { color: §TITLE§; font-size: 24px; font-weight: 800; letter-spacing: 0.5px; }
QLabel#Subtitle { color: §SUBTITLE§; font-size: 12px; }
QLabel { color: §TEXT§; font-size: 13px; }
QLabel#SectionTag { color: §TAG§; font-size: 11px; font-weight: 800; letter-spacing: 1.2px; }
QLabel#RowName { color: §TEXT_STRONG§; font-size: 12px; font-weight: 600; }
QLabel#RowStatus { color: §TAG§; font-size: 11px; }
QLineEdit, QComboBox {
    background-color: §INPUT_BG§;
    border: 1px solid §INPUT_BORDER§;
    border-radius: 12px;
    padding: 9px 12px;
    color: §TEXT_STRONG§;
    font-size: 13px;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid rgba(120,170,255,230); }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView {
    background-color: §DROPDOWN_BG§;
    color: §TEXT_STRONG§;
    selection-background-color: rgba(120,170,255,180);
    border-radius: 8px;
}
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(150, 190, 255, 235), stop:1 rgba(110, 150, 235, 235));
    border: 1px solid rgba(255,255,255,90);
    border-radius: 14px;
    padding: 10px 16px;
    color: white;
    font-size: 13px;
    font-weight: 700;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(170, 205, 255, 245), stop:1 rgba(125, 165, 245, 245));
}
QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(100, 140, 220, 245), stop:1 rgba(90, 125, 210, 245));
}
QPushButton:disabled {
    background: rgba(120,120,140,90);
    color: rgba(255,255,255,130);
    border: 1px solid rgba(255,255,255,40);
}
QPushButton#Secondary {
    background: §SECONDARY_BTN_BG§;
    border: 1px solid §SECONDARY_BTN_BORDER§;
    color: §TEXT_STRONG§;
}
QPushButton#Secondary:hover { background: §SECONDARY_BTN_HOVER§; }
QPushButton#Info {
    background: §SECONDARY_BTN_BG§;
    border: 1px solid §SECONDARY_BTN_BORDER§;
    border-radius: 16px;
    color: §TEXT_STRONG§;
    padding: 8px 12px;
    font-weight: 900;
}
QPushButton#Info:hover { background: §SECONDARY_BTN_HOVER§; }
QPushButton#Danger {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(240, 110, 110, 235), stop:1 rgba(210, 75, 75, 235));
}
QPushButton#Danger:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(250, 130, 130, 245), stop:1 rgba(225, 90, 90, 245));
}
QCheckBox { color: §TEXT§; font-size: 13px; spacing: 8px; }
QCheckBox::indicator {
    width: 18px; height: 18px; border-radius: 6px;
    border: 1px solid §INPUT_BORDER§;
    background: §INPUT_BG§;
}
QCheckBox::indicator:checked {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(150, 190, 255, 235), stop:1 rgba(110, 150, 235, 235));
    border: 1px solid rgba(255,255,255,180);
}
QProgressBar {
    background-color: §INPUT_BG§;
    border-radius: 8px;
    height: 14px;
    text-align: center;
    color: §TEXT_STRONG§;
    border: 1px solid §INPUT_BORDER§;
    font-size: 10px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 rgba(120, 200, 255, 235), stop:1 rgba(150, 150, 255, 235));
    border-radius: 7px;
}
QListWidget {
    background-color: transparent;
    border: none;
    color: §TEXT_STRONG§;
    font-size: 12px;
}
QListWidget::item { border: none; padding: 2px; }
QListWidget::item:selected { background: transparent; }
QTextEdit {
    background-color: §LOG_BG§;
    border: 1px solid §PANEL_BORDER§;
    border-radius: 14px;
    color: §LOG_TEXT§;
    font-size: 11px;
    font-family: Consolas, monospace;
    padding: 6px;
}
QLabel#Strength { font-size: 12px; font-weight: 700; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: transparent; width: 10px; }
QScrollBar::handle:vertical { background: §SCROLLBAR§; border-radius: 5px; min-height: 30px; }
QMenu {
    background-color: §DROPDOWN_BG§;
    color: §TEXT_STRONG§;
    border: 1px solid §PANEL_BORDER§;
    border-radius: 8px;
}
QMenu::item:selected { background: rgba(120,170,255,150); }
QTabWidget::pane {
    border: none;
    background: transparent;
    top: -1px;
}
QTabBar::tab {
    background: §SECONDARY_BTN_BG§;
    border: 1px solid §SECONDARY_BTN_BORDER§;
    color: §TEXT_STRONG§;
    padding: 9px 16px;
    margin-right: 6px;
    border-top-left-radius: 12px;
    border-top-right-radius: 12px;
    font-weight: 700;
    font-size: 12px;
}
QTabBar::tab:selected {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(150, 190, 255, 235), stop:1 rgba(110, 150, 235, 235));
    color: white;
}
QDialog { background-color: §DIALOG_BG§; }
QTableWidget {
    background-color: §CARD_BG§;
    color: §TEXT_STRONG§;
    border: 1px solid §PANEL_BORDER§;
    border-radius: 12px;
    gridline-color: §PANEL_BORDER§;
    font-size: 12px;
}
QHeaderView::section {
    background-color: §SECONDARY_BTN_BG§;
    color: §TEXT_STRONG§;
    padding: 6px;
    border: none;
    font-weight: 700;
}
"""

_DARK_TOKENS = {
    "§PANEL_BG§": "rgba(255, 255, 255, 28)",
    "§PANEL_BORDER§": "rgba(255, 255, 255, 65)",
    "§CARD_BG§": "rgba(255, 255, 255, 20)",
    "§TITLE§": "white",
    "§SUBTITLE§": "rgba(255,255,255,185)",
    "§TEXT§": "rgba(255,255,255,225)",
    "§TEXT_STRONG§": "white",
    "§TAG§": "rgba(255,255,255,150)",
    "§INPUT_BG§": "rgba(255,255,255,45)",
    "§INPUT_BORDER§": "rgba(255,255,255,90)",
    "§DROPDOWN_BG§": "rgb(50, 55, 85)",
    "§DIALOG_BG§": "rgb(38, 42, 68)",
    "§SECONDARY_BTN_BG§": "rgba(255,255,255,35)",
    "§SECONDARY_BTN_BORDER§": "rgba(255,255,255,80)",
    "§SECONDARY_BTN_HOVER§": "rgba(255,255,255,60)",
    "§LOG_BG§": "rgba(15,18,30,150)",
    "§LOG_TEXT§": "rgba(255,255,255,235)",
    "§SCROLLBAR§": "rgba(255,255,255,80)",
}

_LIGHT_TOKENS = {
    "§PANEL_BG§": "rgba(255, 255, 255, 150)",
    "§PANEL_BORDER§": "rgba(255, 255, 255, 210)",
    "§CARD_BG§": "rgba(255, 255, 255, 130)",
    "§TITLE§": "rgb(25, 30, 55)",
    "§SUBTITLE§": "rgba(30,35,65,170)",
    "§TEXT§": "rgba(25,30,55,220)",
    "§TEXT_STRONG§": "rgb(20, 25, 45)",
    "§TAG§": "rgba(30,35,65,150)",
    "§INPUT_BG§": "rgba(255,255,255,170)",
    "§INPUT_BORDER§": "rgba(120,120,170,120)",
    "§DROPDOWN_BG§": "rgb(240, 242, 250)",
    "§DIALOG_BG§": "rgb(235, 238, 248)",
    "§SECONDARY_BTN_BG§": "rgba(255,255,255,150)",
    "§SECONDARY_BTN_BORDER§": "rgba(120,120,170,110)",
    "§SECONDARY_BTN_HOVER§": "rgba(255,255,255,210)",
    "§LOG_BG§": "rgba(255,255,255,185)",
    "§LOG_TEXT§": "rgb(25, 30, 55)",
    "§SCROLLBAR§": "rgba(80,80,110,90)",
}


def build_qss(dark: bool) -> str:
    qss = _QSS_TEMPLATE
    tokens = _DARK_TOKENS if dark else _LIGHT_TOKENS
    for token, value in tokens.items():
        qss = qss.replace(token, value)
    return qss


class GradientBackground(QWidget):
    """Paints a soft, multi-blob iOS-style diffused backdrop - several
    overlapping radial gradients blended together, which is what gives a
    'liquid glass' scene its depth instead of a flat linear gradient.
    Pure paintEvent-based so it costs nothing extra and never breaks on
    resize; no extra libraries required."""

    def __init__(self, dark=True):
        super().__init__()
        self.dark = dark

    def set_dark(self, dark):
        self.dark = dark
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        w, h = max(self.width(), 1), max(self.height(), 1)

        base = QLinearGradient(0, 0, w, h)
        if self.dark:
            base.setColorAt(0.0, QColor(20, 24, 46))
            base.setColorAt(0.5, QColor(42, 30, 74))
            base.setColorAt(1.0, QColor(14, 58, 84))
        else:
            base.setColorAt(0.0, QColor(232, 238, 255))
            base.setColorAt(0.5, QColor(240, 228, 252))
            base.setColorAt(1.0, QColor(222, 245, 248))
        painter.fillRect(self.rect(), QBrush(base))

        blobs_dark = [
            (0.15, 0.20, 0.55, QColor(130, 100, 255, 100)),
            (0.85, 0.15, 0.50, QColor(90, 190, 255, 90)),
            (0.75, 0.85, 0.60, QColor(255, 120, 190, 70)),
            (0.20, 0.85, 0.45, QColor(80, 220, 200, 70)),
        ]
        blobs_light = [
            (0.15, 0.20, 0.55, QColor(170, 150, 255, 90)),
            (0.85, 0.15, 0.50, QColor(140, 210, 255, 90)),
            (0.75, 0.85, 0.60, QColor(255, 170, 210, 80)),
            (0.20, 0.85, 0.45, QColor(150, 235, 220, 80)),
        ]
        blobs = blobs_dark if self.dark else blobs_light

        for fx, fy, frad, color in blobs:
            cx, cy = w * fx, h * fy
            radius = max(w, h) * frad
            radial = QRadialGradient(cx, cy, radius)
            radial.setColorAt(0.0, color)
            transparent = QColor(color)
            transparent.setAlpha(0)
            radial.setColorAt(1.0, transparent)
            painter.setBrush(QBrush(radial))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QPoint(int(cx), int(cy)), int(radius), int(radius))


class GlassPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("GlassPanel")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(55)
        shadow.setColor(QColor(0, 0, 0, 150))
        shadow.setOffset(0, 12)
        self.setGraphicsEffect(shadow)


class Card(QFrame):
    """A smaller frosted sub-panel used to group related controls -
    gives the layout visual hierarchy instead of one long flat stack."""
    def __init__(self):
        super().__init__()
        self.setObjectName("Card")


class DropList(QListWidget):
    paths_added = Signal(list)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setMinimumHeight(120)
        self.setSpacing(4)
        # QListWidget is a scroll area internally too - its viewport
        # auto-fills with an opaque background by default, which can hide
        # the frosted backdrop behind it. Turning off auto-fill (not a
        # stylesheet override, which would wipe child widget styling too)
        # fixes that without touching anything else.
        self.viewport().setAutoFillBackground(False)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragMoveEvent(self, event):
        event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        paths = [url.toLocalFile() for url in event.mimeData().urls() if url.toLocalFile()]
        if paths:
            self.paths_added.emit(paths)
        event.acceptProposedAction()


class FileRowWidget(QWidget):
    """One row in the file list: name, a real inline progress bar, and a
    status label. This is what makes per-file progress genuinely visible
    during encryption/decryption, not just text changing in place."""

    def __init__(self, path: str):
        super().__init__()
        self.path = path
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)

        top_row = QHBoxLayout()
        kind = "📁" if Path(path).is_dir() else "📄"
        self.name_label = QLabel(f"{kind}  {Path(path).name}")
        self.name_label.setObjectName("RowName")
        self.status_label = QLabel("Queued")
        self.status_label.setObjectName("RowStatus")
        top_row.addWidget(self.name_label, stretch=1)
        top_row.addWidget(self.status_label)
        layout.addLayout(top_row)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setFixedHeight(10)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)

    def set_progress(self, percent):
        self.progress.setValue(percent)
        self.status_label.setText(f"{percent}%")

    def set_status(self, text, done=False, failed=False, cancelled=False):
        self.status_label.setText(text)
        if done:
            self.progress.setValue(100)
        elif failed or cancelled:
            pass  # leave progress bar wherever it stopped


# ========================================================================
# ENCRYPTION TYPE INFO DIALOG (expanded) + COMPARISON DIALOG
# ========================================================================
SPEED_RATING = {
    "AES-256-GCM (Standard)": ("Very fast", "★★★★★"),
    "ChaCha20-Poly1305 (Software-Friendly)": ("Fast", "★★★★☆"),
    "AES-256-GCM-SIV (Misuse-Resistant)": ("Fast", "★★★★☆"),
    "AES-256-OCB3 (High Performance)": ("Very fast", "★★★★★"),
    "AES-256-CCM (Compact / IoT Standard)": ("Moderate", "★★★☆☆"),
    "Double Shield (AES-GCM + ChaCha20)": ("Slower (2 layers)", "★★☆☆☆"),
    "Fort Knox (Triple Layer: AES-GCM + ChaCha20 + AES-GCM-SIV)": ("Slowest (3 layers)", "★☆☆☆☆"),
}

REAL_WORLD_USE = {
    "AES-256-GCM (Standard)":
        "Used extensively in TLS (the encryption behind HTTPS), many VPNs, and disk "
        "encryption products. The most common authenticated cipher in production software.",
    "ChaCha20-Poly1305 (Software-Friendly)":
        "Used as an alternative cipher suite in TLS 1.3, and is the sole cipher used by "
        "the WireGuard VPN protocol.",
    "AES-256-GCM-SIV (Misuse-Resistant)":
        "Standardized in RFC 8452, developed with input from Google engineers specifically "
        "to reduce the damage from accidental nonce reuse in large-scale systems.",
    "AES-256-OCB3 (High Performance)":
        "Standardized in RFC 7253. Its adoption was historically limited by patents that "
        "held until 2021 - it's now free to use anywhere, and is prized in performance-"
        "critical systems that need maximum throughput.",
    "AES-256-CCM (Compact / IoT Standard)":
        "The cipher behind WPA2 Wi-Fi security (CCMP), Bluetooth Low Energy, and Zigbee - "
        "chosen there for its compact, well-analyzed design suited to constrained devices.",
    "Double Shield (AES-GCM + ChaCha20)":
        "A layered construction, not a single standardized cipher - used here purely for "
        "extra defense-in-depth on your own files.",
    "Fort Knox (Triple Layer: AES-GCM + ChaCha20 + AES-GCM-SIV)":
        "A layered construction combining three independent, standardized ciphers for "
        "maximum redundancy against any single algorithm ever being broken.",
}


class EncryptionInfoDialog(QDialog):
    def __init__(self, parent, encryption_type, on_compare):
        super().__init__(parent)
        self.setWindowTitle("Encryption Type Info")
        self.setMinimumWidth(440)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        et = encryption_type
        cipher_chain = " → ".join(CIPHER_NAMES[c] for c in et["ciphers"])
        speed_label, stars = SPEED_RATING.get(et["name"], ("Unknown", ""))

        title = QLabel(et["name"])
        title.setObjectName("Title")
        title.setStyleSheet("font-size: 18px;")
        title.setWordWrap(True)
        layout.addWidget(title)

        chain_label = QLabel(f"Algorithm chain: {cipher_chain}")
        chain_label.setWordWrap(True)
        chain_label.setObjectName("Subtitle")
        layout.addWidget(chain_label)

        speed_row = QLabel(f"<b>Relative speed:</b> {speed_label}  {stars}")
        speed_row.setTextFormat(Qt.RichText)
        layout.addWidget(speed_row)

        summary = QLabel(et["summary"])
        summary.setWordWrap(True)
        layout.addWidget(summary)

        pros_card = Card()
        pros_layout = QVBoxLayout(pros_card)
        pros_title = QLabel("✅ Good at")
        pros_title.setStyleSheet("font-weight: 800;")
        pros_layout.addWidget(pros_title)
        pros_text = QLabel(et["pros"])
        pros_text.setWordWrap(True)
        pros_layout.addWidget(pros_text)
        layout.addWidget(pros_card)

        cons_card = Card()
        cons_layout = QVBoxLayout(cons_card)
        cons_title = QLabel("⚠️ Trade-offs")
        cons_title.setStyleSheet("font-weight: 800;")
        cons_layout.addWidget(cons_title)
        cons_text = QLabel(et["cons"])
        cons_text.setWordWrap(True)
        cons_layout.addWidget(cons_text)
        layout.addWidget(cons_card)

        used_card = Card()
        used_layout = QVBoxLayout(used_card)
        used_title = QLabel("🌍 Where it's used in the real world")
        used_title.setStyleSheet("font-weight: 800;")
        used_layout.addWidget(used_title)
        used_text = QLabel(REAL_WORLD_USE.get(et["name"], ""))
        used_text.setWordWrap(True)
        used_layout.addWidget(used_text)
        layout.addWidget(used_card)

        btn_row = QHBoxLayout()
        btn_compare = QPushButton("Compare All Types")
        btn_compare.setObjectName("Secondary")
        btn_compare.clicked.connect(lambda: (self.close(), on_compare()))
        btn_close = QPushButton("Close")
        btn_row.addWidget(btn_compare)
        btn_row.addWidget(btn_close)
        btn_close.clicked.connect(self.close)
        layout.addLayout(btn_row)


class ComparisonDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Compare Encryption Types")
        self.resize(760, 420)
        layout = QVBoxLayout(self)

        intro = QLabel("All of these are strong, modern authenticated ciphers - none is "
                        "\"weak\". The differences are speed, hardware support, and how many "
                        "independent layers are used.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        table = QTableWidget(len(ENCRYPTION_TYPES), 4)
        table.setHorizontalHeaderLabels(["Type", "Algorithm Chain", "Relative Speed", "Best For"])
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionMode(QAbstractItemView.NoSelection)
        table.setWordWrap(True)

        for row, et in enumerate(ENCRYPTION_TYPES):
            chain = " → ".join(CIPHER_NAMES[c] for c in et["ciphers"])
            speed_label, stars = SPEED_RATING.get(et["name"], ("Unknown", ""))
            table.setItem(row, 0, QTableWidgetItem(et["name"]))
            table.setItem(row, 1, QTableWidgetItem(chain))
            table.setItem(row, 2, QTableWidgetItem(f"{speed_label} {stars}"))
            table.setItem(row, 3, QTableWidgetItem(et["summary"]))
            table.resizeRowToContents(row)

        layout.addWidget(table)

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.close)
        layout.addWidget(btn_close)


# ========================================================================
# MAIN WINDOW
# ========================================================================
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptVault")
        self.setMinimumSize(360, 460)

        self.settings = QSettings("CryptVault", "CryptVault")

        self.selected_paths = []
        self.row_widgets = {}   # path -> FileRowWidget
        self.list_items = {}    # path -> QListWidgetItem
        self.output_dir = self.settings.value("output_dir", "", str) or None
        self.last_dir = self.settings.value("last_dir", str(Path.home()), str)
        self.dark_mode = self.settings.value("dark_mode", True, bool)
        self.last_output_dir = None
        self.keyfile_path = None

        self.pool = QThreadPool.globalInstance()
        self.pool.setMaxThreadCount(max(2, min(4, os.cpu_count() or 2)))
        self.cancel_event = threading.Event()
        self.total_tasks = 0
        self.completed_tasks = 0
        self.batch_start_time = None

        self.idle_timer = QTimer(self)
        self.idle_timer.setInterval(5 * 60 * 1000)
        self.idle_timer.setSingleShot(True)
        self.idle_timer.timeout.connect(self.auto_clear_passwords)

        self._build_ui()
        self._apply_theme()
        self._restore_settings()

        size = self.settings.value("window_size", None)
        self.resize(size if size else QSize(760, 900))

    # ---------------- UI construction ----------------
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        self.bg = GradientBackground(dark=True)
        bg_layout = QVBoxLayout(self.bg)
        bg_layout.setContentsMargins(18, 18, 18, 18)
        bg_layout.setSpacing(12)

        header_row = FlowLayout(spacing=8)
        title = QLabel("🔒  CryptVault")
        title.setObjectName("Title")
        self.theme_btn = QPushButton("☀️ Light" if self.dark_mode else "🌙 Dark")
        self.theme_btn.setObjectName("Secondary")
        self.theme_btn.clicked.connect(self.toggle_theme)
        header_row.addWidget(title)
        header_row.addWidget(self.theme_btn)
        bg_layout.addLayout(header_row)

        panel = GlassPanel()
        panel_outer = QVBoxLayout(panel)
        panel_outer.setContentsMargins(18, 18, 18, 18)
        panel_outer.setSpacing(10)

        self.tabs = QTabWidget()
        panel_outer.addWidget(self.tabs)

        self.tabs.addTab(self._build_files_tab(), "Encrypt / Decrypt")
        self.tabs.addTab(self._build_encryption_tab(), "Encryption Type")
        self.tabs.addTab(self._build_settings_tab(), "Settings")
        self.tabs.addTab(self._build_log_tab(), "Activity Log")

        bg_layout.addWidget(panel, stretch=1)
        root.addWidget(self.bg)

    def _wrap_scroll(self, inner_widget):
        # QScrollArea's viewport auto-fills with an opaque background by
        # default (from the widget palette), which silently painted over
        # the glass panel and made text hard to read - especially in light
        # mode. Disabling auto-fill (a plain property, not a stylesheet)
        # fixes that without cascading into and wiping child widget styles
        # the way an unscoped "background: transparent" QSS rule would.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.viewport().setAutoFillBackground(False)
        scroll.setWidget(inner_widget)
        return scroll

    def _build_files_tab(self):
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(10)

        layout.addWidget(self._tag("FILES / FOLDERS  (drag & drop supported)"))
        self.file_list = DropList()
        self.file_list.paths_added.connect(self.add_paths)
        self.file_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_list.customContextMenuRequested.connect(self.show_file_context_menu)
        layout.addWidget(self.file_list, stretch=2)

        picker_row = FlowLayout(spacing=8)
        for label, slot in [("Add Files", self.choose_files), ("Add Folder", self.choose_folder),
                             ("Remove Selected", self.remove_selected), ("Clear All", self.clear_list)]:
            btn = QPushButton(label)
            btn.setObjectName("Secondary")
            btn.clicked.connect(slot)
            picker_row.addWidget(btn)
        layout.addLayout(picker_row)

        pw_card = Card()
        pw_layout = QVBoxLayout(pw_card)
        pw_layout.addWidget(self._tag("PASSWORD"))
        pw_row = FlowLayout(spacing=8)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter a strong password")
        self.password_input.setMinimumWidth(200)
        self.password_input.textChanged.connect(self.on_password_activity)
        btn_generate = QPushButton("Generate")
        btn_generate.setObjectName("Secondary")
        btn_generate.clicked.connect(self.fill_generated_password)
        pw_row.addWidget(self.password_input)
        pw_row.addWidget(btn_generate)
        pw_layout.addLayout(pw_row)

        self.strength_label = QLabel("")
        self.strength_label.setObjectName("Strength")
        pw_layout.addWidget(self.strength_label)

        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setPlaceholderText("Confirm password (required for Encrypt)")
        self.confirm_input.textChanged.connect(self.on_password_activity)
        pw_layout.addWidget(self.confirm_input)

        row2 = FlowLayout(spacing=8)
        self.show_pw_checkbox = QCheckBox("Show password")
        self.show_pw_checkbox.stateChanged.connect(self.toggle_password_visibility)
        btn_verify = QPushButton("Verify Password")
        btn_verify.setObjectName("Secondary")
        btn_verify.clicked.connect(self.verify_password)
        row2.addWidget(self.show_pw_checkbox)
        row2.addWidget(btn_verify)
        pw_layout.addLayout(row2)
        layout.addWidget(pw_card)

        action_row = FlowLayout(spacing=8)
        self.btn_encrypt = QPushButton("🔐  Encrypt All")
        self.btn_encrypt.clicked.connect(self.start_encrypt)
        self.btn_decrypt = QPushButton("🔓  Decrypt All")
        self.btn_decrypt.setObjectName("Secondary")
        self.btn_decrypt.clicked.connect(self.start_decrypt)
        self.btn_cancel = QPushButton("✕ Cancel")
        self.btn_cancel.setObjectName("Danger")
        self.btn_cancel.clicked.connect(self.cancel_batch)
        self.btn_cancel.setEnabled(False)
        action_row.addWidget(self.btn_encrypt)
        action_row.addWidget(self.btn_decrypt)
        action_row.addWidget(self.btn_cancel)
        layout.addLayout(action_row)

        layout.addWidget(self._tag("OVERALL PROGRESS"))
        self.overall_bar = QProgressBar()
        layout.addWidget(self.overall_bar)

        return self._wrap_scroll(content)

    def _build_encryption_tab(self):
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(10)

        layout.addWidget(self._tag("ENCRYPTION TYPE  (decrypting never needs you to remember this)"))
        enc_row = FlowLayout(spacing=8)
        self.encryption_combo = QComboBox()
        self.encryption_combo.setMinimumWidth(260)
        for et in ENCRYPTION_TYPES:
            self.encryption_combo.addItem(et["name"])
        self.encryption_combo.setCurrentIndex(0)
        btn_info = QPushButton("ⓘ More Info")
        btn_info.setObjectName("Info")
        btn_info.clicked.connect(self.show_encryption_type_info)
        btn_compare = QPushButton("⇄ Compare All Types")
        btn_compare.setObjectName("Secondary")
        btn_compare.clicked.connect(self.show_comparison_dialog)
        enc_row.addWidget(self.encryption_combo)
        enc_row.addWidget(btn_info)
        enc_row.addWidget(btn_compare)
        layout.addLayout(enc_row)

        summary_card = Card()
        summary_layout = QVBoxLayout(summary_card)
        self.encryption_summary = QLabel(ENCRYPTION_TYPES[0]["summary"])
        self.encryption_summary.setWordWrap(True)
        summary_layout.addWidget(self.encryption_summary)
        self.encryption_speed = QLabel("")
        self.encryption_speed.setTextFormat(Qt.RichText)
        summary_layout.addWidget(self.encryption_speed)
        layout.addWidget(summary_card)
        self.encryption_combo.currentIndexChanged.connect(self._update_encryption_summary)
        self._update_encryption_summary(0)

        layout.addWidget(self._tag("PASSWORD SECURITY LEVEL"))
        sec_row = FlowLayout(spacing=8)
        sec_row.addWidget(QLabel("How expensive password cracking should be:"))
        self.security_combo = QComboBox()
        self.security_combo.addItems(["Fast", "Balanced (recommended)", "Paranoid (slow)"])
        self.security_combo.setCurrentIndex(1)
        sec_row.addWidget(self.security_combo)
        layout.addLayout(sec_row)

        layout.addStretch()
        return self._wrap_scroll(content)

    def _build_settings_tab(self):
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(10)

        out_card = Card()
        out_layout = QVBoxLayout(out_card)
        out_layout.addWidget(self._tag("OUTPUT LOCATION"))
        self.output_input = QLineEdit()
        self.output_input.setPlaceholderText("(default: same folder as each file)")
        self.output_input.setReadOnly(True)
        out_layout.addWidget(self.output_input)
        out_row = FlowLayout(spacing=8)
        btn_browse_out = QPushButton("Browse")
        btn_browse_out.setObjectName("Secondary")
        btn_browse_out.clicked.connect(self.choose_output_dir)
        btn_reset_out = QPushButton("Reset")
        btn_reset_out.setObjectName("Secondary")
        btn_reset_out.clicked.connect(self.reset_output_dir)
        self.btn_open_output = QPushButton("Open Output Folder")
        self.btn_open_output.setObjectName("Secondary")
        self.btn_open_output.clicked.connect(self.open_output_folder)
        self.btn_open_output.setEnabled(False)
        out_row.addWidget(btn_browse_out)
        out_row.addWidget(btn_reset_out)
        out_row.addWidget(self.btn_open_output)
        out_layout.addLayout(out_row)
        layout.addWidget(out_card)

        key_card = Card()
        key_layout = QVBoxLayout(key_card)
        key_layout.addWidget(self._tag("KEYFILE (OPTIONAL - PASSWORD + FILE BOTH REQUIRED)"))
        self.keyfile_input = QLineEdit()
        self.keyfile_input.setPlaceholderText("(none - password alone unlocks the file)")
        self.keyfile_input.setReadOnly(True)
        key_layout.addWidget(self.keyfile_input)
        keyfile_row = FlowLayout(spacing=8)
        btn_choose_keyfile = QPushButton("Choose Keyfile")
        btn_choose_keyfile.setObjectName("Secondary")
        btn_choose_keyfile.clicked.connect(self.choose_keyfile)
        btn_generate_keyfile = QPushButton("Generate New Keyfile")
        btn_generate_keyfile.setObjectName("Secondary")
        btn_generate_keyfile.clicked.connect(self.generate_keyfile)
        btn_clear_keyfile = QPushButton("Clear Keyfile")
        btn_clear_keyfile.setObjectName("Secondary")
        btn_clear_keyfile.clicked.connect(self.clear_keyfile)
        keyfile_row.addWidget(btn_choose_keyfile)
        keyfile_row.addWidget(btn_generate_keyfile)
        keyfile_row.addWidget(btn_clear_keyfile)
        key_layout.addLayout(keyfile_row)
        layout.addWidget(key_card)

        opts_card = Card()
        opts_layout = QVBoxLayout(opts_card)
        opts_layout.addWidget(self._tag("OPTIONS"))
        self.shred_original = QCheckBox("Securely delete original after success (3-pass overwrite)")
        opts_layout.addWidget(self.shred_original)
        self.compress_folders = QCheckBox("Compress folders before encrypting (smaller output, a bit slower)")
        self.compress_folders.setChecked(True)
        opts_layout.addWidget(self.compress_folders)
        self.play_sound = QCheckBox("Play a sound when a batch finishes")
        opts_layout.addWidget(self.play_sound)
        layout.addWidget(opts_card)

        layout.addStretch()
        return self._wrap_scroll(content)

    def _build_log_tab(self):
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(10)

        log_header = FlowLayout(spacing=8)
        log_header.addWidget(self._tag("ACTIVITY LOG"))
        btn_save_log = QPushButton("Save Log")
        btn_save_log.setObjectName("Secondary")
        btn_save_log.clicked.connect(self.save_log)
        log_header.addWidget(btn_save_log)
        layout.addLayout(log_header)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMinimumHeight(200)
        layout.addWidget(self.log_box, stretch=1)

        return self._wrap_scroll(content)

    @staticmethod
    def _tag(text):
        lbl = QLabel(text)
        lbl.setObjectName("SectionTag")
        return lbl

    # Note: this used to also call an undocumented Windows API
    # (SetWindowCompositionAttribute) for a real OS-level blur-behind
    # effect. It was removed because that API's behavior is inconsistent
    # across Windows builds/updates - it can render fine on one PC and
    # broken on another with identical code, which is exactly the kind of
    # bug that's painful to track down. The painted GradientBackground
    # above gives a liquid-glass look on its own, consistently, everywhere.

    def closeEvent(self, event):
        self.settings.setValue("last_dir", self.last_dir)
        self.settings.setValue("output_dir", self.output_dir or "")
        self.settings.setValue("dark_mode", self.dark_mode)
        self.settings.setValue("security_index", self.security_combo.currentIndex())
        self.settings.setValue("encryption_index", self.encryption_combo.currentIndex())
        self.settings.setValue("shred_original", self.shred_original.isChecked())
        self.settings.setValue("compress_folders", self.compress_folders.isChecked())
        self.settings.setValue("play_sound", self.play_sound.isChecked())
        self.settings.setValue("window_size", self.size())
        super().closeEvent(event)

    def _restore_settings(self):
        idx = self.settings.value("security_index", 1, int)
        self.security_combo.setCurrentIndex(idx)
        enc_idx = self.settings.value("encryption_index", 0, int)
        if 0 <= enc_idx < len(ENCRYPTION_TYPES):
            self.encryption_combo.setCurrentIndex(enc_idx)
        self.shred_original.setChecked(self.settings.value("shred_original", False, bool))
        self.compress_folders.setChecked(self.settings.value("compress_folders", True, bool))
        self.play_sound.setChecked(self.settings.value("play_sound", False, bool))
        if self.output_dir:
            self.output_input.setText(self.output_dir)

    # ---------------- Theme ----------------
    def _apply_theme(self):
        self.setStyleSheet(build_qss(self.dark_mode))
        self.bg.set_dark(self.dark_mode)
        self.theme_btn.setText("☀️ Light" if self.dark_mode else "🌙 Dark")

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self._apply_theme()

    # ---------------- Encryption type ----------------
    def _update_encryption_summary(self, index):
        et = ENCRYPTION_TYPES[index]
        self.encryption_summary.setText(et["summary"])
        speed_label, stars = SPEED_RATING.get(et["name"], ("Unknown", ""))
        self.encryption_speed.setText(f"<b>Relative speed:</b> {speed_label}  {stars}")

    def show_encryption_type_info(self):
        et = ENCRYPTION_TYPES[self.encryption_combo.currentIndex()]
        dialog = EncryptionInfoDialog(self, et, self.show_comparison_dialog)
        dialog.exec()

    def show_comparison_dialog(self):
        dialog = ComparisonDialog(self)
        dialog.exec()

    # ---------------- Password helpers ----------------
    def toggle_password_visibility(self, state):
        mode = QLineEdit.Normal if state else QLineEdit.Password
        self.password_input.setEchoMode(mode)
        self.confirm_input.setEchoMode(mode)

    def on_password_activity(self, text):
        self.update_strength(self.password_input.text())
        self.idle_timer.start()

    def auto_clear_passwords(self):
        if self.password_input.text() or self.confirm_input.text():
            self.password_input.clear()
            self.confirm_input.clear()
            self.log("Password fields auto-cleared after 5 minutes of inactivity.")

    def update_strength(self, text):
        score, label, color = password_strength(text)
        self.strength_label.setText(label)
        self.strength_label.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: 700;")

    def fill_generated_password(self):
        pw = generate_password()
        self.password_input.setEchoMode(QLineEdit.Normal)
        self.confirm_input.setEchoMode(QLineEdit.Normal)
        self.show_pw_checkbox.setChecked(True)
        self.password_input.setText(pw)
        self.confirm_input.setText(pw)
        self.log("Generated a new 20-character random password. Copy it somewhere safe now - it is not stored anywhere.")

    def verify_password(self):
        cvlt_files = [p for p in self.selected_paths if p.endswith(".cvlt")]
        if not cvlt_files:
            QMessageBox.information(self, "Nothing to verify", "Add at least one .cvlt file first.")
            return
        if not self.password_input.text():
            QMessageBox.warning(self, "Missing password", "Enter a password first.")
            return
        target = cvlt_files[0]
        try:
            detected = describe_encryption_type(Path(target))
            ok = verify_password_quick(Path(target), self._build_secret())
        except Exception as e:
            self.log(f"[VERIFY] Could not check {target}: {e}")
            return
        if ok:
            self.log(f"[VERIFY] ✓ Password (and keyfile, if any) correct for {Path(target).name} - detected: {detected}")
        else:
            self.log(f"[VERIFY] ✗ Password/keyfile is WRONG for {Path(target).name} - detected: {detected}")

    # ---------------- Output location ----------------
    def choose_output_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Choose output folder", self.last_dir)
        if path:
            self.output_dir = path
            self.output_input.setText(path)

    def reset_output_dir(self):
        self.output_dir = None
        self.output_input.setText("")

    def open_output_folder(self):
        if self.last_output_dir:
            open_in_file_manager(self.last_output_dir)

    # ---------------- Keyfile ----------------
    def choose_keyfile(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a keyfile", self.last_dir)
        if path:
            self.keyfile_path = path
            self.keyfile_input.setText(path)
            self.log(f"Keyfile set: {Path(path).name} - both this file AND the password will be required.")

    def generate_keyfile(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save new keyfile", "cryptvault.key", "Key files (*.key)")
        if not path:
            return
        Path(path).write_bytes(secrets.token_bytes(256))
        self.keyfile_path = path
        self.keyfile_input.setText(path)
        self.log(f"Generated a new keyfile at {path}. Keep this file safe and BACKED UP - "
                 "losing it means anything encrypted with it becomes unrecoverable, even with the right password.")

    def clear_keyfile(self):
        self.keyfile_path = None
        self.keyfile_input.setText("")

    def _build_secret(self) -> bytes:
        keyfile_bytes = None
        if self.keyfile_path:
            try:
                keyfile_bytes = Path(self.keyfile_path).read_bytes()
            except Exception as e:
                self.log(f"[WARNING] Could not read keyfile: {e}")
        return build_secret(self.password_input.text(), keyfile_bytes)

    # ---------------- File selection ----------------
    def choose_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose files", self.last_dir)
        if paths:
            self.last_dir = str(Path(paths[0]).parent)
            self.add_paths(paths)

    def choose_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Choose a folder", self.last_dir)
        if path:
            self.last_dir = str(Path(path).parent)
            self.add_paths([path])

    def add_paths(self, paths):
        for p in paths:
            if p not in self.selected_paths:
                self.selected_paths.append(p)
                row_widget = FileRowWidget(p)
                item = QListWidgetItem()
                item.setSizeHint(row_widget.sizeHint())
                item.setToolTip(p)
                self.file_list.addItem(item)
                self.file_list.setItemWidget(item, row_widget)
                self.row_widgets[p] = row_widget
                self.list_items[p] = item

    def remove_selected(self):
        for item in self.file_list.selectedItems():
            row = self.file_list.row(item)
            path = self.selected_paths.pop(row)
            self.row_widgets.pop(path, None)
            self.list_items.pop(path, None)
            self.file_list.takeItem(row)

    def clear_list(self):
        self.selected_paths = []
        self.row_widgets = {}
        self.list_items = {}
        self.file_list.clear()

    def show_file_context_menu(self, pos):
        item = self.file_list.itemAt(pos)
        if not item:
            return
        row = self.file_list.row(item)
        path = self.selected_paths[row]

        menu = QMenu(self)
        encrypt_action = QAction("Encrypt This Item Only", self)
        encrypt_action.triggered.connect(lambda: self._run_single(path, "encrypt"))
        decrypt_action = QAction("Decrypt This Item Only", self)
        decrypt_action.triggered.connect(lambda: self._run_single(path, "decrypt"))
        menu.addAction(encrypt_action)
        menu.addAction(decrypt_action)
        menu.addSeparator()

        if Path(path).is_file():
            hash_action = QAction("Compute SHA-256", self)
            hash_action.triggered.connect(lambda: self._compute_hash(path))
            menu.addAction(hash_action)
            if path.endswith(".cvlt"):
                info_action = QAction("Show Encryption Type Used", self)
                info_action.triggered.connect(lambda: self._show_file_encryption_type(path))
                menu.addAction(info_action)

        open_action = QAction("Open Containing Folder", self)
        open_action.triggered.connect(lambda: open_in_file_manager(Path(path).parent))
        remove_action = QAction("Remove From List", self)
        remove_action.triggered.connect(lambda: self._remove_row(row))
        menu.addAction(open_action)
        menu.addAction(remove_action)
        menu.exec(self.file_list.mapToGlobal(pos))

    def _compute_hash(self, path):
        try:
            digest = sha256_of_file(Path(path))
            self.log(f"[SHA-256] {Path(path).name}: {digest}")
        except Exception as e:
            self.log(f"[SHA-256] Could not hash {path}: {e}")

    def _show_file_encryption_type(self, path):
        try:
            desc = describe_encryption_type(Path(path))
            self.log(f"[INFO] {Path(path).name} was encrypted with: {desc}")
        except Exception as e:
            self.log(f"[INFO] Could not read header of {path}: {e}")

    def _run_single(self, path, mode):
        if not self.password_input.text():
            QMessageBox.warning(self, "Missing password", "Enter a password first.")
            return
        if mode == "encrypt" and self.password_input.text() != self.confirm_input.text():
            QMessageBox.warning(self, "Password mismatch", "Password and confirmation don't match.")
            return
        self._run_batch(mode, paths=[path])

    def _remove_row(self, row):
        path = self.selected_paths.pop(row)
        self.row_widgets.pop(path, None)
        self.list_items.pop(path, None)
        self.file_list.takeItem(row)

    # ---------------- Logging ----------------
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_box.append(f"[{timestamp}] {message}")

    def save_log(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save log", "cryptvault_log.txt", "Text files (*.txt)")
        if path:
            Path(path).write_text(self.log_box.toPlainText(), encoding="utf-8")
            self.log(f"Log saved to {path}")

    # ---------------- Batch control ----------------
    def _preset_name(self):
        return ["fast", "balanced", "paranoid"][self.security_combo.currentIndex()]

    def _validate(self, is_encrypt):
        if not self.selected_paths:
            QMessageBox.warning(self, "Missing input", "Add at least one file or folder.")
            return False
        if not self.password_input.text():
            QMessageBox.warning(self, "Missing password", "Enter a password.")
            return False
        if is_encrypt and self.password_input.text() != self.confirm_input.text():
            QMessageBox.warning(self, "Password mismatch", "Password and confirmation don't match.")
            return False
        return True

    def start_encrypt(self):
        if not self._validate(is_encrypt=True):
            return
        self._run_batch("encrypt")

    def start_decrypt(self):
        if not self._validate(is_encrypt=False):
            return
        self._run_batch("decrypt")

    def _set_running_state(self, running):
        self.btn_encrypt.setEnabled(not running)
        self.btn_decrypt.setEnabled(not running)
        self.btn_cancel.setEnabled(running)

    def _run_batch(self, mode, paths=None):
        target_paths = paths if paths is not None else self.selected_paths
        self.cancel_event.clear()
        self.overall_bar.setValue(0)
        self.btn_open_output.setEnabled(False)
        self.total_tasks = len(target_paths)
        self.completed_tasks = 0
        self.batch_start_time = time.time()
        preset = self._preset_name()
        secret = self._build_secret()
        cipher_ids = ENCRYPTION_TYPES[self.encryption_combo.currentIndex()]["ciphers"]
        enc_name = ENCRYPTION_TYPES[self.encryption_combo.currentIndex()]["name"]
        keyfile_note = " + keyfile" if self.keyfile_path else ""

        for p in target_paths:
            row_widget = self.row_widgets.get(p)
            if row_widget:
                row_widget.set_progress(0)
                row_widget.status_label.setText("Starting...")

        if mode == "encrypt":
            self.log(f"Starting encrypt on {self.total_tasks} item(s) "
                     f"[{enc_name}, {preset} password preset{keyfile_note}, "
                     f"{self.pool.maxThreadCount()} parallel workers]...")
        else:
            self.log(f"Starting decrypt on {self.total_tasks} item(s) "
                     f"[encryption type auto-detected per file{keyfile_note}, "
                     f"{self.pool.maxThreadCount()} parallel workers]...")
        self._set_running_state(True)
        self.tabs.setCurrentIndex(0)

        for path in target_paths:
            task = CryptoTask(mode, path, secret, cipher_ids, preset,
                               self.shred_original.isChecked(), self.output_dir, self.cancel_event,
                               compress_folders=self.compress_folders.isChecked())
            task.signals.progress.connect(self.on_item_progress)
            task.signals.done.connect(self.on_item_done)
            task.signals.failed.connect(self.on_item_failed)
            task.signals.cancelled.connect(self.on_item_cancelled)
            self.pool.start(task)

    def cancel_batch(self):
        self.cancel_event.set()
        self.log("Cancel requested - in-progress items will stop shortly...")

    def on_item_progress(self, path, percent):
        row_widget = self.row_widgets.get(path)
        if row_widget:
            row_widget.set_progress(percent)

    def _item_finished(self, output_dir=None):
        self.completed_tasks += 1
        if output_dir:
            self.last_output_dir = output_dir
        self.overall_bar.setValue(int(self.completed_tasks / max(self.total_tasks, 1) * 100))
        if self.completed_tasks >= self.total_tasks:
            total_time = time.time() - (self.batch_start_time or time.time())
            self.log(f"Batch finished in {total_time:.1f}s.")
            self._set_running_state(False)
            if self.last_output_dir:
                self.btn_open_output.setEnabled(True)
            if self.play_sound.isChecked():
                QApplication.beep()

    def on_item_done(self, path, output_path, seconds, size):
        row_widget = self.row_widgets.get(path)
        if row_widget:
            row_widget.set_status("✓ Done", done=True)
        speed = human_size(size / max(seconds, 0.01)) + "/s"
        self.log(f"[OK] {path} -> {output_path} ({human_size(size)}, {seconds:.1f}s, {speed})")
        out_path = Path(output_path)
        out_dir = out_path if out_path.is_dir() else out_path.parent
        self._item_finished(output_dir=out_dir)

    def on_item_failed(self, path, error_msg):
        row_widget = self.row_widgets.get(path)
        if row_widget:
            row_widget.set_status("✗ Failed", failed=True)
        self.log(f"[FAIL] {path}: {error_msg}")
        self._item_finished()

    def on_item_cancelled(self, path):
        row_widget = self.row_widgets.get(path)
        if row_widget:
            row_widget.set_status("⊘ Cancelled", cancelled=True)
        self.log(f"[CANCELLED] {path}")
        self._item_finished()


def _make_windows_dpi_aware():
    """A `python main.py` run automatically gets a DPI-aware manifest from
    the official Python installer, so Qt always scales correctly. A
    PyInstaller .exe does NOT inherit that manifest by default - so on a
    display with different scaling than the build machine, Windows
    silently bitmap-stretches the whole window instead of letting Qt
    render it natively. That produces exactly the symptom of "looks fine
    via python, fine on the build PC, but blurry/wrong-sized/misaligned
    on a different PC" - not a styling bug, a scaling one. This declares
    the process DPI-aware at the OS level before Qt ever starts, so the
    packaged exe behaves identically to the source version everywhere."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        # PROCESS_PER_MONITOR_DPI_AWARE - correct, modern scaling behavior
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            # Older Windows fallback (pre-8.1) - basic system DPI awareness
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def main():
    _make_windows_dpi_aware()

    # Must be set before QApplication is constructed. On displays using a
    # fractional scale factor (125%, 150%, etc. - very common on laptops)
    # the default rounding policy can produce slightly-wrong-sized,
    # blurry-looking UI. PassThrough uses the exact scale factor Windows
    # reports instead of rounding it, which renders crisply everywhere.
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)

    app = QApplication(sys.argv)
    # Force Qt's built-in "Fusion" style instead of the native Windows
    # theme style. Fusion is compiled directly into Qt itself - it's not
    # a separate plugin DLL that a packaged exe can fail to bundle or
    # load correctly on a different machine.
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
