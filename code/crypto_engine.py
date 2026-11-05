"""Streaming authenticated encryption and safe local file operations."""

import hashlib
import os
import re
import secrets
import shutil
import stat
import string
import struct
import tempfile
import threading
import zipfile
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import (
    AESCCM,
    AESGCM,
    AESGCMSIV,
    AESOCB3,
    ChaCha20Poly1305,
)
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"CVL4"
VERSION = 4
KEY_LEN = 32
CHUNK_SIZE = 1024 * 1024  # 1 MB chunks - keeps memory flat & progress smooth
SHRED_PASSES = 3

SCRYPT_PRESETS = {
    "fast": dict(n=2**14, r=8, p=1),
    "balanced": dict(n=2**15, r=8, p=1),
    "paranoid": dict(n=2**17, r=8, p=1),
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


_KDF_LOCK = threading.Lock()


def derive_key(secret: bytes, salt: bytes, preset: str) -> bytes:
    params = SCRYPT_PRESETS[preset]
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=params["n"], r=params["r"], p=params["p"])
    with _KDF_LOCK:
        return kdf.derive(secret)


def secret_with_keyfile(secret, keyfile, cancel_check=None, expected=None):
    path = Path(keyfile)
    validate_source(path)
    digest = hashlib.sha256()
    with path.open("rb") as source:
        initial = source_signature(os.fstat(source.fileno()))
        if initial[2] == 0 or (expected is not None and initial != expected):
            raise CryptoError("The selected keyfile is empty or changed.")
        while True:
            _cancel(cancel_check)
            data = source.read(CHUNK_SIZE)
            if not data:
                break
            digest.update(data)
        if initial != source_signature(os.fstat(source.fileno())):
            raise CryptoError("The keyfile changed while being read.")
    return secret + b"|keyfile|" + digest.digest()


def sha256_of_file(path: Path, progress_cb=None, cancel_check=None) -> str:
    """Streams the file to compute its SHA-256 - lets you independently
    verify two files are byte-identical (e.g. before/after transfer)."""
    total = max(path.stat().st_size, 1)
    h = hashlib.sha256()
    read = 0
    with open(path, "rb") as f:
        while True:
            _cancel(cancel_check)
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


def _cancel(check):
    if check and check():
        raise Cancelled()


def _read_exact(fin, length):
    value = fin.read(length)
    if len(value) != length:
        raise CryptoError("Truncated CryptVault file.")
    return value


def _parse_header(fin):
    fixed = _read_exact(fin, 15)
    magic, version, layers, folder = fixed[:4], fixed[4], fixed[5], fixed[6]
    if (magic, version) not in ((b"CVL3", 3), (MAGIC, VERSION)):
        raise CryptoError("Unsupported CryptVault format or version.")
    if not 1 <= layers <= 3 or folder not in (0, 1):
        raise CryptoError("Invalid layer count or folder flag.")
    try:
        preset = fixed[7:15].rstrip(b"\0").decode("ascii")
    except UnicodeDecodeError as exc:
        raise CryptoError("Invalid password preset.") from exc
    if preset not in SCRYPT_PRESETS or fixed[7:15] != preset.encode().ljust(8, b"\0"):
        raise CryptoError("Invalid password preset.")
    records = _read_exact(fin, layers * 21)
    ids, salts, prefixes = [], [], []
    for i in range(layers):
        record = records[i * 21 : (i + 1) * 21]
        if record[0] not in CIPHER_REGISTRY:
            raise CryptoError("Unsupported encryption algorithm.")
        ids.append(record[0])
        salts.append(record[1:17])
        prefixes.append(record[17:21])
    return (
        (layers, bool(folder), preset, ids, salts, prefixes),
        fixed + records,
        version,
    )


def _aad(header, version, index, last):
    return (header if version >= 4 else b"") + struct.pack(">QB", index, int(last))


def publish_file(source, destination):
    """Publish a completed file on the same filesystem without replacing data."""
    source, destination = Path(source), Path(destination)
    if os.name == "nt":
        os.rename(source, destination)
    else:
        os.link(source, destination)
        sync_directory(destination.parent)


@contextmanager
def staged_output(destination):
    """Publish only complete outputs, without replacing any existing path."""
    destination = Path(destination)
    if os.path.lexists(destination):
        raise CryptoError(f"Output already exists: {destination}")
    fd, name = tempfile.mkstemp(prefix=".cryptvault-", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as fout:
            yield fout
            fout.flush()
            os.fsync(fout.fileno())
        publish_file(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def encrypt_stream(
    src_path,
    dst_path,
    secret,
    cipher_ids,
    is_folder,
    preset,
    progress_cb=None,
    cancel_check=None,
):
    src_path, dst_path = Path(src_path), Path(dst_path)
    if preset not in SCRYPT_PRESETS or not 1 <= len(cipher_ids) <= 3:
        raise CryptoError("Invalid encryption settings.")
    if any(c not in CIPHER_REGISTRY for c in cipher_ids):
        raise CryptoError("Unsupported encryption algorithm.")
    _cancel(cancel_check)
    layers = len(cipher_ids)
    salts = [secrets.token_bytes(16) for _ in cipher_ids]
    prefixes = [secrets.token_bytes(4) for _ in cipher_ids]
    header = (
        MAGIC
        + bytes([VERSION, layers, int(is_folder)])
        + preset.encode().ljust(8, b"\0")
    )
    header += b"".join(
        bytes([c]) + salt + prefix
        for c, salt, prefix in zip(cipher_ids, salts, prefixes)
    )
    ciphers = [
        _cipher_by_id(c, derive_key(secret + f"|layer{i}".encode(), salts[i], preset))
        for i, c in enumerate(cipher_ids)
    ]
    total = max(src_path.stat().st_size, 1)
    validate_source(src_path)
    with open(src_path, "rb") as fin, staged_output(dst_path) as fout:
        initial = source_signature(os.fstat(fin.fileno()))
        fout.write(header)
        buf, index, count = fin.read(CHUNK_SIZE), 0, 0
        while True:
            _cancel(cancel_check)
            nxt = fin.read(CHUNK_SIZE)
            last = not nxt
            current = buf
            for i, cipher in enumerate(ciphers):
                current = cipher.encrypt(
                    _nonce_for_chunk(prefixes[i], index),
                    current,
                    _aad(header, VERSION, index, last),
                )
            fout.write(struct.pack(">I", len(current)))
            fout.write(current)
            count += len(buf)
            if progress_cb:
                progress_cb(min(99, int(count / total * 100)))
            if last:
                break
            buf, index = nxt, index + 1
        _cancel(cancel_check)
        if source_signature(os.fstat(fin.fileno())) != initial:
            raise CryptoError("Input changed during encryption; original was kept.")
    if progress_cb:
        progress_cb(100)


def _read_chunk(fin, layers):
    length = struct.unpack(">I", _read_exact(fin, 4))[0]
    if not 16 * layers <= length <= CHUNK_SIZE + 16 * layers:
        raise CryptoError("Invalid encrypted chunk length.")
    ciphertext = _read_exact(fin, length)
    # Look ahead without trusting a potentially stale file size.
    following = fin.read(1)
    if following:
        fin.seek(-1, os.SEEK_CUR)
    return ciphertext, not following


def _decrypt_chunk(ciphertext, ciphers, prefixes, aad, index):
    try:
        for i in reversed(range(len(ciphers))):
            ciphertext = ciphers[i].decrypt(
                _nonce_for_chunk(prefixes[i], index), ciphertext, aad
            )
    except InvalidTag as exc:
        raise CryptoError(
            "Wrong password/keyfile, or corrupted/tampered file."
        ) from exc
    return ciphertext


def decrypt_stream(src_path, dst_path, secret, progress_cb=None, cancel_check=None):
    src_path = Path(src_path)
    total = max(src_path.stat().st_size, 1)
    _cancel(cancel_check)
    with open(src_path, "rb") as fin:
        (layers, folder, preset, ids, salts, prefixes), header, version = _parse_header(
            fin
        )
        ciphers = [
            _cipher_by_id(
                c, derive_key(secret + f"|layer{i}".encode(), salts[i], preset)
            )
            for i, c in enumerate(ids)
        ]
        with staged_output(dst_path) as fout:
            index = 0
            while True:
                _cancel(cancel_check)
                ciphertext, last = _read_chunk(fin, layers)
                plaintext = _decrypt_chunk(
                    ciphertext,
                    ciphers,
                    prefixes,
                    _aad(header, version, index, last),
                    index,
                )
                if not last and len(plaintext) != CHUNK_SIZE:
                    raise CryptoError("Invalid non-final chunk size.")
                fout.write(plaintext)
                if progress_cb:
                    progress_cb(min(99, int(fin.tell() / total * 100)))
                if last:
                    break
                index += 1
            _cancel(cancel_check)
    if progress_cb:
        progress_cb(100)
    return folder


def verify_password_quick(src_path, secret):
    """Authenticate the first chunk only; this is not full-file verification."""
    with open(src_path, "rb") as fin:
        (layers, folder, preset, ids, salts, prefixes), header, version = _parse_header(
            fin
        )
        ciphers = [
            _cipher_by_id(
                c, derive_key(secret + f"|layer{i}".encode(), salts[i], preset)
            )
            for i, c in enumerate(ids)
        ]
        ciphertext, last = _read_chunk(fin, layers)
        try:
            _decrypt_chunk(
                ciphertext, ciphers, prefixes, _aad(header, version, 0, last), 0
            )
            return True
        except CryptoError:
            return False


def describe_encryption_type(src_path):
    with open(src_path, "rb") as fin:
        (layers, folder, preset, ids, salts, prefixes), header, version = _parse_header(
            fin
        )
    names = " + ".join(CIPHER_NAMES[c] for c in ids)
    legacy = "; legacy header is not authenticated" if version == 3 else ""
    return f"{names} ({layers} layers, {preset} preset, v{version}{legacy})"


def _reject_link(path):
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise CryptoError(f"Links and junctions are not supported: {path}")


def validate_source(path):
    path = Path(path)
    _reject_link(path)
    if not path.is_file() and not path.is_dir():
        raise CryptoError(f"Input is not a regular file or folder: {path}")
    if path.is_file() and path.stat().st_nlink > 1:
        raise CryptoError(f"Hard-linked inputs are not supported: {path}")


def source_signature(st):
    # Windows stat() and fstat() can report different legacy ctime values.
    changed = st.st_ctime_ns if os.name != "nt" else None
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, changed)


def snapshot_tree(path, cancel_check=None):
    path = Path(path)
    validate_source(path)
    result = {path: source_signature(path.stat())}
    if path.is_dir():

        def walk_error(error):
            raise error

        for parent, dirs, files in os.walk(path, followlinks=False, onerror=walk_error):
            _cancel(cancel_check)
            for name in dirs + files:
                entry = Path(parent) / name
                validate_source(entry)
                result[entry] = source_signature(entry.stat())
                if len(result) > 100000:
                    raise CryptoError("Folder has too many entries (limit: 100,000).")
    return result


def verify_snapshot(path, expected, cancel_check=None):
    if snapshot_tree(path, cancel_check) != expected:
        raise CryptoError("Input changed during the operation; original was kept.")


def archive_parts(name):
    name = name[:-1] if name.endswith("/") else name
    parts = name.split("/")
    reserved = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CONIN$",
        "CONOUT$",
        *("COM" + str(i) for i in range(1, 10)),
        *("LPT" + str(i) for i in range(1, 10)),
        *("COM" + i for i in "¹²³"),
        *("LPT" + i for i in "¹²³"),
    }
    if (
        not name
        or chr(92) in name
        or len(parts) > 128
        or any(
            part in ("", ".", "..")
            or part.endswith((" ", "."))
            or any(ch in '<>:"|?*' or ord(ch) < 32 for ch in part)
            or part.split(".")[0].upper() in reserved
            or len(part.encode("utf-8")) > 255
            for part in parts
        )
    ):
        raise CryptoError("Unsafe or non-portable archive path.")
    return parts


def check_archive_path(parts, is_dir, seen, paths):
    name = "/".join(parts)
    key = name.casefold()
    if key in seen:
        raise CryptoError("Duplicate archive path.")
    seen.add(key)
    for index in range(1, len(parts) + 1):
        prefix = "/".join(parts[:index])
        folded = prefix.casefold()
        directory = index < len(parts) or is_dir
        previous = paths.get(folded)
        if previous is not None and previous != (prefix, directory):
            raise CryptoError("Conflicting archive paths.")
        paths[folded] = (prefix, directory)


def sync_directory(path):
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def zip_folder_to_file(
    folder_path,
    dst_zip,
    compress=True,
    progress_cb=None,
    cancel_check=None,
    snapshot=None,
):
    folder_path = Path(folder_path)
    if snapshot is None:
        snapshot = snapshot_tree(folder_path, cancel_check)
    entries = list(snapshot)
    seen, paths = set(), {}
    for entry in entries:
        name = entry.relative_to(folder_path.parent).as_posix()
        check_archive_path(archive_parts(name), entry.is_dir(), seen, paths)
    method = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    with zipfile.ZipFile(dst_zip, "w", method) as zf:
        for i, entry in enumerate(entries):
            _cancel(cancel_check)
            validate_source(entry)
            arcname = entry.relative_to(folder_path.parent).as_posix()
            if entry.is_dir():
                zf.write(entry, arcname + "/")
            else:
                with (
                    entry.open("rb") as source,
                    zf.open(arcname, "w", force_zip64=True) as target,
                ):
                    if source_signature(os.fstat(source.fileno())) != snapshot[entry]:
                        raise CryptoError("Input changed while archiving.")
                    while True:
                        _cancel(cancel_check)
                        chunk = source.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        target.write(chunk)
                    if source_signature(os.fstat(source.fileno())) != snapshot[entry]:
                        raise CryptoError("Input changed while archiving.")
            if progress_cb:
                progress_cb(int((i + 1) / max(len(entries), 1) * 100))
        verify_snapshot(folder_path, snapshot, cancel_check)


def unzip_file_to_folder(src_zip, dest_dir, cancel_check=None):
    """Extract only portable regular paths inside a newly reserved directory."""
    dest_dir = Path(dest_dir)
    with zipfile.ZipFile(src_zip) as zf:
        members = []
        seen, paths = set(), {}
        budget = max(0, shutil.disk_usage(dest_dir.parent).free - 64 * 1024 * 1024)
        expanded = 0
        if len(zf.infolist()) > 100000:
            raise CryptoError("Archive has too many entries (limit: 100,000).")
        for info in zf.infolist():
            parts = archive_parts(info.orig_filename)
            kind = stat.S_IFMT(info.external_attr >> 16)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise CryptoError("Archive links and special files are not supported.")
            if (
                info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                or info.flag_bits & 1
            ):
                raise CryptoError(
                    "Unsupported archive compression or encrypted ZIP entry."
                )
            check_archive_path(parts, info.is_dir(), seen, paths)
            expanded += info.file_size
            if expanded > budget:
                raise CryptoError(
                    "Not enough free space to safely extract this archive."
                )
            members.append((info, parts))
        # Reserve exclusively; never merge into an existing tree.
        dest_dir.mkdir(mode=0o700)
        try:
            for info, parts in members:
                _cancel(cancel_check)
                target = dest_dir.joinpath(*parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as source, target.open("xb") as output:
                    while True:
                        _cancel(cancel_check)
                        data = source.read(CHUNK_SIZE)
                        if not data:
                            break
                        output.write(data)
                    output.flush()
                    os.fsync(output.fileno())
            _cancel(cancel_check)
            for parent, dirs, files in os.walk(dest_dir, topdown=False):
                sync_directory(parent)
            sync_directory(dest_dir.parent)
        except BaseException:
            shutil.rmtree(dest_dir)
            raise


def shred_file(path, passes=SHRED_PASSES):
    path = Path(path)
    validate_source(path)
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "r+b") as output:
        opened = os.fstat(output.fileno())
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_ino, opened.st_dev) != (current.st_ino, current.st_dev)
        ):
            raise CryptoError("Source changed or is not a private regular file.")
        length = opened.st_size
        for _ in range(passes):
            output.seek(0)
            remaining = length
            while remaining:
                count = min(CHUNK_SIZE, remaining)
                output.write(secrets.token_bytes(count))
                remaining -= count
            output.flush()
            os.fsync(output.fileno())
    path.unlink()


def shred_path(path, passes=SHRED_PASSES):
    path = Path(path)
    validate_source(path)
    if not path.is_dir():
        shred_file(path, passes)
        return
    entries = [entry for entry in snapshot_tree(path) if entry != path]
    for entry in sorted(entries, key=lambda p: len(p.parts), reverse=True):
        if entry.is_dir():
            entry.rmdir()
        else:
            shred_file(entry, passes)
    path.rmdir()


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
    labels = {
        0: ("Very weak", "#ff5b5b"),
        1: ("Weak", "#ff8a5b"),
        2: ("Fair", "#ffd15b"),
        3: ("Strong", "#8bd85b"),
        4: ("Very strong", "#4be0a0"),
    }
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
