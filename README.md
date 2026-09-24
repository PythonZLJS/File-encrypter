# CryptVault

A fast, secure, cross-platform file and folder encryption app with a
liquid-glass GUI, a choice of authenticated encryption algorithms, and
zero telemetry — everything stays on your machine.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---
## Base info
I made this to encrypt my own files locally with no sending teleatry data to me :)
You will probably need internet when instilling/setting it up for the first time if you are installing the python packages. But that's just python not me.
The instructions to set up, run, compile, and install python are lower down on the page.
I am working on a python script to automatically set up/downloaded the python libraries needed. But I have not coded that yet but it will come evetialy.
Also when using the app is self explanatory but if you need help there is a instructions section for use (also lower down)
Have fun also you don't need to know what encription method you used to encripted a file when decripting.

## Features

- **7 authenticated encryption types** to choose from — AES-256-GCM,
  ChaCha20-Poly1305, AES-256-GCM-SIV, AES-256-OCB3, AES-256-CCM, and two
  layered options (Double Shield, Fort Knox) that stack independent
  ciphers for extra defense-in-depth. Every type has an in-app info panel
  explaining what it's good and bad at, plus a side-by-side comparison
  table of all seven.
- **Decrypting never requires remembering which type you used.** Each
  encrypted file stores which cipher(s) it needs in its own header, so
  the app detects and applies the right algorithm automatically.
- **Streaming encryption** — files are processed in 1MB chunks with
  constant memory use, so a 50GB file doesn't need 50GB (or 100GB) of RAM.
- **Parallel batch processing** — multiple files/folders are
  encrypted or decrypted at once across your CPU's cores.
- **Optional keyfile (two-factor) unlock** — require both a password
  *and* a specific file to decrypt.
- **Password generator + live strength meter + instant password
  verification** (checks just the first data chunk, so you get an answer
  in an instant even on huge files).
- **SHA-256 hashing tool** to independently verify file integrity.
- **Secure delete** — 3-pass random overwrite of the original file before
  removal, for when you don't want plaintext left behind.
- **Drag-and-drop, batch queue, per-file live progress bars, and one
  overall progress bar.**
- **Cancel mid-file** — stops cleanly and removes any partial output.
- **Liquid-glass GUI** with light/dark themes and a layout that holds up
  at any window size. Uses Qt's built-in "Fusion" style (compiled into Qt
  itself, not a separate plugin file) and explicit DPI-awareness, so it
  renders identically on every machine regardless of display scaling -
  rather than depending on things a packaged exe doesn't automatically
  inherit the way running from source does.
- **Settings persist** between runs (theme, output folder, security
  level, encryption type, etc.).
- 100% local. No network calls, no accounts, no telemetry.

---

## How the encryption works

Every encrypted file is a self-contained `.cvlt` file:

```
MAGIC(4) | VERSION(1) | LAYER COUNT(1) | IS_FOLDER(1) | KDF PRESET(8)
for each layer: CIPHER ID(1) | SALT(16) | NONCE PREFIX(4)
then: a stream of [LENGTH(4) | CIPHERTEXT+TAG] chunks until end of file
```

- **Key derivation** uses `scrypt`, a memory-hard function that resists
  GPU/ASIC password-cracking rigs far better than a plain hash. Three
  cost presets are available (Fast / Balanced / Paranoid).
- **Folders** are zipped to a temporary file on disk (not held in
  memory), then streamed through the same per-chunk encryption as a
  single file.
- **Every chunk is authenticated** with associated data binding its index
  and whether it's the final chunk, so chunks can't be reordered, dropped,
  or the file truncated without decryption failing loudly.
- **Nonces are never reused** — built from a random 4-byte prefix (unique
  per file, per layer) plus an 8-byte counter.
- **An optional keyfile** mixes its SHA-256 hash into the key-derivation
  input, so both the password and the exact keyfile are needed to decrypt
  if one was used.

---

## Getting started (run from source)

### 1. Install Python
You need Python 3.9 or newer. See **[Installing Python](#installing-python)**
at the bottom of this file if you don't have it yet.

### 2. Get the code
```bash
git clone https://github.com/yourusername/cryptvault.git
cd cryptvault
```
you can also just download it with the download buton.

### 3. Install the dependencies
before hand open terminal in that folder that you download (that contains the code) or navigate to the location in terminal.

```bash
pip install -r requirements.txt
```
This installs:
| Package | What it's for |
|---|---|
| `PySide6` | The GUI toolkit |
| `cryptography` | The actual encryption (AES-GCM, ChaCha20-Poly1305, etc. via OpenSSL) |
| `pyinstaller` | Only needed if you want to compile a standalone executable — see below |

### 4. Run it
```bash
python main.py
```
Or just double click the file.

---

## Compiling a standalone executable

You don't need to run it from source every time — you can compile it
into a single file that runs with **no Python installed** on the machine
that uses it. (Building still needs Python + the dependencies installed
*once*, on the machine doing the build.) Also for some reason it wont
run on a VM like the compiled version.

Just to clarify you can only compile it for windows if the OS you use when compiling it is windows and same for all Operating systems.

### Windows

Find the file in the folder with the python code.

```bash
build_windows.bat
```
Just double-click it, or run it from Command Prompt. It creates a virtual
environment, installs dependencies, and builds the app for you.
Result: **`dist\CryptVault.exe`** — a single file, copy it anywhere.

### Linux / macOS
```bash
chmod +x build_unix.sh
./build_unix.sh
```
Same process. Result: **`dist/CryptVault`** (may appear as
`dist/CryptVault.app` on some macOS setups).

### What the build scripts actually do
Both scripts run PyInstaller with:
```bash
pyinstaller --onefile --windowed --clean --noupx --name CryptVault \
    --collect-all PySide6 \
    --collect-all shiboken6 \
    --collect-all cryptography \
    main.py
```
- `--onefile` — bundles the Python interpreter, every dependency, and all
  Qt plugin files into **one single executable**. There is no separate
  folder to copy alongside it — the one file *is* the whole app.
- `--windowed` — no terminal window behind the GUI
- `--collect-all PySide6` / `--collect-all shiboken6` / `--collect-all cryptography`
  — explicitly bundles every Qt plugin, binding runtime, and OpenSSL
  binding these packages need. Relying on PyInstaller's autodetection
  instead of `--collect-all` is the most common reason a built app runs
  fine on the machine that built it but fails or looks broken on a
  different one.
- `--noupx` — skips UPX compression. UPX makes the file smaller, but some
  antivirus tools quarantine or corrupt UPX-compressed executables, which
  can look exactly like "the exe doesn't fully work" on another machine.

The result really is one self-contained file — copying just that `.exe`
(or the Linux/macOS binary) to another machine is correct and is all you
need to do.

### A build only runs on the OS it was built on
A Windows `.exe` won't run on macOS, a macOS app won't run on Linux, and
so on — PyInstaller always builds for whichever OS it's running on. To
ship all three, run the matching script once on a Windows machine, once
on Linux, and once on a Mac. `main.py` never changes between them.

### If the built app opens but looks wrong on another machine
If it opens fine but looks blurry, wrong-sized, or misaligned only on
certain other PCs — while it looks correct on the machine that built it
— that's a display-scaling (DPI) issue, not a missing file. Running from
source (`python main.py`) always looks right because Python's own
installer embeds a DPI-aware manifest automatically; a packaged `.exe`
doesn't inherit that unless the app declares it itself. `main.py` already
does this (`_make_windows_dpi_aware()` in `main()`), so as long as you're
building from the current version of this file, this shouldn't happen —
if it still does, it means the target PC is on an older Windows build
where this API behaves slightly differently; let us know the Windows
version and display scaling percentage (Settings → Display) on the
affected machine.

### If the built app doesn't open at all on another machine
This is almost always one of two things:
1. **Missing Qt plugins** — fixed by the `--collect-all PySide6` flag
   already in the build scripts above.
2. **Missing Microsoft Visual C++ Redistributable** (Windows only) — a
   free, standard Microsoft package that most Windows PCs already have,
   but a few don't. If the `.exe` won't launch on a second PC, install it
   there from: https://aka.ms/vs/17/release/vc_redist.x64.exe

To see the actual error instead of nothing happening, temporarily remove
`--windowed` from the build command and rebuild — a console window will
stay open and show any Python traceback.

---

## Project structure
```
cryptvault/
├── main.py              # the entire application (engine + GUI)
├── requirements.txt      # Python dependencies
├── build_windows.bat     # one-click Windows build script
├── build_unix.sh         # one-click Linux/macOS build script
└── README.md
```

---

## Installing Python

If you don't already have Python installed:

1. Go to https://www.python.org/downloads/
2. Download the latest Python 3 installer for your OS
3. **Windows:** during install, tick **"Add python.exe to PATH"** before
   clicking Install — this is the single most common setup mistake.
4. **macOS:** the installer from python.org works fine, or use
   `brew install python` if you have Homebrew.
5. **Linux:** most distributions include Python already; if not,
   `sudo apt install python3 python3-pip python3-venv` (Debian/Ubuntu) or
   your distribution's equivalent package manager.
6. Confirm it worked:
   ```bash
   python --version      # Windows
   python3 --version     # Linux/macOS
   ```

---

## License
MIT — do whatever you like with it.
