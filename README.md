# 🔒 CryptVault

A fast, secure, cross-platform file and folder encryption app with a
nice GUI, a choice of authenticated encryption algorithms, and
zero telemetry — everything stays on your machine, always.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

**Repo:** https://github.com/PythonZLJS/File-encrypter

---

## 👋 Hey, welcome

I made this to encrypt my own files locally, with nothing being sent
anywhere — no telemetry, no accounts, no "phoning home." Just your files,
your password, on your machine.

A couple of honest heads-ups before you dive in:
- You'll need an internet connection the *first* time you set it up, so
  Python can download the couple of packages this app runs on. That's
  just how Python works, not anything sketchy on my end.
- Using the app should be pretty self-explanatory once it's open, but
  there's a full **"How to Use It"** section below anyway, just in case.
- You genuinely don't need to remember which encryption method you used
  on a file when it comes time to decrypt it — the app figures that out
  on its own. More on that further down.
- I'm slowly working on a script that automatically sets up all the
  Python bits for you, so eventually you won't even need this whole
  install dance. Not built yet, but it's coming.
- Alongside the raw source code, I'm also attaching the pre-compiled
  version and a few other variations of the code in the repo — worth a
  look if you'd rather skip straight to a working `.exe`.
- Also I may add more features in the future as well as some other code on my GitHub account that could be useful.
- If you enjoyed this project, please star the repo.

Have fun with it, and if something breaks, open an issue — I'd genuinely
like to know.

---

## ✨ Features

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
- **Parallel batch processing** — multiple files/folders are encrypted or
  decrypted at once across your CPU's cores.
- **Optional keyfile (two-factor) unlock** — require both a password
  *and* a specific file to decrypt.
- **Password generator + live strength meter + instant password
  verification** (checks just the first data chunk, so you get an answer
  instantly even on huge files).
- **SHA-256 hashing tool** to independently verify file integrity.
- **Secure delete** — 3-pass random overwrite of the original file before
  removal, for when you don't want plaintext left behind.
- **Drag-and-drop, batch queue, per-file live progress bars, and one
  overall progress bar.**
- **Cancel mid-file** — stops cleanly and removes any partial output.
- **Liquid-glass GUI** with light/dark themes and a layout that holds up
  at any window size. Uses Qt's built-in "Fusion" style and explicit
  DPI-awareness so it renders consistently across different machines and
  display setups, rather than depending on things a packaged `.exe`
  doesn't automatically inherit the way running from source does.
- **Settings persist** between runs (theme, output folder, security
  level, encryption type, etc.).
- 100% local. No network calls, no accounts, no telemetry.

---

## 🚀 How to use it

Once the app is open (see the setup steps below if it isn't yet), here's
the actual day-to-day workflow:

### Encrypting something
1. Go to the **Encrypt / Decrypt** tab.
2. Drag files or folders into the box, or use **Add Files** / **Add
   Folder**.
3. Type a password (or hit **Generate** for a strong random one — just
   make sure to save it somewhere, it's not stored anywhere by the app).
4. *(Optional)* Head to the **Encryption Type** tab to pick a different
   cipher, or the **Settings** tab to attach a keyfile, change the output
   folder, or turn on secure delete.
5. Back on the main tab, hit **Encrypt All**.
6. Each file gets its own `.cvlt` file sitting next to the original (or
   in your chosen output folder), with a live progress bar while it works.

### Decrypting something
1. Drag your `.cvlt` file(s) into the same box.
2. Enter the password you encrypted it with (and attach the keyfile too,
   if you used one).
3. Hit **Decrypt All**.
4. That's it — you don't need to know or select which encryption type
   was used. The app reads that straight out of the file itself.

### A few handy extras
- **Verify Password** — checks your password against a `.cvlt` file
  instantly, without doing a full decrypt. Great before running a big
  batch, so you don't find out you typo'd the password halfway through.
- **Right-click any file** in the queue for quick actions — encrypt/decrypt
  just that one item, compute its SHA-256 hash, see which encryption type
  it uses, or open its folder.
- **Compare All Types** (Encryption Type tab) — a side-by-side table of
  every cipher option if you want to pick one deliberately instead of
  going with the default.
- Check the **Activity Log** tab any time to see exactly what happened,
  and save it to a text file if you want a record.

---

## 🧠 How the encryption actually works

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

## 🛠️ Getting started (running from source)

### 1. Install Python
You need Python 3.9 or newer. Jump to **[Installing Python](#-installing-python)**
at the very bottom of this page if you don't have it yet.

### 2. Get the code
```bash
git clone https://github.com/PythonZLJS/File-encrypter.git
cd File-encrypter
```
Or just hit the green **Code → Download ZIP** button on the repo page if
you'd rather not use git.

### 3. Install the dependencies
Open a terminal in the folder you just downloaded/cloned (or `cd` into
it), then run:
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
Or, once your file manager knows to open `.py` files with Python, just
double-click `main.py`.

---

## 📦 Compiling a standalone executable

You don't need to run it from source every time — you can compile it
into a single file that runs with **no Python installed** on the machine
that uses it. (Building still needs Python + the dependencies installed
*once*, on the machine doing the build.)

> **Heads up:** the compiled version doesn't currently run properly
> inside virtual machines (tested with VMware) — something about the VM's
> graphics handling doesn't play nicely with it yet. Running it on a
> normal, physical machine works fine. If you only have a VM to test in,
> run it from source (`python main.py`) instead for now.

You can only compile it for the OS you're currently running it on —
compiling on Windows gets you a Windows build, compiling on macOS gets
you a macOS build, and so on. See **["A build only runs on the OS it was
built on"](#a-build-only-runs-on-the-os-it-was-built-on)** below.

### Windows
Find `build_windows.bat` in the folder with the source code, then:
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
  Qt plugin files into **one single executable**. There's no separate
  folder to copy alongside it — the one file *is* the whole app.
- `--windowed` — no terminal window behind the GUI.
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
(or the Linux/macOS binary) to another machine is correct, and is all you
need to do.

### A build only runs on the OS it was built on
A Windows `.exe` won't run on macOS, a macOS app won't run on Linux, and
so on — PyInstaller always builds for whichever OS it's running on. To
ship all three, run the matching script once on a Windows machine, once
on Linux, and once on a Mac. `main.py` never changes between them.

### If the built app opens but looks wrong on another machine
If it opens fine but looks blurry, wrong-sized, or misaligned only on
certain other PCs — while it looks correct on the machine that built it
— that's almost always a display-scaling (DPI) issue, not a missing
file. Running from source (`python main.py`) always looks right because
Python's own installer embeds a DPI-aware manifest automatically; a
packaged `.exe` doesn't inherit that unless the app declares it itself.
`main.py` already handles this, so this shouldn't come up if you're
building from the current version — if it still does, let me know the
Windows version and display scaling percentage (Settings → Display) on
the affected machine.

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

## 📁 Project structure
```
File-encrypter/
├── main.py              # the entire application (engine + GUI)
├── requirements.txt     # Python dependencies
├── build_windows.bat    # one-click Windows build script
├── build_unix.sh        # one-click Linux/macOS build script
└── README.md
```

---

## 🐍 Installing Python

If you don't already have Python installed:

1. Go to https://www.python.org/downloads/
2. Download the latest Python 3 installer for your OS.
3. **Windows:** during install, tick **"Add python.exe to PATH"** before
   clicking Install — this is the single most common setup mistake, and
   skipping it is why `python` or `pip` might say "not recognized" later.
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

## 📜 License
MIT — do whatever you like with it.
