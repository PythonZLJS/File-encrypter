# 🔒 CryptVault

A fast, secure, cross-platform file and folder encryption app with a
nice GUI, a choice of authenticated encryption algorithms, and
zero telemetry — everything stays on your machine, always.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
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
- **No virtual environment needed.** Install the libraries directly, or
  use the included install script, then launch the app.
- This checkout contains the source and build scripts. If you'd like
  a standalone executable, build it using the steps below.
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
  File decryption saves the authenticated temporary file directly,
  avoiding a second full plaintext copy.
- **Parallel batch processing** — multiple files/folders are encrypted or
  decrypted at once across your CPU's cores.
- **Optional password + keyfile unlock** — require both a password
  *and* a specific file to decrypt. Missing, empty, or unreadable keyfiles
  stop the operation rather than silently using the password alone.
- **Password generator + live strength meter + quick password
  verification** (checks just the first data chunk, so huge files don't
  require a full decrypt; password derivation still takes time).
- **SHA-256 hashing tool** to independently verify file integrity.
- **Optional original deletion** — best-effort 3-pass random overwrite
  before removal. This cannot guarantee erasure on SSDs, journaled or
  copy-on-write filesystems, snapshots, or backups.
- **Drag-and-drop, batch queue, per-file live progress bars, and one
  overall progress bar.**
- **Cancel mid-file** — removes temporary partial output. Completed items
  stay saved. ZIP creation and extraction can be cancelled too.
- **Output protection** — existing files and folders are never replaced.
  Overlapping batch inputs are rejected, and folder outputs must sit
  outside the folder being encrypted.
- **Liquid-glass GUI** with light/dark themes and a layout that holds up
  at any window size. Uses Qt's built-in "Fusion" style and explicit
  DPI-awareness so it renders consistently across different machines and
  display setups, rather than depending on things a packaged `.exe`
  doesn't automatically inherit the way running from source does.
- **Settings persist** between runs (theme, output folder, security
  level, encryption type, etc.).
- 100% local. No network calls, no accounts, no telemetry.

---

## 🪟 A little glass, a lot more clarity

The GUI keeps the liquid-glass look, with a softer background, translucent
panels, pill navigation, readable light/dark themes, a proper drop area,
and a live status line. **Files** is the main workspace; **Ciphers**,
**Settings**, and **Activity** keep the other controls easy to find.

---

## 🚀 How to use it

Once the app is open (see the setup steps below if it isn't yet), here's
the actual day-to-day workflow:

### Encrypting something
1. Go to the **Files** tab.
2. Drag files or folders into the box, or use **Add Files** / **Add
   Folder**.
3. Type a password (or hit **Generate** for a strong random one — just
   make sure to save it somewhere, it's not stored anywhere by the app).
4. *(Optional)* Head to the **Ciphers** tab to pick a different
   cipher, or the **Settings** tab to attach a keyfile, change the output
   folder, or turn on optional original deletion.
5. Back on the main tab, hit **Encrypt files**.
6. Each file gets its own `.cvlt` file sitting next to the original (or
   in your chosen output folder), with a live progress bar while it works.

### Decrypting something
1. Drag your `.cvlt` file(s) into the same box.
2. Enter the password you encrypted it with (and attach the keyfile too,
   if you used one).
3. Hit **Decrypt files**.
4. A file restores to its original name. A folder restores inside
   `<original-name>_decrypted/<original-name>/`, including empty folders.
   Existing destinations cause an error; move them or choose a different
   output folder first.
5. You don't need to select the encryption type. The app reads that
   straight out of the file itself.

### A few handy extras
- **Verify Password** — checks your password against a `.cvlt` file
  by authenticating its first chunk, without doing a full decrypt.
  Password derivation still takes time, especially on Paranoid. This
  checks the password/keyfile, not the integrity of the entire file.
- **Right-click any file** in the queue for quick actions — encrypt/decrypt
  just that one item, compute its SHA-256 hash, see which encryption type
  it uses, or open its folder.
- **Compare All Types** (Ciphers tab) — a side-by-side table of
  every cipher option if you want to pick one deliberately instead of
  going with the default.
- Check the **Activity** tab any time to see exactly what happened,
  and save it to a text file if you want a record.

---

## 🧠 How the encryption actually works

New encrypted files use the **v4** format and are self-contained `.cvlt`
files:

```
MAGIC(4)="CVL4" | VERSION(1)=4 | LAYER COUNT(1) | IS_FOLDER(1) | KDF PRESET(8)
for each layer: CIPHER ID(1) | SALT(16) | NONCE PREFIX(4)
then: a stream of [LENGTH(4) | CIPHERTEXT+TAG] chunks until end of file
```

- **Key derivation** uses `scrypt`, a memory-hard function that resists
  GPU/ASIC password-cracking rigs far better than a plain hash. Three
  cost presets are available (Fast / Balanced / Paranoid). New settings
  default to Paranoid: `N=2^17, r=8, p=1`, using about 128MB per derivation.
  Faster presets remain available and existing files keep their original
  parameters. The stronger preset follows the parameter guidance in the
  [OWASP scrypt notes](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt).
- **Folders** are zipped to a temporary file on disk (not held in
  memory), then streamed through the same per-chunk encryption as a
  single file.
- **Every chunk is authenticated** with associated data binding the entire
  header, its index, and whether it's the final chunk. Header changes,
  reordered chunks, missing chunks, truncation, and trailing garbage
  cause decryption to fail. Headers and chunk lengths are validated.
- **Nonces** use a random 4-byte prefix plus an 8-byte chunk counter.
  Each file/layer also gets a fresh random 16-byte salt and its own
  derived key; the counter never repeats within a stream.
- **An optional keyfile** mixes its SHA-256 hash into the key-derivation
  input, so both the password and the exact keyfile are needed to decrypt
  if one was used. Back it up separately: losing the password or keyfile
  means losing access.

### A few security details worth knowing
- **Existing v3 files can still be decrypted.** Their old headers were
  not authenticated, so optional original deletion is blocked for v3.
  Keep the source, inspect the recovered contents, then encrypt again
  to create a v4 file. Older versions of the app cannot open v4 files.
- File outputs are written to private temporary files and published
  only after successful completion, without replacing existing paths.
  Windows uses a rename that refuses existing destinations; other
  platforms use hard links and fail safely if the filesystem doesn't
  support them.
- Folder recovery validates ZIP paths and rejects links, special files,
  traversal paths, and duplicate names. It never merges into an existing
  directory. Extraction is limited to 100,000 entries and available disk
  space (with a 64MB reserve). Symlinks, junctions, and hard-linked input
  files are rejected.
- Folder encryption needs a temporary plaintext ZIP; decryption also
  uses temporary plaintext on disk. Normal cleanup removes these files,
  but a crash or power loss may leave them behind. Use an encrypted
  drive if temporary plaintext is a concern.
- Keep input files unchanged while a job runs. Original deletion checks
  for source changes first, but cannot make a live folder into a snapshot.
  Unreadable folder entries abort the operation instead of being skipped.
  Source changes abort encryption, and non-portable archive names are
  rejected before folder encryption. Keep backups and test recovery
  before enabling deletion.
- File contents are encrypted; output filenames, approximate sizes, cipher
  choices, and the folder flag are visible. Passwords are not saved in
  settings, but Python cannot guarantee wiping secrets from process memory.
- Original deletion starts **off** each time you open the app. Generated
  passwords stay masked until you choose Show password.
- Password checks, keyfile reads, and hashing run in the background.
  Password derivations are serialized to limit peak memory use, while
  file processing uses two workers. Closing cancels active work and
  waits for safe cleanup.

---

## 🛠️ Getting started (running from source)

### 1. Install Python
Use 64-bit Python 3.10 or newer (Python 3.14 and 3.15 were used for local testing). Jump to **[Installing Python](#-installing-python)**
at the very bottom of this page if you don't have it yet.

### 2. Get the code
```bash
git clone https://github.com/PythonZLJS/File-encrypter.git
cd File-encrypter
cd code
```
Or just hit the green **Code → Download ZIP** button on the repo page if
you'd rather not use git.

### 3. Install and open — one launcher, no venv
Open the **`code`** folder. It contains the launcher, GUI, encryption
engine, and requirements. The README and license stay in the outer folder.

On Windows:
```powershell
python cryptvault.py install
python cryptvault.py
```
After the first install, just run **`python cryptvault.py`** whenever you
want to open the app. There are no batch files or shell scripts.

On Linux / macOS, use `python3`:
```bash
python3 cryptvault.py install
python3 cryptvault.py
```

Prefer downloading the libraries yourself? This works too:
```bash
python -m pip install --upgrade -r requirements.txt
```

| Command | What it does |
|---|---|
| `python cryptvault.py` | Open the app |
| `python cryptvault.py install` | Install/update the runtime libraries |
| `python cryptvault.py check` | Check the Python installation and libraries |
| `python cryptvault.py build` | Install build tools and create a standalone app |

Use the **same Python command** for installing and running. Libraries
installed for one Python version aren't automatically available to another.

The runtime dependencies are **`PySide6-Essentials`** for the GUI and
**`cryptography`** for encryption. PyInstaller is installed only when you
run `build`; it isn't needed to run the source.

If Linux/macOS pip reports an **externally managed environment**, use a
user-managed Python installation. The launcher respects the OS's package
protections. See the
[Python packaging explanation](https://packaging.python.org/en/latest/specifications/externally-managed-environments/).

### 4. If it doesn't launch
Run `python cryptvault.py check` to diagnose startup problems. Missing libraries show the install command for the
Python that actually tried to run the app.

Windows startup errors also appear in a dialog. Details are saved to
`%LOCALAPPDATA%\CryptVault\startup.log`, or `~/CryptVault/startup.log`
when LOCALAPPDATA isn't set. Logs contain tracebacks, not file contents
or password fields.

If you have several Python versions, choose the same one for both steps:
```powershell
py -3.14 cryptvault.py install
py -3.14 cryptvault.py
```

---

## 📦 Compiling a standalone executable

From the `code` folder, run:
```bash
python cryptvault.py build
```
Use `python3` on Linux/macOS.

The launcher installs the runtime libraries and PyInstaller, then bundles
the app with `--onefile --windowed --clean --noupx` and the required
Qt/cryptography package data. No venv is created, and no manual cleanup
of your previous build folders is needed.

- **Windows:** `dist/CryptVault.exe`.
- **Linux:** `dist/CryptVault`.
- **macOS:** `dist/CryptVault` and/or a `.app` bundle, depending on the build.

The machine running the finished app doesn't need Python installed.
Build separately for each OS and CPU architecture, and test the result
on your target machine before sharing it. Existing executables need
rebuilding to pick up source changes.

### If a packaged app doesn't open
Check that its OS and CPU architecture match the machine. On Windows,
you may need the Microsoft Visual C++ Redistributable:
https://aka.ms/vs/17/release/vc_redist.x64.exe

Graphics drivers, VM settings, missing Qt plugins, and system libraries
can also affect startup. The
[PyInstaller guide](https://pyinstaller.org/en/stable/usage.html) explains
the platform requirements and one-file behavior.

---

## 📁 Project structure
```
File-encrypter/
├── README.md
├── LICENSE.md
└── code/
    ├── cryptvault.py    # run, install, check, build, and startup diagnostics
    ├── app.py           # GUI and background tasks
    ├── crypto_engine.py # encryption and safe file operations
    └── requirements.txt
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
   `sudo apt install python3 python3-pip` (Debian/Ubuntu) or
   your distribution's equivalent package manager.
6. Confirm it worked:
   ```bash
   python --version      # Windows
   python3 --version     # Linux/macOS
   ```

---

## 📜 License
[MIT](LICENSE.md) — do whatever you like with it.
