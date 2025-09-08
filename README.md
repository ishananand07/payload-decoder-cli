# Payload Decoder CLI

*All-in-one Python CLI that auto-detects and decodes common payload encodings (PowerShell -enc UTF-16LE base64, Base64/URL/HTML, hex, gzip/zlib/bz2/lzma, ROT, XOR, etc.).*

---

## 🔄 What’s new in this build
- ✅ **Hex prioritized before Base64** to prevent false positives on hex strings.
- ✅ **Readability auto-stop** — the pipeline stops early once output looks like plain, natural text (prevents over-decoding like double-Base64 on “Hello World”).

### Example
```bash
# Plain Base64 (Hello World)
echo -n SGVsbG8gV29ybGQ= | python decoder_cli.py -
# Decoding steps:
#   [1] base64 -> 11 bytes
# Final preview: Hello World
```

```bash
# UTF-16 hex (Hello!)
echo -n 480065006C006C006F002100 | python decoder_cli.py -
# Decoding steps:
#   [1] hex      -> 12 bytes
#   [2] utf16le  -> 12 bytes
# Final preview: Hello!
```

---

## ✨ Features
- Detects & unwraps Base64, Base64URL, UTF-16 LE/BE, URL percent-encoding, HTML entities, Hex (with/without spaces), and compression (gzip/zlib/bz2/lzma).
- PowerShell **`-enc`** support (UTF-16LE → Base64).
- **Iterative decoding pipeline** that restarts after each successful transform.
- **Line-aware modes** for partial encodings:
  - `--linewise`: decode each line independently.
  - `--inplace-blocks`: decode **embedded blocks** (Base64/Hex/URL/HTML) inside lines without touching surrounding text.
- **Optional heuristics**: `--enable-rot` (ROT13/ROT-N), `--enable-xor` (single-byte XOR hunt).
- **Three input modes**: file, stdin (`-`), or **interactive paste** (no args).
- Export final output to a file with `-o` and print JSON reports with `--json`.

---

## 📦 Installation
```bash
git clone https://github.com/<your-username>/payload-decoder-cli.git
cd payload-decoder-cli
python3 -m venv .venv && source .venv/bin/activate   # macOS/Linux
# Windows: python -m venv .venv; .\.venv\Scripts\activate
```

> No external dependencies required (stdlib only).

---

## 🖥️ Usage
```bash
# File input
python decoder_cli.py payload.txt

# Stdin (pipe)
echo -n SGVsbG8gV29ybGQ= | python decoder_cli.py -

# Interactive paste mode
python decoder_cli.py
# Paste your blob, then press Ctrl+D (macOS/Linux) or Ctrl+Z then Enter (Windows)

# Per-line decoding (and decode embedded blocks in place)
python decoder_cli.py sample.txt --linewise
python decoder_cli.py sample.txt --linewise --inplace-blocks

# Enable ROT & XOR heuristics
python decoder_cli.py payload.txt --enable-rot --enable-xor --max-steps 10

# Save decoded output
python decoder_cli.py payload.txt -o decoded.txt

# JSON report
python decoder_cli.py payload.txt --json
```

---

## ⚖️ Ethics
For **defensive security** and **research** use only. Do not use to aid malicious activity.

---

## 📜 License
MIT License.

---

## ✍️ Credits
Created with ❤️ by **Ishan Anand**
