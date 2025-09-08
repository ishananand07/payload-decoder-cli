# Payload Decoder CLI

A command-line tool to automatically detect and decode **common obfuscations** found in malicious scripts and payloads.  
Useful for quick triage of encoded blobs (e.g. PowerShell `-enc`, Base64 payloads, compressed strings).

---

## ✨ Features
- Detects and decodes:
  - **Base64** / Base64URL
  - **UTF-16 LE/BE** text (common in PowerShell `-enc`)
  - **Hex** (strict detection for byte sequences)
  - **URL encoding** (`%20`, `+`, etc.)
  - **HTML entities** (`&amp;`, `&#x21;`, etc.)
  - **Compression**: gzip, zlib, bz2, lzma
- Optional heuristics:
  - **ROT13 / ROT-N** (`--enable-rot`)
  - **Single-byte XOR hunt** (`--enable-xor`)
- **Linewise & in-place block decoding**:
  - Can decode embedded encoded strings inside larger text lines.
- **Readability auto-stop**:
  - Stops decoding when output looks like natural text (prevents over-decoding).

---

## ⚡ Installation

```bash
git clone https://github.com/<your-username>/payload-decoder-cli.git
cd payload-decoder-cli

# Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate   # macOS/Linux
# Windows: .\.venv\Scripts\activate
```

No external dependencies — everything is standard library.

---

## 🚀 Usage

Run the tool with input from **stdin** or a file:

```bash
python decoder_cli.py <file>
# or
echo -n SGVsbG8gV29ybGQ= | python decoder_cli.py -
```

### Examples

**Base64 → Hello World**
```bash
echo -n SGVsbG8gV29ybGQ= | python decoder_cli.py -
# Output: Hello World
```

**Hex(UTF-16LE) → Hello!**
```bash
echo -n 480065006C006C006F002100 | python decoder_cli.py -
# Output: Hello!
```

**Base64(UTF-16LE('Ishan is a Genius'))**
```bash
echo -n AEkAcwBoAGEAbgAgAGkAcwAgAGEAIABHAGUAbgBpAHUAcw== | python decoder_cli.py -
# Output: Ishan is a Genius
```

---

## ⚙️ Options

```bash
--linewise         Decode each line independently
--inplace-blocks   Decode Base64/Hex/URL/HTML blocks inside lines
--enable-rot       Enable ROT13/ROT-N detection
--enable-xor       Enable single-byte XOR hunt (slower on big blobs)
--json             Output JSON report (steps + preview)
--max-steps N      Limit decoding iterations (default: 6)
```

---

## ⚠️ Disclaimer
This tool is intended for **educational and defensive purposes only**.  
Do not use it to decode or run untrusted payloads outside of a safe analysis environment.

---

## 📄 License
MIT License © 2025  
Author: **Ishan Anand**
