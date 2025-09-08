# Payload Decoder CLI

*All-in-one Python CLI that auto-detects and decodes common payload encodings (PowerShell -enc UTF-16LE base64, Base64/URL/HTML, hex, gzip/zlib/bz2/lzma, ROT, XOR, etc.).*

---

## ✨ Features
- Detects & unwraps Base64, Base64URL, UTF-16 LE/BE, URL percent-encoding, HTML entities, Hex, and compression (gzip/zlib/bz2/lzma).
- PowerShell **`-enc`** support (UTF-16LE → Base64).
- **Iterative decoding pipeline**: runs multiple passes until no more progress or step limit reached.
- **Line-aware modes** for partial encodings:
  - `--linewise`: decode each line independently.
  - `--inplace-blocks`: decode **embedded blocks** (Base64/Hex/URL/HTML) inside lines without touching surrounding text.
- **Optional heuristics**: `--enable-rot` (ROT13/ROT-N), `--enable-xor` (single-byte XOR hunt).
- **Three input modes**: file, stdin (`-`), or **interactive paste** (no args).
- Export final output to a file with `-o` and print JSON reports with `--json`.

---

## 📦 Installation
```bash
git clone https://github.com/ishananand07/payload-decoder-cli.git
cd payload-decoder-cli
python3 -m venv .venv && source .venv/bin/activate   # macOS/Linux
# Windows: python -m venv .venv; .\.venv\Scripts\activate
```

> No external dependencies required (stdlib only).

---

## 🖥️ Usage

### File input
```bash
python decoder_cli.py payload.txt
```

### Stdin (pipe)
```bash
echo "SGVsbG8gd29ybGQ=" | python decoder_cli.py -
```

### Interactive paste mode
```bash
python decoder_cli.py
# Paste your blob, then press Ctrl+D (macOS/Linux) or Ctrl+Z then Enter (Windows)
```

### Per-line decoding
```bash
python decoder_cli.py sample.txt --linewise
python decoder_cli.py sample.txt --linewise --inplace-blocks
```

### Enable ROT & XOR heuristics
```bash
python decoder_cli.py payload.txt --enable-rot --enable-xor --max-steps 10
```

### Save decoded output
```bash
python decoder_cli.py payload.txt -o decoded.txt
```

### JSON report (steps + preview)
```bash
python decoder_cli.py payload.txt --json
```

---

## 🔍 What it can decode (out of the box)
- PowerShell `-enc` (Base64 of UTF-16LE)
- Base64 / Base64URL (auto-padding)
- Hex bytes (filters non-hex separators first)
- URL percent-encoding & form `+`
- HTML entities (`&#xNN;`, `&amp;`, etc.)
- Compression: `gzip`, `zlib/deflate`, `bz2`, `lzma`
- UTF-16 LE/BE text (even without BOM)
- Optional: **ROT13/ROT-N**, **single-byte XOR**

---

## 🧭 How it works
The tool iteratively applies a set of decoders. If a decoder changes the data meaningfully, the pipeline restarts from the top with the new bytes, until no further progress is made or the step limit is reached. A readability score helps decide when to accept UTF-16 text and guides a hybrid linewise pass when output looks mixed.

---

## 🛣️ Roadmap ideas
- Multi-byte XOR and key-length brute force (small sizes)
- Static JavaScript unescape & concatenation normalization
- YARA/regex tagging on final output
- Entropy-based stopping & confidence scoring

---

## ⚖️ Ethics
For **defensive security** and **research** use only. Do not use to aid malicious activity.

---

## 📜 License
MIT License.

---

## ✍️ Credits
Created with ❤️ by **Ishan Anand**
