#!/usr/bin/env python3
"""
All-in-One Payload Decoder (CLI)
Auto-detects and iteratively decodes common encodings/obfuscations
(e.g., PowerShell -enc UTF-16LE base64, URL/HTML entities, hex,
gzip/zlib/bz2/lzma, ROT/ROT-N, XOR).

Updates in this build:
- HEX prioritized before Base64
- Readability auto-stop after each successful step
- **Stricter Base64 detection** and **hard stop** when decoded data is plain text
"""
import argparse
import base64
import binascii
import html
import json
import re
import string
import sys
import urllib.parse
import zlib
import gzip
import bz2
import lzma
from io import BytesIO
from typing import List, Tuple, Optional, Callable

# ---------- Utilities ----------
PRINTABLE_SET = set(bytes(string.printable, "ascii"))

def is_mostly_printable(b: bytes, threshold: float = 0.9) -> bool:
    if not b:
        return False
    printable = sum(ch in PRINTABLE_SET for ch in b)
    return printable / max(1, len(b)) >= threshold

def safe_decode(b: bytes, enc: str) -> Optional[str]:
    try:
        return b.decode(enc)
    except Exception:
        return None

def score_readability(s: str) -> float:
    if not s:
        return 0.0
    tokens = len(s.split())
    ascii_ratio = sum(ch in string.printable for ch in s) / max(1, len(s))
    return 0.3 * min(tokens/20.0, 1.0) + 0.7 * ascii_ratio

def looks_like_final_text(b: bytes) -> bool:
    if not is_mostly_printable(b, 0.9):
        return False
    s = b.decode("utf-8", errors="ignore")
    return score_readability(s) >= 0.9

# ---------- Decoders (return (name, out_bytes) or None) ----------
def try_base64_raw(data: bytes) -> Optional[Tuple[str, bytes]]:
    s = data.strip().replace(b"\n", b"").replace(b" ", b"")
    # stricter: require multiple of 4 and allowed alphabet only
    if len(s) < 8 or len(s) % 4 != 0:
        return None
    if not re.fullmatch(rb"[A-Za-z0-9+/=]+", s or b""):
        return None
    try:
        out = base64.b64decode(s, validate=True)
        # If the decoded result is clearly plain text, mark as final
        if looks_like_final_text(out):
            return ("base64_final", out)
        return ("base64", out)
    except Exception:
        return None

def try_base64_urlsafe(data: bytes) -> Optional[Tuple[str, bytes]]:
    s = data.strip().replace(b"\n", b"").replace(b" ", b"")
    if len(s) < 8 or len(s) % 4 != 0:
        return None
    if not re.fullmatch(rb"[A-Za-z0-9\-_=]+", s or b""):
        return None
    try:
        out = base64.urlsafe_b64decode(s)
        if looks_like_final_text(out):
            return ("base64url_final", out)
        return ("base64url", out)
    except Exception:
        return None

def try_powershell_b64_utf16le(data: bytes) -> Optional[Tuple[str, bytes]]:
    res = try_base64_raw(data) or try_base64_urlsafe(data)
    if not res:
        return None
    name, b = res
    # If the raw b64 looked like final ASCII text, don't treat as PS
    if name.endswith("_final"):
        return res
    txt = safe_decode(b, "utf-16le")
    if not txt:
        return None
    if re.search(r"\b(Invoke-|FromBase64String|IEX|New-Object|Set-Item|DownloadString|Start-Process)\b", txt, re.I):
        enc = txt.encode("utf-8", errors="ignore")
        if looks_like_final_text(enc):
            return ("powershell_b64_utf16le_final", enc)
        return ("powershell_b64_utf16le", b)
    if is_mostly_printable(txt.encode("utf-8", errors="ignore"), 0.6):
        enc = txt.encode("utf-8", errors="ignore")
        if looks_like_final_text(enc):
            return ("powershell_b64_utf16le_final", enc)
        return ("powershell_b64_utf16le", b)
    return None

def try_utf16le_text(data: bytes) -> Optional[Tuple[str, bytes]]:
    txt = safe_decode(data, "utf-16le")
    if txt and score_readability(txt) > 0.5:
        enc = txt.encode("utf-8", errors="ignore")
        if looks_like_final_text(enc):
            return ("utf16le_final", enc)
        return ("utf16le", enc)
    return None

def try_utf16be_text(data: bytes) -> Optional[Tuple[str, bytes]]:
    txt = safe_decode(data, "utf-16be")
    if txt and score_readability(txt) > 0.5:
        enc = txt.encode("utf-8", errors="ignore")
        if looks_like_final_text(enc):
            return ("utf16be_final", enc)
        return ("utf16be", enc)
    return None

def try_hex_bytes(data: bytes) -> Optional[Tuple[str, bytes]]:
    s = re.sub(rb"[^0-9A-Fa-f]", b"", data)  # allow spaces/colons etc.
    if len(s) < 4 or len(s) % 2 != 0:
        return None
    try:
        out = binascii.unhexlify(s)
        if looks_like_final_text(out):
            return ("hex_final", out)
        return ("hex", out)
    except Exception:
        return None

def try_url_decode(data: bytes) -> Optional[Tuple[str, bytes]]:
    s = data.decode("utf-8", errors="ignore")
    if "%" not in s and "+" not in s:
        return None
    try:
        out = urllib.parse.unquote_plus(s)
        out_b = out.encode("utf-8", errors="ignore")
        if out and out != s:
            if looks_like_final_text(out_b):
                return ("url_final", out_b)
            return ("url", out_b)
    except Exception:
        pass
    return None

def try_html_entities(data: bytes) -> Optional[Tuple[str, bytes]]:
    s = data.decode("utf-8", errors="ignore")
    if "&" not in s:
        return None
    out = html.unescape(s)
    out_b = out.encode("utf-8", errors="ignore")
    if out and out != s:
        if looks_like_final_text(out_b):
            return ("html_entities_final", out_b)
        return ("html_entities", out_b)
    return None

def try_zlib(data: bytes) -> Optional[Tuple[str, bytes]]:
    try:
        out = zlib.decompress(data)
        if looks_like_final_text(out):
            return ("zlib_final", out)
        return ("zlib", out)
    except Exception:
        return None

def try_gzip(data: bytes) -> Optional[Tuple[str, bytes]]:
    try:
        with gzip.GzipFile(fileobj=BytesIO(data)) as g:
            out = g.read()
        if looks_like_final_text(out):
            return ("gzip_final", out)
        return ("gzip", out)
    except Exception:
        return None

def try_bz2(data: bytes) -> Optional[Tuple[str, bytes]]:
    try:
        out = bz2.decompress(data)
        if looks_like_final_text(out):
            return ("bz2_final", out)
        return ("bz2", out)
    except Exception:
        return None

def try_lzma(data: bytes) -> Optional[Tuple[str, bytes]]:
    try:
        out = lzma.decompress(data)
        if looks_like_final_text(out):
            return ("lzma_final", out)
        return ("lzma", out)
    except Exception:
        return None

def try_plain_text_identity(data: bytes) -> Optional[Tuple[str, bytes]]:
    if looks_like_final_text(data):
        return ("text_final", data)
    s = data.decode("utf-8", errors="ignore")
    if score_readability(s) > 0.8:
        return ("text", s.encode("utf-8"))
    return None

# ---------- OPTIONAL: ROT & XOR (enabled via flags) ----------
def rot_n_bytes(data: bytes, n: int) -> bytes:
    out = bytearray()
    for b in data:
        if 65 <= b <= 90:      # A-Z
            out.append((b - 65 + n) % 26 + 65)
        elif 97 <= b <= 122:   # a-z
            out.append((b - 97 + n) % 26 + 97)
        else:
            out.append(b)
    return bytes(out)

def try_rot_any(data: bytes, min_improve: float = 0.08) -> Optional[Tuple[str, bytes]]:
    base = score_readability(data.decode("utf-8", errors="ignore"))
    best = (None, base, data)
    for n in range(1, 26):
        cand = rot_n_bytes(data, n)
        sc = score_readability(cand.decode("utf-8", errors="ignore"))
        if sc > best[1]:
            best = (n, sc, cand)
    if best[0] is not None and (best[1] - base) >= min_improve:
        if looks_like_final_text(best[2]):
            return (f"rot{best[0]}_final", best[2])
        return (f"rot{best[0]}", best[2])
    return None

def try_xor_single_byte(data: bytes, min_printable: float = 0.9) -> Optional[Tuple[str, bytes]]:
    best_key = None
    best_out = None
    best_ratio = 0.0
    for k in range(1, 256):
        cand = bytes(b ^ k for b in data)
        ratio = sum(ch in PRINTABLE_SET for ch in cand) / max(1, len(cand))
        if ratio > best_ratio:
            best_ratio = ratio
            best_out = cand
            best_key = k
    if best_key is not None and best_out and best_ratio >= min_printable:
        if looks_like_final_text(best_out):
            return (f"xor_{best_key}_final", best_out)
        return (f"xor_{best_key}", best_out)
    return None

# ---------- Core pipeline ----------
def build_decoders(enable_rot: bool, enable_xor: bool) -> List[Callable[[bytes], Optional[Tuple[str, bytes]]]]:
    decoders = [
        try_powershell_b64_utf16le,
        try_hex_bytes,          # prioritized
        try_base64_raw,
        try_base64_urlsafe,
        try_utf16le_text,
        try_utf16be_text,
        try_url_decode,
        try_html_entities,
        try_gzip,
        try_zlib,
        try_bz2,
        try_lzma,
        try_plain_text_identity,
    ]
    if enable_rot:
        decoders.insert(-1, try_rot_any)
    if enable_xor:
        decoders.insert(-1, try_xor_single_byte)
    return decoders

def auto_decode(data: bytes, max_steps: int, enable_rot: bool, enable_xor: bool) -> Tuple[bytes, List[Tuple[int,str,int]]]:
    decoders = build_decoders(enable_rot=enable_rot, enable_xor=enable_xor)
    log: List[Tuple[int,str,int]] = []
    cur = data
    for i in range(1, max_steps + 1):
        progress = False
        for dec in decoders:
            res = dec(cur)
            if not res:
                continue
            name, out = res
            if out and out != cur:
                cur = out
                log.append((i, name, len(out)))
                progress = True
                # HARD STOP on *_final
                if name.endswith("_final"):
                    return cur, log
                # also stop if overall looks like final text
                if looks_like_final_text(cur):
                    return cur, log
                break
        if not progress:
            break
    return cur, log

# ---------- NEW: linewise & in-place block decoding ----------
RE_B64_BLOCK = re.compile(r"(?:^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
RE_B64URL_BLOCK = re.compile(r"(?:^|[^A-Za-z0-9\-_])([A-Za-z0-9\-_]{16,})(?![A-Za-z0-9\-_])")
RE_HEX_BLOCK = re.compile(r"(?:^|[^0-9A-Fa-f])([0-9A-Fa-f]{8,})(?![0-9A-Fa-f])")

def decode_block(b: bytes, max_steps: int, enable_rot: bool, enable_xor: bool) -> Optional[bytes]:
    out, steps = auto_decode(b, max_steps=max_steps, enable_rot=enable_rot, enable_xor=enable_xor)
    if steps and out != b:
        return out
    return None

def inplace_decode_line(line: str, max_steps: int, enable_rot: bool, enable_xor: bool) -> str:
    changed = True
    current = line
    rounds = 0
    while changed and rounds < 5:
        changed = False
        rounds += 1

        def _replace_with(m):
            nonlocal changed
            blob = m.group(1).encode("utf-8")
            dec = decode_block(blob, max_steps=max_steps, enable_rot=enable_rot, enable_xor=enable_xor)
            if dec:
                changed = True
                try:
                    return m.group(0).replace(m.group(1), dec.decode("utf-8", errors="replace"))
                except Exception:
                    return m.group(0)
            return m.group(0)

        current = RE_B64_BLOCK.sub(_replace_with, current)
        current = RE_B64URL_BLOCK.sub(_replace_with, current)
        current = RE_HEX_BLOCK.sub(_replace_with, current)

        tmp = urllib.parse.unquote_plus(current)
        if tmp != current:
            current = tmp
            changed = True
        tmp2 = html.unescape(current)
        if tmp2 != current:
            current = tmp2
            changed = True

    return current

def process_linewise(data: bytes, max_steps: int, inplace_blocks: bool, enable_rot: bool, enable_xor: bool) -> bytes:
    text = data.decode("utf-8", errors="replace").splitlines(keepends=False)
    out_lines: List[str] = []
    for line in text:
        if not line.strip():
            out_lines.append(line)
            continue
        if inplace_blocks:
            out_lines.append(inplace_decode_line(line, max_steps=max_steps, enable_rot=enable_rot, enable_xor=enable_xor))
        else:
            decoded, _ = auto_decode(line.encode("utf-8", errors="ignore"), max_steps=max_steps, enable_rot=enable_rot, enable_xor=enable_xor)
            out_lines.append(decoded.decode("utf-8", errors="replace"))
    return ("\n".join(out_lines)).encode("utf-8")

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="All-in-One Payload Decoder")
    ap.add_argument("input", nargs="?", default=None,
                    help="Input file path, '-' for stdin, or leave empty for interactive paste mode")
    ap.add_argument("-o", "--out", help="Write final output to file")
    ap.add_argument("--max-steps", type=int, default=6, help="Max decoding iterations (default: 6)")
    ap.add_argument("--json", action="store_true", help="Print JSON report (steps + preview)")
    ap.add_argument("--preview-bytes", type=int, default=300, help="Preview length for stdout/log (default: 300)")
    # Modes
    ap.add_argument("--linewise", action="store_true", help="Decode per line (each line independently).")
    ap.add_argument("--inplace-blocks", action="store_true",
                    help="With --linewise, decode base64/hex/url/html blocks inside lines, preserving other text.")
    # Optional heavy heuristics
    ap.add_argument("--enable-rot", action="store_true", help="Enable ROT13/ROT-N detection.")
    ap.add_argument("--enable-xor", action="store_true", help="Enable single-byte XOR hunt (can be slow; careful with large blobs).")
    args = ap.parse_args()

    # Input handling
    if args.input == "-":
        raw = sys.stdin.buffer.read()
    elif args.input is None:
        print("[*] Interactive mode: Paste your encoded text (end with Ctrl-D on Linux/macOS or Ctrl-Z then Enter on Windows):")
        try:
            raw = sys.stdin.buffer.read()
        except Exception:
            raw = sys.stdin.read().encode("utf-8", errors="ignore")
    else:
        with open(args.input, "rb") as f:
            raw = f.read()

    # Choose strategy
    if args.linewise:
        final = process_linewise(raw, max_steps=args.max_steps, inplace_blocks=args.inplace_blocks,
                                 enable_rot=args.enable_rot, enable_xor=args.enable_xor)
        steps_log = [("linewise", "per-line" + ("+inplace" if args.inplace_blocks else ""), len(final))]
    else:
        final, steps = auto_decode(raw, max_steps=args.max_steps, enable_rot=args.enable_rot, enable_xor=args.enable_xor)
        steps_log = steps
        # Hybrid assist if not very readable (but don't mess with already final-looking text)
        if not args.json and not looks_like_final_text(final):
            final = process_linewise(final, max_steps=max(2, args.max_steps // 2), inplace_blocks=True,
                                     enable_rot=args.enable_rot, enable_xor=args.enable_xor)
            steps_log.append((999, "linewise_inplace_hybrid", len(final)))

    preview = final[: args.preview_bytes]

    # Write output
    if args.out:
        with open(args.out, "wb") as f:
            f.write(final)

    # Report
    if args.json:
        report = {
            "steps": [{"i": i if isinstance(i, int) else -1, "decoder": name, "out_len": out_len} for (i, name, out_len) in steps_log],
            "final_len": len(final),
            "final_preview": preview.decode("utf-8", errors="replace")
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("Decoding steps:")
        if steps_log:
            for i, name, out_len in steps_log:
                tag = f"[{i}]" if isinstance(i, int) else "[-]"
                print(f"  {tag} {name:24s} -> {out_len} bytes")
        else:
            print("  (no decoding applied or already plain text)")
        print("\nFinal preview (truncated):\n")
        try:
            sys.stdout.write(preview.decode("utf-8", errors="replace") + "\n")
        except BrokenPipeError:
            pass

if __name__ == "__main__":
    main()
