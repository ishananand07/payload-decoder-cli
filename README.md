# Payload Decoder CLI

All-in-one Python CLI that auto-detects and decodes common obfuscations.

## Usage

**Base64 → Hello World**
```bash
echo -n SGVsbG8gV29ybGQ= | python decoder_cli.py -
```

**Hex(UTF‑16LE) → Hello!**
```bash
echo -n 480065006C006C006F002100 | python decoder_cli.py -
```

**Base64(UTF‑16LE('Ishan is a Genius'))**
```bash
echo -n AEkAcwBoAGEAbgAgAGkAcwAgAGEAIABHAGUAbgBpAHUAcw== | python decoder_cli.py -
```
