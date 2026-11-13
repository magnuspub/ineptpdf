# ineptpdf — FileOpen PDF tools

Tools to decrypt and fix FileOpen-protected PDFs (`FOPN_foweb`), for documents
you have legitimate access to (e.g. licensed CEI/IEC technical standards).
GPL v3, continuing the i♥cabbages / Tetrachroma / noDRM lineage.

## What's here

| File | What it is |
|------|------------|
| `ineptpdf.py` | Original Python 2 script (ineptpdf 8.4.51). |
| `ineptpdf8.5.0-fixed.pyw` | Original Python 2 script **+ colour-image fix** (drop-in). |
| `ineptpdf_fo3.py` | **Python 3** rewrite of the FileOpen decryptor, standalone, with the colour fix. |
| `fileopen_online.py` | Companion module for `ineptpdf_fo3.py --online`: fetches the key from the FileOpen server (Windows). |
| `keycrack/` | Document-key brute-forcer (40-bit): CPU (`fo_keycrack.py`), GPU/CuPy (`fo_keycrack_cuda.py`), standalone C/CUDA (`fo_keycrack.cu`). |
| `docs/` | Report, changelog and user manuals (Italian). |

## The colour-image bug (fixed)

Indexed-colour images keep their palette as a **string inside the image
stream's dictionary**: `/ColorSpace [ /Indexed /DeviceRGB 255 <...768 bytes...> ]`.
The old `decipher_all` returned a `PDFStream` unchanged and never descended into
its dictionary, so that palette stayed RC4-encrypted — producing pink
backgrounds and salt-and-pepper noise on paletted colour images (grey and JPEG
images have no palette string, so they were unaffected). The fix decrypts the
strings inside stream dictionaries too.

## Quick start (Python 3)

```bash
# show encryption params (and the decrypted INFO field)
python3 ineptpdf_fo3.py --info file.pdf

# decrypt with a known document key (offline)
python3 ineptpdf_fo3.py --key <hex> in.pdf out.pdf

# key-free colour repair: start from an already-decrypted-but-pink file
python3 ineptpdf_fo3.py --repair-with original_encrypted.pdf unlocked.pdf fixed.pdf

# fetch the key from the FileOpen server (Windows + PyWin32 + internet)
python3 ineptpdf_fo3.py --online in.pdf out.pdf        # add --debug to log server I/O
```

Requirements: Python 3.8+ (pure-Python RC4, zero deps for the common case);
`pycryptodome` only for AES files; `pikepdf` only for `--repair-with`;
PyWin32 only for `--online`.

## Key notes

- The `FOPN_foweb` key is **per-document** and issued by the publisher's server
  against the authorized PC's fingerprint. Offline options: `--key` (if known),
  `--repair-with` (colours only), or 40-bit brute force (`keycrack/`).
- See `docs/RESOCONTO.md` for the full write-up and `docs/MANUALE_*.md` for usage.

## Legal

For documents you are licensed to access. Keys are per-document. No copyrighted
sample PDFs are included in this repository (`.gitignore` excludes `*.pdf`).
