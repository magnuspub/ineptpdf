# ineptpdf — FileOpen PDF tools

Strumenti per decifrare e correggere i PDF protetti **FileOpen** (`FOPN_foweb`),
per documenti di cui si ha **accesso legittimo** (es. norme CEI/IEC con licenza).
GPL v3, lignaggio i♥cabbages / Tetrachroma / noDRM.

## File del progetto

| File | Cos'è |
|------|-------|
| `ineptpdf.py` | Script originale Python 2 (ineptpdf 8.4.51). |
| `ineptpdf8.5.0-fixed.pyw` | Script Python 2 originale **+ fix immagini a colori** (drop-in). |
| `ineptpdf_fo3.py` | Riscrittura **Python 3** del decrittatore FileOpen, autonomo, con il fix colori. |
| `fileopen_online.py` | Modulo companion per `ineptpdf_fo3.py --online`: recupera la chiave dal server FileOpen (Windows). |
| `keycrack/fo_keycrack.py` | Brute-forcer chiave a 40 bit — **CPU** (multiprocess). |
| `keycrack/fo_keycrack_cuda.py` | Brute-forcer — **GPU Nvidia** via CuPy. |
| `keycrack/fo_keycrack.cu` | Brute-forcer — **C/CUDA autonomo** (compila GPU con `nvcc` o CPU con `gcc`). |
| `keycrack/Makefile` | Build della versione C/CUDA. |
| `docs/` | Resoconto, changelog e manuali (italiano). |

---

## Riferimento comandi

### 1) `ineptpdf_fo3.py` — decrittatore Python 3

Requisiti: Python 3.8+. `pycryptodome` solo per file AES; `pikepdf` solo per
`--repair-with`; PyWin32 solo per `--online`. Il caso RC4 (il più comune) non ha
dipendenze esterne.

```bash
# Mostra i parametri di cifratura e decifra il campo INFO
python3 ineptpdf_fo3.py --info FILE.pdf

# Decifra con una chiave documento nota (offline, qualsiasi OS)
python3 ineptpdf_fo3.py --key HEX        IN.pdf OUT.pdf
python3 ineptpdf_fo3.py --keyfile F.bin  IN.pdf OUT.pdf

# Correggi i colori SENZA chiave: parti dal file già sbloccato ma "rosa"
#   e passa l'originale cifrato (richiede pikepdf)
python3 ineptpdf_fo3.py --repair-with ORIGINALE_CIFRATO.pdf  SBLOCCATO.pdf  OUT.pdf

# Recupera la chiave dal server FileOpen (Windows + PyWin32 + internet)
python3 ineptpdf_fo3.py --online         IN.pdf OUT.pdf
python3 ineptpdf_fo3.py --online --debug IN.pdf OUT.pdf   # scrive ineptpdf_online_debug.txt
```

Opzioni: `--key HEX`, `--keyfile PATH`, `--repair-with ENCRYPTED`, `--online`,
`--debug`, `--info`. La chiave accetta esadecimale (`6263646566`) o testo
grezzo (`bcdef`).

### 2) `ineptpdf8.5.0-fixed.pyw` — script Python 2 (Windows, GUI)

Si usa come l'originale: ambiente Python 2 (PyCrypto + PyWin32), si avvia e si
carica il PDF dall'interfaccia. Recupera la chiave dal server e decifra in un
passaggio (richiede internet e documento autorizzato sul PC). Include il fix
colori.

### 3) `keycrack/fo_keycrack.py` — brute force chiave (CPU)

Recupera i 5 byte (40 bit) della chiave documento. Opzionale `pycryptodome`
(ARC4 in C, molto più veloce).

```bash
# Header mode (nessun riferimento), tutti i core
python3 fo_keycrack.py CIFRATO.pdf

# Reference mode: 8 byte di plaintext noti dal file già decifrato (consigliata)
python3 fo_keycrack.py CIFRATO.pdf --reference GIA_DECIFRATO.pdf

# Sharding / ripresa su un intervallo (hex per --start)
python3 fo_keycrack.py CIFRATO.pdf --start 0x1100000000 --count 0x100000000
```

Opzioni: `--reference PATH`, `--objid N`, `--klen BYTE`, `--workers N`,
`--start 0xHEX`, `--count N`.

### 4) `keycrack/fo_keycrack_cuda.py` — brute force (GPU, CuPy)

Requisiti: GPU Nvidia + `pip install cupy-cuda12x` (o `cupy-cuda11x`). Tieni
`fo_keycrack.py` nella **stessa cartella** (ne riusa l'estrazione dell'oggetto).

```bash
python3 fo_keycrack_cuda.py CIFRATO.pdf --reference GIA_DECIFRATO.pdf
python3 fo_keycrack_cuda.py CIFRATO.pdf
```

Opzioni: `--reference PATH`, `--objid N`, `--klen BYTE`, `--start 0xHEX`,
`--count N`, `--batch-log2 N` (chiavi/lancio = 2^N), `--tpb N`, `--blocks N`.

### 5) `keycrack/fo_keycrack.cu` — brute force (C/CUDA autonomo)

```bash
# Build
make gpu      # -> fo_keycrack       (nvcc, GPU Nvidia)
make cpu      # -> fo_keycrack_cpu   (gcc, fallback senza GPU)
# oppure:
nvcc -O3 -o fo_keycrack fo_keycrack.cu -lz
gcc  -O3 -x c -DNO_CUDA -o fo_keycrack_cpu fo_keycrack.cu -lz

# Uso
./fo_keycrack CIFRATO.pdf --reference GIA_DECIFRATO.pdf
./fo_keycrack CIFRATO.pdf
./fo_keycrack CIFRATO.pdf --start 0x1100000000 --count 0x10000000000
```

Opzioni: `--reference PATH`, `--objid N`, `--klen BYTE`, `--start 0xHEX`,
`--count DEC`, `--tpb N`, `--blocks N`.

---

## Note importanti sul brute force

- La chiave `FOPN_foweb` è un valore casuale a **40 bit** (2^40 ≈ 1,1·10¹²). Il
  brute force enumera **in ordine da 0 in su**: una chiave come `bcdef`
  (`0x6263646566` ≈ 4,2·10¹¹, ~40% dello spazio) viene trovata solo dopo aver
  testato ~420 miliardi di chiavi — **minuti/ore su GPU, non è istantaneo**.
  Per un test rapido su chiave nota, usa una finestra: `--start 0x6263640000
  --count 0x200000`.
- **`--reference` è consigliata**: usa 8 byte di plaintext noti → filtro a
  64 bit, quasi zero falsi positivi. In header mode il filtro è di 2 byte e i
  candidati passano dalla conferma `zlib`.
- Vale solo per `FOPN_foweb V=1` a 40 bit; i file AES/128-bit non sono
  attaccabili a forza bruta.

## Il bug delle immagini a colori (corretto)

Le immagini indicizzate tengono la palette come stringa nel dizionario dello
stream: `/ColorSpace [ /Indexed /DeviceRGB 255 <...768 byte...> ]`. La vecchia
`decipher_all` restituiva lo `PDFStream` invariato e non decifrava quella
stringa → sfondi rosa e "sale e pepe". Le immagini in grigio/JPEG non hanno
palette, quindi erano a posto. Il fix decifra anche le stringhe nei dizionari
degli stream.

## Chiave: come ottenerla

`FOPN_foweb` consegna la chiave dal server del publisher solo dietro impronta
del PC autorizzato. Vie: `--online` (Windows), `--key` se già nota,
`--repair-with` (solo colori, senza chiave), o brute force (`keycrack/`). La
chiave è **per-documento**.

## Note legali

Per documenti di cui si ha accesso legittimo. Nessun PDF incluso nel repository
(`.gitignore` esclude `*.pdf`). Vedi `docs/RESOCONTO.md` e `docs/MANUALE_*.md`.
