# Manuale — Brute-forcer della chiave documento (fo_keycrack)

Recupera **offline** i 5 byte della chiave documento FileOpen `FOPN_foweb V=1`,
sfruttando l'unica debolezza reale: la chiave è lunga `/Length` bit, cioè
**40 bit** (2^40 combinazioni). Tre implementazioni: CPU Python, GPU CuPy,
C/CUDA autonomo.

> Serve a file di cui hai **accesso legittimo**. La chiave è per-documento:
> quella trovata vale solo per quel PDF. Per il solo fix colori NON serve il
> brute force: usa `ineptpdf_fo3.py --repair-with` (istantaneo, senza chiave).

---

## 1. Come funziona (tutte le versioni)
Per ogni chiave candidata: `md5(chiave + objid + genno)[:10]` → RC4 → confronto
con un plaintext noto di uno stream `/FlateDecode`:
- **modalità header**: ogni stream FlateDecode inizia con l'header zlib `78 xx`;
  nessun file di riferimento necessario;
- **modalità `--reference`**: gli passi lo stesso PDF già decifrato e usa 8 byte
  di plaintext esatti → filtro a 64 bit, praticamente zero falsi positivi.
I candidati che passano il filtro vengono confermati decomprimendo l'intero
stream con `zlib` (certezza del risultato).

---

## 2. Versione CPU — `fo_keycrack.py`
### Requisiti
Python 3; opzionale `pycryptodome` (ARC4 in C, molto più veloce).
### Uso
```
python3 fo_keycrack.py cifrato.pdf                       # header, tutti i core
python3 fo_keycrack.py cifrato.pdf --reference gia_decifrato.pdf
python3 fo_keycrack.py cifrato.pdf --start 0x1100000000 --count 0x100000000
```
### Opzioni
`--reference`, `--objid`, `--klen`, `--workers`, `--start` (hex), `--count`.
### Prestazioni
~167k chiavi/s per core → **2^40 ≈ 9,5 giorni su 8 core** (in media la metà).

---

## 3. Versione GPU (CuPy) — `fo_keycrack_cuda.py`
### Requisiti
GPU Nvidia + driver CUDA; `pip install cupy-cuda12x` (o `cupy-cuda11x` secondo
la tua versione CUDA). Tieni `fo_keycrack.py` nella stessa cartella (ne riusa
estrazione/RC4 di conferma).
### Uso
```
python3 fo_keycrack_cuda.py cifrato.pdf --reference gia_decifrato.pdf
python3 fo_keycrack_cuda.py cifrato.pdf
```
### Opzioni
`--reference`, `--objid`, `--klen`, `--start`, `--count`, `--batch-log2`,
`--tpb`, `--blocks`.

---

## 4. Versione C/CUDA autonoma — `fo_keycrack.cu`
La più indipendente: un solo sorgente, niente Python/CuPy. Fa parsing PDF in C,
brute su GPU, conferma `zlib` su CPU.
### Compilazione (vedi anche `Makefile`)
```
make gpu     # -> fo_keycrack       (nvcc, GPU Nvidia)
make cpu     # -> fo_keycrack_cpu   (gcc, fallback senza GPU)
```
oppure a mano:
```
nvcc -O3 -o fo_keycrack fo_keycrack.cu -lz
gcc  -O3 -x c -DNO_CUDA -o fo_keycrack_cpu fo_keycrack.cu -lz
```
Suggerimento: puoi forzare l'architettura, es. `-arch=sm_86` (RTX 30xx) o
`-arch=sm_89` (RTX 40xx).
### Uso
```
./fo_keycrack cifrato.pdf --reference gia_decifrato.pdf
./fo_keycrack cifrato.pdf
./fo_keycrack cifrato.pdf --start 0x1100000000 --count 0x10000000000
```
### Prestazioni attese (GPU, stima)
RTX 4090 ~20 min–1 h; RTX 3060 ~2–4 h su tutto lo spazio 2^40. Cioè 100–300×
rispetto alla CPU.

---

## 5. Trovata la chiave
Esce in esadecimale, es. `1122334455`. Usala per decifrare:
```
python3 ineptpdf_fo3.py --key <hex> cifrato.pdf chiaro.pdf
```

---

## 6. Consigli pratici
- Preferisci **`--reference`** quando puoi: filtro molto più stretto, zero falsi
  positivi.
- In modalità header i candidati passano dalla conferma `zlib` (buffer da 1M
  slot nelle versioni GPU); se il buffer trabocca, riduci `--batch-log2` o usa
  `--reference`.
- `--start/--count` servono per **spezzare** lo spazio su più macchine e per
  **riprendere** dopo un'interruzione.
- Vale solo per `FOPN_foweb V=1` a 40 bit; i file AES/128-bit non sono
  attaccabili a forza bruta.
