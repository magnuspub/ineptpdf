# CHANGELOG / Versioni

Tracciamento delle versioni degli strumenti di questo progetto.
Convenzione: _lignaggio_ → _versione_ — data — note.

---

## Decrittatore FileOpen

### ineptpdf 8.4.51 (origine, Python 2)
- Script di partenza fornito dall'utente (`ineptpdf8.4.51.pyw`).
- Ramo FileOpen `FOPN_foweb`; recupero chiave dal server + impronta Windows.
- **Bug noto:** immagini a colori indicizzate con palette non decifrata
  (sfondi rosa + "sale e pepe").
- **Non gira su Python 3** (print Py2, `except Exception, a`, `0L`,
  `.decode('hex')`, `Tkinter`, `httplib`, `iteritems`, ecc.).

### ineptpdf 8.5.0-fixed (Python 2) — 2026-11-13
File: `decryptor/ineptpdf8.5.0-fixed.pyw`
- **FIX colori:** `decipher_all` ora decifra anche le stringhe nel dizionario
  degli stream (palette `/Indexed`).
- Nessun'altra modifica: resta Python 2, Windows + server per la chiave.
- Uso consigliato: chi ha già l'ambiente originale funzionante e vuole solo i
  colori giusti in un passaggio.

### ineptpdf-fo 3.0.0 (Python 3) — 2026-11-13
File: `decryptor/ineptpdf_fo3.py`
- Riscrittura completa su Python 3 del ramo FileOpen.
- FIX colori incluso.
- RC4 in **puro Python** (zero dipendenze per i file RC4 = caso comune).
- AES opzionale (PyCryptodome) solo per eventuali file AESV2/AESV3.
- Tkinter non necessario; tutto da riga di comando.
- Nuove modalità:
  - `--key` / `--keyfile` → decifratura offline con chiave nota;
  - `--repair-with` → correzione colori **senza chiave** (known-plaintext);
  - `--info` → mostra parametri di cifratura e decifra il campo INFO.
- Recupero chiave dal server inizialmente **non reimplementato**; ora
  disponibile come modulo companion `fileopen_online.py` (vedi sotto).

### fileopen_online 1.0 (companion di ineptpdf-fo) — 2026-11-13
File: `decryptor/fileopen_online.py`
- Porting Python 3 del recupero chiave dal server FileOpen (`initialize_fopn` +
  impronta hardware Windows): INFO → Setting → DocPerm → `Code`.
- Usato da `ineptpdf_fo3.py --online`.
- **Windows-only**, richiede internet, PyWin32 e che il PDF sia stato aperto in
  Adobe Reader (per `Fowp3Uuid`). Copre il caso standard foweb; i rami con
  dialog utente/password e cookie di sessione NON sono reimplementati (errore
  esplicito → usare lo script Py2 o il brute force).

### fileopen_online 1.1 — 2026-11-13 — VERIFICATO FUNZIONANTE
File: `decryptor/fileopen_online.py`
- **FIX MAC 64-bit:** `GetAdaptersInfo` usava un offset fisso valido solo a
  32 bit → su Python 64-bit dava MAC a zero (`Machine=22222222`) e il server
  rispondeva `Max allowed HOST number exceeded`. Ora lettura via `Structure`
  ctypes (corretta a 32/64 bit) con elenco di tutti gli adattatori.
- `_reg_read` prova anche la variante di case della chiave di registro.
- Aggiunto `--debug` in `ineptpdf_fo3.py`: scrive richieste/risposte del server
  e le fonti dell'impronta in `ineptpdf_online_debug.txt`.
- **Esito reale:** su `CEI_IEC_TR_60909-1.pdf` il server ha restituito
  `RetVal=2`, `Code=bcdef`; PDF decifrato e verificato (86 pagine, colori ok).

---

## Brute-forcer della chiave documento (40 bit)

### fo_keycrack 1.0 — CPU — 2026-11-13
File: `keycrack/fo_keycrack.py`
- Multiprocess; ARC4 in C via PyCryptodome se presente, altrimenti RC4 puro.
- Modalità header (nessun riferimento) o `--reference` (plaintext esatto).
- Throughput misurato: ~167k chiavi/s per core (Python) → 2^40 ≈ 9,5 giorni su
  8 core.

### fo_keycrack 1.1 — CPU — 2026-11-13 — BUGFIX selezione oggetto
File: `keycrack/fo_keycrack.py`
- **FIX:** la ricerca dello stream bersaglio agganciava lo `stream` di un
  oggetto successivo quando l'oggetto corrente non ne aveva (es. un
  `/FontDescriptor`), attribuendolo all'objid sbagliato → chiave per-oggetto
  errata → la chiave non veniva MAI trovata. Ora si controlla che non ci sia
  `endobj` prima di `stream` (stesso controllo già presente nella versione
  C/CUDA). Verificato: su un file CEI reale ritrova `bcdef` (`6263646566`).
- `fo_keycrack_cuda.py` eredita il fix (riusa `find_flate_target`).

### fo_keycrack-cuda 1.0 — GPU Nvidia (CuPy) — 2026-11-13
File: `keycrack/fo_keycrack_cuda.py`
- Kernel CUDA MD5+RC4 via CuPy `RawModule`.
- Conferma `zlib` su CPU dei candidati.
- Richiede `cupy-cuda12x` (o 11x).

### fo_keycrack 1.0 — C/CUDA autonomo — 2026-11-13
File: `keycrack/fo_keycrack.cu` (+ `keycrack/Makefile`)
- Un solo sorgente: parsing PDF in C, brute su GPU, conferma `zlib` su CPU.
- Compila come **GPU** (`nvcc`) o come **CPU** (`gcc -DNO_CUDA`, fallback).
- Kernel MD5+RC4 validato su CPU: ritrova la chiave sintetica `1122334455`.

---

## Validazione comune
Tutti i motori testati su un PDF cifrato **sintetico** a chiave nota
(`DOCKEY = 1122334455`, `FOPN_foweb V=1`): palette, indici e stringhe tornano
esatti; i cracker ritrovano la chiave; `ineptpdf_fo3 --key` decifra in modo
identico alla chiave nota.

## File d'esempio
- `esempi/CEI_IEC_TR_60909-4_fixed.pdf` — norma d'esempio con le 61 palette
  ripristinate.
