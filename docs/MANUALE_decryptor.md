# Manuale — Decrittatore FileOpen

Copre `ineptpdf_fo3.py` (Python 3) e `ineptpdf8.5.0-fixed.pyw` (Python 2).

---

## 1. Quale usare

| Situazione | Strumento |
|---|---|
| Hai Python 3, vuoi uno strumento pulito e offline | `ineptpdf_fo3.py` |
| Hai già l'ambiente Python 2 + Windows originale funzionante | `ineptpdf8.5.0-fixed.pyw` |
| Hai un file già sbloccato ma coi colori sbagliati | `ineptpdf_fo3.py --repair-with` |

Entrambi correggono il bug delle immagini a colori.

---

## 2. ineptpdf_fo3.py (Python 3)

### Requisiti
- **Python 3.8+** e nient'altro per i file RC4 (il caso comune).
- `pycryptodome` **solo** se il PDF usa AES (raro): `pip install pycryptodome`.
- `pikepdf` **solo** per `--repair-with`: `pip install pikepdf`.

Funziona su **Windows, Linux e macOS**. Le modalità `--key`, `--keyfile`,
`--repair-with` e `--info` sono **completamente offline**.

### Comandi

**Vedere i parametri di cifratura (e l'INFO decifrato):**
```
python3 ineptpdf_fo3.py --info documento.pdf
```

**Decifrare con una chiave già nota (offline):**
```
python3 ineptpdf_fo3.py --key 1122334455 cifrato.pdf chiaro.pdf
python3 ineptpdf_fo3.py --keyfile chiave.bin cifrato.pdf chiaro.pdf
```
La chiave va in esadecimale (es. `1122334455`) oppure come testo grezzo.

**Correggere i colori SENZA chiave** (parti dal file già sbloccato ma "rosa" e
passa l'originale cifrato):
```
python3 ineptpdf_fo3.py --repair-with originale_cifrato.pdf gia_sbloccato.pdf riparato.pdf
```

### Come ottenere la chiave la prima volta
FileOpen `FOPN_foweb` consegna la chiave dal server del publisher solo a fronte
dell'impronta del PC Windows autorizzato. Opzioni:
1. **recupero online** (`--online`, Windows): vedi sezione sotto;
2. esegui una volta lo script Python 2 (`ineptpdf8.5.0-fixed.pyw`) sul PC
   Windows dove il PDF si apre in Adobe Reader (in modalità debug stampa la
   chiave); poi riusala con `--key` ovunque e offline;
3. se hai già un file decifrato ma coi colori sbagliati, usa `--repair-with`:
   nessuna chiave necessaria;
4. recupero della chiave via brute force: vedi `MANUALE_keycrack.md`.

### Recupero chiave online (`--online`, Windows)
Modulo: `fileopen_online.py` (tienilo nella stessa cartella di
`ineptpdf_fo3.py`).
```
python ineptpdf_fo3.py --online cifrato.pdf chiaro.pdf
```
Replica ciò che fa il plug-in FileOpen: decifra l'INFO, costruisce l'impronta
del PC (seriale volume, MAC, `Fowp3Uuid` dal registro) e chiede la chiave al
server (`Request=Setting` → `Request=DocPerm`).
**Requisiti:** Windows, connessione internet, **PyWin32** (`pip install pywin32`),
e il PDF **già aperto almeno una volta in Adobe Reader col plug-in FileOpen** su
quel PC (altrimenti manca `Fowp3Uuid`). Copre il caso standard; se il server
chiede utente/password o cookie di sessione, il modulo si ferma con un messaggio
chiaro: in quel caso usa lo script Py2 originale o il brute force.
_Nota: porting fedele ma non verificabile fuori da Windows; da provare sul PC._

### Messaggi/errore tipici
- _"No decryption key…"_ → non hai passato `--key`/`--keyfile` né `--online`;
  usa una delle vie sopra.
- _"This file uses AES…"_ → installa `pycryptodome`.
- _"repair mode needs pikepdf"_ → `pip install pikepdf`.

---

## 3. ineptpdf8.5.0-fixed.pyw (Python 2, Windows)

È lo script originale con la **sola** patch dei colori. Si usa esattamente come
l'originale: lo apri/avvii nell'ambiente Python 2 con PyCrypto + PyWin già
configurato, carichi il PDF protetto e decifri. Richiede **internet** e che il
documento sia autorizzato sul PC (serve per farsi dare la chiave dal server
FileOpen). Vantaggio: fa tutto in un passaggio (recupero chiave + decifratura +
colori corretti).

---

## 4. Il bug dei colori, in breve
Le immagini a palette (`/Indexed`) tenevano la tavolozza come stringa dentro il
dizionario dello stream; quella stringa non veniva decifrata → sfondi rosa e
disturbo. La correzione decifra anche le stringhe nei dizionari degli stream.
Le immagini in grigio e JPEG non erano interessate perché non hanno palette.

---

## 5. Avvertenze
- Per `FOPN_foweb` serve la chiave dal server (o il brute force): il decrittatore
  da solo non la inventa.
- Usa questi strumenti su documenti di cui hai **accesso legittimo**.
- La chiave è **per-documento**.
