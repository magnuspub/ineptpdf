# Resoconto — FileOpen PDF decoder

_Progetto: correzione e porting del decrittatore FileOpen `ineptpdf` per PDF
protetti (norme tecniche CEI/IEC con licenza personale)._
_Data: 13 novembre 2026._

---

## 1. Problema di partenza

Lo script `ineptpdf8.4.51.pyw` (ramo FileOpen di ineptpdf, lignaggio
i♥cabbages / Tetrachroma / noDRM) decifra i PDF protetti **FileOpen
`FOPN_foweb`**, ma produceva **immagini a colori sbagliate**: sfondi rosa/magenta
e un disturbo "sale e pepe", mentre il testo e le immagini in grigio erano
corretti.

Materiale fornito: lo script, l'installer ufficiale FileOpen, e una coppia
PDF originale cifrato + versione sbloccata (buggata) della norma
CEI/IEC TR 60909-4.

## 2. Diagnosi del bug (dimostrata)

La causa è **una sola**, nella funzione `decipher_all`.

Le immagini indicizzate tengono la tavolozza (palette) come **stringa dentro il
dizionario dello stream**:

```
/ColorSpace [ /Indexed /DeviceRGB 255 <...768 byte...> ]
```

La vecchia `decipher_all`, ricevendo un oggetto `PDFStream`, lo restituiva
**invariato**: decifrava i dati dello stream (via `get_decdata`) ma **non
scendeva mai nel dizionario dello stream**. Quindi la palette restava cifrata
RC4 → colori sbagliati. Le immagini in grigio / JPEG `DeviceRGB` non hanno una
stringa-palette, perciò non erano toccate — ecco perché il sintomo colpiva
**solo** le immagini a colori indicizzate.

**Prova.** Nello stesso oggetto, stream e palette sono cifrati con la stessa
chiave per-oggetto (RC4 riparte a ogni elemento). Ricavando il keystream da
`stream_cifrato ⊕ stream_decifrato` e applicandolo alla palette cifrata si
ottiene:

| | indice 0 |
|---|---|
| palette "passante" (buggata) | `#F5B1E0` → rosa |
| palette decifrata corretta | `#FFFFFF` → bianco |

Rigenerando l'immagine con la palette corretta, lo sfondo torna bianco e il
disturbo sparisce.

## 3. La correzione

In `decipher_all` è stato aggiunto il ramo mancante per gli stream:

```python
elif isinstance(x, PDFStream):
    # decifra anche le stringhe nel dizionario dello stream
    # (es. la palette di una colorspace /Indexed)
    x.dic = dict((k, decf(v)) for (k, v) in x.dic.items())
```

Sicuro e minimale: i dati dello stream continuano a essere decifrati a parte
(nessuna doppia decifratura), nomi/numeri/riferimenti restano intatti, vengono
decifrate solo le stringhe effettive — come prescrive lo standard PDF.

## 4. Verifiche di sicurezza (malware)

- **`FileOpenInstaller_1.exe`**: installer ufficiale FileOpen (Inno Setup),
  **firmato digitalmente** da *FileOpen Systems Inc.* (DigiCert EV). Entropia
  normale, URL interni solo DigiCert + fileopen.com, nessun dropper/injection.
  **Pulito.**
- **Script `.pyw`**: nessun `eval`/`exec`/shell; l'unica connessione va al
  server FileOpen indicato dentro il PDF (per questi file: `drm.ceinorme.it`).
  Invia un'impronta della macchina (utente, ID da MAC, seriale volume, cookie
  Firefox) a quel server — inerente a FileOpen, non esfiltrazione.

## 5. Porting a Python 3 e strumenti prodotti

- **`ineptpdf_fo3.py`** — riscrittura Python 3 autonoma del decrittatore
  FileOpen, con la correzione colori, RC4 in puro Python (zero dipendenze per
  il caso RC4), AES opzionale, Tkinter non necessario, e modalità offline
  (`--key`, `--keyfile`, `--repair-with`, `--info`).
- **`ineptpdf8.5.0-fixed.pyw`** — lo script originale Python 2 con la sola patch
  colori applicata (per chi ha già l'ambiente Py2 + Windows funzionante).
- **`fileopen_online.py`** — porting Python 3 del recupero chiave dal server
  (INFO → impronta Windows → Setting → DocPerm → `Code`), companion di
  `ineptpdf_fo3.py --online`. **Verificato funzionante** (vedi §7).
- **Brute-forcer della chiave documento** (sfrutta la debolezza reale: chiave a
  **40 bit**):
  - `fo_keycrack.py` (CPU, multiprocess)
  - `fo_keycrack_cuda.py` (GPU Nvidia, CuPy)
  - `fo_keycrack.cu` (C/CUDA autonomo, con fallback CPU `-DNO_CUDA`)

Tutti i motori sono stati validati su un PDF cifrato sintetico a chiave nota:
parser, RC4, `genkey_v2`, correzione palette, serializzazione e conferma `zlib`
producono risultati esatti.

## 6. Risultato

- PDF d'esempio corretto: `esempi/CEI_IEC_TR_60909-4_fixed.pdf` (61 palette
  ripristinate, sfondi bianchi).
- Catena completa di strumenti in `decryptor/` e `keycrack/`.

## 7. Secondo file (`CEI_IEC_TR_60909-1`) — RISOLTO

Il file dava errore nell'app (e in `--online`) con `RetVal=0 / Max allowed HOST
number exceeded`. Causa reale: l'**impronta del PC era sbagliata**, non il file.
La lettura della MAC via `GetAdaptersInfo` usava un offset fisso valido solo a
32 bit → su Python 64-bit restituiva zeri (`Machine=22222222`), così il server
vedeva un PC nuovo e, con la licenza al limite di host, rifiutava.

**Correzione:** lettura MAC con `Structure` ctypes (offset corretti a 32/64
bit). Con la MAC reale (`58:11:22:2d:f6:e7` → `Machine=KJAU4VZW`) e l'UUID vero
(`cryptmach OK`), il server ha riconosciuto il PC come **host già autorizzato**
e ha rilasciato la chiave: `RetVal=2`, `Code=bcdef`.

- Chiave documento: `bcdef` (5 byte); riusabile offline con
  `--key 6263646566` (o `--key bcdef`).
- Output `CEI.pdf`: **verificato** — 86 pagine, apre senza password, colori
  corretti (nessuna immagine indicizzata, bug colori non applicabile).
- `fileopen_online.py` aggiornato (MAC 64-bit) e `--debug` aggiunto a
  `ineptpdf_fo3.py` per diagnosticare le risposte del server.

## 8. Nota generale

La chiave `FOPN_foweb` è **per-documento** e rilasciata dal server solo dietro
impronta del PC autorizzato. Vie disponibili per ogni file:
`--online` (server, Windows), `--key` (se già nota), `--repair-with` (solo
colori, senza chiave), oppure brute force a 40 bit (`keycrack`) se un documento
non è autorizzato su questo PC.

## 9. Promemoria legale/etico

Strumenti pensati per documenti di cui si ha **accesso legittimo** (licenza
personale, es. norme CEI/IEC acquistate). La chiave è per-documento.
Tutto il codice è GPL v3, coerente con il lignaggio originale.
