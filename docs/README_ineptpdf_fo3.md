# ineptpdf_fo3 — FileOpen PDF decryptor (Python 3)

Port autonomo e indipendente del ramo FileOpen di ineptpdf, con il bug delle
immagini a colori corretto. GPL v3.

## Requisiti
- **Python 3.8+** e nient'altro per i file RC4 (il caso comune, incluso questo).
- `pycryptodome` **solo** se il PDF usa AES (`AESV2`/`AESV3`).
- `pikepdf` **solo** per `--repair-with`.

Nessun PyCrypto, nessun PyWin32, nessun Tkinter obbligatorio.

## Il bug corretto (immagini a colori)
Le immagini indicizzate tengono la **palette come stringa dentro il dizionario
dello stream**: `/ColorSpace [ /Indexed /DeviceRGB 255 <...768 byte...> ]`.
Nel vecchio script `decipher_all` restituiva lo stream invariato e **non
decifrava mai le stringhe del suo dizionario**: la palette restava cifrata →
sfondi rosa e "sale e pepe". I pixel e le immagini in grigio/JPEG erano a
posto perché non hanno una stringa-palette. Qui `decipher_all` scende anche nel
dizionario dello stream (i dati dello stream restano gestiti a parte: niente
doppia decifratura).

## Uso

    # 1) vedere i parametri di cifratura (e l'INFO decifrato)
    python3 ineptpdf_fo3.py --info documento.pdf

    # 2) decifrare avendo la chiave del documento (modalità indipendente/offline)
    python3 ineptpdf_fo3.py --key 1122334455 cifrato.pdf chiaro.pdf
    python3 ineptpdf_fo3.py --keyfile chiave.bin cifrato.pdf chiaro.pdf

    # 3) riparazione SENZA chiave: parti da un file già decifrato ma "rosa"
    #    e passa l'originale cifrato; ricostruisce le palette dal keystream
    python3 ineptpdf_fo3.py --repair-with originale_cifrato.pdf gia_sbloccato.pdf riparato.pdf

## Come ottenere la chiave (una volta sola)
FileOpen `FOPN_foweb` consegna la chiave dal server del publisher
(qui `drm.ceinorme.it`) solo a chi invia l'impronta hardware del PC come farebbe
il plug-in del lettore: è un passo Windows-only, l'opposto di "indipendente", e
di proposito **non** è reimplementato qui. Due vie pratiche:

- esegui una volta lo script Python-2 originale (patchato) sul PC Windows dove il
  PDF si apre in Adobe Reader; in modalità DEBUG stampa la chiave. Poi riusala
  con `--key` su qualsiasi macchina;
- se hai già prodotto un file decifrato ma con i colori sbagliati, usa
  `--repair-with`: non serve nessuna chiave.

## Verifiche svolte
- `--info` e la decifratura del campo INFO: OK sul file reale.
- Motore completo (parser → RC4 → genkey_v2 → fix palette → serializer):
  testato su un PDF sintetico cifrato con chiave nota — palette, indici e
  stringhe tornano esatti.
- `--repair-with`: 61 palette ripristinate sul file CEI, rese bianche.

## Sicurezza
- L'installer `FileOpenInstaller_1.exe` è il client FileOpen ufficiale, firmato
  (DigiCert EV, "FileOpen Systems Inc."), non impacchettato: **pulito**.
- Lo script originale non contiene malware: nessun `eval`/`exec`/shell; l'unica
  connessione è verso il server FileOpen indicato dentro il PDF. Invia però
  un'impronta della macchina (utente, ID da MAC, seriale volume, cookie
  Firefox) a quel server — inerente a FileOpen, non esfiltrazione.
