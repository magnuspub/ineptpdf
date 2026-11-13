#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# fo_keycrack.py  --  brute-forcer della chiave documento FileOpen (FOPN_foweb)
# ============================================================================
#
# Pensato per recuperare OFFLINE la chiave di un PDF FileOpen di cui hai già
# accesso legittimo (licenza personale), quando non vuoi/puoi passare dal
# server.  Sfrutta l'unica, vera debolezza del caso V=1: la chiave documento
# e' lunga /Length bit, tipicamente **40 bit** (5 byte) -> spazio 2^40.
#
#   * known-plaintext da header zlib  : non serve nessun file di riferimento,
#     basta un qualunque stream /FlateDecode del PDF cifrato (inizia per 78 xx);
#   * known-plaintext esatto          : se passi --reference (lo stesso PDF gia'
#     decifrato), il controllo e' piu' stretto e piu' veloce.
#
# ONESTA' SUI TEMPI
#   2^40 ~= 1.1e12 chiavi.  Con PyCryptodome (ARC4 in C) + md5 in C si fanno
#   ~3e5-5e5 chiavi/s per core.  Quindi, ordine di grandezza:
#       1 core  ~ 1 mese        8 core ~ 3-5 giorni
#   In Python puro (senza PyCryptodome) e' ~100x piu' lento: non finisce.
#   Per una decifratura ISTANTANEA e senza chiave usa invece la modalita'
#   --repair-with di ineptpdf_fo3.py (known-plaintext per-oggetto).  Questo
#   cracker serve solo se vuoi davvero i 5 byte della chiave documento.
#
# GPL v3.

import sys
import os
import re
import zlib
import struct
import hashlib
import time
import argparse
import multiprocessing as mp

# ---- cifrario veloce: ARC4 in C se disponibile, altrimenti puro Python ----
try:
    try:
        from Cryptodome.Cipher import ARC4 as _ARC4
    except ImportError:
        from Crypto.Cipher import ARC4 as _ARC4

    def rc4_prefix(key, n):
        return _ARC4.new(key).encrypt(b'\x00' * n)
    FAST = True
except ImportError:
    def rc4_prefix(key, n):
        S = list(range(256))
        j = 0
        klen = len(key)
        for i in range(256):
            j = (j + S[i] + key[i % klen]) & 255
            S[i], S[j] = S[j], S[i]
        out = bytearray(n)
        i = j = 0
        for k in range(n):
            i = (i + 1) & 255
            j = (j + S[i]) & 255
            S[i], S[j] = S[j], S[i]
            out[k] = S[(S[i] + S[j]) & 255]
        return bytes(out)
    FAST = False


# ---------------------------------------------------------------------------
#  Estrazione di un oggetto-stimolo dal PDF cifrato
# ---------------------------------------------------------------------------

def find_flate_target(path, want_objid=None):
    """
    Trova uno stream /FlateDecode nel PDF cifrato e ne restituisce
    (objid, genno, ciphertext).  Sceglie, se non specificato, uno stream
    abbastanza lungo (>256 byte) per un controllo di conferma robusto.
    """
    raw = open(path, 'rb').read()
    best = None
    for m in re.finditer(rb'(\d+)\s+(\d+)\s+obj', raw):
        objid = int(m.group(1))
        genno = int(m.group(2))
        if want_objid is not None and objid != want_objid:
            continue
        body_start = m.end()
        # dizionario fino a 'stream'
        si = raw.find(b'stream', body_start)
        if si < 0 or si - body_start > 4000:
            continue
        # lo 'stream' deve appartenere a QUESTO oggetto: se c'e' un 'endobj'
        # prima, l'oggetto non ha stream e 'si' punta allo stream di un altro
        # oggetto -> objid sbagliato -> chiave per-oggetto sbagliata.
        eo = raw.find(b'endobj', body_start)
        if eo != -1 and eo < si:
            continue
        dic = raw[body_start:si]
        if b'/FlateDecode' not in dic:
            continue
        mL = re.search(rb'/Length\s+(\d+)', dic)
        if not mL:
            continue
        length = int(mL.group(1))
        a = si + 6
        if raw[a:a + 2] == b'\r\n':
            a += 2
        elif raw[a:a + 1] in (b'\r', b'\n'):
            a += 1
        cipher = raw[a:a + length]
        if want_objid is not None:
            return (objid, genno, cipher)
        if len(cipher) >= 256 and (best is None or len(cipher) < best[3]):
            best = (objid, genno, cipher, len(cipher))
    if best is None:
        raise SystemExit("Nessuno stream /FlateDecode adatto trovato.")
    return (best[0], best[1], best[2])


def reference_plaintext(path, objid, nbytes):
    """Primi nbytes di plaintext dello stesso oggetto da un PDF decifrato."""
    raw = open(path, 'rb').read()
    m = re.search((r'(?<![0-9])%d\s+\d+\s+obj' % objid).encode(), raw)
    if not m:
        return None
    si = raw.find(b'stream', m.end())
    eo = raw.find(b'endobj', m.end())
    if si < 0 or (eo != -1 and eo < si):
        return None
    a = si + 6
    if raw[a:a + 2] == b'\r\n':
        a += 2
    elif raw[a:a + 1] in (b'\r', b'\n'):
        a += 1
    return raw[a:a + nbytes]


# ---------------------------------------------------------------------------
#  Nucleo del brute force
# ---------------------------------------------------------------------------

ZLIB_SECOND = frozenset((0x01, 0x5e, 0x9c, 0xda))   # livelli zlib comuni


def _derive_objkey(dk, obj3, gen2, cap):
    return hashlib.md5(dk + obj3 + gen2).digest()[:cap]


def worker(args):
    (start, count, klen, obj3, gen2, cap, cipher_head, cipher_full_hex,
     known_plain, progress_q, wid) = args
    cipher_full = bytes.fromhex(cipher_full_hex) if cipher_full_hex else None
    probe = len(known_plain) if known_plain else 2
    t0 = time.time()
    done = 0
    STEP = 200000
    i = start
    end = start + count
    while i < end:
        dk = i.to_bytes(klen, 'big')
        ks = rc4_prefix(_derive_objkey(dk, obj3, gen2, cap), probe)
        hit = False
        if known_plain:
            # XOR noto: plaintext = ciphertext ^ keystream
            if bytes(c ^ k for c, k in zip(cipher_head, ks)) == known_plain:
                hit = True
        else:
            if cipher_head[0] ^ ks[0] == 0x78 and (cipher_head[1] ^ ks[1]) in ZLIB_SECOND:
                hit = True
        if hit and cipher_full is not None:
            # conferma definitiva: l'intero stream si decomprime?
            full_ks = rc4_prefix(_derive_objkey(dk, obj3, gen2, cap), len(cipher_full))
            plain = bytes(c ^ k for c, k in zip(cipher_full, full_ks))
            try:
                zlib.decompress(plain)
                progress_q.put(('FOUND', dk.hex(), wid))
                return dk.hex()
            except Exception:
                hit = False
        elif hit:
            progress_q.put(('FOUND', dk.hex(), wid))
            return dk.hex()
        i += 1
        done += 1
        if done % STEP == 0:
            progress_q.put(('PROG', STEP, wid))
    progress_q.put(('DONE', done % STEP, wid))
    return None


def crack(path, reference=None, objid=None, klen=None, workers=None,
          start=0, count=None):
    # parametri di cifratura
    raw = open(path, 'rb').read()
    if klen is None:
        mL = re.search(rb'/Filter\s*/FOPN\w*.*?/Length\s+(\d+)', raw, re.S)
        bits = int(mL.group(1)) if mL else 40
        klen = bits // 8
    oid, gen, cipher = find_flate_target(path, objid)
    obj3 = struct.pack('<L', oid)[:3]
    gen2 = struct.pack('<L', gen)[:2]
    cap = min(klen + 5, 16)

    known_plain = None
    if reference:
        known_plain = reference_plaintext(reference, oid, 8)
        if known_plain:
            print("[*] Riferimento: 8 byte di plaintext noti per obj %d" % oid)
    print("[*] Target obj %d gen %d  stream cifrato %d byte" % (oid, gen, len(cipher)))
    print("[*] Chiave documento: %d byte (%d bit)  ->  spazio 2^%d"
          % (klen, klen * 8, klen * 8))
    print("[*] ARC4 veloce (C):", FAST)

    total = (1 << (klen * 8)) if count is None else count
    workers = workers or os.cpu_count() or 1
    chunk = total // workers
    ranges = []
    s = start
    for w in range(workers):
        c = chunk if w < workers - 1 else total - chunk * (workers - 1)
        ranges.append((s, c, w))
        s += c

    cipher_full_hex = cipher.hex()
    cipher_head = cipher[:max(2, len(known_plain) if known_plain else 2)]
    mgr = mp.Manager()
    q = mgr.Queue()
    jobs = [(r[0], r[1], klen, obj3, gen2, cap, cipher_head, cipher_full_hex,
             known_plain, q, r[2]) for r in ranges]

    print("[*] Avvio %d worker su %d chiavi...\n" % (workers, total))
    pool = mp.Pool(workers)
    res = pool.map_async(worker, jobs)

    tested = 0
    t0 = time.time()
    found = None
    live = workers
    while live > 0:
        kind, val, wid = q.get()
        if kind == 'FOUND':
            found = val
            break
        elif kind == 'PROG':
            tested += val
        elif kind == 'DONE':
            tested += val
            live -= 1
        dt = time.time() - t0
        if dt > 0 and tested:
            rate = tested / dt
            eta = (total - tested) / rate if rate else 0
            sys.stdout.write("\r[+] %d / %d  (%.0f chiavi/s, ETA %.1f h)   "
                             % (tested, total, rate, eta / 3600))
            sys.stdout.flush()
    pool.terminate()
    print()
    if found:
        print("\n[OK] CHIAVE DOCUMENTO TROVATA: %s" % found)
        print("     usala con:  ineptpdf_fo3.py --key %s  <in.pdf> <out.pdf>" % found)
    else:
        print("\n[--] Chiave non trovata nell'intervallo esaminato.")
    return found


def main():
    p = argparse.ArgumentParser(
        description="Brute-forcer della chiave documento FileOpen (FOPN_foweb V=1).")
    p.add_argument('pdf', help='PDF cifrato')
    p.add_argument('--reference', help='stesso PDF gia decifrato (controllo esatto)')
    p.add_argument('--objid', type=int, help='forza l\'objid dello stream bersaglio')
    p.add_argument('--klen', type=int, help='lunghezza chiave in byte (default: da /Length)')
    p.add_argument('--workers', type=int, help='numero di processi (default: tutti i core)')
    p.add_argument('--start', type=lambda x: int(x, 0), default=0,
                   help='chiave iniziale (per sharding/ripresa), es. 0x1122330000')
    p.add_argument('--count', type=lambda x: int(x, 0),
                   help='quante chiavi provare da --start (default: tutto lo spazio)')
    a = p.parse_args()
    crack(a.pdf, reference=a.reference, objid=a.objid, klen=a.klen,
          workers=a.workers, start=a.start, count=a.count)


if __name__ == '__main__':
    main()
