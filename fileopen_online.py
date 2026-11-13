#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# fileopen_online.py -- recupero online della chiave FileOpen (FOPN_foweb)
# ========================================================================
#
# Porting Python 3 del passo di recupero chiave dal server FileOpen del vecchio
# ineptpdf (initialize_fopn + impronta hardware Windows). Modulo companion di
# ineptpdf_fo3.py: quando lanci `ineptpdf_fo3.py --online`, quest'ultimo chiama
# fetch_key() qui dentro.
#
#   fetch_key(doc, docid, param) -> bytes (la chiave documento)
#
# ATTENZIONE / LIMITI
#   * E' **Windows-only**: l'impronta richiede il registro (Fowp3Uuid scritto
#     dal plug-in FileOpen di Adobe Reader), il seriale del volume, la MAC, ecc.
#     Serve inoltre che il PDF sia stato APERTO almeno una volta in Adobe Reader
#     col plug-in FileOpen su quel PC (così esiste la Fowp3Uuid).
#   * Richiede connessione a internet verso il server del publisher.
#   * Richiede PyWin32 (win32api/win32file/win32security).
#   * Copre il caso standard foweb (Request=Setting -> Request=DocPerm).
#     NON reimplementa i rami con dialog utente/password e cookie di sessione
#     (SEMO/CSES/AskUnp): se il server li richiede, viene sollevato un errore
#     esplicito e conviene usare il vecchio script Py2 o il brute force.
#   * NON testato in questo ambiente (niente Windows/server qui): porting fedele
#     dall'originale, da verificare sul campo.
#
# GPL v3.

import sys
import os
import time
import struct
import hashlib
import base64
import socket
import urllib.request
import urllib.parse


try:
    # condividi la stessa eccezione del tool principale, cosi' i messaggi
    # d'errore escono puliti ("Error: ...") invece che come traceback
    from ineptpdf_fo3 import ADEPTError
except Exception:
    class ADEPTError(Exception):
        pass


# --- RC4: riusa quello del modulo principale se presente, altrimenti locale ---
try:
    from ineptpdf_fo3 import rc4_decrypt as _rc4
except Exception:
    def _rc4(key, data):
        if isinstance(key, str):
            key = key.encode('latin-1')
        S = list(range(256)); j = 0; kl = len(key)
        for i in range(256):
            j = (j + S[i] + key[i % kl]) & 255; S[i], S[j] = S[j], S[i]
        out = bytearray(len(data)); i = j = 0
        for n, c in enumerate(data):
            i = (i + 1) & 255; j = (j + S[i]) & 255; S[i], S[j] = S[j], S[i]
            out[n] = c ^ S[(S[i] + S[j]) & 255]
        return bytes(out)


def _s(x):
    """A str, da bytes/str, per costruire URL."""
    if isinstance(x, (bytes, bytearray)):
        return bytes(x).decode('latin-1')
    return '' if x is None else str(x)


def _q(x):
    return urllib.parse.quote(_s(x), safe='')


# ---------------------------------------------------------------------------
#  INFO (campo cifrato con chiave fissa) -> dizionario diritti
# ---------------------------------------------------------------------------

def genkey_fileopeninfo(data):
    """Decifra il campo INFO. Chiave RC4 da due costanti offuscate (versione
    corretta: niente 'key = hash.update(...)' che azzerava la chiave)."""
    h = hashlib.md5()
    i1 = struct.pack('<L', 0xa4da49de)
    h.update(bytes([i1[3], i1[2], i1[1], i1[0], 0x82]))
    s4 = struct.pack('<L', 0xec8d6c58)
    h.update(bytes([s4[3], s4[2], s4[1], s4[0], 0x07]))
    key = h.digest()[0:10]
    return _rc4(key, data).decode('latin-1')


# ---------------------------------------------------------------------------
#  Impronta hardware (Windows)
# ---------------------------------------------------------------------------

DARRAY = [0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44,0x45,
          0x46,0x47,0x48,0x4A,0x4B,0x4C,0x4D,0x4E,0x50,0x51,0x52,0x53,0x54,
          0x55,0x56,0x57,0x58,0x59,0x5A]


def fo_convert5to8(edisk):
    """5 byte -> 8 caratteri (algoritmo FileOpen). edisk: bytes (>=5)."""
    pdid = struct.unpack('<I', edisk[0:4])[0]
    out = ''
    for _ in range(6):
        out += chr(DARRAY[pdid & 0x1f]); pdid >>= 5
    pdid = (edisk[4] << 2) | pdid
    for _ in range(2):
        out += chr(DARRAY[pdid & 0x1f]); pdid >>= 5
    return out


def get_win_macaddresses():
    """Ritorna la lista delle MAC (6 byte) di tutti gli adattatori, nell'ordine
    di GetAdaptersInfo. Usa una Structure ctypes: offset corretti sia a 32 che
    a 64 bit (il vecchio offset fisso 0x194 valeva solo a 32 bit -> MAC a zero
    su Python 64 bit)."""
    from ctypes import (windll, Structure, c_char, c_ubyte, c_uint, c_ulong,
                        c_void_p, POINTER, byref, cast, create_string_buffer)

    class IP_ADAPTER_INFO(Structure):
        pass
    IP_ADAPTER_INFO._fields_ = [
        ("Next", POINTER(IP_ADAPTER_INFO)),
        ("ComboIndex", c_ulong),
        ("AdapterName", c_char * (256 + 4)),
        ("Description", c_char * (128 + 4)),
        ("AddressLength", c_uint),
        ("Address", c_ubyte * 8),
        ("Index", c_ulong),
        ("Type", c_uint),
        # (resto della struct non necessario per leggere Address/iterare Next)
        ("_pad", c_ubyte * 256),
    ]
    GetAdaptersInfo = windll.iphlpapi.GetAdaptersInfo
    size = c_ulong(0)
    GetAdaptersInfo(None, byref(size))              # dimensione necessaria
    if size.value == 0:
        size = c_ulong(0x4000)
    buf = create_string_buffer(size.value)
    if GetAdaptersInfo(buf, byref(size)) != 0:
        return []
    macs = []
    p = cast(buf, POINTER(IP_ADAPTER_INFO))
    while p:
        a = p.contents
        n = a.AddressLength or 6
        macs.append(bytes(bytearray(a.Address[:min(n, 6)])).ljust(6, b'\x00'))
        p = a.Next
    return macs


def get_win_macaddress():
    macs = get_win_macaddresses()
    if not macs:
        raise ADEPTError('Impossibile leggere la MAC (GetAdaptersInfo).')
    return macs[0]


def genkey_cryptmach(user, data_list):
    """Decifra la Uuid/Machine/Disk dal registro. data_list: lista di bytes."""
    key_string = bytes.fromhex('37A4DA49DE82064939A60B1D8D7B5F0F8873B6D93E')

    def sub(uname_b, mode):
        m = hashlib.md5()
        m.update(key_string[:3])
        m.update(uname_b[:13])
        if (13 - len(uname_b)) > 0 and mode:
            m.update(key_string[:(13 - len(uname_b))])
        md5sum = m.digest()[0:16]
        for sdata in data_list:
            rval = _rc4(md5sum, sdata)
            if rval[:4] == b'ec20':
                return rval[4:].decode('latin-1')
        return False

    variants = [user, user + '\x00', user.lower(), user.lower() + '\x00',
                user.upper(), user.upper() + '\x00']
    for uname in variants:
        ub = uname.encode('latin-1')
        r = sub(ub, True)
        if r is not False:
            return r
        r = sub(ub, False)
        if r is not False:
            return r
    return False


def fo_setattributes(fo):
    fo.update({
        'Request': 'DocPerm', 'Mode': 'CNR', 'DocStrFmt': 'ASCII',
        'Language': 'ENU', 'LngLCID': 'ENU', 'LngRFC1766': 'en',
        'LngISO4Char': 'en-us', 'ProdVer': '1.8.7.9', 'FormHFT': 'Yes',
        'SelServer': 'Yes', 'AcroCanEdit': 'Yes', 'AcroPrefIDib': 'Yes',
        'InBrowser': 'Unk', 'CliAppName': '', 'DocIsLocal': 'Yes',
        'FowpKbd': 'Yes', 'RequestSchema': 'Default',
    })


def _reg_read(winreg, value):
    """Legge un valore da HKCU\\Software\\Fileopen (prova anche varianti case)."""
    for sub in ('Software\\Fileopen', 'Software\\FileOpen'):
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub)
            return winreg.QueryValueEx(k, value)[0]
        except Exception:
            continue
    return None


def fo_win_sethwids(fo, inputfilepath, log=None):
    if log is None:
        log = lambda *a: None
    if sys.platform != 'win32':
        raise ADEPTError('Il recupero online e\' Windows-only.')
    try:
        import win32api, win32security, win32file
    except ImportError:
        raise ADEPTError('Serve PyWin32 (pip install pywin32).')
    try:
        import winreg
    except ImportError:
        import _winreg as winreg

    fo.update({'OSType': 'Windows', 'OSName': 'Vista',
               'OSData': 'Service%20Pack%204', 'AcroProduct': 'Reader',
               'AcroReader': 'Yes', 'OSBuild': '7600',
               'AcroVersion': '9.1024', 'Build': '998'})

    # Disk: seriale volume C: + 2 byte cpu
    try:
        v0 = win32api.GetVolumeInformation('C:\\')
        v1 = win32api.GetSystemInfo()[6]
        volserial = struct.pack('<I', v0[1] & 0xffffffff)
        edisk = volserial + bytes([v1 & 255, (v1 >> 8) & 255])
        fo['Disk'] = fo_convert5to8(edisk)
        log('DISK src', 'C: serial=%08x cpu=%04x edisk=%s -> Disk=%s'
            % (v0[1] & 0xffffffff, v1 & 0xffff, edisk.hex(), fo['Disk']))
    except Exception as e:
        fo['Disk'] = ''
        log('DISK src', 'errore: %r' % e)

    # Machine: dalla MAC del primo adattatore (byte 1..5)
    try:
        macs = get_win_macaddresses()
        log('MAC adattatori', '\n'.join('%d: %s' % (i, m.hex())
                                        for i, m in enumerate(macs)))
        pmac = macs[0] if macs else b'\x00' * 6
    except Exception as e:
        log('MAC adattatori', 'errore: %r' % e)
        pmac = b'\x00' * 6
    fo['Machine'] = fo_convert5to8(pmac[1:6])
    # candidati Machine per TUTTI gli adattatori (per il debug/scelta)
    try:
        log('MACHINE candidati', '\n'.join(
            '%d: mac=%s -> %s' % (i, m.hex(), fo_convert5to8(m[1:6]))
            for i, m in enumerate(macs)))
    except Exception:
        pass

    user = win32api.GetUserName().lower()
    sauser = win32api.GetUserName()
    log('USER', 'GetUserName=%r lower=%r' % (sauser, user))

    if fo.get('LILA') == 'Yes':
        try:
            psid = win32security.LookupAccountName("", sauser)[0]
            fo['SaSID'] = win32security.ConvertSidToStringSid(psid)
            fo['User'] = _q(user)
            fo['SaUser'] = _q(sauser)
        except Exception:
            fo['SaSID'] = 'S-1-5-21-1380067357-584463869-1343024091-1000'

    # Uuid dal registro Fowp3Uuid (o AppData\FileOpen\Fowpmadi.txt)
    userkey = []
    ruuid = _reg_read(winreg, 'Fowp3Uuid')
    if ruuid is not None:
        userkey.append(ruuid)
        try:
            log('Fowp3Uuid (registro)', (ruuid if isinstance(ruuid, (bytes, bytearray))
                 else bytes(ruuid, 'latin-1')).hex())
        except Exception:
            log('Fowp3Uuid (registro)', repr(ruuid))
    else:
        log('Fowp3Uuid (registro)', 'ASSENTE')
    try:
        p = os.environ['AppData'] + '\\FileOpen\\Fowpmadi.txt'
        with open(p, 'rb') as f:
            fm = f.read()
        userkey.append(fm[0:40])
        log('Fowpmadi.txt', 'presente, %d byte; [0:40]=%s' % (len(fm), fm[0:40].hex()))
    except Exception:
        log('Fowpmadi.txt', 'ASSENTE')
    if not userkey:
        raise ADEPTError('Fowp3Uuid non trovata (registro o file).\n'
                         'Il PDF e\' stato aperto in Adobe Reader su questo PC?')
    userkey = [k if isinstance(k, (bytes, bytearray)) else bytes(k, 'latin-1')
               for k in userkey]
    res = genkey_cryptmach(user, userkey)
    if res is not False:
        fo['Uuid'] = res
        log('UUID', 'cryptmach OK -> %s' % res)
    else:
        import uuid as _uuid
        fo['Uuid'] = str(_uuid.uuid1())
        log('UUID', 'cryptmach FALLITO per tutte le varianti username; '
                    'uso fallback uuid1=%s (NON corrispondera\' al server)'
            % fo['Uuid'])

    fo['Stamp'] = str(time.time())[:-3]
    fo['DocPathUrl'] = 'file%3a%2f%2f%2f' + _q(inputfilepath)

    voltype = ('Unknown', 'Invalid', 'Removable', 'Fixed', 'Remote',
               'CDRom', 'RamDisk')
    dletter = (os.path.splitdrive(inputfilepath)[0] or 'C:') + '\\'
    try:
        fo['VolType'] = voltype[win32file.GetDriveType(dletter)]
        fo['VolName'] = _q(win32api.GetVolumeInformation(dletter)[0])
        fo['VolSN'] = str(win32api.GetVolumeInformation(dletter)[1])
        fo['FSName'] = win32api.GetVolumeInformation(dletter)[4]
    except Exception:
        pass

    # PrevMach / PrevDisk da Fowp3Madi
    prev = []
    try:
        regkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Fileopen')
        prev.append(winreg.QueryValueEx(regkey, 'Fowp3Madi')[0])
    except Exception:
        pass
    try:
        p = os.environ['AppData'] + '\\FileOpen\\Fowpmadi.txt'
        with open(p, 'rb') as f:
            prev.append(f.read()[40:])
    except Exception:
        pass
    prev = [k if isinstance(k, (bytes, bytearray)) else bytes(k, 'latin-1')
            for k in prev if k]
    if prev:
        md = genkey_cryptmach(user, prev)
        if md is not False:
            machine, disk = md[:8], md[8:]
            if machine != fo.get('Machine'):
                fo['PrevMach'] = machine
            if disk != fo.get('Disk'):
                fo['PrevDisk'] = disk
    return user


# ---------------------------------------------------------------------------
#  Richieste HTTP
# ---------------------------------------------------------------------------

def _http_get(url, useragent):
    req = urllib.request.Request(url, headers={'User-Agent': useragent})
    try:
        with urllib.request.urlopen(req, timeout=30) as u:
            return u.read().decode('latin-1')
    except Exception:
        raise ADEPTError('Nessuna connessione internet o firewall bloccante.')


def _parse_amp(result):
    result = result.strip('\r\n')
    out = {}
    for pair in result.split('&'):
        if '=' in pair:
            k, v = pair.split('=', 1)
            out.setdefault(k, v)
    return out


SURL = ('Stamp','Mode','USR','ServiceID','DocumentID','Ident3ID','Ident4ID',
        'DocStrFmt','OSType','OSName','OSData','Language','LngLCID','LngRFC1766',
        'LngISO4Char','Build','ProdVer','EncrVer','Machine','Disk','Uuid',
        'PrevMach','PrevDisk','FormHFT','SelServer','AcroVersion','AcroProduct',
        'AcroReader','AcroCanEdit','AcroPrefIDib','InBrowser','CliAppName',
        'DocIsLocal','DocPathUrl','VolName','VolType','VolSN','FSName','FowpKbd',
        'OSBuild','RequestSchema')

BURL = ('Stamp','Mode','USR','ServiceID','DocumentID','Ident3ID','Ident4ID',
        'DocStrFmt','OSType','Language','LngLCID','LngRFC1766','LngISO4Char',
        'Build','ProdVer','EncrVer','Machine','Disk','Uuid','PrevMach','PrevDisk',
        'User','SaUser','SaSID','HostIsDomain','PhysHostname','LogiHostname',
        'SaRefDomain','FormHFT','UserName','UserPass','Session','SelServer',
        'AcroVersion','AcroProduct','AcroReader','AcroCanEdit','AcroPrefIDib',
        'InBrowser','CliAppName','DocIsLocal','DocPathUrl','VolName','VolType',
        'VolSN','FSName','ServerSessionData','FowpKbd','OSBuild',
        'DocumentSessionData','RequestSchema')

KATTR = {'SVID': 'ServiceID', 'DUID': 'DocumentID', 'I3ID': 'Ident3ID',
         'I4ID': 'Ident4ID', 'VERS': 'EncrVer', 'PRID': 'USR'}


def fetch_key(doc, docid, param):
    """Punto d'ingresso chiamato da ineptpdf_fo3.py --online.
    Restituisce la chiave documento (bytes)."""
    fo = {}
    # parametri dal dizionario Encrypt
    for k in ('VEID', 'BUILD', 'SVID', 'DUID'):
        if k in param:
            fo[k] = _s(param.get(k))
    fo['V'] = int(param.get('V', 2) or 2)

    # INFO -> diritti
    info = param.get('INFO')
    if not info:
        raise ADEPTError('Campo INFO assente: impossibile il recupero online.')
    rights = genkey_fileopeninfo(base64.b64decode(_s(info)))
    for pair in rights.split(';'):
        if '=' in pair:
            k, v = pair.split('=', 1)
            fo[k] = v

    # rinomina + quote
    for src, dst in KATTR.items():
        if src in fo:
            fo[dst] = urllib.parse.quote(fo[src], safe='')
            del fo[src]

    # --- debug log (--debug) ---
    debug = bool(getattr(doc, 'fo_debug', False))
    dbg = []
    def log(label, text):
        dbg.append('==== %s ====\n%s\n' % (label, text))
    def flush():
        if not debug:
            return
        body = '\n'.join(dbg)
        try:
            path = (getattr(doc, 'debug_path', None)
                    or os.path.join(os.getcwd(), 'ineptpdf_online_debug.txt'))
            with open(path, 'w', encoding='utf-8') as f:
                f.write(body)
            sys.stderr.write('[debug] log scritto in: %s\n' % path)
        except Exception:
            pass
        sys.stderr.write(body + '\n')

    useragent = fo.get('AGEN', 'Windows NT 6.0')

    try:
        log('INFO (diritti decifrati)', rights)
        inputfilepath = getattr(doc, 'input_path', '') or ''
        fo_setattributes(fo)
        fo_win_sethwids(fo, inputfilepath, log)
        log('FINGERPRINT fo dict', '\n'.join('%s=%s' % (k, fo[k])
                                             for k in sorted(fo)))

        # URL base
        base = fo.get('UURL') or fo.get('PURL')
        if not base:
            raise ADEPTError('URL del server assente nell\'INFO (PURL/UURL).')
        dprm = fo.get('DPRM', '/')
        if not dprm.startswith('/'):
            dprm = '/' + dprm
        base = base + dprm + ('&' if '?' in dprm else '?')
        if 'EVER' in fo:
            try:
                if float(fo['EVER']) < 3.8:
                    fo['Mode'] = 'ICx'
            except ValueError:
                pass

        # --- Request=Setting ---
        url = base + 'Request=Setting'
        for k in SURL:
            if k in fo:
                url += '&' + k + '=' + fo[k]
        setting_raw = _http_get(url, useragent)
        surl = _parse_amp(setting_raw)
        log('SETTING request URL', url)
        log('SETTING raw response', setting_raw)
        log('SETTING parsed', repr(surl))
        for k in ('RequestSchema', 'ServerSessionData'):
            if k in surl:
                fo[k] = surl[k]
        if 'SetScope' in surl:
            fo['RequestSchema'] = surl['SetScope']

        if ('RetVal' in surl and (surl.get('Reason') == 'AskUnp'
                                  or surl.get('SetTarget') == 'UnpDlg')):
            raise ADEPTError('Il server richiede utente/password (dialog) non '
                             'supportato da questo modulo. Usa lo script Py2 '
                             'originale o il brute force.')
        if fo.get('SEMO') in ('1', '2') and fo.get('CSES', 'fileopen') != 'fileopen':
            raise ADEPTError('Il server richiede cookie di sessione non '
                             'supportati da questo modulo. Usa lo script Py2.')

        # --- Request=DocPerm ---
        url = base + 'Request=DocPerm'
        for k in BURL:
            if k in fo:
                url += '&' + k + '=' + fo[k]
        docperm_raw = _http_get(url, useragent)
        res = _parse_amp(docperm_raw)
        log('DOCPERM request URL', url)
        log('DOCPERM raw response', docperm_raw)
        log('DOCPERM parsed', repr(res))

        if 'code' in res:
            res['Code'] = res['code']

        if 'Code' not in res or ('RetVal' in res and
                                 res['RetVal'] not in ('1', '2', 'Update', 'Answer')):
            reason = res.get('Error') or res.get('Reason') or res.get('RetVal') \
                or (docperm_raw.strip()[:200] if docperm_raw.strip() else '(risposta vuota)')
            raise ADEPTError('Decifratura non riuscita. Risposta server: %s'
                             % reason)

        code = res['Code']
    finally:
        flush()

    if len(code) in (5, 16):
        return code.encode('latin-1')
    return bytes.fromhex(code)
