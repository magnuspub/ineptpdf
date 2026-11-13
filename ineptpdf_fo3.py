#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ineptpdf_fo3.py  --  FileOpen PDF decryptor, Python 3, standalone
# =================================================================
#
# A modern, self-contained Python 3 port of the FileOpen branch of ineptpdf
# (originally i<3cabbages / Tetrachroma / noDRM, GPL v3).  This rewrite:
#
#   * runs on Python 3 only (the original was Python 2);
#   * fixes the "colour images come out pink / speckled" bug
#     (indexed-colour palettes stored as strings inside an image stream's
#      dictionary were never decrypted -- see decipher_all below);
#   * needs NO external crypto library for the common RC4 case
#     (a pure-Python ARC4 is built in; AES is only needed for the rare
#      AESV2/AESV3 FileOpen files and is imported lazily);
#   * works head-less: Tkinter is optional, everything is on the CLI;
#   * adds offline / independent modes:
#       --key / --keyfile   decrypt with a document key you already have
#       --repair-with ORIG  key-free repair of an already-decrypted file
#                           whose indexed-colour palettes are still garbled
#       --info              just print the encryption parameters
#
# Released under the GNU GPL v3, like its ancestors.

__license__ = 'GPL v3'
__version__ = '3.0.0'

import sys
import os
import re
import zlib
import struct
import hashlib
import binascii
import base64
import itertools
from io import BytesIO
from decimal import Decimal

if sys.version_info[0] < 3:
    sys.exit("This version requires Python 3.")


class ADEPTError(Exception):
    pass


# ---------------------------------------------------------------------------
#  Crypto primitives
# ---------------------------------------------------------------------------
#  RC4 is implemented in pure Python so the common FileOpen case has zero
#  third-party dependencies.  AES (needed only for AESV2/AESV3 files) is
#  pulled from PyCryptodome / PyCrypto on demand.

class _RC4:
    """Minimal, dependency-free ARC4 stream cipher."""
    __slots__ = ('S', 'i', 'j')

    def __init__(self, key):
        if isinstance(key, str):
            key = key.encode('latin-1')
        S = list(range(256))
        j = 0
        klen = len(key)
        for i in range(256):
            j = (j + S[i] + key[i % klen]) & 0xFF
            S[i], S[j] = S[j], S[i]
        self.S = S
        self.i = 0
        self.j = 0

    def crypt(self, data):
        S = self.S
        i = self.i
        j = self.j
        out = bytearray(len(data))
        for n, c in enumerate(data):
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            out[n] = c ^ S[(S[i] + S[j]) & 0xFF]
        self.i = i
        self.j = j
        return bytes(out)


def rc4_decrypt(key, data):
    return _RC4(key).crypt(data)


def _load_aes():
    """Return an AES-CBC decryptor factory, importing a crypto lib lazily."""
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        try:
            from Crypto.Cipher import AES
        except ImportError:
            raise ADEPTError(
                "This file uses AES encryption; install 'pycryptodome' "
                "(pip install pycryptodome) to decrypt it.")
    return AES


# ---------------------------------------------------------------------------
#  Small utilities
# ---------------------------------------------------------------------------

STRICT = 0


def choplist(n, seq):
    '''Groups every n elements of the list.'''
    r = []
    for x in seq:
        r.append(x)
        if len(r) == n:
            yield tuple(r)
            r = []
    return


def nunpack(s, default=0):
    '''Unpacks up to 4 bytes big endian.'''
    l = len(s)
    if not l:
        return default
    elif l == 1:
        return s[0]
    elif l == 2:
        return struct.unpack('>H', s)[0]
    elif l == 3:
        return struct.unpack('>L', b'\x00' + s)[0]
    elif l == 4:
        return struct.unpack('>L', s)[0]
    else:
        raise TypeError('invalid length: %d' % l)


# ---------------------------------------------------------------------------
#  PostScript / PDF tokenizer  (from pdfminer, Py3-only)
# ---------------------------------------------------------------------------

class PSException(Exception): pass
class PSEOF(PSException): pass
class PSSyntaxError(PSException): pass
class PSTypeError(PSException): pass
class PSValueError(PSException): pass


class PSObject(object): pass


class PSLiteral(PSObject):
    '''PS literals (e.g. "/Name"). Use PSLiteralTable.intern().'''
    def __init__(self, name):
        # Tokens arrive as bytes in Py3; keep .name as str so that dict keys
        # (literal_name) and serialization (key.encode) behave consistently.
        if isinstance(name, bytes):
            name = name.decode('latin-1')
        self.name = name

    def __repr__(self):
        name = []
        for char in self.name:
            if not char.isalnum():
                char = '#%02x' % ord(char)
            name.append(char)
        return '/%s' % ''.join(name)


class PSKeyword(PSObject):
    '''PS keywords (e.g. "showpage"). Use PSKeywordTable.intern().'''
    def __init__(self, name):
        self.name = name.decode('utf-8') if isinstance(name, bytes) else name

    def __repr__(self):
        return self.name


class PSSymbolTable(object):
    '''Symbol table that stores PSLiteral or PSKeyword.'''
    def __init__(self, classe):
        self.dic = {}
        self.classe = classe

    def intern(self, name):
        if name in self.dic:
            lit = self.dic[name]
        else:
            lit = self.classe(name)
            self.dic[name] = lit
        return lit


PSLiteralTable = PSSymbolTable(PSLiteral)
PSKeywordTable = PSSymbolTable(PSKeyword)
LIT = PSLiteralTable.intern
KWD = PSKeywordTable.intern
KEYWORD_BRACE_BEGIN = KWD(b'{')
KEYWORD_BRACE_END = KWD(b'}')
KEYWORD_ARRAY_BEGIN = KWD(b'[')
KEYWORD_ARRAY_END = KWD(b']')
KEYWORD_DICT_BEGIN = KWD(b'<<')
KEYWORD_DICT_END = KWD(b'>>')


def literal_name(x):
    if not isinstance(x, PSLiteral):
        if STRICT:
            raise PSTypeError('Literal required: %r' % x)
        return str(x)
    return x.name


def keyword_name(x):
    if not isinstance(x, PSKeyword):
        if STRICT:
            raise PSTypeError('Keyword required: %r' % x)
        return str(x)
    return x.name


EOL = re.compile(br'[\r\n]')
SPC = re.compile(br'\s')
NONSPC = re.compile(br'\S')
HEX = re.compile(br'[0-9a-fA-F]')
END_LITERAL = re.compile(br'[#/%\[\]()<>{}\s]')
END_HEX_STRING = re.compile(br'[^\s0-9a-fA-F]')
HEX_PAIR = re.compile(br'[0-9a-fA-F]{2}|.')
END_NUMBER = re.compile(br'[^0-9]')
END_KEYWORD = re.compile(br'[#/%\[\]()<>{}\s]')
END_STRING = re.compile(br'[()\\]')
OCT_STRING = re.compile(br'[0-7]')
ESC_STRING = {b'b': 8, b't': 9, b'n': 10, b'f': 12, b'r': 13,
              b'(': 40, b')': 41, b'\\': 92}


class EmptyArrayValue(object):
    def __str__(self):
        return "<>"


class PSBaseParser(object):
    '''Most basic PostScript parser that performs only basic tokenization.'''
    BUFSIZ = 4096

    def __init__(self, fp):
        self.fp = fp
        self.seek(0)

    def __repr__(self):
        return '<PSBaseParser: %r, bufpos=%d>' % (self.fp, self.bufpos)

    def flush(self):
        return

    def close(self):
        self.flush()

    def tell(self):
        return self.bufpos + self.charpos

    def poll(self, pos=None, n=80):
        pos0 = self.fp.tell()
        if not pos:
            pos = self.bufpos + self.charpos
        self.fp.seek(pos)
        self.fp.seek(pos0)

    def seek(self, pos):
        '''Seeks the parser to the given position.'''
        self.fp.seek(pos)
        self.bufpos = pos
        self.buf = b''
        self.charpos = 0
        self.parse1 = self.parse_main
        self.tokens = []

    def fillbuf(self):
        if self.charpos < len(self.buf):
            return
        self.bufpos = self.fp.tell()
        self.buf = self.fp.read(self.BUFSIZ)
        if not self.buf:
            raise PSEOF('Unexpected EOF')
        self.charpos = 0

    def parse_main(self, s, i):
        m = NONSPC.search(s, i)
        if not m:
            return (self.parse_main, len(s))
        j = m.start(0)
        c = bytes([s[j]])
        self.tokenstart = self.bufpos + j
        if c == b'%':
            self.token = c
            return (self.parse_comment, j + 1)
        if c == b'/':
            self.token = b''
            return (self.parse_literal, j + 1)
        if c in b'-+' or c.isdigit():
            self.token = c
            return (self.parse_number, j + 1)
        if c == b'.':
            self.token = c
            return (self.parse_decimal, j + 1)
        if c.isalpha():
            self.token = c
            return (self.parse_keyword, j + 1)
        if c == b'(':
            self.token = b''
            self.paren = 1
            return (self.parse_string, j + 1)
        if c == b'<':
            self.token = b''
            return (self.parse_wopen, j + 1)
        if c == b'>':
            self.token = b''
            return (self.parse_wclose, j + 1)
        self.add_token(KWD(c))
        return (self.parse_main, j + 1)

    def add_token(self, obj):
        self.tokens.append((self.tokenstart, obj))

    def parse_comment(self, s, i):
        m = EOL.search(s, i)
        if not m:
            self.token += s[i:]
            return (self.parse_comment, len(s))
        j = m.start(0)
        self.token += s[i:j]
        return (self.parse_main, j)

    def parse_literal(self, s, i):
        m = END_LITERAL.search(s, i)
        if not m:
            self.token += s[i:]
            return (self.parse_literal, len(s))
        j = m.start(0)
        self.token += s[i:j]
        c = bytes([s[j]])
        if c == b'#':
            self.hex = b''
            return (self.parse_literal_hex, j + 1)
        self.add_token(LIT(self.token))
        return (self.parse_main, j)

    def parse_literal_hex(self, s, i):
        c = bytes([s[i]])
        if HEX.match(c) and len(self.hex) < 2:
            self.hex += c
            return (self.parse_literal_hex, i + 1)
        if self.hex:
            self.token += bytes([int(self.hex, 16)])
        return (self.parse_literal, i)

    def parse_number(self, s, i):
        m = END_NUMBER.search(s, i)
        if not m:
            self.token += s[i:]
            return (self.parse_number, len(s))
        j = m.start(0)
        self.token += s[i:j]
        c = bytes([s[j]])
        if c == b'.':
            self.token += c
            return (self.parse_decimal, j + 1)
        try:
            self.add_token(int(self.token))
        except ValueError:
            pass
        return (self.parse_main, j)

    def parse_decimal(self, s, i):
        m = END_NUMBER.search(s, i)
        if not m:
            self.token += s[i:]
            return (self.parse_decimal, len(s))
        j = m.start(0)
        self.token += s[i:j]
        self.add_token(Decimal(self.token.decode('utf-8')))
        return (self.parse_main, j)

    def parse_keyword(self, s, i):
        m = END_KEYWORD.search(s, i)
        if not m:
            self.token += s[i:]
            return (self.parse_keyword, len(s))
        j = m.start(0)
        self.token += s[i:j]
        if self.token == b'true':
            token = True
        elif self.token == b'false':
            token = False
        else:
            token = KWD(self.token)
        self.add_token(token)
        return (self.parse_main, j)

    def parse_string(self, s, i):
        m = END_STRING.search(s, i)
        if not m:
            self.token += s[i:]
            return (self.parse_string, len(s))
        j = m.start(0)
        self.token += s[i:j]
        c = bytes([s[j]])
        if c == b'\\':
            self.oct = b''
            return (self.parse_string_1, j + 1)
        if c == b'(':
            self.paren += 1
            self.token += c
            return (self.parse_string, j + 1)
        if c == b')':
            self.paren -= 1
            if self.paren:
                self.token += c
                return (self.parse_string, j + 1)
        self.add_token(self.token)
        return (self.parse_main, j + 1)

    def parse_string_1(self, s, i):
        c = bytes([s[i]])
        if OCT_STRING.match(c) and len(self.oct) < 3:
            self.oct += c
            return (self.parse_string_1, i + 1)
        if self.oct:
            self.token += bytes([int(self.oct, 8)])
            return (self.parse_string, i)
        if c in ESC_STRING:
            self.token += bytes([ESC_STRING[c]])
        return (self.parse_string, i + 1)

    def parse_wopen(self, s, i):
        c = bytes([s[i]])
        if c.isspace() or HEX.match(c):
            return (self.parse_hexstring, i)
        if c == b'<':
            self.add_token(KEYWORD_DICT_BEGIN)
            i += 1
        if c == b'>':
            self.add_token(EmptyArrayValue())
            i += 1
        return (self.parse_main, i)

    def parse_wclose(self, s, i):
        c = bytes([s[i]])
        if c == b'>':
            self.add_token(KEYWORD_DICT_END)
            i += 1
        return (self.parse_main, i)

    def parse_hexstring(self, s, i):
        m = END_HEX_STRING.search(s, i)
        if not m:
            self.token += s[i:]
            return (self.parse_hexstring, len(s))
        j = m.start(0)
        self.token += s[i:j]
        token = HEX_PAIR.sub(lambda m: bytes([int(m.group(0), 16)]),
                             SPC.sub(b'', self.token))
        self.add_token(token)
        return (self.parse_main, j)

    def nexttoken(self):
        while not self.tokens:
            self.fillbuf()
            (self.parse1, self.charpos) = self.parse1(self.buf, self.charpos)
        token = self.tokens.pop(0)
        return token

    def nextline(self):
        '''Fetches a next line that ends either with \\r or \\n.'''
        linebuf = b''
        linepos = self.bufpos + self.charpos
        eol = False
        while 1:
            self.fillbuf()
            if eol:
                c = bytes([self.buf[self.charpos]])
                if c == b'\n':
                    linebuf += c
                    self.charpos += 1
                break
            m = EOL.search(self.buf, self.charpos)
            if m:
                linebuf += self.buf[self.charpos:m.end(0)]
                self.charpos = m.end(0)
                if bytes([linebuf[-1]]) == b'\r':
                    eol = True
                else:
                    break
            else:
                linebuf += self.buf[self.charpos:]
                self.charpos = len(self.buf)
        return (linepos, linebuf)

    def revreadlines(self):
        '''Fetches a next line backward (to locate trailers at EOF).'''
        self.fp.seek(0, 2)
        pos = self.fp.tell()
        buf = b''
        while 0 < pos:
            prevpos = pos
            pos = max(0, pos - self.BUFSIZ)
            self.fp.seek(pos)
            s = self.fp.read(prevpos - pos)
            if not s:
                break
            while 1:
                n = max(s.rfind(b'\r'), s.rfind(b'\n'))
                if n == -1:
                    buf = s + buf
                    break
                yield s[n:] + buf
                s = s[:n]
                buf = b''
        return


class PSStackParser(PSBaseParser):

    def __init__(self, fp):
        PSBaseParser.__init__(self, fp)
        self.reset()

    def reset(self):
        self.context = []
        self.curtype = None
        self.curstack = []
        self.results = []

    def seek(self, pos):
        PSBaseParser.seek(self, pos)
        self.reset()

    def push(self, *objs):
        self.curstack.extend(objs)

    def pop(self, n):
        objs = self.curstack[-n:]
        self.curstack[-n:] = []
        return objs

    def popall(self):
        objs = self.curstack
        self.curstack = []
        return objs

    def add_results(self, *objs):
        self.results.extend(objs)

    def start_type(self, pos, type):
        self.context.append((pos, self.curtype, self.curstack))
        (self.curtype, self.curstack) = (type, [])

    def end_type(self, type):
        if self.curtype != type:
            raise PSTypeError('Type mismatch: %r != %r' % (self.curtype, type))
        objs = [obj for (_, obj) in self.curstack]
        (pos, self.curtype, self.curstack) = self.context.pop()
        return (pos, objs)

    def do_keyword(self, pos, token):
        return

    def nextobject(self, direct=False):
        '''Yields a list of objects.'''
        while not self.results:
            (pos, token) = self.nexttoken()
            if (isinstance(token, (int, Decimal, bool, bytearray, bytes, str,
                                   PSLiteral))):
                self.push((pos, token))
            elif token == KEYWORD_ARRAY_BEGIN:
                self.start_type(pos, 'a')
            elif token == KEYWORD_ARRAY_END:
                try:
                    self.push(self.end_type('a'))
                except PSTypeError:
                    if STRICT:
                        raise
            elif token == KEYWORD_DICT_BEGIN:
                self.start_type(pos, 'd')
            elif token == KEYWORD_DICT_END:
                try:
                    (pos, objs) = self.end_type('d')
                    if len(objs) % 2 != 0:
                        objs.append(b"")
                    d = dict((literal_name(k), v)
                             for (k, v) in choplist(2, objs))
                    self.push((pos, d))
                except PSTypeError:
                    if STRICT:
                        raise
            else:
                self.do_keyword(pos, token)
            if self.context:
                continue
            else:
                if direct:
                    return self.pop(1)[0]
                self.flush()
        obj = self.results.pop(0)
        return obj


LITERAL_CRYPT = LIT(b'Crypt')
LITERALS_FLATE_DECODE = (LIT(b'FlateDecode'), LIT(b'Fl'))
LITERALS_LZW_DECODE = (LIT(b'LZWDecode'), LIT(b'LZW'))
LITERALS_ASCII85_DECODE = (LIT(b'ASCII85Decode'), LIT(b'A85'))


# ---------------------------------------------------------------------------
#  PDF objects
# ---------------------------------------------------------------------------

class PDFObject(PSObject): pass
class PDFException(PSException): pass
class PDFTypeError(PDFException): pass
class PDFValueError(PDFException): pass
class PDFNotImplementedError(PSException): pass


class PDFObjRef(PDFObject):
    def __init__(self, doc, objid, genno):
        if objid == 0:
            if STRICT:
                raise PDFValueError('PDF object id cannot be 0.')
        self.doc = doc
        self.objid = objid
        self.genno = genno

    def __repr__(self):
        return '<PDFObjRef:%d %d>' % (self.objid, self.genno)

    def resolve(self):
        return self.doc.getobj(self.objid)


def resolve1(x):
    while isinstance(x, PDFObjRef):
        x = x.resolve()
    return x


def resolve_all(x):
    while isinstance(x, PDFObjRef):
        x = x.resolve()
    if isinstance(x, list):
        x = [resolve_all(v) for v in x]
    elif isinstance(x, dict):
        for (k, v) in x.items():
            x[k] = resolve_all(v)
    return x


def decipher_all(decipher, objid, genno, x):
    '''
    Recursively decipher X (strings and the strings inside stream dicts).
    '''
    if isinstance(x, (bytearray, bytes, str)):
        return decipher(objid, genno, x)
    decf = lambda v: decipher_all(decipher, objid, genno, v)
    if isinstance(x, list):
        x = [decf(v) for v in x]
    elif isinstance(x, dict):
        x = dict((k, decf(v)) for (k, v) in x.items())
    elif isinstance(x, PDFStream):
        # BUGFIX (colour images): strings that live INSIDE a stream's
        # dictionary must also be decrypted.  The classic casualty is the
        # palette (lookup table) of an /Indexed colour space, e.g.
        #     /ColorSpace [ /Indexed /DeviceRGB 255 <...768 bytes...> ]
        # Leaving that palette RC4-encrypted turns the background of
        # paletted colour images pink and speckled.  (Grey and plain
        # RGB/JPEG images have no palette string, so they were unaffected
        # -- which is exactly why only *colour* images looked broken.)
        # The stream DATA is deciphered separately in get_decdata(), so we
        # only walk the dictionary here, never the body.
        x.dic = dict((k, decf(v)) for (k, v) in x.dic.items())
    return x


def int_value(x):
    x = resolve1(x)
    if not isinstance(x, int):
        if STRICT:
            raise PDFTypeError('Integer required: %r' % x)
        return 0
    return x


def decimal_value(x):
    x = resolve1(x)
    if not isinstance(x, Decimal):
        if STRICT:
            raise PDFTypeError('Decimal required: %r' % x)
        return 0.0
    return x


def num_value(x):
    x = resolve1(x)
    if not isinstance(x, (int, Decimal)):
        if STRICT:
            raise PDFTypeError('Int or Decimal required: %r' % x)
        return 0
    return x


def str_value(x):
    x = resolve1(x)
    if not isinstance(x, (bytearray, bytes, str)):
        if STRICT:
            raise PDFTypeError('String required: %r' % x)
        return b''
    return x


def list_value(x):
    x = resolve1(x)
    if not isinstance(x, (list, tuple)):
        if STRICT:
            raise PDFTypeError('List required: %r' % x)
        return []
    return x


def dict_value(x):
    x = resolve1(x)
    if not isinstance(x, dict):
        if STRICT:
            raise PDFTypeError('Dict required: %r' % x)
        return {}
    return x


def stream_value(x):
    x = resolve1(x)
    if not isinstance(x, PDFStream):
        if STRICT:
            raise PDFTypeError('PDFStream required: %r' % x)
        return PDFStream({}, b'')
    return x


def ascii85decode(data):
    n = b = 0
    out = b''
    for c in data:
        if 33 <= c and c <= 117:          # '!'..'u'
            n += 1
            b = b * 85 + (c - 33)
            if n == 5:
                out += struct.pack('>L', b)
                n = b = 0
        elif c == 122:                    # 'z'
            assert n == 0
            out += b'\0\0\0\0'
        elif c == 126:                    # '~'
            if n:
                for _ in range(5 - n):
                    b = b * 85 + 84
                out += struct.pack('>L', b)[:n - 1]
            break
    return out


class PDFStream(PDFObject):
    def __init__(self, dic, rawdata, decipher=None):
        length = int_value(dic.get('Length', 0))
        eol = rawdata[length:]
        # quick and dirty fix for a false /Length attribute
        if decipher is not None and getattr(decipher, '__name__', '') == 'decrypt_aes':
            if (len(rawdata) % 16) != 0:
                cutdiv = len(rawdata) // 16
                rawdata = rawdata[:16 * cutdiv]
        else:
            if eol in (b'\r', b'\n', b'\r\n'):
                rawdata = rawdata[:length]
        self.dic = dic
        self.rawdata = rawdata
        self.decipher = decipher
        self.data = None
        self.decdata = None
        self.objid = None
        self.genno = None

    def set_objid(self, objid, genno):
        self.objid = objid
        self.genno = genno

    def __repr__(self):
        if self.rawdata:
            return '<PDFStream(%r): raw=%d, %r>' % \
                   (self.objid, len(self.rawdata), self.dic)
        else:
            return '<PDFStream(%r): data=%d, %r>' % \
                   (self.objid, len(self.data), self.dic)

    def decode(self):
        assert self.data is None and self.rawdata is not None
        data = self.rawdata
        if self.decipher:
            data = self.decipher(self.objid, self.genno, data)
            if gen_xref_stm:
                self.decdata = data
        if 'Filter' not in self.dic:
            self.data = data
            self.rawdata = None
            return
        filters = self.dic['Filter']
        if not isinstance(filters, list):
            filters = [filters]
        for f in filters:
            if f in LITERALS_FLATE_DECODE:
                data = zlib.decompress(data)
            elif f in LITERALS_LZW_DECODE:
                data = b''.join(LZWDecoder(BytesIO(data)).run())
            elif f in LITERALS_ASCII85_DECODE:
                data = ascii85decode(data)
            elif f == LITERAL_CRYPT:
                raise PDFNotImplementedError('/Crypt filter is unsupported')
            else:
                raise PDFNotImplementedError('Unsupported filter: %r' % f)
            # apply predictors
            if 'DP' in self.dic:
                params = self.dic['DP']
            else:
                params = self.dic.get('DecodeParms', {})
            if isinstance(params, list):
                params = params[0] if params else {}
            if 'Predictor' in params:
                pred = int_value(params['Predictor'])
                if pred:
                    if pred != 12:
                        raise PDFNotImplementedError(
                            'Unsupported predictor: %r' % pred)
                    if 'Columns' not in params:
                        raise PDFValueError(
                            'Columns undefined for predictor=12')
                    columns = int_value(params['Columns'])
                    buf = b''
                    ent0 = b'\x00' * columns
                    for i in range(0, len(data), columns + 1):
                        pred = data[i]
                        ent1 = data[i + 1:i + 1 + columns]
                        if pred == 2:
                            ent1 = bytes((a + b) & 255
                                         for (a, b) in zip(ent0, ent1))
                        buf += ent1
                        ent0 = ent1
                    data = buf
        self.data = data
        self.rawdata = None

    def get_data(self):
        if self.data is None:
            self.decode()
        return self.data

    def get_rawdata(self):
        return self.rawdata

    def get_decdata(self):
        if self.decdata is not None:
            return self.decdata
        data = self.rawdata
        if self.decipher and data:
            data = self.decipher(self.objid, self.genno, data)
        return data


class PDFSyntaxError(PDFException): pass
class PDFNoValidXRef(PDFSyntaxError): pass
class PDFEncryptionError(PDFException): pass
class PDFPasswordIncorrect(PDFEncryptionError): pass

LITERAL_OBJSTM = LIT(b'ObjStm')
LITERAL_XREF = LIT(b'XRef')
LITERAL_PAGE = LIT(b'Page')
LITERAL_PAGES = LIT(b'Pages')
LITERAL_CATALOG = LIT(b'Catalog')


class PDFXRef(object):
    def __init__(self):
        self.offsets = None

    def __repr__(self):
        return '<PDFXRef: objs=%d>' % len(self.offsets)

    def objids(self):
        return iter(self.offsets.keys())

    def load(self, parser):
        self.offsets = {}
        while 1:
            try:
                (pos, line) = parser.nextline()
            except PSEOF:
                raise PDFNoValidXRef('Unexpected EOF - file corrupted?')
            if not line:
                raise PDFNoValidXRef('Premature eof: %r' % parser)
            if line.startswith(b'trailer'):
                parser.seek(pos)
                break
            f = line.strip().split(b' ')
            if len(f) != 2:
                raise PDFNoValidXRef('Trailer not found: %r: line=%r' % (parser, line))
            try:
                (start, nobjs) = map(int, f)
            except ValueError:
                raise PDFNoValidXRef('Invalid line: %r: line=%r' % (parser, line))
            for objid in range(start, start + nobjs):
                try:
                    (_, line) = parser.nextline()
                except PSEOF:
                    raise PDFNoValidXRef('Unexpected EOF - file corrupted?')
                f = line.strip().split(b' ')
                if len(f) != 3:
                    raise PDFNoValidXRef('Invalid XRef format: %r, line=%r' % (parser, line))
                (pos, genno, use) = f
                if use != b'n':
                    continue
                self.offsets[objid] = (int(genno.decode('utf-8')),
                                       int(pos.decode('utf-8')))
        self.load_trailer(parser)

    KEYWORD_TRAILER = PSKeywordTable.intern(b'trailer')

    def load_trailer(self, parser):
        try:
            (_, kwd) = parser.nexttoken()
            assert kwd is self.KEYWORD_TRAILER
            (_, dic) = parser.nextobject(direct=True)
        except PSEOF:
            x = parser.pop(1)
            if not x:
                raise PDFNoValidXRef('Unexpected EOF - file corrupted')
            (_, dic) = x[0]
        self.trailer = dict_value(dic)

    def getpos(self, objid):
        try:
            (genno, pos) = self.offsets[objid]
        except KeyError:
            raise
        return (None, pos)


class PDFXRefStream(object):
    def __init__(self):
        self.index = None
        self.data = None
        self.entlen = None
        self.fl1 = self.fl2 = self.fl3 = None

    def __repr__(self):
        return '<PDFXRef: objids=%s>' % self.index

    def objids(self):
        for first, size in self.index:
            for objid in range(first, first + size):
                yield objid

    def load(self, parser, debug=0):
        (_, objid) = parser.nexttoken()
        (_, genno) = parser.nexttoken()
        (_, kwd) = parser.nexttoken()
        (_, stream) = parser.nextobject()
        if not isinstance(stream, PDFStream) or \
                stream.dic['Type'] is not LITERAL_XREF:
            raise PDFNoValidXRef('Invalid PDF stream spec.')
        size = stream.dic['Size']
        index = stream.dic.get('Index', (0, size))
        self.index = list(zip(itertools.islice(index, 0, None, 2),
                              itertools.islice(index, 1, None, 2)))
        (self.fl1, self.fl2, self.fl3) = stream.dic['W']
        self.data = stream.get_data()
        self.entlen = self.fl1 + self.fl2 + self.fl3
        self.trailer = stream.dic

    def getpos(self, objid):
        offset = 0
        for first, size in self.index:
            if first <= objid and objid < (first + size):
                break
            offset += size
        else:
            raise KeyError(objid)
        i = self.entlen * ((objid - first) + offset)
        ent = self.data[i:i + self.entlen]
        f1 = nunpack(ent[:self.fl1], 1)
        if f1 == 1:
            pos = nunpack(ent[self.fl1:self.fl1 + self.fl2])
            genno = nunpack(ent[self.fl1 + self.fl2:])
            return (None, pos)
        elif f1 == 2:
            objid = nunpack(ent[self.fl1:self.fl1 + self.fl2])
            index = nunpack(ent[self.fl1 + self.fl2:])
            return (objid, index)
        raise KeyError(objid)


# ---------------------------------------------------------------------------
#  PDFDocument  (FileOpen)
# ---------------------------------------------------------------------------

gen_xref_stm = False          # set by PDFSerializer


class PDFDocument(object):

    def __init__(self):
        self.xrefs = []
        self.objs = {}
        self.parsed_objs = {}
        self.root = None
        self.catalog = None
        self.parser = None
        self.encryption = None
        self.decipher = None
        self.fileopen = {}
        self.decrypt_key = None
        self.ready = False

    def set_parser(self, parser):
        if self.parser:
            return
        self.parser = parser
        self.ready = True
        self.xrefs = parser.read_xref()
        for xref in self.xrefs:
            trailer = xref.trailer
            if not trailer:
                continue
            if 'Encrypt' in trailer:
                try:
                    self.encryption = (list_value(trailer['ID']),
                                       dict_value(trailer['Encrypt']))
                except Exception:
                    self.encryption = (b'ffffffffffffffffffffffffffffffffffff',
                                       dict_value(trailer['Encrypt']))
            if 'Root' in trailer:
                self.set_root(dict_value(trailer['Root']))
                break
        else:
            raise PDFSyntaxError('No /Root object! - Is this really a PDF?')
        self.ready = False

    def set_root(self, root):
        self.root = root
        self.catalog = dict_value(self.root)
        if self.catalog.get('Type') is not LITERAL_CATALOG:
            if STRICT:
                raise PDFSyntaxError('Catalog not found!')

    # -- introspection ------------------------------------------------------

    def encryption_filter(self):
        if not self.encryption:
            return None
        (docid, param) = self.encryption
        return literal_name(param['Filter'])

    def fileopen_params(self):
        '''Return the FileOpen parameters as a plain dict (for --info).'''
        if not self.encryption:
            return {}
        (docid, param) = self.encryption
        out = {}
        for k in ('Filter', 'V', 'Length', 'VEID', 'BUILD', 'SVID', 'DUID'):
            if k in param:
                v = param[k]
                out[k] = literal_name(v) if isinstance(v, PSLiteral) else v
        info = param.get('INFO')
        if info:
            try:
                out['INFO_decrypted'] = self.genkey_fileopeninfo(
                    base64.b64decode(str_value(info)))
            except Exception as e:
                out['INFO_decrypted'] = '<error: %s>' % e
        return out

    # -- initialization -----------------------------------------------------

    def initialize(self, key=None, online=False):
        '''
        Prepare the document for decryption.

        key     : explicit document key (bytes or hex str).  Offline mode.
        online  : if True and no key given, try the Windows/FileOpen-server
                  handshake to fetch the key (needs Windows + network).
        '''
        if not self.encryption:
            self.is_printable = self.is_modifiable = self.is_extractable = True
            self.ready = True
            return
        (docid, param) = self.encryption
        ftype = literal_name(param['Filter'])
        if ftype in ('Adobe.APS', 'Standard', 'EBX_HANDLER'):
            raise PDFEncryptionError(
                'This file uses %s encryption, not FileOpen. '
                'Use an ADEPT/standard decryptor instead.' % ftype)
        if ftype not in ('FOPN_foweb', 'FOPN_fLock'):
            raise PDFEncryptionError('Unknown FileOpen filter: %r' % ftype)

        self.is_printable = self.is_modifiable = self.is_extractable = True
        self.fileopen['Length'] = int_value(param.get('Length', 0)) // 8
        self.fileopen['V'] = int_value(param.get('V', 2))

        # ---- obtain the document key ----
        if key is not None:
            if isinstance(key, str):
                key = key.strip()
                try:
                    key = binascii.unhexlify(key)
                except (binascii.Error, ValueError):
                    key = key.encode('latin-1')
            self.decrypt_key = key
        elif online:
            self.decrypt_key = self._fetch_key_online(docid, param)
        else:
            raise ADEPTError(
                'No decryption key.  Supply one with --key/--keyfile, '
                'use --online on a Windows machine that can reach the '
                'FileOpen server, or use --repair-with to fix an '
                'already-decrypted file.')

        self._select_algorithms(param)
        self.ready = True

    def _select_algorithms(self, param):
        V = int_value(param.get('V', 2))
        if V in (1, 2, 4):
            self.genkey = self.genkey_v2
        elif V == 3:
            self.genkey = self.genkey_v3
        elif V >= 5:
            self.genkey = self.genkey_v5

        set_decipher = False
        if V >= 4:
            try:
                for name in param['CF']:
                    algo = str(param['CF'][name]['CFM'])
                    if algo in ('/AESV2', '/AESV3'):
                        if V == 4:
                            self.genkey = self.genkey_v4
                        set_decipher = True
                        self.decipher = self.decrypt_aes
                    elif algo == '/V2':
                        set_decipher = True
                        self.decipher = self.decrypt_rc4
            except Exception:
                pass
        if V < 4:
            self.decipher = self.decrypt_rc4
        if not set_decipher and V >= 4:
            self.decipher = self.decrypt_aes

    # -- key generation -----------------------------------------------------

    def genkey_v2(self, objid, genno):
        objid = struct.pack('<L', objid)[:3]
        genno = struct.pack('<L', genno)[:2]
        key = self.decrypt_key + objid + genno
        key = hashlib.md5(key).digest()[:min(len(self.decrypt_key) + 5, 16)]
        return key

    def genkey_v3(self, objid, genno):
        objid = struct.pack('<L', objid ^ 0x3569ac)
        genno = struct.pack('<L', genno ^ 0xca96)
        key = self.decrypt_key
        key += bytes([objid[0], genno[0], objid[1], genno[1], objid[2]]) + b'sAlT'
        key = hashlib.md5(key).digest()[:min(len(self.decrypt_key) + 5, 16)]
        return key

    def genkey_v4(self, objid, genno):
        objid = struct.pack('<L', objid)[:3]
        genno = struct.pack('<L', genno)[:2]
        key = self.decrypt_key + objid + genno + b'sAlT'
        key = hashlib.md5(key).digest()[:min(len(self.decrypt_key) + 5, 16)]
        return key

    def genkey_v5(self, objid, genno):
        return self.decrypt_key

    # -- ciphers ------------------------------------------------------------

    def decrypt_rc4(self, objid, genno, data):
        return rc4_decrypt(self.genkey(objid, genno), data)

    def decrypt_aes(self, objid, genno, data):
        AES = _load_aes()
        key = self.genkey(objid, genno)
        ivector = data[:16]
        data = data[16:]
        plaintext = AES.new(key, AES.MODE_CBC, ivector).decrypt(data)
        if plaintext:
            pad = plaintext[-1]
            if 1 <= pad <= 16:
                plaintext = plaintext[:-pad]
        return plaintext

    # -- FileOpen INFO field decryption (fixed) -----------------------------

    def genkey_fileopeninfo(self, data):
        # Build the 10-byte RC4 key from two obfuscated 32-bit constants.
        hash = hashlib.md5()
        input1 = struct.pack('<L', 0xa4da49de)        # little-endian store
        hash.update(bytes([input1[3], input1[2], input1[1], input1[0], 0x82]))
        spointer4 = struct.pack('<L', 0xec8d6c58)
        hash.update(bytes([spointer4[3], spointer4[2], spointer4[1],
                           spointer4[0], 0x07]))
        key = hash.digest()[0:10]
        return rc4_decrypt(key, data).decode('latin-1')

    # -- online key retrieval (Windows + FileOpen server) -------------------

    def _fetch_key_online(self, docid, param):
        # The FOPN_foweb key is handed out by the publisher's licence server.
        # That handshake is Windows-only (needs the registry Fowp3Uuid written
        # by Adobe Reader, volume serial, NIC MAC, ...) and lives in the
        # companion module fileopen_online.py.
        try:
            import fileopen_online
        except ImportError:
            raise ADEPTError(
                "Online retrieval needs 'fileopen_online.py' in the same "
                "folder as this script. Offline alternatives: --key / "
                "--repair-with.")
        try:
            return fileopen_online.fetch_key(self, docid, param)
        except Exception as e:
            # normalizza qualunque errore del modulo nella nostra ADEPTError,
            # cosi' esce come messaggio pulito e non come traceback
            raise ADEPTError(str(e))

    # -- object access ------------------------------------------------------

    KEYWORD_OBJ = KWD(b'obj')

    def getobj(self, objid):
        if not self.ready:
            raise PDFException('PDFDocument not initialized')
        if objid in self.objs:
            return self.objs[objid]
        for xref in self.xrefs:
            try:
                (stmid, index) = xref.getpos(objid)
                break
            except KeyError:
                pass
        else:
            return None
        if stmid:
            if gen_xref_stm:
                return PDFObjStmRef(objid, stmid, index)
            stream = stream_value(self.getobj(stmid))
            if stream.dic.get('Type') is not LITERAL_OBJSTM:
                if STRICT:
                    raise PDFSyntaxError('Not a stream object: %r' % stream)
            try:
                n = stream.dic['N']
            except KeyError:
                if STRICT:
                    raise PDFSyntaxError('N is not defined: %r' % stream)
                n = 0
            if stmid in self.parsed_objs:
                objs = self.parsed_objs[stmid]
            else:
                parser = PDFObjStrmParser(stream.get_data(), self)
                objs = []
                try:
                    while 1:
                        (_, obj) = parser.nextobject()
                        objs.append(obj)
                except PSEOF:
                    pass
                self.parsed_objs[stmid] = objs
            genno = 0
            i = n * 2 + index
            try:
                obj = objs[i]
            except IndexError:
                raise PDFSyntaxError('Invalid object number: objid=%r' % objid)
            if isinstance(obj, PDFStream):
                obj.set_objid(objid, 0)
        else:
            self.parser.seek(index)
            (_, objid1) = self.parser.nexttoken()
            (_, genno) = self.parser.nexttoken()
            (_, kwd) = self.parser.nexttoken()
            if kwd is not self.KEYWORD_OBJ:
                raise PDFSyntaxError('Invalid object spec: offset=%r' % index)
            (_, obj) = self.parser.nextobject()
            if isinstance(obj, PDFStream):
                obj.set_objid(objid, genno)
            if self.decipher:
                obj = decipher_all(self.decipher, objid, genno, obj)
        self.objs[objid] = obj
        return obj


class PDFObjStmRef(object):
    maxindex = 0

    def __init__(self, objid, stmid, index):
        self.objid = objid
        self.stmid = stmid
        self.index = index
        if index > PDFObjStmRef.maxindex:
            PDFObjStmRef.maxindex = index


# ---------------------------------------------------------------------------
#  PDF parser
# ---------------------------------------------------------------------------

class PDFParser(PSStackParser):

    def __init__(self, doc, fp):
        PSStackParser.__init__(self, fp)
        self.doc = doc
        self.doc.set_parser(self)

    def __repr__(self):
        return '<PDFParser>'

    KEYWORD_R = KWD(b'R')
    KEYWORD_ENDOBJ = KWD(b'endobj')
    KEYWORD_STREAM = KWD(b'stream')
    KEYWORD_XREF = KWD(b'xref')
    KEYWORD_STARTXREF = KWD(b'startxref')

    def do_keyword(self, pos, token):
        if token in (self.KEYWORD_XREF, self.KEYWORD_STARTXREF):
            self.add_results(*self.pop(1))
            return
        if token is self.KEYWORD_ENDOBJ:
            self.add_results(*self.pop(4))
            return
        if token is self.KEYWORD_R:
            try:
                ((_, objid), (_, genno)) = self.pop(2)
                (objid, genno) = (int(objid), int(genno))
                obj = PDFObjRef(self.doc, objid, genno)
                self.push((pos, obj))
            except PSSyntaxError:
                pass
            return
        if token is self.KEYWORD_STREAM:
            ((_, dic),) = self.pop(1)
            dic = dict_value(dic)
            try:
                objlen = int_value(dic['Length'])
            except KeyError:
                if STRICT:
                    raise PDFSyntaxError('/Length is undefined: %r' % dic)
                objlen = 0
            self.seek(pos)
            try:
                (_, line) = self.nextline()  # 'stream'
            except PSEOF:
                if STRICT:
                    raise PDFSyntaxError('Unexpected EOF')
                return
            pos += len(line)
            self.fp.seek(pos)
            data = self.fp.read(objlen)
            self.seek(pos + objlen)
            while 1:
                try:
                    (linepos, line) = self.nextline()
                except PSEOF:
                    if STRICT:
                        raise PDFSyntaxError('Unexpected EOF')
                    break
                if b'endstream' in line:
                    i = line.index(b'endstream')
                    objlen += i
                    data += line[:i]
                    break
                objlen += len(line)
                data += line
            self.seek(pos + objlen)
            obj = PDFStream(dic, data, self.doc.decipher)
            self.push((pos, obj))
            return
        self.push((pos, token))

    def find_xref(self):
        prev = None
        for line in self.revreadlines():
            line = line.strip()
            if line == b'startxref':
                break
            if line:
                prev = line
        else:
            raise PDFNoValidXRef('Unexpected EOF')
        return int(prev)

    def read_xref_from(self, start, xrefs):
        self.seek(start)
        self.reset()
        try:
            (pos, token) = self.nexttoken()
        except PSEOF:
            raise PDFNoValidXRef('Unexpected EOF')
        if isinstance(token, int):
            if GEN_XREF_STM == 1:
                global gen_xref_stm
                gen_xref_stm = True
            self.seek(pos)
            self.reset()
            xref = PDFXRefStream()
            xref.load(self)
        else:
            if token is not self.KEYWORD_XREF:
                raise PDFNoValidXRef('xref not found: pos=%d, token=%r' %
                                     (pos, token))
            self.nextline()
            xref = PDFXRef()
            xref.load(self)
        xrefs.append(xref)
        trailer = xref.trailer
        if 'XRefStm' in trailer:
            pos = int_value(trailer['XRefStm'])
            self.read_xref_from(pos, xrefs)
        if 'Prev' in trailer:
            pos = int_value(trailer['Prev'])
            self.read_xref_from(pos, xrefs)

    def read_xref(self):
        xrefs = []
        trailerpos = None
        try:
            pos = self.find_xref()
            self.read_xref_from(pos, xrefs)
        except PDFNoValidXRef:
            self.seek(0)
            pat = re.compile(br'^(\d+)\s+(\d+)\s+obj\b')
            offsets = {}
            xref = PDFXRef()
            while 1:
                try:
                    (pos, line) = self.nextline()
                except PSEOF:
                    break
                if line.startswith(b'trailer'):
                    trailerpos = pos
                m = pat.match(line)
                if not m:
                    continue
                (objid, genno) = m.groups()
                offsets[int(objid)] = (0, pos)
            if not offsets:
                raise
            xref.offsets = offsets
            if trailerpos:
                self.seek(trailerpos)
                xref.load_trailer(self)
                xrefs.append(xref)
        return xrefs


class PDFObjStrmParser(PDFParser):
    def __init__(self, data, doc):
        PSStackParser.__init__(self, BytesIO(data))
        self.doc = doc

    def flush(self):
        self.add_results(*self.popall())

    KEYWORD_R = KWD(b'R')

    def do_keyword(self, pos, token):
        if token is self.KEYWORD_R:
            try:
                ((_, objid), (_, genno)) = self.pop(2)
                (objid, genno) = (int(objid), int(genno))
                obj = PDFObjRef(self.doc, objid, genno)
                self.push((pos, obj))
            except PSSyntaxError:
                pass
            return
        self.push((pos, token))


# ---------------------------------------------------------------------------
#  Serializer
# ---------------------------------------------------------------------------

# Cross-reference streams on output: 0=never, 1=if present in input, 2=always
GEN_XREF_STM = 1


class PDFSerializer(object):
    def __init__(self, inf, key=None, online=False, input_path=None, debug=False):
        global GEN_XREF_STM, gen_xref_stm
        gen_xref_stm = GEN_XREF_STM > 1
        self.version = inf.read(8)
        inf.seek(0)
        self.doc = doc = PDFDocument()
        doc.input_path = input_path or ''
        doc.fo_debug = debug
        PDFParser(doc, inf)
        doc.initialize(key=key, online=online)
        self.objids = objids = set()
        trailer = {}
        for xref in reversed(doc.xrefs):
            trailer = xref.trailer
            for objid in xref.objids():
                objids.add(objid)
        trailer = dict(trailer)
        trailer.pop('Prev', None)
        trailer.pop('XRefStm', None)
        if 'Encrypt' in trailer:
            objids.discard(trailer.pop('Encrypt').objid)
        self.trailer = trailer

    def dump(self, outf):
        self.outf = outf
        self.write(self.version)
        self.write(b'\n%\xe2\xe3\xcf\xd3\n')
        doc = self.doc
        objids = self.objids
        xrefs = {}
        maxobj = max(objids)
        trailer = dict(self.trailer)
        trailer['Size'] = maxobj + 1
        for objid in objids:
            obj = doc.getobj(objid)
            if isinstance(obj, PDFObjStmRef):
                xrefs[objid] = obj
                continue
            if obj is not None:
                try:
                    genno = obj.genno
                except AttributeError:
                    genno = 0
                xrefs[objid] = (self.tell(), genno)
                self.serialize_indirect(objid, obj)
        startxref = self.tell()

        if not gen_xref_stm:
            self.write(b'xref\n')
            self.write(b'0 %d\n' % (maxobj + 1,))
            for objid in range(0, maxobj + 1):
                if objid in xrefs:
                    self.write(b"%010d 00000 n \n" % xrefs[objid][0])
                else:
                    self.write(b"%010d %05d f \n" % (0, 65535))
            self.write(b'trailer\n')
            self.serialize_object(trailer)
            self.write(b'\nstartxref\n%d\n%%%%EOF' % startxref)
        else:
            maxoffset = max(startxref, maxobj)
            maxindex = PDFObjStmRef.maxindex
            fl2 = 2
            power = 65536
            while maxoffset >= power:
                fl2 += 1
                power *= 256
            fl3 = 1
            power = 256
            while maxindex >= power:
                fl3 += 1
                power *= 256
            index = []
            first = None
            prev = None
            data = []
            startxref = self.tell()
            maxobj += 1
            xrefs[maxobj] = (startxref, 0)
            for objid in sorted(xrefs):
                if first is None:
                    first = objid
                elif objid != prev + 1:
                    index.extend((first, prev - first + 1))
                    first = objid
                prev = objid
                objref = xrefs[objid]
                if isinstance(objref, PDFObjStmRef):
                    f1 = 2
                    f2 = objref.stmid
                    f3 = objref.index
                else:
                    f1 = 1
                    f2 = objref[0]
                    f3 = 0
                data.append(struct.pack('>B', f1))
                data.append(struct.pack('>L', f2)[-fl2:])
                data.append(struct.pack('>L', f3)[-fl3:])
            index.extend((first, prev - first + 1))
            data = zlib.compress(b''.join(data))
            dic = {'Type': LITERAL_XREF, 'Size': prev + 1, 'Index': index,
                   'W': [1, fl2, fl3], 'Length': len(data),
                   'Filter': LITERALS_FLATE_DECODE[0],
                   'Root': trailer['Root'], }
            if 'Info' in trailer:
                dic['Info'] = trailer['Info']
            xrefstm = PDFStream(dic, data)
            self.serialize_indirect(maxobj, xrefstm)
            self.write(b'startxref\n%d\n%%%%EOF' % startxref)

    def write(self, data):
        self.outf.write(data)
        self.last = data[-1:]

    def tell(self):
        return self.outf.tell()

    def escape_string(self, string):
        string = string.replace(b'\\', b'\\\\')
        string = string.replace(b'\n', b'\\n')
        string = string.replace(b'(', b'\\(')
        string = string.replace(b')', b'\\)')
        return string

    def serialize_object(self, obj):
        if isinstance(obj, dict):
            if 'ResFork' in obj and 'Type' in obj and 'Subtype' not in obj \
                    and isinstance(obj['Type'], int):
                obj['Subtype'] = obj['Type']
                del obj['Type']
            self.write(b'<<')
            for key, val in obj.items():
                self.write(str(LIT(key.encode('utf-8'))).encode('utf-8'))
                self.serialize_object(val)
            self.write(b'>>')
        elif isinstance(obj, list):
            self.write(b'[')
            for val in obj:
                self.serialize_object(val)
            self.write(b']')
        elif isinstance(obj, bytearray):
            self.write(b'(%s)' % self.escape_string(bytes(obj)))
        elif isinstance(obj, bytes):
            self.write(b'<%s>' % binascii.hexlify(obj).upper())
        elif isinstance(obj, str):
            self.write(b'(%s)' % self.escape_string(obj.encode('utf-8')))
        elif isinstance(obj, bool):
            if self.last.isalnum():
                self.write(b' ')
            self.write(str(obj).lower().encode('utf-8'))
        elif isinstance(obj, (int, Decimal)):
            if self.last.isalnum():
                self.write(b' ')
            self.write(str(obj).encode('utf-8'))
        elif isinstance(obj, PDFObjRef):
            if self.last.isalnum():
                self.write(b' ')
            self.write(b'%d %d R' % (obj.objid, 0))
        elif isinstance(obj, PDFStream):
            if obj.dic.get('Type') == LITERAL_OBJSTM and not gen_xref_stm:
                self.write(b'(deleted)')
            else:
                data = obj.get_decdata()
                if 'Length' in obj.dic:
                    obj.dic['Length'] = len(data)
                self.serialize_object(obj.dic)
                self.write(b'stream\n')
                self.write(data)
                self.write(b'\nendstream')
        elif isinstance(obj, EmptyArrayValue):
            self.write(b'')
        else:
            data = str(obj).encode('utf-8')
            if data and bytes([data[0]]).isalnum() and self.last.isalnum():
                self.write(b' ')
            self.write(data)

    def serialize_indirect(self, objid, obj):
        self.write(b'%d 0 obj' % (objid,))
        self.serialize_object(obj)
        if self.last.isalnum():
            self.write(b'\n')
        self.write(b'endobj\n')


# ---------------------------------------------------------------------------
#  Key-free palette repair
# ---------------------------------------------------------------------------

def _orig_stream_bytes(orig_raw, objid, length):
    m = re.search((r'(?<![0-9])%d\s+\d+\s+obj' % objid).encode(), orig_raw)
    if not m:
        return None
    si = orig_raw.find(b'stream', m.end())
    if si < 0:
        return None
    a = si + 6
    if orig_raw[a:a + 2] == b'\r\n':
        a += 2
    elif orig_raw[a:a + 1] in (b'\r', b'\n'):
        a += 1
    return orig_raw[a:a + length]


def repair_palettes(encrypted_path, decrypted_path, output_path):
    '''
    Fix the indexed-colour palettes of an already-decrypted FileOpen PDF,
    WITHOUT needing the document key.  For each indexed-colour image whose
    palette is still encrypted, recover the per-object RC4 keystream from the
    (known) stream ciphertext/plaintext pair and use it to decrypt the palette.
    '''
    try:
        import pikepdf
    except ImportError:
        raise ADEPTError("repair mode needs pikepdf (pip install pikepdf).")
    orig_raw = open(encrypted_path, 'rb').read()
    pdf = pikepdf.open(decrypted_path)
    fixed = 0
    for obj in pdf.objects:
        try:
            if not isinstance(obj, pikepdf.Object):
                continue
            if obj.get('/Subtype') != pikepdf.Name('/Image'):
                continue
            cs = obj.get('/ColorSpace')
            if cs is None or not isinstance(cs, pikepdf.Array) or len(cs) < 4:
                continue
            if cs[0] != pikepdf.Name('/Indexed'):
                continue
            lut = cs[3]
            if not isinstance(lut, pikepdf.String):
                continue
            enc_pal = bytes(lut)
            objid = obj.objgen[0]
            dec = obj.read_raw_bytes()
            oenc = _orig_stream_bytes(orig_raw, objid, len(dec))
            if oenc is None or len(oenc) < len(enc_pal):
                continue
            ks = bytes(oenc[i] ^ dec[i] for i in range(len(enc_pal)))
            dec_pal = bytes(enc_pal[i] ^ ks[i] for i in range(len(enc_pal)))
            cs[3] = pikepdf.String(dec_pal)
            obj.ColorSpace = cs
            fixed += 1
        except Exception:
            continue
    pdf.save(output_path)
    return fixed


# ---------------------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------------------

def _read_key_arg(args):
    if args.keyfile:
        with open(args.keyfile, 'rb') as f:
            return f.read().strip()
    return args.key


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(
        prog='ineptpdf_fo3',
        description='Decrypt FileOpen-protected PDF files (Python 3).')
    p.add_argument('input', help='input PDF')
    p.add_argument('output', nargs='?', help='output PDF')
    p.add_argument('--key', help='document key (hex, or raw text)')
    p.add_argument('--keyfile', help='file containing the document key')
    p.add_argument('--online', action='store_true',
                   help='fetch the key from the FileOpen server (Windows)')
    p.add_argument('--repair-with', metavar='ENCRYPTED',
                   help='key-free palette repair: pass the original encrypted '
                        'PDF; INPUT is the already-decrypted (but pink) file')
    p.add_argument('--info', action='store_true',
                   help='print encryption parameters and exit')
    p.add_argument('--debug', action='store_true',
                   help='with --online: dump server requests/responses to a log')
    args = p.parse_args(argv)

    # --- info only ---
    if args.info:
        with open(args.input, 'rb') as inf:
            doc = PDFDocument()
            PDFParser(doc, inf)
            ftype = doc.encryption_filter()
            if ftype is None:
                print('Not encrypted.')
                return 0
            print('Filter:', ftype)
            for k, v in doc.fileopen_params().items():
                print('  %-14s %s' % (k, v))
        return 0

    # --- key-free repair ---
    if args.repair_with:
        if not args.output:
            p.error('repair mode needs an OUTPUT path')
        n = repair_palettes(args.repair_with, args.input, args.output)
        print('Palettes repaired: %d  ->  %s' % (n, args.output))
        return 0

    # --- normal decryption ---
    if not args.output:
        p.error('OUTPUT path required')
    key = _read_key_arg(args)
    with open(args.input, 'rb') as inf:
        serializer = PDFSerializer(inf, key=key, online=args.online,
                                   input_path=os.path.abspath(args.input),
                                   debug=args.debug)
        with open(args.output, 'wb') as outf:
            serializer.dump(outf)
    print('Decrypted ->', args.output)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except ADEPTError as e:
        sys.stderr.write('Error: %s\n' % e)
        sys.exit(1)
