#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# fo_keycrack_cuda.py -- brute force della chiave documento FileOpen su GPU Nvidia
# ==============================================================================
#
# Versione CUDA di fo_keycrack.py.  Ogni thread della GPU calcola
# md5(chiave+objid+genno) -> RC4 -> confronto known-plaintext, su una porzione
# dello spazio 2^(Length) (tipicamente 2^40).  Il kernel MD5+RC4 e' identico a
# quello validato su CPU (gcc) in questo progetto.
#
# Requisiti:  una GPU Nvidia + driver CUDA, e CuPy che corrisponda alla tua
#             versione CUDA:   pip install cupy-cuda12x   (oppure cupy-cuda11x)
#
# Uso:
#     python3 fo_keycrack_cuda.py cifrato.pdf
#     python3 fo_keycrack_cuda.py cifrato.pdf --reference gia_decifrato.pdf
#     python3 fo_keycrack_cuda.py cifrato.pdf --start 0x1100000000 --count 0x10000000000
#
# NOTA: non esegue la crittoanalisi se non su file di cui hai accesso legittimo.
# La chiave e' per-documento: quella trovata vale solo per quel PDF.
# GPL v3.

import sys
import re
import zlib
import struct
import time
import hashlib
import argparse

# riuso dell'estrazione e dell'RC4 gia' testati (stessa cartella)
from fo_keycrack import find_flate_target, reference_plaintext, rc4_prefix

CUDA_SRC = r'''
typedef unsigned int   u32;
typedef unsigned char  u8;
typedef unsigned long long u64;
#define ROTL(x,c) (((x)<<(c))|((x)>>(32-(c))))

__device__ __forceinline__ void md5_small(const u8 *msg, int len, u8 *digest){
    const u32 K[64]={
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
    const int R[64]={7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
                     5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
                     4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
                     6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
    u8 blk[64]; int i;
    for(i=0;i<64;i++) blk[i]=0;
    for(i=0;i<len;i++) blk[i]=msg[i];
    blk[len]=0x80;
    u32 bits=(u32)(len*8);
    blk[56]=bits&0xff; blk[57]=(bits>>8)&0xff; blk[58]=(bits>>16)&0xff; blk[59]=(bits>>24)&0xff;
    u32 M[16];
    for(i=0;i<16;i++) M[i]=blk[i*4]|(blk[i*4+1]<<8)|(blk[i*4+2]<<16)|((u32)blk[i*4+3]<<24);
    u32 a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476;
    u32 A=a,B=b,C=c,D=d;
    for(i=0;i<64;i++){
        u32 F; int g;
        if(i<16){F=(B&C)|(~B&D);g=i;}
        else if(i<32){F=(D&B)|(~D&C);g=(5*i+1)&15;}
        else if(i<48){F=B^C^D;g=(3*i+5)&15;}
        else {F=C^(B|~D);g=(7*i)&15;}
        F=F+A+K[i]+M[g]; A=D; D=C; C=B; B=B+ROTL(F,R[i]);
    }
    a+=A;b+=B;c+=C;d+=D;
    digest[0]=a&0xff;digest[1]=(a>>8)&0xff;digest[2]=(a>>16)&0xff;digest[3]=(a>>24)&0xff;
    digest[4]=b&0xff;digest[5]=(b>>8)&0xff;digest[6]=(b>>16)&0xff;digest[7]=(b>>24)&0xff;
    digest[8]=c&0xff;digest[9]=(c>>8)&0xff;digest[10]=(c>>16)&0xff;digest[11]=(c>>24)&0xff;
    digest[12]=d&0xff;digest[13]=(d>>8)&0xff;digest[14]=(d>>16)&0xff;digest[15]=(d>>24)&0xff;
}

__device__ __forceinline__ void rc4_prefix(const u8 *key, int klen, u8 *out, int n){
    u8 S[256]; int i,j=0,t;
    for(i=0;i<256;i++) S[i]=(u8)i;
    for(i=0;i<256;i++){ j=(j+S[i]+key[i%klen])&255; t=S[i];S[i]=S[j];S[j]=(u8)t; }
    int ii=0,jj=0;
    for(i=0;i<n;i++){ ii=(ii+1)&255; jj=(jj+S[ii])&255; t=S[ii];S[ii]=S[jj];S[jj]=(u8)t;
                      out[i]=S[(S[ii]+S[jj])&255]; }
}

extern "C" __global__
void brute(u64 start, u64 n, int klen,
           const u8* obj3, const u8* gen2,
           const u8* chead, const u8* kplain, int kplen, int mode,
           u64* hits, int* nhits, int maxhits)
{
    u64 idx = (u64)blockIdx.x*blockDim.x + threadIdx.x;
    u64 stride = (u64)gridDim.x*blockDim.x;
    for(u64 i=idx; i<n; i+=stride){
        u64 cand = start + i;
        u8 msg[16], dig[16], ks[8]; int k;
        for(k=0;k<klen;k++) msg[k]=(u8)(cand>>(8*(klen-1-k)));   /* big-endian */
        msg[klen]=obj3[0]; msg[klen+1]=obj3[1]; msg[klen+2]=obj3[2];
        msg[klen+3]=gen2[0]; msg[klen+4]=gen2[1];
        int cap=klen+5; if(cap>16)cap=16;
        md5_small(msg, klen+5, dig);
        int probe = (mode==1)? kplen : 2;
        rc4_prefix(dig, cap, ks, probe);
        int ok=0;
        if(mode==1){
            ok=1;
            for(k=0;k<kplen;k++){ if((u8)(chead[k]^ks[k])!=kplain[k]){ ok=0; break; } }
        } else {
            u8 p0=chead[0]^ks[0], p1=chead[1]^ks[1];
            if(p0==0x78 && (p1==0x01||p1==0x5e||p1==0x9c||p1==0xda)) ok=1;
        }
        if(ok){
            int p=atomicAdd(nhits,1);
            if(p<maxhits) hits[p]=cand;
        }
    }
}
'''


def crack_gpu(path, reference=None, objid=None, klen=None,
              start=0, count=None, batch_log2=32, tpb=256, blocks=0):
    try:
        import cupy as cp
        import numpy as np
    except ImportError:
        sys.exit("Serve CuPy: pip install cupy-cuda12x  (o cupy-cuda11x).")

    raw = open(path, 'rb').read()
    if klen is None:
        mL = re.search(rb'/Filter\s*/FOPN\w*.*?/Length\s+(\d+)', raw, re.S)
        klen = (int(mL.group(1)) if mL else 40) // 8
    oid, gen, cipher = find_flate_target(path, objid)
    obj3 = struct.pack('<L', oid)[:3]
    gen2 = struct.pack('<L', gen)[:2]

    mode = 0
    kplain = b'\x00'
    chead = cipher[:2]
    if reference:
        kp = reference_plaintext(reference, oid, 8)
        if kp:
            mode = 1
            kplain = kp
            chead = cipher[:len(kp)]
            print("[*] Riferimento: %d byte di plaintext noti (obj %d)" % (len(kp), oid))

    dev = cp.cuda.Device()
    name = cp.cuda.runtime.getDeviceProperties(dev.id)['name'].decode()
    nsm = cp.cuda.runtime.getDeviceProperties(dev.id)['multiProcessorCount']
    if blocks <= 0:
        blocks = nsm * 32
    print("[*] GPU: %s  (%d SM)" % (name, nsm))
    print("[*] Target obj %d gen %d, stream %d byte" % (oid, gen, len(cipher)))
    print("[*] Chiave: %d byte (%d bit) -> spazio 2^%d" % (klen, klen*8, klen*8))

    mod = cp.RawModule(code=CUDA_SRC)
    brute = mod.get_function("brute")

    d_obj3 = cp.asarray(np.frombuffer(obj3, dtype=np.uint8))
    d_gen2 = cp.asarray(np.frombuffer(gen2, dtype=np.uint8))
    d_chead = cp.asarray(np.frombuffer(chead, dtype=np.uint8))
    d_kplain = cp.asarray(np.frombuffer(kplain, dtype=np.uint8))
    # In modalita' header il filtro e' di soli 2 byte: ~1 chiave su 16k passa,
    # quindi servono molti slot per i falsi positivi (confermati poi su CPU).
    MAXHITS = (1 << 20) if mode == 0 else 4096
    d_hits = cp.zeros(MAXHITS, dtype=np.uint64)
    d_nhits = cp.zeros(1, dtype=np.int32)

    total = (1 << (klen*8)) if count is None else count
    BATCH = 1 << batch_log2
    cipher_full = cipher
    t0 = time.time()
    done = 0
    pos = start
    found = None
    while pos < start + total and found is None:
        n = min(BATCH, start + total - pos)
        d_nhits.fill(0)
        brute((blocks,), (tpb,),
              (np.uint64(pos), np.uint64(n), np.int32(klen),
               d_obj3, d_gen2, d_chead, d_kplain, np.int32(len(kplain)),
               np.int32(mode), d_hits, d_nhits, np.int32(MAXHITS)))
        cp.cuda.Stream.null.synchronize()
        nh = int(d_nhits.get()[0])
        if nh > MAXHITS:
            sys.stderr.write("\n[!] %d candidati > buffer %d: usa --batch-log2 piu' "
                             "piccolo o --reference.\n" % (nh, MAXHITS))
        if nh:
            for cand in (int(x) for x in d_hits.get()[:min(nh, MAXHITS)]):
                dk = cand.to_bytes(klen, 'big')
                # conferma definitiva su CPU: l'intero stream si decomprime?
                okey = hashlib.md5(dk + obj3 + gen2).digest()[:min(klen+5, 16)]
                plain = bytes(c ^ k for c, k in
                              zip(cipher_full, rc4_prefix(okey, len(cipher_full))))
                try:
                    zlib.decompress(plain)
                    found = dk.hex()
                    break
                except Exception:
                    pass
        done += n
        pos += n
        dt = time.time() - t0
        rate = done / dt if dt else 0
        eta = (total - done) / rate if rate else 0
        sys.stdout.write("\r[+] %d / %d  (%.3g chiavi/s, ETA %.2f h)   "
                         % (done, total, rate, eta/3600))
        sys.stdout.flush()
    print()
    if found:
        print("\n[OK] CHIAVE DOCUMENTO TROVATA: %s" % found)
        print("     ineptpdf_fo3.py --key %s  <in.pdf> <out.pdf>" % found)
    else:
        print("\n[--] Non trovata nell'intervallo esaminato.")
    return found


def main():
    p = argparse.ArgumentParser(
        description="Brute force CUDA della chiave documento FileOpen (FOPN_foweb V=1).")
    p.add_argument('pdf')
    p.add_argument('--reference', help='stesso PDF gia decifrato (controllo esatto)')
    p.add_argument('--objid', type=int)
    p.add_argument('--klen', type=int, help='byte della chiave (default: da /Length)')
    p.add_argument('--start', type=lambda x: int(x, 0), default=0)
    p.add_argument('--count', type=lambda x: int(x, 0))
    p.add_argument('--batch-log2', type=int, default=32,
                   help='chiavi per lancio = 2^N (default 32)')
    p.add_argument('--tpb', type=int, default=256, help='thread per blocco')
    p.add_argument('--blocks', type=int, default=0, help='numero blocchi (0=auto)')
    a = p.parse_args()
    crack_gpu(a.pdf, reference=a.reference, objid=a.objid, klen=a.klen,
              start=a.start, count=a.count, batch_log2=a.batch_log2,
              tpb=a.tpb, blocks=a.blocks)


if __name__ == '__main__':
    main()
