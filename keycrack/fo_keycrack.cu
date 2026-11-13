/* fo_keycrack.cu -- brute force della chiave documento FileOpen (FOPN_foweb V=1)
 * ============================================================================
 * Autonomo: fa parsing del PDF, brute MD5+RC4 su GPU Nvidia, conferma zlib su CPU.
 * Niente Python, niente CuPy.
 *
 * BUILD (GPU):   nvcc -O3 -o fo_keycrack fo_keycrack.cu -lz
 * BUILD (CPU):   gcc  -O3 -x c -DNO_CUDA -o fo_keycrack_cpu fo_keycrack.cu -lz
 *
 * USO:   ./fo_keycrack cifrato.pdf [--reference gia_decifrato.pdf]
 *                      [--objid N] [--klen BYTE] [--start 0xHEX] [--count DEC]
 *                      [--tpb 256] [--blocks 0]
 *
 * Solo FOPN_foweb V=1 (chiave a 40 bit, 5 byte). La chiave e' per-documento.
 * Usalo su file di cui hai accesso legittimo. GPL v3.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <zlib.h>

#ifdef NO_CUDA
  #define DEV
  #define HOST
#else
  #define DEV  __device__ __forceinline__
  #define HOST __host__
#endif

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;
#define ROTL(x,c) (((x)<<(c))|((x)>>(32-(c))))

/* ----------------------- MD5 (blocco singolo, len<=55) ------------------- */
DEV void md5_small(const u8 *msg, int len, u8 *digest){
    const u32 K[64]={
    0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
    0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
    0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
    0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
    0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
    0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
    0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
    0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u};
    const int Rt[64]={7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
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
    u32 a=0x67452301u,b=0xefcdab89u,c=0x98badcfeu,d=0x10325476u,A=a,B=b,C=c,D=d;
    for(i=0;i<64;i++){
        u32 F; int g;
        if(i<16){F=(B&C)|(~B&D);g=i;}
        else if(i<32){F=(D&B)|(~D&C);g=(5*i+1)&15;}
        else if(i<48){F=B^C^D;g=(3*i+5)&15;}
        else {F=C^(B|~D);g=(7*i)&15;}
        F=F+A+K[i]+M[g]; A=D; D=C; C=B; B=B+ROTL(F,Rt[i]);
    }
    a+=A;b+=B;c+=C;d+=D;
    digest[0]=a;digest[1]=a>>8;digest[2]=a>>16;digest[3]=a>>24;
    digest[4]=b;digest[5]=b>>8;digest[6]=b>>16;digest[7]=b>>24;
    digest[8]=c;digest[9]=c>>8;digest[10]=c>>16;digest[11]=c>>24;
    digest[12]=d;digest[13]=d>>8;digest[14]=d>>16;digest[15]=d>>24;
}

/* --------------------------- RC4 (prefisso) ----------------------------- */
DEV void rc4_prefix(const u8 *key, int klen, u8 *out, int n){
    u8 S[256]; int i,j=0,t;
    for(i=0;i<256;i++) S[i]=(u8)i;
    for(i=0;i<256;i++){ j=(j+S[i]+key[i%klen])&255; t=S[i];S[i]=S[j];S[j]=(u8)t; }
    int ii=0,jj=0;
    for(i=0;i<n;i++){ ii=(ii+1)&255; jj=(jj+S[ii])&255; t=S[ii];S[ii]=S[jj];S[jj]=(u8)t;
                      out[i]=S[(S[ii]+S[jj])&255]; }
}

/* prova una chiave; mode 0 = header zlib, mode 1 = known-plaintext esatto */
DEV int test_key(u64 cand, int klen, const u8 *obj3, const u8 *gen2,
                 const u8 *chead, const u8 *kplain, int kplen, int mode){
    u8 msg[16], dig[16], ks[8]; int k;
    for(k=0;k<klen;k++) msg[k]=(u8)(cand>>(8*(klen-1-k)));
    msg[klen]=obj3[0]; msg[klen+1]=obj3[1]; msg[klen+2]=obj3[2];
    msg[klen+3]=gen2[0]; msg[klen+4]=gen2[1];
    int cap=klen+5; if(cap>16)cap=16;
    md5_small(msg, klen+5, dig);
    int probe=(mode==1)?kplen:2;
    rc4_prefix(dig, cap, ks, probe);
    if(mode==1){
        for(k=0;k<kplen;k++) if((u8)(chead[k]^ks[k])!=kplain[k]) return 0;
        return 1;
    } else {
        u8 p0=chead[0]^ks[0], p1=chead[1]^ks[1];
        return (p0==0x78 && (p1==0x01||p1==0x5e||p1==0x9c||p1==0xda));
    }
}

/* =========================== motore di ricerca =========================== */
#ifndef NO_CUDA
__global__ void brute(u64 start,u64 n,int klen,const u8*obj3,const u8*gen2,
                      const u8*chead,const u8*kplain,int kplen,int mode,
                      u64*hits,int*nhits,int maxhits){
    u64 idx=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    u64 stride=(u64)gridDim.x*blockDim.x;
    for(u64 i=idx;i<n;i+=stride){
        if(test_key(start+i,klen,obj3,gen2,chead,kplain,kplen,mode)){
            int p=atomicAdd(nhits,1);
            if(p<maxhits) hits[p]=start+i;
        }
    }
}
#endif

/* ----------------------------- utilita' PDF ----------------------------- */
static u8* read_file(const char*path,size_t*len){
    FILE*f=fopen(path,"rb"); if(!f){perror(path);exit(1);}
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    u8*b=(u8*)malloc(n+1); if(fread(b,1,n,f)!=(size_t)n){exit(1);} fclose(f);
    *len=n; b[n]=0; return b;
}
static u8* mem_find(u8*h,size_t hn,const char*n,u8*from){
    size_t nn=strlen(n); u8*p=from?from:h; u8*end=h+hn-nn;
    for(;p<=end;p++) if(memcmp(p,n,nn)==0) return p;
    return NULL;
}
/* trova uno stream FlateDecode: ritorna objid,genno,cipher(ptr,len).
 * se want_objid>=0 cerca quell'oggetto, altrimenti il primo FlateDecode>=256B */
static int find_stream(u8*raw,size_t rn,long want_objid,
                       long*objid,long*genno,u8**cip,size_t*ciplen){
    u8*p=raw;
    while((p=mem_find(raw,rn," obj",p))){
        /* backtrack: "<id> <gen> obj" */
        u8*q=p; while(q>raw && (q[-1]==' '||(q[-1]>='0'&&q[-1]<='9'))) q--;
        long id,gen; if(sscanf((char*)q,"%ld %ld obj",&id,&gen)!=2){p+=4;continue;}
        u8*body=p+4;
        u8*endobj=mem_find(raw,rn,"endobj",body);
        u8*strm=mem_find(raw,rn,"stream",body);
        if(!strm||(endobj&&strm>endobj)){p+=4;continue;}
        /* dizionario = body..strm */
        size_t dlen=strm-body;
        u8 save=strm[0]; strm[0]=0;
        int isflate=(strstr((char*)body,"/FlateDecode")!=NULL);
        char*lp=strstr((char*)body,"/Length");
        long L=-1; if(lp) sscanf(lp+7,"%ld",&L);
        strm[0]=save;
        if(!isflate||L<=0){p+=4;continue;}
        if(want_objid>=0 && id!=want_objid){p+=4;continue;}
        u8*a=strm+6; if(a[0]=='\r'&&a[1]=='\n')a+=2; else if(a[0]=='\r'||a[0]=='\n')a++;
        if(want_objid>=0 || L>=256){
            *objid=id;*genno=gen;*cip=a;*ciplen=L; (void)dlen; return 1;
        }
        p+=4;
    }
    return 0;
}

/* ------------------------- conferma zlib su CPU -------------------------- */
static int confirm(u64 cand,int klen,const u8*obj3,const u8*gen2,
                   const u8*cipher,size_t clen){
    u8 dk[8],okey[16]; int k;
    for(k=0;k<klen;k++) dk[k]=(u8)(cand>>(8*(klen-1-k)));
    u8 msg[16]; for(k=0;k<klen;k++)msg[k]=dk[k];
    msg[klen]=obj3[0];msg[klen+1]=obj3[1];msg[klen+2]=obj3[2];
    msg[klen+3]=gen2[0];msg[klen+4]=gen2[1];
    int cap=klen+5; if(cap>16)cap=16;
    md5_small(msg,klen+5,okey);
    u8*ks=(u8*)malloc(clen); rc4_prefix(okey,cap,ks,clen);
    u8*plain=(u8*)malloc(clen); for(size_t i=0;i<clen;i++) plain[i]=cipher[i]^ks[i];
    u8 out[64]; z_stream zs; memset(&zs,0,sizeof zs);
    zs.next_in=plain; zs.avail_in=clen; zs.next_out=out; zs.avail_out=sizeof out;
    int ok=0;
    if(inflateInit(&zs)==Z_OK){ int r=inflate(&zs,Z_NO_FLUSH);
        if(r==Z_OK||r==Z_STREAM_END) ok=1; inflateEnd(&zs); }
    free(ks);free(plain); return ok;
}

int main(int argc,char**argv){
    if(argc<2){fprintf(stderr,"uso: %s cifrato.pdf [--reference ref.pdf] [--objid N] "
                        "[--klen B] [--start 0xHEX] [--count DEC] [--tpb N] [--blocks N]\n",argv[0]);return 1;}
    const char*pdf=argv[1]; const char*ref=NULL;
    long want_objid=-1, klen=0; u64 start=0, count=0; int tpb=256, blocks=0;
    for(int i=2;i<argc;i++){
        if(!strcmp(argv[i],"--reference")) ref=argv[++i];
        else if(!strcmp(argv[i],"--objid")) want_objid=atol(argv[++i]);
        else if(!strcmp(argv[i],"--klen")) klen=atol(argv[++i]);
        else if(!strcmp(argv[i],"--start")) start=strtoull(argv[++i],0,0);
        else if(!strcmp(argv[i],"--count")) count=strtoull(argv[++i],0,0);
        else if(!strcmp(argv[i],"--tpb")) tpb=atoi(argv[++i]);
        else if(!strcmp(argv[i],"--blocks")) blocks=atoi(argv[++i]);
    }
    size_t rn; u8*raw=read_file(pdf,&rn);
    if(!klen){ u8*f=mem_find(raw,rn,"FOPN",NULL); char*lp=f?strstr((char*)f,"/Length"):NULL;
               long bits=40; if(lp) sscanf(lp+7,"%ld",&bits); klen=bits/8; }
    long objid,genno; u8*cip; size_t clen;
    if(!find_stream(raw,rn,want_objid,&objid,&genno,&cip,&clen)){
        fprintf(stderr,"Nessuno stream /FlateDecode adatto.\n"); return 1; }
    u8 obj3[3]={(u8)objid,(u8)(objid>>8),(u8)(objid>>16)};
    u8 gen2[2]={(u8)genno,(u8)(genno>>8)};

    int mode=0, kplen=2; u8 kplain[8]={0}, chead[8];
    chead[0]=cip[0]; chead[1]=cip[1];
    if(ref){
        size_t rn2; u8*raw2=read_file(ref,&rn2);
        long o2,g2; u8*c2; size_t cl2;
        if(find_stream(raw2,rn2,objid,&o2,&g2,&c2,&cl2)){
            mode=1; kplen=8; for(int i=0;i<8;i++){kplain[i]=c2[i]; chead[i]=cip[i];}
            printf("[*] Riferimento: 8 byte di plaintext noti (obj %ld)\n",objid);
        }
        /* raw2 intenzionalmente non liberato: kplain gia' copiato */
    }
    printf("[*] Target obj %ld gen %ld, stream %zu byte; chiave %ld byte (%ld bit)\n",
           objid,genno,clen,klen,klen*8);

    u64 total = count? count : (1ULL<<(klen*8));
    u64 t0=(u64)time(0);

#ifdef NO_CUDA
    /* ---- motore CPU (fallback / validazione) ---- */
    u64 found=0; int got=0;
    for(u64 i=0;i<total && !got;i++){
        u64 cand=start+i;
        if(test_key(cand,klen,obj3,gen2,chead,kplain,kplen,mode)){
            if(confirm(cand,klen,obj3,gen2,cip,clen)){ found=cand; got=1; }
        }
        if((i&0xFFFFF)==0xFFFFF){ double dt=(double)time(0)-t0+1e-9;
            fprintf(stderr,"\r[+] %llu / %llu (%.0f k/s)   ",
                    (unsigned long long)i,(unsigned long long)total,(i/dt)/1000.0); }
    }
    fprintf(stderr,"\n");
    if(got){ printf("\n[OK] CHIAVE: "); for(int k=0;k<klen;k++)printf("%02x",(u8)(found>>(8*(klen-1-k)))); printf("\n"); }
    else printf("\n[--] non trovata nell'intervallo.\n");
#else
    /* ---- motore GPU ---- */
    int maxhits = (mode==0)? (1<<20) : 4096;
    u8 *d_obj3,*d_gen2,*d_chead,*d_kplain; u64*d_hits; int*d_nhits;
    cudaMalloc(&d_obj3,3); cudaMalloc(&d_gen2,2); cudaMalloc(&d_chead,8); cudaMalloc(&d_kplain,8);
    cudaMalloc(&d_hits,(size_t)maxhits*8); cudaMalloc(&d_nhits,4);
    cudaMemcpy(d_obj3,obj3,3,cudaMemcpyHostToDevice);
    cudaMemcpy(d_gen2,gen2,2,cudaMemcpyHostToDevice);
    cudaMemcpy(d_chead,chead,8,cudaMemcpyHostToDevice);
    cudaMemcpy(d_kplain,kplain,8,cudaMemcpyHostToDevice);
    if(blocks<=0){ int dev=0; cudaDeviceProp pr; cudaGetDeviceProperties(&pr,dev);
                   blocks=pr.multiProcessorCount*32;
                   printf("[*] GPU: %s (%d SM) -> %d blocchi x %d thread\n",pr.name,pr.multiProcessorCount,blocks,tpb);}
    u64 BATCH = 1ULL<<30;
    u64 *h_hits=(u64*)malloc((size_t)maxhits*8);
    u64 pos=start, done=0, found=0; int got=0;
    while(pos<start+total && !got){
        u64 n = (BATCH < start+total-pos)? BATCH : (start+total-pos);
        cudaMemset(d_nhits,0,4);
        brute<<<blocks,tpb>>>(pos,n,klen,d_obj3,d_gen2,d_chead,d_kplain,kplen,mode,d_hits,d_nhits,maxhits);
        cudaDeviceSynchronize();
        int nh=0; cudaMemcpy(&nh,d_nhits,4,cudaMemcpyDeviceToHost);
        if(nh>maxhits){ fprintf(stderr,"\n[!] %d candidati > buffer %d: usa batch piu' piccolo o --reference\n",nh,maxhits); nh=maxhits; }
        if(nh>0){ cudaMemcpy(h_hits,d_hits,(size_t)nh*8,cudaMemcpyDeviceToHost);
            for(int k=0;k<nh && !got;k++) if(confirm(h_hits[k],klen,obj3,gen2,cip,clen)){found=h_hits[k];got=1;} }
        done+=n; pos+=n;
        double dt=(double)time(0)-t0+1e-9; double rate=done/dt;
        fprintf(stderr,"\r[+] %llu / %llu (%.3g k/s, ETA %.2f h)   ",
                (unsigned long long)done,(unsigned long long)total,rate/1000.0,(total-done)/rate/3600.0);
    }
    fprintf(stderr,"\n");
    if(got){ printf("\n[OK] CHIAVE: "); for(int k=0;k<klen;k++)printf("%02x",(u8)(found>>(8*(klen-1-k)))); printf("\n"); }
    else printf("\n[--] non trovata nell'intervallo.\n");
#endif
    return 0;
}
