/* Untimed OpenSSL allocation-hook accounting for the private SHA-2 path. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include "sha2_api.h"
#include <stdio.h>
#include <stdlib.h>
static int active;
static size_t mallocs, reallocs, frees, requested;
static void *m(size_t n,const char *f,int l) { (void)f;(void)l;if(active){mallocs++;requested+=n;}return malloc(n); }
static void *r(void *p,size_t n,const char *f,int l) { (void)f;(void)l;if(active){reallocs++;requested+=n;}return realloc(p,n); }
static void d(void *p,const char *f,int l) { (void)f;(void)l;if(active && p!=NULL)frees++;free(p); }
static void hex(const unsigned char *p,size_t n) { for(size_t i=0;i<n;++i)printf("%02x",p[i]); }
int main(void)
{
    static const size_t sizes[]={0,1,55,56,63,64,65,111,112,127,128,129,1024};
    unsigned char input[1024], out256[32], out512[64];
    if(!CRYPTO_set_mem_functions(m,r,d))return 2;
    for(size_t sample=0;sample<4;++sample) {
        for(size_t i=0;i<sizeof(input);++i)input[i]=(unsigned char)(i*17+sample*31);
        for(size_t j=0;j<sizeof(sizes)/sizeof(sizes[0]);++j) {
            mallocs=reallocs=frees=requested=0;active=1;
            sha2_256(out256,input,sizes[j]);sha2_512(out512,input,sizes[j]);
            active=0;
            if(mallocs||reallocs||frees||requested)return 3;
            printf("{\"sample\":%zu,\"bytes\":%zu,\"openssl_mallocs\":%zu,\"openssl_reallocs\":%zu,\"openssl_frees\":%zu,\"openssl_requested_bytes\":%zu,\"sha256_ctx_size\":%zu,\"sha512_ctx_size\":%zu,\"sha256\":\"",sample,sizes[j],mallocs,reallocs,frees,requested,sizeof(SHA256_CTX),sizeof(SHA512_CTX));
            hex(out256,32);printf("\",\"sha512\":\"");hex(out512,64);puts("\"}");
        }
    }
    OPENSSL_cleanup();return 0;
}
