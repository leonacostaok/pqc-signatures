/* Public-API indicator driver. Fixed entropy is test-only, never production. */
#define _DARWIN_C_SOURCE
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#ifdef USE_OQS
#include <oqs/oqs.h>
#endif
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(x) do { if (!(x)) { fprintf(stderr,"check failed at %d: %s\n",__LINE__,#x); exit(2); } } while (0)
#define CAP 65536
#define RECORDS 11
typedef struct { unsigned char *p; size_t n; } bytes;
typedef struct { bytes seed, krnd, srnd, msg, ctx, pk, sk, sig; } fixture;
typedef struct { void *p; size_t n; } slot;
static slot slots[8192];
static size_t a_count, a_bytes, a_live, a_peak, a_frees;
static int a_active;
static const char *algorithm;
static fixture inputs[RECORDS];
static unsigned char output_pk[CAP], output_sk[CAP], output_sig[CAP];
static size_t output_pk_len, output_sk_len, output_sig_len;
static int action, result;
static fixture *current;
#ifdef USE_OQS
static const unsigned char *entropy;
static size_t entropy_left, entropy_used;
#else
static EVP_PKEY *input_key, *output_key;
#endif

static void *a_malloc(size_t n, const char *file, int line)
{
    (void)file; (void)line;
    void *p = malloc(n); REQUIRE(p != NULL);
    if (a_active) {
        size_t i; for(i=0;i<8192 && slots[i].p;i++) {} REQUIRE(i<8192);
        slots[i]=(slot){p,n}; a_count++; a_bytes+=n; a_live+=n;
        if(a_live>a_peak)a_peak=a_live;
    }
    return p;
}
static void a_free(void *p, const char *file, int line)
{
    (void)file; (void)line;
    for(size_t i=0;p && i<8192;i++)if(slots[i].p==p){REQUIRE(a_live>=slots[i].n);a_live-=slots[i].n;slots[i].p=NULL;a_frees++;break;}
    free(p);
}
static void *a_realloc(void *p, size_t n, const char *file, int line)
{
    /* None of the audited public-operation paths should require realloc.
       Fail closed rather than invent requested-byte accounting semantics. */
    REQUIRE(!a_active); (void)file;(void)line; return realloc(p,n);
}
static void a_begin(void)
{
    REQUIRE(a_live==0);memset(slots,0,sizeof(slots));a_count=a_bytes=a_peak=a_frees=0;a_active=1;
}
static uint64_t ns(clockid_t id)
{
    struct timespec t;REQUIRE(clock_gettime(id,&t)==0);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;
}
static uint64_t peak_rss(void)
{
    struct rusage u;REQUIRE(getrusage(RUSAGE_SELF,&u)==0);
#ifdef __APPLE__
    return (uint64_t)u.ru_maxrss;
#else
    return (uint64_t)u.ru_maxrss*1024;
#endif
}
static uint32_t u32(FILE *f)
{
    unsigned char b[4];REQUIRE(fread(b,1,4,f)==4);return b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16)|((uint32_t)b[3]<<24);
}
static void put32(FILE *f,size_t n)
{
    REQUIRE(n<=UINT32_MAX);unsigned char b[4]={(unsigned char)n,(unsigned char)(n>>8),(unsigned char)(n>>16),(unsigned char)(n>>24)};REQUIRE(fwrite(b,1,4,f)==4);
}
static bytes blob(FILE *f,size_t limit)
{
    size_t n=u32(f);REQUIRE(n<=limit);bytes b={malloc(n?n:1),n};REQUIRE(b.p && fread(b.p,1,n,f)==n);return b;
}
static void putblob(FILE *f,const unsigned char *p,size_t n)
{
    put32(f,n);REQUIRE(fwrite(p,1,n,f)==n);
}
static void load_inputs(const char *path)
{
    FILE *f=fopen(path,"rb");REQUIRE(f);char m[8];REQUIRE(fread(m,1,8,f)==8 && !memcmp(m,"CPCIN01\0",8));REQUIRE(u32(f)==RECORDS);
    for(size_t i=0;i<RECORDS;i++) {
        inputs[i].seed=blob(f,96);inputs[i].krnd=blob(f,4096);inputs[i].srnd=blob(f,4096);inputs[i].msg=blob(f,4096);inputs[i].ctx=blob(f,255);
        REQUIRE(inputs[i].seed.n>=32 && inputs[i].krnd.n==4096 && inputs[i].srnd.n==4096);
    }
    REQUIRE(fgetc(f)==EOF && fclose(f)==0);
}
static void load_expected(const char *path)
{
    FILE *f=fopen(path,"rb");REQUIRE(f);char m[8];REQUIRE(fread(m,1,8,f)==8 && !memcmp(m,"CPCOUT1\0",8));REQUIRE(u32(f)==RECORDS);
    for(size_t i=0;i<RECORDS;i++){inputs[i].pk=blob(f,CAP);inputs[i].sk=blob(f,CAP);inputs[i].sig=blob(f,CAP);REQUIRE(inputs[i].pk.n && inputs[i].sk.n && inputs[i].sig.n);}
    REQUIRE(fgetc(f)==EOF && fclose(f)==0);
}
#ifdef USE_OQS
static void fixed_random(unsigned char *out,size_t n)
{
    REQUIRE(n<=entropy_left);memcpy(out,entropy,n);entropy+=n;entropy_left-=n;entropy_used+=n;
}
static void setup(fixture *f,int op)
{
    current=f;action=op;bytes rnd=op==0?f->krnd:f->srnd;entropy=rnd.p;entropy_left=rnd.n;entropy_used=0;
}
static void core(void)
{
    OQS_SIG *s=OQS_SIG_new(algorithm);REQUIRE(s);
    REQUIRE(s->length_public_key<=CAP && s->length_secret_key<=CAP && s->length_signature<=CAP);
    output_pk_len=s->length_public_key;output_sk_len=s->length_secret_key;output_sig_len=0;
    if(action==0) result=OQS_SIG_keypair(s,output_pk,output_sk)==OQS_SUCCESS;
    else if(action==1)result=OQS_SIG_sign_with_ctx_str(s,output_sig,&output_sig_len,current->msg.p,current->msg.n,current->ctx.n?current->ctx.p:NULL,current->ctx.n,current->sk.p)==OQS_SUCCESS;
    else result=OQS_SIG_verify_with_ctx_str(s,current->msg.p,current->msg.n,current->sig.p,current->sig.n,current->ctx.n?current->ctx.p:NULL,current->ctx.n,current->pk.p)==OQS_SUCCESS;
    OQS_SIG_free(s);
}
static void post_core(void) {}
static void cleanup(void) {}
#else
static void setup(fixture *f,int op)
{
    current=f;action=op;input_key=NULL;output_key=NULL;
    if(op) {
        EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_from_name(NULL,algorithm,NULL);REQUIRE(c);
        bytes b=op==2?f->pk:f->sk;
        OSSL_PARAM p[]={OSSL_PARAM_construct_octet_string(op==2?OSSL_PKEY_PARAM_PUB_KEY:OSSL_PKEY_PARAM_PRIV_KEY,b.p,b.n),OSSL_PARAM_construct_end()};
        REQUIRE(EVP_PKEY_fromdata_init(c)>0 && EVP_PKEY_fromdata(c,&input_key,op==2?EVP_PKEY_PUBLIC_KEY:EVP_PKEY_KEYPAIR,p)>0);EVP_PKEY_CTX_free(c);
    }
}
static void core(void)
{
    EVP_PKEY_CTX *c=action==0?EVP_PKEY_CTX_new_from_name(NULL,algorithm,NULL):EVP_PKEY_CTX_new_from_pkey(NULL,input_key,NULL);
    REQUIRE(c);result=0;
    if(action==0) {
        const char *seed_name=!strncmp(algorithm,"ML-DSA",6)?OSSL_PKEY_PARAM_ML_DSA_SEED:OSSL_PKEY_PARAM_SLH_DSA_SEED;
        OSSL_PARAM p[]={OSSL_PARAM_construct_octet_string(seed_name,current->seed.p,current->seed.n),OSSL_PARAM_construct_end()};
        if(EVP_PKEY_keygen_init(c)>0 && EVP_PKEY_CTX_set_params(c,p)>0)result=EVP_PKEY_keygen(c,&output_key)>0;
    } else {
        int deterministic=1;OSSL_PARAM p[]={OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC,&deterministic),OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,current->ctx.p,current->ctx.n),OSSL_PARAM_construct_end()};
        if(action==1){output_sig_len=CAP;if(EVP_PKEY_sign_message_init(c,NULL,p)>0)result=EVP_PKEY_sign(c,output_sig,&output_sig_len,current->msg.p,current->msg.n)==1;}
        else if(EVP_PKEY_verify_message_init(c,NULL,p+1)>0)result=EVP_PKEY_verify(c,current->sig.p,current->sig.n,current->msg.p,current->msg.n)==1;
    }
    EVP_PKEY_CTX_free(c);
}
static void post_core(void)
{
    if(action==0)REQUIRE(EVP_PKEY_get_octet_string_param(output_key,OSSL_PKEY_PARAM_PUB_KEY,output_pk,CAP,&output_pk_len) && EVP_PKEY_get_octet_string_param(output_key,OSSL_PKEY_PARAM_PRIV_KEY,output_sk,CAP,&output_sk_len));
}
static void cleanup(void){EVP_PKEY_free(input_key);EVP_PKEY_free(output_key);input_key=output_key=NULL;}
#endif
static void hash_fixture(fixture *f,unsigned char out[32])
{
    SHA256_CTX c;SHA256_Init(&c);bytes a[]={f->seed,f->krnd,f->srnd,f->msg,f->ctx,f->pk,f->sk,f->sig};
    for(size_t i=0;i<sizeof(a)/sizeof(a[0]);i++){SHA256_Update(&c,&a[i].n,sizeof(a[i].n));SHA256_Update(&c,a[i].p,a[i].n);}SHA256_Final(out,&c);
}
static void check_output(fixture *f,int op)
{
    REQUIRE(result);post_core();
    if(op==0)REQUIRE(output_pk_len==f->pk.n && output_sk_len==f->sk.n && !memcmp(output_pk,f->pk.p,f->pk.n) && !memcmp(output_sk,f->sk.p,f->sk.n));
    if(op==1)REQUIRE(output_sig_len==f->sig.n && !memcmp(output_sig,f->sig.p,f->sig.n));
}
static void output_hash(int op,unsigned char h[32])
{
    SHA256_CTX c;SHA256_Init(&c);
    if(op==0){SHA256_Update(&c,output_pk,output_pk_len);SHA256_Update(&c,output_sk,output_sk_len);}
    else if(op==1)SHA256_Update(&c,output_sig,output_sig_len);
    else {unsigned char yes=1;SHA256_Update(&c,&yes,1);}SHA256_Final(h,&c);
}
static void *thread_core(void *ignored){(void)ignored;core();return NULL;}
static void *thread_noop(void *ignored){(void)ignored;return NULL;}
static size_t stack_probe(int noop,unsigned char paint)
{
    const size_t size=16*1024*1024;size_t guard=(size_t)sysconf(_SC_PAGESIZE);
    unsigned char *p=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);REQUIRE(p!=MAP_FAILED);
    REQUIRE(mprotect(p,guard,PROT_NONE)==0);memset(p+guard,paint,size-guard);
    pthread_attr_t a;pthread_t t;REQUIRE(pthread_attr_init(&a)==0);REQUIRE(pthread_attr_setstack(&a,p+guard,size-guard)==0);
    REQUIRE(pthread_create(&t,&a,noop?thread_noop:thread_core,NULL)==0);REQUIRE(pthread_join(t,NULL)==0);REQUIRE(pthread_attr_destroy(&a)==0);
    size_t i=guard;while(i<size && p[i]==paint)i++;size_t touched=size-i;REQUIRE(touched>0 && touched<size-guard);
    REQUIRE(munmap(p,size)==0);return touched;
}
static void prepare(const char *path)
{
    FILE *out=fopen(path,"wbx");REQUIRE(out);REQUIRE(fwrite("CPCOUT1\0",1,8,out)==8);put32(out,RECORDS);
    for(size_t i=0;i<RECORDS;i++) {
        fixture *f=&inputs[i];setup(f,0);core();REQUIRE(result);post_core();
        f->pk=(bytes){malloc(output_pk_len),output_pk_len};f->sk=(bytes){malloc(output_sk_len),output_sk_len};REQUIRE(f->pk.p && f->sk.p);
        memcpy(f->pk.p,output_pk,f->pk.n);memcpy(f->sk.p,output_sk,f->sk.n);cleanup();
        setup(f,1);core();REQUIRE(result && output_sig_len>0);f->sig=(bytes){malloc(output_sig_len),output_sig_len};REQUIRE(f->sig.p);memcpy(f->sig.p,output_sig,f->sig.n);cleanup();
        setup(f,2);core();REQUIRE(result);cleanup();
        f->sig.p[f->sig.n/2]^=1;setup(f,2);core();REQUIRE(!result);cleanup();f->sig.p[f->sig.n/2]^=1;
        putblob(out,f->pk.p,f->pk.n);putblob(out,f->sk.p,f->sk.n);putblob(out,f->sig.p,f->sig.n);
    }
    REQUIRE(fclose(out)==0);puts("{\"complete\":true,\"records\":11,\"verified\":true,\"tamper_rejected\":true}");
}
int main(int argc,char **argv)
{
    if(argc==3 && !strcmp(argv[1],"support")) {
#ifdef USE_OQS
        OQS_init();OQS_SIG *s=OQS_SIG_new(argv[2]);int available=s!=NULL;OQS_SIG_free(s);
#else
        EVP_PKEY_CTX *s=EVP_PKEY_CTX_new_from_name(NULL,argv[2],NULL);int available=s!=NULL;EVP_PKEY_CTX_free(s);
#endif
        printf("{\"available\":%s}\n",available?"true":"false");return 0;
    }
    REQUIRE(argc>=5);const char *mode=argv[1];algorithm=argv[2];int resource=!strcmp(mode,"allocation");
    REQUIRE(!strcmp(mode,"prepare") || !strcmp(mode,"check") || !strcmp(mode,"timing") || resource || !strcmp(mode,"rss") || !strcmp(mode,"stack-a5") || !strcmp(mode,"stack-5a") || !strcmp(mode,"stack-control-a5") || !strcmp(mode,"stack-control-5a"));
    if(resource)REQUIRE(CRYPTO_set_mem_functions(a_malloc,a_realloc,a_free));
#ifdef USE_OQS
    OQS_init();OQS_randombytes_custom_algorithm(fixed_random);
#endif
    load_inputs(argv[3]);
    if(!strcmp(mode,"prepare")){prepare(argv[4]);return 0;}
    REQUIRE(argc==7);load_expected(argv[4]);int op=atoi(argv[5]);REQUIRE(op>=0 && op<=2);int selected=atoi(argv[6]);REQUIRE(selected>=0 && selected<=10);
    int timing=!strcmp(mode,"timing"),rss=!strcmp(mode,"rss"),stack=!strncmp(mode,"stack-",6),control=!strncmp(mode,"stack-control-",14);
    /* RSS is cold process occupancy. Other modes use a disjoint input warmup. */
    if(!rss){setup(&inputs[0],op);core();check_output(&inputs[0],op);cleanup();}
    int first=selected?selected:1,last=selected?selected:10;
    for(int i=first;i<=last;i++) {
        fixture *f=&inputs[i];unsigned char before[32],after[32],digest[32];hash_fixture(f,before);setup(f,op);
        uint64_t pre=rss?peak_rss():0,post=0,wall=0,cpu=0;size_t touched=0,retained=0;
        if(resource)a_begin();
        if(stack)touched=stack_probe(control,mode[strlen(mode)-2]=='a'?0xa5:0x5a);
        else if(timing){uint64_t c=ns(CLOCK_PROCESS_CPUTIME_ID),w=ns(CLOCK_MONOTONIC);core();wall=ns(CLOCK_MONOTONIC)-w;cpu=ns(CLOCK_PROCESS_CPUTIME_ID)-c;}
        else core();
        if(resource){a_active=0;retained=a_live;}
        if(rss)post=peak_rss();
        if(!control){check_output(f,op);output_hash(op,digest);}cleanup();
        if(!strcmp(mode,"check")) {
            f->sig.p[f->sig.n/2]^=1;setup(f,2);core();REQUIRE(!result);cleanup();f->sig.p[f->sig.n/2]^=1;
        }
        hash_fixture(f,after);REQUIRE(!memcmp(before,after,32));
        if(resource)REQUIRE(a_live==0 && a_count==a_frees);
        printf("{\"parameter\":\"%s\",\"operation\":%d,\"key\":%d,\"mode\":\"%s\",\"valid\":true,\"input_unchanged\":true,\"wall_ns\":%llu,\"cpu_ns\":%llu,\"peak_rss_pre_bytes\":%llu,\"peak_rss_post_bytes\":%llu,\"observed_overwritten_thread_stack_bytes\":%zu,\"allocations\":%zu,\"allocated_requested_bytes\":%zu,\"peak_tracked_live_bytes\":%zu,\"retained_at_return_bytes\":%zu,\"net_after_cleanup_bytes\":%zu,\"frees\":%zu,\"output_sha256\":\"",algorithm,op,i,mode,(unsigned long long)wall,(unsigned long long)cpu,(unsigned long long)pre,(unsigned long long)post,touched,resource?a_count:0,resource?a_bytes:0,resource?a_peak:0,retained,resource?a_live:0,resource?a_frees:0);
        if(control)printf("not-an-operation");else for(size_t j=0;j<32;j++)printf("%02x",digest[j]);
        printf("\",\"tamper_check_executed\":%s}\n",!strcmp(mode,"check")?"true":"false");REQUIRE(fflush(stdout)==0);
    }
    OPENSSL_cleanse(output_sk,sizeof(output_sk));return 0;
}
