#!/usr/bin/env python3
"""Build diagnostic drivers and check deterministic fixtures; no measurements."""
import argparse, datetime, hashlib, json, os, struct, subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[4]
SOURCE=Path(__file__).with_name('driver.c')
PARAMS=['128f','128s','192f','192s','256f','256s']
def need(ok,message):
    if not ok: raise ValueError(message)
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def dump(path,value): Path(path).write_text(json.dumps(value,indent=2)+'\n')
def run(command,path):
    started=datetime.datetime.now(datetime.timezone.utc).isoformat()
    p=subprocess.run(list(map(str,command)),capture_output=True,text=True)
    dump(path,dict(command=list(map(str,command)),started_at=started,finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),returncode=p.returncode,stdout=p.stdout,stderr=p.stderr))
    need(p.returncode==0,'failed command; see '+str(path));return p.stdout
def generate(path,provider,parameter):
    data=bytearray(b'CPCIN01\0'+struct.pack('<I',11))
    metadata=[]
    for index in range(11):
        domain=f'complete-indicators-v1/{provider}/{parameter}/{index}'.encode()
        n=int(parameter.split('-')[-1][:3])//8 if parameter.startswith('SLH') else 0
        k=hashlib.shake_256(domain+b'/keygen').digest(4096);r=hashlib.shake_256(domain+b'/sign').digest(4096)
        seed=k[:3*n if n else 32]
        mlen=[17,0,64,4096,32,256,1024,63,65,1,4096][index]
        clen=0 if parameter.startswith('Falcon') else [7,0,17,255,1,0,32,0,255,1,17][index]
        msg=hashlib.shake_256(domain+b'/message').digest(mlen);ctx=hashlib.shake_256(domain+b'/context').digest(clen)
        for b in [seed,k,r,msg,ctx]: data+=struct.pack('<I',len(b))+b
        metadata.append(dict(key=index,warmup=index==0,seed_sha256=hashlib.sha256(seed).hexdigest(),message_bytes=mlen,context_bytes=clen))
    path.write_bytes(data);return metadata
def outputs(path):
    data=Path(path).read_bytes();need(data[:8]==b'CPCOUT1\0','output magic');offset=8
    def u32():
        nonlocal offset
        need(offset+4<=len(data),'truncated length');n=struct.unpack_from('<I',data,offset)[0];offset+=4;return n
    def blob():
        nonlocal offset
        n=u32();need(0<n<=65536 and offset+n<=len(data),'truncated output');b=data[offset:offset+n];offset+=n;return b
    need(u32()==11,'wrong output count');records=[]
    for i in range(11):
        pk,sk,sig=blob(),blob(),blob()
        records.append(dict(key=i,pk_sha256=hashlib.sha256(pk).hexdigest(),sk_sha256=hashlib.sha256(sk).hexdigest(),signature_sha256=hashlib.sha256(sig).hexdigest(),operation_sha256=[hashlib.sha256(pk+sk).hexdigest(),hashlib.sha256(sig).hexdigest(),hashlib.sha256(b'\1').hexdigest()],pk_bytes=len(pk),sk_bytes=len(sk),signature_bytes=len(sig)))
    need(offset==len(data),'trailing output');need(len({r['pk_sha256'] for r in records})==11,'duplicate keys');return records
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('provider',choices=['openssl','liboqs']);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    build=ROOT/'libs'/args.provider/'build/complete-indicators'/out.name;build.mkdir(parents=True,exist_ok=False)
    frozen=ROOT.parent/'provider-performance/libs/openssl/build/sha512-prefix';oqs=ROOT.parent/'liboqs-performance/libs/liboqs/build/sha2-openssl'
    if args.provider=='openssl': builds={s:frozen/s for s in ['baseline','candidate']}
    else: builds={s:oqs/s for s in ['baseline','candidate']};builds['extended']=ROOT/'libs/liboqs/build/complete-indicators/baseline-extended-make'
    binaries={};artifacts={str(SOURCE):sha(SOURCE),str(Path(__file__)):sha(__file__)}
    for side,library_build in builds.items():
        binary=build/side
        if args.provider=='openssl':library=library_build/'libcrypto.a';cmd=['cc','-O2','-Wall','-Wextra','-I'+str(library_build/'include'),str(SOURCE),str(library),'-lpthread','-o',str(binary)]
        else:
            library=library_build/'lib/liboqs.a';ssl=Path('/opt/homebrew/Cellar/openssl@3/3.6.4_1')
            cmd=['cc','-O2','-Wall','-Wextra','-DUSE_OQS','-I'+str(library_build/'include'),'-I'+str(ssl/'include'),str(SOURCE),str(library),str(ssl/'lib/libcrypto.3.dylib'),'-lpthread','-o',str(binary)]
            artifacts[str(ssl/'lib/libcrypto.3.dylib')]=sha(ssl/'lib/libcrypto.3.dylib')
        run(cmd,out/(side+'-compile.json'));binaries[side]=str(binary)
        artifacts[str(binary)]=sha(binary);artifacts[str(library)]=sha(library)
        for name in ['CMakeCache.txt','include/oqs/oqsconfig.h','include/openssl/configuration.h','configdata.pm']:
            p=library_build/name
            if p.exists():artifacts[str(p)]=sha(p)
    parameters=['ML-DSA-'+x for x in ['44','65','87']]+['SLH-DSA-'+h+'-'+p for h in ['SHA2','SHAKE'] for p in PARAMS]
    if args.provider=='liboqs':parameters+=['Falcon-512','Falcon-1024']
    specs=[]
    for parameter in parameters:
        native=parameter if args.provider=='openssl' or not parameter.startswith('SLH') else parameter.replace('SLH-DSA-','SLH_DSA_PURE_').replace('-','_').upper()
        affected=parameter.startswith('SLH-DSA-SHA2-');baseline='baseline' if args.provider=='openssl' or affected else 'extended'
        available=json.loads(run([binaries[baseline],'support',native],out/(parameter+'-support.json')))['available'];need(available,'expected algorithm unavailable '+parameter)
        inp=out/(parameter+'.input');corpus=out/(parameter+'.outputs');metadata=generate(inp,args.provider,parameter)
        report=json.loads(run([binaries[baseline],'prepare',native,inp,corpus],out/(parameter+'-prepare.json')));need(report==dict(complete=True,records=11,verified=True,tamper_rejected=True),'bad prepare output')
        records=outputs(corpus);checks={}
        for side in [baseline]+(['candidate'] if affected else []):
            checks[side]={}
            for op in range(3):
                result=run([binaries[side],'check',native,inp,corpus,op,0],out/(parameter+'-'+side+'-'+str(op)+'-check.json'))
                rows=[json.loads(s) for s in result.splitlines()];need(len(rows)==10 and [r['key'] for r in rows]==list(range(1,11)),'wrong check coverage')
                for row in rows:need(row['valid'] is True and row['input_unchanged'] is True and row['tamper_check_executed'] is True and row['output_sha256']==records[row['key']]['operation_sha256'][op],'wrong checked result')
                checks[side][str(op)]=True
        specs.append(dict(parameter=parameter,native_parameter=native,baseline=baseline,paired_resource=affected,baseline_timing=not affected and not(args.provider=='openssl' and parameter=='SLH-DSA-SHAKE-128f'),input=str(inp),corpus=str(corpus),metadata=metadata,records=records,checks=checks))
        artifacts[str(inp)]=sha(inp);artifacts[str(corpus)]=sha(corpus)
    capabilities=[]
    if args.provider=='openssl':
        for name in ['Falcon-512','Falcon-1024']:
            supported=json.loads(run([binaries['baseline'],'support',name],out/(name+'-support.json')))['available']
            capabilities.append(dict(parameter=name,supported=supported,scope='Stock default provider in exact OpenSSL build; third-party providers not loaded'))
            need(not supported,'unexpected new capability; update inventory')
    for p in out.glob('*.json'):artifacts[str(p)]=sha(p)
    dump(out/'manifest.json',dict(schema='c-provider-indicators-prepared-v1',complete=True,provider=args.provider,baseline_commit='122db7eb076bf0625df87b91bcc2dccfaccc4900' if args.provider=='openssl' else 'fd44469daeffe6b28f031f54f9bb66cbae69a572',published_commit='857cb293518745277fcf2594e8042fcc6eda549c' if args.provider=='openssl' else '94b42a7232057236dcb3dd56310df3d9d0a1cbd7',binaries=binaries,parameters=specs,capabilities=capabilities,sha256=artifacts,environment={k:os.environ.get(k) for k in ['DYLD_INSERT_LIBRARIES','DYLD_LIBRARY_PATH','OPENSSL_CONF','OPENSSL_MODULES','OPENSSL_armcap']},compiler=run(['cc','--version'],out/'compiler.json')))
    print(str(out/'manifest.json'),flush=True)
if __name__=='__main__':main()
