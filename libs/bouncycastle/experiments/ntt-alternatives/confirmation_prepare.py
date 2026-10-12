#!/usr/bin/env python3
"""Prepare held-out Java 17 confirmation; does not collect timing/allocation."""
import argparse,json,os,shutil,sys
from pathlib import Path
if sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
    raise RuntimeError('Python optimization is forbidden, including PYTHONOPTIMIZE')
from prepare import HERE,ROOT,PIN,JVM,PACKAGE,digest,tree,hmap,stamp,write,run
from audit import read_corpus
VARIANTS=['baseline','companion','both']
DOMAINS={x:'ntt-java17-confirm-'+x+'-v1' for x in ['correctness','warmup','measured']}

def main():
    p=argparse.ArgumentParser();p.add_argument('--screen-manifest',required=True);p.add_argument('--java-home',required=True);p.add_argument('--native-manifest',required=True);p.add_argument('--native-evidence',required=True);p.add_argument('--native-driver',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    oldp=Path(a.screen_manifest).resolve();old=json.loads(oldp.read_text());assert old['upstream']==PIN
    out=Path(a.out).resolve();out.mkdir(parents=True,exist_ok=False);logs=out/'logs';logs.mkdir();build=ROOT/'results/bouncycastle/ntt-alternatives/.build'/out.name;build.mkdir(parents=True,exist_ok=False)
    inputs={str(p.relative_to(ROOT)):digest(p)for p in sorted(HERE.glob('*'))if p.is_file()and p.suffix in ['.py','.java']}
    for v in VARIANTS:
        assert tree(Path(old['variants'][v]['classes']),'.class')==old['variants'][v]['class_hashes']
        assert tree(Path(old['variants'][v]['source']),'.java')==old['variants'][v]['source_hashes']
    assert digest(old['source_archive'])==old['source_archive_sha256'];shutil.copy2(old['source_archive'],out/'baseline-source.tar.gz');shutil.copy2(oldp,out/'screen-manifest.json')
    for v in VARIANTS:shutil.copytree(oldp.parent/'overlays'/v,out/'overlays'/v)
    java=Path(a.java_home).resolve()/'bin/java';driver=build/'driver';driver.mkdir();driver_sources=out/'driver-sources';driver_sources.mkdir()
    for original in sorted(HERE.glob('*.java')):
        text=original.read_text();adapted=text.replace('.threadId()','.getId()');(driver_sources/original.name).write_text(adapted)
        assert adapted.replace('.getId()','.threadId()')==text
    run([java.with_name('javac'),'-J-XX:ActiveProcessorCount=2','--release','17','-cp',old['variants']['baseline']['classes'],'-d',driver,*sorted(driver_sources.glob('*.java'))],logs,'driver-build')
    corpora={};fixtures=out/'fixtures';fixtures.mkdir();cp=os.pathsep.join([str(driver),old['variants']['baseline']['classes']])
    for label,count,modes in [('correctness',12,True),('warmup',2,False),('measured',128,False)]:
        target=fixtures/(label+'.bin');run([java,*JVM,'-cp',cp,'org.bouncycastle.crypto.signers.mldsa.MLDeep','emit',target,str(count),DOMAINS[label],str(modes).lower()],logs,'emit-'+label);corpora[label]={'path':str(target),'sha256':digest(target),'domain':DOMAINS[label]}
    oldseeds=set()
    for info in old['corpora'].values():
        assert digest(info['path'])==info['sha256'];oldseeds.update(d[0]for _,d in read_corpus(info['path']).values())
    newseeds=set()
    for label,info in corpora.items():
        cases=read_corpus(info['path']);seeds=[d[0]for _,d in cases.values()];assert len(seeds)==len(set(seeds));assert not(set(seeds)&(oldseeds|newseeds));newseeds.update(seeds)
        assert len(cases)=={'correctness':72,'warmup':6,'measured':384}[label]
    np=Path(a.native_manifest).resolve();native=json.loads(np.read_text());ep=Path(a.native_evidence).resolve();evidence=json.loads(ep.read_text());assert evidence['manifest_sha256']==digest(np)
    assert tree(Path(native['classes']),'.class')==native['class_hashes']
    native_files={str(Path(native['test_data'])/p):h for p,h in evidence['test_data_hashes'].items()};native_files.update(native['dependencies']);nd=Path(a.native_driver).resolve();native_files[str(nd/'NativeMethods.class')]=evidence['driver_class_sha256']
    for path,expected in native_files.items():assert digest(path)==expected,path
    shutil.copy2(np,out/'native-manifest.json');shutil.copy2(ep,out/'native-parent-evidence.json')
    m={'schema':'bc-ntt-java17-prepared-v1','upstream':PIN,'created_at':stamp(),'parent_manifest':{'path':str(oldp),'sha256':digest(oldp)},'source_archive':str(out/'baseline-source.tar.gz'),'source_archive_sha256':old['source_archive_sha256'],'inputs':inputs,'java':str(java),'jvm_args':JVM,'corpora':corpora,'variants':{},'held_out':{'old_unique_seed_count':len(oldseeds),'new_unique_seed_count':len(newseeds),'overlap':0},'environment':{k:os.environ.get(k,'')for k in old['environment']},'native':{'manifest_sha256':digest(np),'parent_evidence_sha256':digest(ep),'classes':native['classes'],'class_hashes':native['class_hashes'],'files':native_files,'test_data_pin':'3c385e9f4c0b12ce5a86d2b29a17fb3b68dd4e1a','wycheproof_cases_per_variant':631},'production_classes_unchanged':True,'production_release':8,'driver_release':17,'driver_adaptation':'Only .threadId() replaced by .getId() in separate Java driver source copies.'}
    home=java.parent.parent;m['runtime_files']={str(p):digest(p)for p in [java,java.with_name('javac'),home/'release',home/'lib/modules',home/'lib/server/libjvm.dylib']}
    m['java_version']=run([java,'-version'],logs,'java-version')+(logs/'java-version.stderr').read_text();assert '17.0.11' in m['java_version']
    for v in VARIANTS:
        info={k:old['variants'][v][k]for k in ['source','classes','source_hashes','class_hashes','source_identity','class_identity']};cp=os.pathsep.join([str(driver),info['classes']])
        for gate,clazz in [('arithmetic','NTTGate'),('correctness','MLDeep'),('malformed','MalformedCheck')]:
            args=[]if gate=='arithmetic'else ['check',corpora['correctness']['path']]if gate=='correctness'else[corpora['correctness']['path']]
            info[gate]=json.loads(run([java,*JVM,'-cp',cp,'org.bouncycastle.crypto.signers.mldsa.'+clazz,*args],logs,v+'-'+gate))
        assert info['correctness']=={'operation_checks':432,'negative_checks':288,'inputs_preserved':True};assert info['malformed']=={'cases':72,'checks':936,'ownership':True};assert info['arithmetic']['passed']
        info['corpus_checks']={}
        for label in ['warmup','measured']:
            data=json.loads(run([java,*JVM,'-cp',cp,'org.bouncycastle.crypto.signers.mldsa.MLDeep','check',corpora[label]['path']],logs,v+'-'+label+'-exact'));n=6 if label=='warmup' else 384;assert data=={'operation_checks':n*6,'negative_checks':n*4,'inputs_preserved':True};info['corpus_checks'][label]=data
        ncp=os.pathsep.join([info['classes'],str(nd),native['classes'],native['junit'],native['hamcrest']])
        output=run([java,*JVM,'-Dtest.full=true','-Dbc.test.data.home='+native['test_data'],'-cp',ncp,'NativeMethods',info['classes'],'org.bouncycastle.crypto.signers.mldsa.Ntt,org.bouncycastle.crypto.signers.mldsa.PolyVecMatrix,org.bouncycastle.crypto.signers.mldsa.Poly,org.bouncycastle.crypto.signers.mldsa.MLDSAEngine','org.bouncycastle.pqc.crypto.test.MLDSATest','org.bouncycastle.pqc.crypto.test.MLDSAWycheproofTest'],logs,v+'-native')
        assert 'MLDSATest count=14 ignored=0 failures=0'in output and 'MLDSAWycheproofTest count=3 ignored=0 failures=0'in output and 'PASS native methods=17'in output
        info['native']={'methods':17,'wycheproof_cases':631,'passed':True,'class_origins_checked':True};m['variants'][v]=info;print('Checked Java17 '+v,flush=True)
    for v in VARIANTS:assert tree(Path(m['variants'][v]['classes']),'.class')==m['variants'][v]['class_hashes']
    for path,expected in native_files.items():assert digest(path)==expected,path
    assert tree(Path(native['classes']),'.class')==native['class_hashes'];assert inputs=={str(p.relative_to(ROOT)):digest(p)for p in sorted(HERE.glob('*'))if p.is_file()and p.suffix in ['.py','.java']}
    m['driver']={'path':str(driver),'class_hashes':tree(driver,'.class')};m['portable_hashes']=tree(out,'.java')|tree(out,'.patch');m['completed_at']=stamp();write(out/'manifest.json',m);print(out/'manifest.json');print(digest(out/'manifest.json'))
if __name__=='__main__':main()
