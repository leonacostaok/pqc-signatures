#!/usr/bin/env python3
"""Add/check direct production companion checks before the confirmation plan is sealed."""
import argparse,json,os,shutil,sys
from pathlib import Path
if sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
    raise RuntimeError('Python optimization is forbidden, including PYTHONOPTIMIZE')
from prepare import HERE,ROOT,JVM,digest,tree,write,run,stamp
EXPECTED={'passed':True,'production_origin_checked':True,'stored_companions':256,'final_scale_constants':2,'helper_checks':78128,'signed_inputs':152}

def audit(path):
    m=json.loads(path.read_text());base=path.parent;s=m['direct_companion_supplement'];assert digest(base/'manifest-before-supplement.json')==s['parent_manifest_sha256']
    assert digest(base/'supplement-source/DirectCompanionGate.java')==s['source_sha256']==digest(HERE/'DirectCompanionGate.java')
    available=Path(s['classes']).exists()
    if available:assert tree(Path(s['classes']),'.class')==s['class_hashes']
    for v in ['companion','both']:
        assert json.loads((base/'logs'/(v+'-direct-companion.stdout')).read_text())==s['results'][v]==EXPECTED
        assert json.loads((base/'logs'/(v+'-direct-companion.status.json')).read_text())['exit_code']==0
        assert digest(base/'logs'/(v+'-direct-companion.stdout'))==s['stdout_sha256'][v]
    return {'passed':True,'manifest_sha256':digest(path),'direct_production_table_and_helper':True,'local_supplement_class_checks':'passed'if available else'unavailable; supplemental classes absent'}

def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['prepare','audit']);p.add_argument('--manifest',required=True);p.add_argument('--out');a=p.parse_args();path=Path(a.manifest).resolve()
    if a.command=='prepare':
        m=json.loads(path.read_text());base=path.parent;assert 'direct_companion_supplement'not in m
        for p,h in m['inputs'].items():assert digest(ROOT/p)==h
        classes=ROOT/'results/bouncycastle/ntt-alternatives/.build'/base.name/'supplement';classes.mkdir(exist_ok=False);source=base/'supplement-source';source.mkdir();shutil.copy2(HERE/'DirectCompanionGate.java',source/'DirectCompanionGate.java')
        java=Path(m['java']);logs=base/'logs';run([java.with_name('javac'),'-J-XX:ActiveProcessorCount=2','--release','17','-cp',m['variants']['baseline']['classes'],'-d',classes,source/'DirectCompanionGate.java'],logs,'direct-companion-build')
        results={};hashes={}
        for v in ['companion','both']:
            assert tree(Path(m['variants'][v]['classes']),'.class')==m['variants'][v]['class_hashes'];cp=os.pathsep.join([str(classes),m['variants'][v]['classes']]);results[v]=json.loads(run([java,*JVM,'-cp',cp,'org.bouncycastle.crypto.signers.mldsa.DirectCompanionGate',m['variants'][v]['classes']],logs,v+'-direct-companion'));assert results[v]==EXPECTED;hashes[v]=digest(logs/(v+'-direct-companion.stdout'))
        oldhash=digest(path);path.rename(base/'manifest-before-supplement.json');m['direct_companion_supplement']={'parent_manifest_sha256':oldhash,'source_sha256':digest(source/'DirectCompanionGate.java'),'classes':str(classes),'class_hashes':tree(classes,'.class'),'results':results,'stdout_sha256':hashes,'completed_at':stamp()};m['portable_hashes']['supplement-source/DirectCompanionGate.java']=digest(source/'DirectCompanionGate.java')
        m['inputs'].update({str(p.relative_to(ROOT)):digest(p)for p in [HERE/'DirectCompanionGate.java',Path(__file__).resolve()]});write(path,m)
    result=audit(path)
    if a.out:write(a.out,result)
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
