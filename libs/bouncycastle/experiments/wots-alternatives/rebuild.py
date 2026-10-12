#!/usr/bin/env python3
"""Rebuild retained sources on another host without the original parent checkout."""
import argparse,hashlib,json,pathlib,shutil,subprocess,sys,tarfile
if sys.flags.optimize:raise RuntimeError('Assertions required; do not use Python -O or PYTHONOPTIMIZE')
HERE=pathlib.Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--evidence',type=pathlib.Path,default=HERE.parents[3]/'results/bouncycastle/wots-alternatives');p.add_argument('--javac',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
assert not a.out.exists(),'Use a new output directory';a.out.mkdir(parents=True)
pre=a.evidence/'preparation';pkg='org/bouncycastle/crypto/signers/slhdsa'
m=json.loads((a.evidence/'manifest.json').read_text())
for variant in m['variants']:
    src=a.out/(variant+'-src');src.mkdir()
    with tarfile.open(pre/'baseline-source.tar.gz') as archive:
        assert all(not x.name.startswith('/') and '..' not in pathlib.Path(x.name).parts and (x.isfile() or x.isdir()) for x in archive.getmembers())
        archive.extractall(src)
    main=src/'core/src/main/java';target=main/pkg
    for name in ['WotsPlus.java','SLHDSAEngine.java']:shutil.copyfile(pre/variant/name,target/name)
    classes=a.out/(variant+'-classes');drivers=a.out/(variant+'-driver');classes.mkdir();drivers.mkdir()
    entries=[main/'org/bouncycastle'/x for x in ['crypto/signers/SLHDSASigner.java','crypto/signers/HashSLHDSASigner.java','crypto/generators/SLHDSAKeyPairGenerator.java']]
    subprocess.run([str(a.javac),'--release','8','-sourcepath',str(main),'-d',str(classes),*map(str,entries)],check=True)
    subprocess.run([str(a.javac),'--release','8','-cp',str(classes),'-d',str(drivers),*map(str,sorted(HERE.glob('*.java')))],check=True)
    actual={str(f.relative_to(classes)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(classes.rglob('*.class'))}
    print(json.dumps({'variant':variant,'classes':str(classes),'drivers':str(drivers),'matches_recorded_classes':actual==m['class_hashes'][variant]}))
