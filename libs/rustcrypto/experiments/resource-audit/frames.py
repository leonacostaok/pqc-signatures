#!/usr/bin/env python3
"""Inspect fixed constructor frames in the original uninstrumented timing executable."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--manifest',required=True);parser.add_argument('--out',required=True);args=parser.parse_args()
 manifest=Path(args.manifest).resolve();m=json.loads(manifest.read_text());binary=Path(m['binary']);assert sha(binary)==m['provenance']['binary']
 output=Path(args.out);assert not output.exists();raw=output.parent/'stack-original';raw.mkdir(exist_ok=True)
 command=['nm','-nm',str(binary)];nm=subprocess.check_output(command,text=True)
 rows=[]
 for line in nm.splitlines():
  if 'from_seed' not in line:continue
  symbol=line.split()[-1];side='baseline' if 'ml_dsa_baseline' in symbol else 'candidate';assert 'ml_dsa_'+side in symbol
  cmd=['xcrun','llvm-objdump','--disassemble-symbols='+symbol,'--no-show-raw-insn',str(binary)]
  text=subprocess.check_output(cmd,text=True)
  name=side+'-'+symbol.split('17h')[-1].rstrip('E');path=raw/(name+'.txt')
  if path.exists():assert path.read_text()==text
  else:path.write_text(text)
  lengths=set(re.findall(r'\bmov\s+w8, #(0x(?:520|7a0|a20))\b',text));assert len(lengths)==1,(name,lengths)
  length=int(lengths.pop(),16);parameter={1312:'ML-DSA-44',1952:'ML-DSA-65',2592:'ML-DSA-87'}[length]
  prologue=text.splitlines()[6:22]
  joined='\n'.join(prologue)
  assert re.search(r'stp\s+x28, x27, \[sp, #-0x60\]!',joined)
  pages=re.findall(r'sub\s+x9, sp, #(0x[0-9a-f]+), lsl #12',joined);assert len(pages)==1
  tails=re.findall(r'sub\s+sp, sp, #(0x[0-9a-f]+)$',joined,re.M);assert len(tails)==1
  assert 'cmp\tsp, x9' in joined and 'b.ne' in joined
  frame=96+int(pages[0],16)*4096+int(tails[0],16)
  rows.append({'variant':side,'parameter':parameter,'symbol':symbol,'reserved_frame_bytes':frame,
   'saved_register_bytes':96,'probe_loop_pages':int(pages[0],16),'tail_bytes':int(tails[0],16),
   'mapping':'unique encoded-public-key length immediate loaded into w8','encoded_public_key_bytes':length,
   'command':cmd,'disassembly':str(path),'disassembly_sha256':sha(path),'prologue':prologue})
 assert {(r['variant'],r['parameter']) for r in rows}=={(v,p) for v in ['baseline','candidate'] for p in ['ML-DSA-44','ML-DSA-65','ML-DSA-87']}
 result={'schema':'rust-constructor-frames-v1','original_manifest':str(manifest),'original_manifest_sha256':sha(manifest),'binary':str(binary),'binary_sha256':sha(binary),'compiler':m['compiler'],
  'tool_version':subprocess.check_output(['xcrun','llvm-objdump','--version'],text=True),
  'limits':'Individual static prologue reservations in the original uninstrumented default+zeroize timing executable. Excludes caller/callee frames and dynamic stack high water; does not generalize across compilers, targets or features. Parameter mapping is inferred from the unique encoded-public-key length literal.',
  'rows':rows}
 with output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
 print(output)
if __name__=='__main__':main()
