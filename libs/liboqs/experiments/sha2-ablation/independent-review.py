#!/usr/bin/env python3
"""Independently validate archived ablation data; does not rebuild or time code."""
import argparse
import hashlib
import json
import statistics
import struct
from datetime import datetime
from pathlib import Path

ORDERS=[['original','sha256-only','sha512-only','full'],['full','sha512-only','sha256-only','original'],['sha256-only','full','original','sha512-only'],['sha512-only','original','full','sha256-only'],['full','original','sha512-only','sha256-only'],['sha256-only','sha512-only','original','full']]
PARAMS=['SLH_DSA_PURE_SHA2_'+s for s in ['128F','128S','192F','192S','256F','256S']]
SIZES=dict(zip(PARAMS,[16,16,24,24,32,32]))
SIGS=dict(zip(PARAMS,[17088,7856,35664,16224,49856,29792]))

def require(ok,why):
    if not ok: raise ValueError(why)

def read(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def stamp(s):return datetime.fromisoformat(s)

def artifact(data):
    require(data[:8]==b'OQSTENO1','artifact magic')
    offset=8;keys=[]
    for p in PARAMS:
        for i in range(10):
            lengths=struct.unpack_from('<III',data,offset);offset+=12
            require(lengths==(SIZES[p]*2,SIZES[p]*4,SIGS[p]),'artifact lengths')
            parts=[]
            for n in lengths:
                value=data[offset:offset+n];offset+=n
                require(len(value)==n,'truncated artifact');parts.append(value)
            keys.append(parts)
    require(offset==len(data),'extra artifact bytes')
    require(len({x[0] for x in keys})==60 and len({x[1] for x in keys})==60,'duplicate keys')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',type=Path,default=Path(__file__).resolve().parent/'evidence')
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args();e=args.evidence;f=e/'final';ready=read(e/'ready.json');complete=read(f/'complete.json');summary=read(f/'summary.json')
    require(ready['complete'] and complete['complete'] and summary['complete'],'incomplete')
    require(ready['orders']==complete['orders']==summary['orders']==ORDERS,'changed schedule')
    require(summary['rounds']==6 and summary['keys_per_parameter_per_round']==10 and ready['screening_margin']==0.03,'changed protocol')
    require(set(complete['result_sha256'])=={f'{i:02d}-{v}' for i,o in enumerate(ORDERS,1) for v in o},'completion coverage')
    require(complete['ready_sha256']==summary['ready_sha256']==sha(e/'ready.json'),'ready binding')
    require(summary['complete_sha256']==sha(f/'complete.json'),'completion binding')
    require(sha(e/'inputs.bin')==ready['identity']['input_sha256'],'input changed')
    require(sha(e/'inputs.json')==ready['identity']['input_metadata_sha256'],'input metadata changed')
    reference=(e/'preflight/original/outputs.bin').read_bytes();artifact(reference)
    require(hashlib.sha256(reference).hexdigest()==ready['reference_output_sha256'],'reference changed')
    workload={(r['parameter'],r['key']):r for r in read(e/'inputs.json')['cases'] if r['key']>=0}
    require(set(workload)=={(p,i) for p in PARAMS for i in range(10)},'input coverage')
    data={};last=None;bound={}
    for round_index,order in enumerate(ORDERS,1):
        for v in order:
            name=f'{round_index:02d}-{v}';folder=f/name;r=read(folder/'result.json');cmd=read(folder/'command.json');status=read(folder/'status.json')
            require(sha(folder/'result.json')==complete['result_sha256'][name],'result changed')
            require(r['complete'] and r['returncode']==status['returncode']==0 and r['variant']==v and r['round']==round_index,'batch identity/status')
            require(r['ready_sha256']==sha(e/'ready.json'),'batch seal')
            require(sha(folder/'command.json')==r['command_sha256'] and sha(folder/'status.json')==r['status_sha256'],'invocation metadata changed')
            drivers=[x for x in ready['identity']['build_files'][v] if Path(x).name=='driver']
            require(len(drivers)==1 and len(cmd['command'])==4 and cmd['command'][0]==drivers[0] and cmd['command'][-1]=='10','driver invocation')
            require(sha(e/'preflight'/v/'command.json')==ready['preflight_metadata_sha256'][v]['command.json'],'preflight command changed')
            require(cmd['command'][1]==read(e/'preflight'/v/'command.json')['command'][1],'different input path')
            require(Path(cmd['command'][2]).parts[-3:]==('final',name,'outputs.bin'),'wrong output destination')
            rows=[json.loads(line) for line in (folder/'stdout.jsonl').read_text().splitlines()]
            require(rows==r['rows'] and sha(folder/'stdout.jsonl')==r['raw_sha256'],'raw rows changed')
            require((folder/'outputs.bin').read_bytes()==reference,'different full key/signature bytes')
            require(sha(folder/'outputs.bin')==r['artifact_sha256'],'artifact changed')
            start,end=stamp(cmd['started_utc']),stamp(status['finished_utc'])
            require(start.tzinfo is not None and end.tzinfo is not None and start<end and (last is None or last<start),'nonserial chronology');last=end
            require(len(rows)==60 and [(x['parameter'],x['key']) for x in rows]==[(p,i) for p in PARAMS for i in range(10)],'row coverage')
            for x in rows:
                require(x['valid'] is True and x['tamper_rejected'] is True,'signature acceptance')
                expected=workload[x['parameter'],x['key']]
                require(all(x[k]==expected[k] for k in ['message_bytes','context_bytes']),'wrong workload size')
                require(x['rng_keygen_bytes']==3*SIZES[x['parameter']] and x['rng_sign_bytes']==SIZES[x['parameter']],'wrong entropy consumption')
                for op in ['keygen','sign','verify']:
                    for clock in ['wall','cpu']:
                        n=x[f'{op}_{clock}_ns'];require(type(n) is int and n>0,'invalid timing')
            data[round_index,v]={ (x['parameter'],x['key']):x for x in rows}
            bound[name]=sha(folder/'result.json')
    cells={(x['variant'],x['parameter'],x['operation']):x for x in summary['summary']}
    require(len(cells)==len(summary['summary'])==54,'summary coverage')
    results=[]
    for v in ['sha256-only','sha512-only','full']:
        for param in PARAMS:
            for op in ['keygen','sign','verify']:
                saved=cells[v,param,op];result=dict(variant=v,parameter=param,operation=op)
                for clock in ['wall','cpu']:
                    field=f'{op}_{clock}_ns';totals={s:[sum(data[i,s][param,k][field] for k in range(10)) for i in range(1,7)] for s in {'original','full',v}}
                    speeds=[a/b for a,b in zip(totals['original'],totals[v])];relative=[a/b for a,b in zip(totals[v],totals['full'])]
                    require(totals==saved[clock]['round_total_ns'],'total mismatch')
                    require(speeds==saved[clock]['speedup_vs_original'] and relative==saved[clock]['reduced_over_full_time'],'ratio mismatch')
                    require(statistics.median(speeds)==saved[clock]['median_speedup_vs_original'] and statistics.median(relative)==saved[clock]['median_reduced_over_full_time'],'median mismatch')
                    individual=[data[i,'original'][param,k][field]/data[i,v][param,k][field] for i in range(1,7) for k in range(10)]
                    require(individual==saved[clock]['individual_key_speedups_vs_original'],'per-key mismatch')
                    require(sum(x<1 for x in individual)==saved[clock]['individual_key_losses_vs_original'],'lost loss')
                    derived=dict(min_speedup_vs_original=min(speeds),max_speedup_vs_original=max(speeds),slower_than_original_rounds=sum(x<1 for x in speeds),min_reduced_over_full_time=min(relative),max_reduced_over_full_time=max(relative),latency_penalty_vs_full=[x-1 for x in relative],median_latency_penalty_vs_full=statistics.median(relative)-1,speedup_fraction_of_full=[1/x for x in relative],median_speedup_fraction_of_full=statistics.median(1/x for x in relative),rounds_over_three_percent_slower_than_full=sum(x>1.03 for x in relative),median_within_three_percent_of_full=statistics.median(relative)<=1.03)
                    require(all(saved[clock][k]==value for k,value in derived.items()),'derived field mismatch')
                    result[clock]=dict(speedup_vs_original=statistics.median(speeds),relative_time_to_full=statistics.median(relative),relative_time_range=[min(relative),max(relative)],latency_penalty_to_full=statistics.median(relative)-1)
                results.append(result)
    args.out.write_text(json.dumps(dict(complete=True,scope='Archived raw-data verification; live source/build/backend gates are recorded by the experiment runner',batches=24,distinct_test_keys=60,measured_key_pipelines=1440,raw_operation_timings=4320,variant_vs_original_operation_pairs=3240,exact_outputs_match=True,serial_order_verified=True,summary_cells=54,result_sha256=bound,summary=results),indent=2)+'\n')
    print('PASS: 24 serial batches; 1440 exact key/signature pipelines; 54 independently recomputed cells')

if __name__=='__main__':main()
