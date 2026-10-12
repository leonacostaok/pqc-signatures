#!/usr/bin/env python3
"""Independently verify BC deep-experiment evidence without executing Java.

Requires the retained source/class trees and the pinned upstream Git object.
Hashes establish artifact identity; this is not an independent compilation or
cryptographic implementation. Stage-output digests are checked against the
sealed, cross-implementation preparation results.
"""
import argparse
import datetime
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import statistics
import struct
import subprocess

PIN = 'c314b9cdffa3958a0eff5344f8fdcdb0181ed830'
METRICS = ('wall_ns', 'cpu_ns', 'thread_cpu_ns', 'allocated_bytes')
SLH_STAGES = ('verify.decode', 'sign.prf_msg', 'hmsg', 'fors.indices', 'verify.fors_leaves',
              'verify.fors_auth', 'verify.fors_compress', 'verify.fors', 'verify.wots_chains',
              'verify.wots_compress', 'verify.wots', 'verify.xmss_auth', 'verify.hypertree',
              'sign.fors', 'sign.wots', 'sign.xmss_auth', 'sign.hypertree', 'sign.serialize')
TOTALS = ('keygen.total', 'sign.total', 'verify.total')
JVM = ['-Xmx512m', '-XX:ActiveProcessorCount=2']


class ReviewError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ReviewError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(text):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'duplicate JSON key: ' + key)
            out[key] = value
        return out
    def finite(value):
        if isinstance(value, float):
            require(math.isfinite(value), 'nonfinite JSON number')
        elif isinstance(value, dict):
            for child in value.values():
                finite(child)
        elif isinstance(value, list):
            for child in value:
                finite(child)
    try:
        result = json.loads(text, object_pairs_hook=pairs)
        finite(result)
        return result
    except (ValueError, TypeError) as error:
        raise ReviewError(str(error)) from error


def read_json(path):
    return strict_json(Path(path).read_text())


def integer(value, minimum, name):
    require(type(value) is int and value >= minimum, 'invalid integer: ' + name)
    return value


def match(expected, actual, name):
    if isinstance(expected, dict):
        require(isinstance(actual, dict) and expected.keys() == actual.keys(), name + ': object keys differ')
        for key in expected:
            match(expected[key], actual[key], name + '.' + str(key))
    elif isinstance(expected, (list, tuple)):
        require(isinstance(actual, (list, tuple)) and len(expected) == len(actual), name + ': sequence size differs')
        for index, (left, right) in enumerate(zip(expected, actual)):
            match(left, right, name + '[' + str(index) + ']')
    elif isinstance(expected, float):
        require(type(actual) in (int, float) and math.isfinite(actual)
                and math.isclose(expected, actual, rel_tol=1e-12, abs_tol=1e-12), name + ': numeric claim differs')
    else:
        require(type(expected) is type(actual) and expected == actual, name + ': value differs')


def timestamp(value):
    try:
        result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, TypeError, AttributeError) as error:
        raise ReviewError('invalid timestamp') from error
    require(result.tzinfo is not None, 'timestamp lacks timezone')
    return result


def read_process(stem, expected_command):
    stem = str(stem)
    command = read_json(stem + '.command.json')
    status = read_json(stem + '.status.json')
    match(expected_command, command['command'], stem + ': command')
    require(type(status['exit_code']) is int and status['exit_code'] == 0, stem + ': process failed')
    start, finish = timestamp(command['started_at']), timestamp(status['finished_at'])
    require(start <= finish, stem + ': reversed process timestamps')
    stdout = Path(stem + '.stdout.txt').read_text()
    require(Path(stem + '.stderr.txt').is_file(), stem + ': missing stderr')
    rows = [strict_json(line) for line in stdout.splitlines()]
    require(rows, stem + ': empty process output')
    return dict(rows=rows, start=start, finish=finish,
                hashes={suffix: sha(stem + suffix) for suffix in
                        ('.command.json', '.status.json', '.stdout.txt', '.stderr.txt')})


def tree_files(path, suffix):
    root = Path(path)
    require(root.is_dir(), 'missing artifact directory: ' + str(root))
    result = {p.relative_to(root).as_posix(): p.read_bytes()
              for p in sorted(root.rglob('*' + suffix)) if p.is_file()}
    require(result, 'empty artifact tree: ' + str(root))
    return result


def tree_hash(files):
    result = hashlib.sha256()
    for name in sorted(files):
        result.update(name.encode() + b'\0' + hashlib.sha256(files[name]).digest())
    return result.hexdigest()


def check_hashes(mapping, root=None):
    require(isinstance(mapping, dict) and mapping, 'empty hash binding')
    for name, expected in mapping.items():
        require(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected), 'malformed digest')
        path = Path(name) if root is None else Path(root) / name
        require(path.is_file() and sha(path) == expected, 'hash mismatch: ' + str(path))


def verify_git_baseline(files, upstream):
    command = ['git', '-C', str(upstream), 'ls-tree', '-r', PIN, '--', 'core/src/main/java']
    text = subprocess.check_output(command, text=True)
    wanted = {}
    for line in text.splitlines():
        header, name = line.split('\t', 1)
        mode, kind, oid = header.split()
        if name.endswith('.java'):
            require(kind == 'blob' and mode in ('100644', '100755'), 'unexpected upstream file type')
            wanted[name] = oid
    require(wanted and files.keys() == wanted.keys(), 'baseline source coverage differs from pinned Git tree')
    for name, content in files.items():
        blob = b'blob ' + str(len(content)).encode() + b'\0' + content
        require(hashlib.sha1(blob).hexdigest() == wanted[name], 'baseline differs from pinned Git: ' + name)


def apply_patch_files(baseline, patch):
    """Strictly reconstruct ordinary edited-file unified diffs; no Git discovery."""
    lines = patch.splitlines(keepends=True)
    result, changed, index = dict(baseline), set(), 0
    while index < len(lines):
        require(lines[index].startswith('diff --git a/'), 'unexpected patch header')
        index += 1
        while index < len(lines) and not lines[index].startswith('--- '):
            require(lines[index].startswith('index '), 'unsupported patch metadata')
            index += 1
        require(index + 1 < len(lines), 'truncated patch header')
        old, new = lines[index].strip()[4:], lines[index + 1].strip()[4:]
        require(old.startswith('a/') and new.startswith('b/') and old[2:] == new[2:], 'unsupported patch paths')
        name = old[2:]
        require(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,
                'unsafe patch path')
        require(name in baseline and name not in changed, 'missing/duplicate patch file: ' + name)
        changed.add(name)
        source = baseline[name].decode().splitlines(keepends=True)
        out, position, hunks = [], 0, 0
        index += 2
        while index < len(lines) and not lines[index].startswith('diff --git '):
            header = re.match(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', lines[index])
            require(header is not None, 'missing unified hunk')
            old_start, old_count, new_start, new_count = [int(x) if x is not None else 1 for x in header.groups()]
            target = old_start - 1 if old_count else old_start
            require(position <= target <= len(source), 'invalid hunk location')
            out.extend(source[position:target]); position = target
            require(len(out) == (new_start - 1 if new_count else new_start), 'new hunk location differs')
            index += 1
            consumed = produced = 0
            while index < len(lines) and not lines[index].startswith(('@@ ', 'diff --git ')):
                line = lines[index]
                require(line[:1] in (' ', '+', '-'), 'unsupported or malformed hunk line')
                content = line[1:]
                if line[0] in (' ', '-'):
                    require(position < len(source) and source[position] == content, 'patch baseline/context mismatch')
                    position += 1; consumed += 1
                if line[0] in (' ', '+'):
                    out.append(content); produced += 1
                index += 1
            require((consumed, produced) == (old_count, new_count), 'hunk line counts differ')
            hunks += 1
        require(hunks > 0, 'patch file has no hunks')
        out.extend(source[position:])
        result[name] = ''.join(out).encode()
        require(result[name] != baseline[name], 'patch makes no source change')
    require(changed, 'empty production patch')
    return result


def read_ml_corpus(path):
    data = Path(path).read_bytes()
    position = 0
    def take(size):
        nonlocal position
        require(0 <= size <= 100000 and position + size <= len(data), 'truncated/oversized corpus field')
        value = data[position:position + size]; position += size
        return value
    def number(size):
        return int.from_bytes(take(size), 'big')
    def string():
        try:
            return take(number(2)).decode('ascii')
        except UnicodeError as error:
            raise ReviewError('unexpected non-ASCII fixture identifier') from error
    require(take(4) == b'MLD1', 'ML corpus magic')
    count = number(4); require(0 < count <= 100000, 'ML corpus count')
    cases, ids = [], set()
    for _ in range(count):
        name, identity = string(), string()
        require(identity not in ids, 'duplicate corpus ID'); ids.add(identity)
        fields = [take(number(4)) for _ in range(7)]
        cases.append(dict(parameter=name, id=identity, fields=fields))
    require(position == len(data), 'trailing corpus bytes')
    return cases


def validate_slh_rows(rows, expected, meta):
    require(rows, 'empty SLH measurement')
    cases = [0, 3, 6, 9]
    require(set(expected) == set(cases), 'missing SLH expected outputs')
    previous = None
    for row in rows:
        for key, value in [('variant', meta['side']), ('parameter', meta['parameter']),
                           ('operation', meta['operation']), ('fork', meta['fork']),
                           ('class_source', meta['classes']), ('warmup_calls', meta['warmup_calls']), ('checked', True)]:
            match(value, row[key], 'SLH ' + key)
        require(row['case'] in cases and type(row['case']) is int, 'unexpected measured case')
        match(expected[row['case']], row['output_sha256'], 'SLH output digest')
        identity = tuple(integer(row[k], 0, k) for k in ('round', 'cycle', 'case'))
        require(previous is None or previous < identity, 'duplicate or unordered SLH row')
        previous = identity
        for metric in METRICS:
            integer(row[metric], 0, metric)
        if meta['mode'] == 'bench':
            require(row['wall_ns'] > 0 and (row['thread_cpu_ns'] > 0 or meta.get('allow_zero_cpu', False)) and row['allocated_bytes'] == 0,
                    'invalid SLH timing counters')
        else:
            require(meta['mode'] == 'allocation' and row['allocated_bytes'] > 0
                    and row['wall_ns'] == row['cpu_ns'] == row['thread_cpu_ns'] == 0, 'invalid allocation counters')
    require({r['round'] for r in rows} == set(range(meta['rounds'])), 'SLH round coverage')
    metrics = []
    for round_id in range(meta['rounds']):
        current = [r for r in rows if r['round'] == round_id]
        cycles = sorted({r['cycle'] for r in current})
        require(cycles == list(range(len(cycles))), 'noncontiguous SLH cycles')
        match([(cycle, case) for cycle in cycles for case in cases],
              [(r['cycle'], r['case']) for r in current], 'whole SLH corpus cycles')
        if meta['mode'] == 'bench':
            require(sum(r['wall_ns'] for r in current) >= meta['budget_ns'], 'SLH budget not reached')
            require(sum(r['wall_ns'] for r in current if r['cycle'] < cycles[-1]) < meta['budget_ns'],
                    'SLH process continued beyond stopping rule')
        else:
            require(len(cycles) == 1, 'allocation repeats differ')
        metrics.append(dict(round=round_id, iterations=len(current),
                            **{key: sum(r[key] for r in current) / len(current) for key in METRICS}))
    return dict(rows=rows, rounds=metrics,
                medians={key: statistics.median(r[key] for r in metrics) for key in METRICS})


def slh_command(m, side, *args):
    return [m['java'], *JVM, '-cp', m['drivers'][side] + ':' + m['classes'][side],
            'org.bouncycastle.crypto.signers.slhdsa.SlhDeepProbe', str(args[0]),
            m['fixtures'], str(args[1]), side, *map(str, args[2:])]


def read_slh_corpus(path):
    lines = Path(path).read_text().splitlines()
    require(lines[0] == 'pqc-tenkeys-v1/bouncycastle', 'SLH fixture header')
    cases, seeds = {}, set()
    params = [a+'_'+b+c for a in ('sha2','shake') for b in ('128','192','256') for c in ('f','s')]
    sizes = {'128f':17088,'128s':7856,'192f':35664,'192s':16224,'256f':49856,'256s':29792}
    for line in lines[1:]:
        parts = line.split('\t'); require(len(parts) == 10, 'SLH fixture columns')
        phase, param, index = parts[:3]
        require(param in params and phase in ('warmup','measured') and index.isdecimal(), 'SLH fixture identity')
        identity = (param, phase, int(index)); require(identity not in cases, 'duplicate SLH fixture')
        require(all(re.fullmatch('(?:[0-9a-f]{2})*', value) for value in parts[3:]), 'SLH fixture hex')
        fields = list(map(bytes.fromhex, parts[3:]))
        seed,msg,ctx,rnd,pk,sk,sig = fields; n = int(param.split('_')[1][:3])//8
        require(len(seed)==3*n and len(rnd)==n and len(ctx)<=255 and len(pk)==2*n and len(sk)==4*n
                and sk[2*n:]==pk and len(sig)==sizes[param.split('_')[1]], 'SLH fixture sizes/layout')
        require(seed not in seeds, 'repeated SLH fixture seed'); seeds.add(seed)
        cases[identity] = {'keygen.total':digest(pk+sk),'sign.total':digest(sig),'verify.total':digest(b'\1')}
    expected = {(param,phase,index) for param in params for phase,count in [('warmup',2),('measured',10)] for index in range(count)}
    require(cases.keys()==expected, 'SLH fixture coverage')
    return cases


def verify_slh_prepared(path, upstream):
    m=read_json(path)
    match('bc-slh-deep-prepared-v1',m['schema'],'SLH prepared schema'); match(PIN,m['upstream_commit'],'SLH upstream')
    match(['baseline','candidate'],m['variants'],'SLH variants'); match(JVM,m['jvm_args'],'SLH JVM')
    match({'JAVA_TOOL_OPTIONS':'','JDK_JAVA_OPTIONS':'','_JAVA_OPTIONS':''},m['environment'],'SLH JVM environment')
    params=m['parameters']; require(params and len(params)==len(set(params)), 'SLH parameter duplicates/empty')
    prov=m['provenance']; match(set(m['bound_files']),set(prov['files']),'SLH bound file coverage')
    check_hashes(prov['files']); match(sha(m['java']),prov['java'],'SLH Java')
    sources={}
    for field,seal,suffix in [('sources','sources','.java'),('classes','classes','.class'),('drivers','driver_classes','.class'),('tests','test_classes','.class')]:
        for side in m['variants']:
            files=tree_files(m[field][side],suffix)
            match(tree_hash(files),prov[seal][side],'SLH '+field+' '+side)
            if field=='sources': sources[side]=files
    verify_git_baseline(sources['baseline'],upstream)
    patches=[p for p in m['bound_files'] if Path(p).name=='wots-buffer.patch']; require(len(patches)==1,'SLH patch binding')
    expected=apply_patch_files(sources['baseline'],Path(patches[0]).read_text())
    match(expected,sources['candidate'],'SLH actual candidate from pinned patch')
    changed=sorted(k for k in expected if expected[k]!=sources['baseline'][k])
    require(changed==['core/src/main/java/org/bouncycastle/crypto/signers/slhdsa/'+n for n in ['SLHDSAEngine.java','WotsPlus.java']], 'SLH changed source scope')
    match(changed,m['patch_verification']['changed_files'],'SLH changed source claim')
    for side in m['variants']:
        match({n:digest(sources[side][n]) for n in changed},m['patch_verification'][side+'_hashes'],'SLH source hashes')
    require(prov['classes']['baseline']!=prov['classes']['candidate'],'SLH identical implementation classes')
    fixture=read_slh_corpus(m['fixtures']); logs=Path(path).parent/'checks'; hashes={}
    for side in m['variants']:
        for param in params:
            for field,mode,suffix,ops,identities in [
                ('checks','check','check',TOTALS,[(phase,i) for phase,n in [('warmup',2),('measured',10)] for i in range(n)]),
                ('stage_checks','stages-check','stages',SLH_STAGES,[('measured',i) for i in [0,3,6,9]])]:
                stem=logs/(side+'-'+param+'-'+suffix)
                process=read_process(stem,slh_command(m,side,mode,param)); rows=process['rows']
                match(rows,m[field][side][param],'SLH prepared raw rows')
                match([(phase,i,op) for phase,i in identities for op in ops],[(r['phase'],r['case'],r['operation']) for r in rows],'SLH check coverage/order')
                for row in rows:
                    for key,val in [('variant',side),('parameter',param),('checked',True),('class_source',m['classes'][side])]: match(val,row[key],'SLH checked '+key)
                    require(re.fullmatch('[0-9a-f]{64}',row['output_sha256']) is not None,'SLH output digest format')
                    if field=='checks': match(fixture[(param,row['phase'],row['case'])][row['operation']],row['output_sha256'],'SLH fixture digest')
                hashes[str(stem)]=process['hashes']
                if side=='candidate':
                    strip=lambda r:{k:v for k,v in r.items() if k not in ('variant','class_source')}
                    match(list(map(strip,m[field]['baseline'][param])),list(map(strip,rows)),'SLH cross-variant outputs')
    return m,hashes


def slh_summary(pairs, parameters, operations, forks):
    result=[]
    for param in parameters:
        for op in operations:
            selected=[r for r in pairs if (r['parameter'],r['operation'])==(param,op)]
            require(len(selected)==forks and len({r['fork'] for r in selected})==forks,'SLH pair coverage')
            row=dict(parameter=param,operation=op,forks=forks)
            for key in METRICS:
                ratios=[r[key+'_ratio'] for r in selected]; nonnull=all(v is not None for v in ratios)
                row[key]=dict(baseline=statistics.median(r['baseline']['medians'][key] for r in selected),
                              candidate=statistics.median(r['candidate']['medians'][key] for r in selected),ratios=ratios,
                              median_ratio=statistics.median(ratios) if nonnull else None,
                              min_ratio=min(ratios) if nonnull else None,max_ratio=max(ratios) if nonnull else None,
                              losses=sum(v<1 for v in ratios if v is not None))
            result.append(row)
    return result


def review_slh(path, upstream):
    result=read_json(path); match('bc-slh-deep-results-v1',result['schema'],'SLH results schema')
    plan=result['plan']; raw=Path(result['raw_directory'])
    saved=read_json(raw/'plan.json')
    if 'original_plan' in plan:
        match(saved,plan['original_plan'],'SLH original plan');match(plan,read_json(raw/'resume-plan.json'),'SLH resume plan')
        for key in ['manifest_sha256','prepared','mode','parameters','operations','forks','start','rounds','budget_ms','warmup_cycles','jit_trace']:match(saved[key],plan[key],'SLH unchanged resume '+key)
        require(timestamp(saved['started_at'])<=timestamp(plan['started_at']),'SLH reversed resume timestamps')
    else:match(saved,plan,'SLH saved plan')
    if 'collector' in plan:match(sha(plan['collector']),plan['collector_sha256'],'SLH amended collector seal')
    match('bc-slh-deep-plan-v1',plan['schema'],'SLH plan schema'); match(0,plan['python_optimize'],'SLH assertions')
    match(sha(plan['prepared_manifest']),plan['manifest_sha256'],'SLH manifest seal')
    m,hashes=verify_slh_prepared(plan['prepared_manifest'],upstream); match(m,plan['prepared'],'SLH embedded manifest')
    forks=integer(plan['forks'],2,'forks'); require(forks<=20 and forks%2==0,'SLH unbalanced forks')
    start=integer(plan['start'],0,'start'); rounds=integer(plan['rounds'],1,'rounds'); require(rounds<=20,'SLH rounds bound')
    budget=integer(plan['budget_ms'],1,'budget'); require(budget<=10000,'SLH budget bound')
    warm=integer(plan['warmup_cycles'],1,'warmup cycles'); require(warm<=1000,'SLH warmup bound')
    match(2*warm,plan['warmup_calls'],'SLH warmup calls'); match([0,3,6,9],plan['measured_cases'],'SLH cases')
    parameters,operations=plan['parameters'],plan['operations']
    require(parameters and len(parameters)==len(set(parameters)) and set(parameters)<=set(m['parameters']),'SLH selected parameters')
    require(operations and len(operations)==len(set(operations)) and set(operations)<=set(TOTALS+SLH_STAGES),'SLH selected operations')
    previous=timestamp(saved['started_at']); pairs=[]; stems=[]
    for fork in range(start,start+forks):
        for pi,param in enumerate(parameters):
            for oi,op in enumerate(operations):
                order=['baseline','candidate'] if (fork+pi+oi)%2==0 else ['candidate','baseline']
                pair=dict(fork=fork,parameter=param,operation=op,order=order)
                expected={r['case']:r['output_sha256'] for r in m['checks' if op in TOTALS else 'stage_checks']['baseline'][param] if r['operation']==op and r['phase']=='measured' and r['case'] in [0,3,6,9]}
                for side in order:
                    stem=raw/(f'{fork:04d}-{param}-{op}-{side}'); stems.append(stem.name)
                    command=slh_command(m,side,plan['mode'],param,op,fork,rounds,budget,warm)
                    if plan['jit_trace']: command.insert(1,'-Xlog:jit+compilation=debug:file='+str(stem)+'.jit.log:uptimemillis,level,tags')
                    process=read_process(stem,command); require(previous<=process['start'],'overlapping/reordered SLH processes'); previous=process['finish']
                    hashes[str(stem)]=process['hashes']
                    if plan['jit_trace']: hashes[str(stem)+'.jit.log']=sha(str(stem)+'.jit.log')
                    pair[side]=validate_slh_rows(process['rows'],expected,dict(side=side,parameter=param,operation=op,fork=fork,rounds=rounds,budget_ns=budget*1000000,mode=plan['mode'],warmup_calls=2*warm,classes=m['classes'][side],allow_zero_cpu='collector' in plan))
                    match(pair[side],read_json(str(stem)+'.metrics.json'),'SLH process metrics')
                for key in METRICS:
                    a,b=pair['baseline']['medians'][key],pair['candidate']['medians'][key]; pair[key+'_ratio']=a/b if b else None
                match(pair,read_json(raw/f'{fork:04d}-{param}-{op}.pair.json'),'SLH pair claim'); pairs.append(pair)
    require(previous<=timestamp(result['finished_at']),'SLH result precedes final process')
    match(set(stems),{p.name[:-len('.stdout.txt')] for p in raw.glob('*.stdout.txt')},'SLH raw process coverage')
    match(pairs,result['process_pairs'],'SLH all pair claims')
    summary=slh_summary(pairs,parameters,operations,forks); match(summary,result['summary'],'SLH summary claims')
    return dict(schema='bc-deep-independent-review-v1',kind='slh',complete=True,result_sha256=sha(path),manifest_sha256=sha(plan['prepared_manifest']),
                upstream=PIN,processes=len(stems),samples=sum(len(r[s]['rows']) for r in pairs for s in ['baseline','candidate']),
                raw_hashes=hashes,summary=summary,limitations=['Retained classes are hash-bound, not independently recompiled.','Stage digests use sealed cross-variant preparation outputs; whole-operation digests are independently derived from fixture bytes.','Four measured keys repeat in complete cycles; stage probes overlap and cannot be summed.'])


def java_shuffle(values, seed):
    values=list(values); state=(seed^0x5DEECE66D)&((1<<48)-1)
    def next_bits(bits):
        nonlocal state
        state=(state*0x5DEECE66D+0xB)&((1<<48)-1)
        return state>>(48-bits)
    def next_int(bound):
        if bound&(bound-1)==0: return (bound*next_bits(31))>>31
        while True:
            bits=next_bits(31); val=bits%bound
            if bits-val+(bound-1)<(1<<31): return val
    for i in range(len(values),1,-1):
        j=next_int(i); values[i-1],values[j]=values[j],values[i-1]
    return values


def ml_pair(baseline,candidate):
    require(baseline and len(baseline)==len(candidate),'ML matched sample count')
    match([r['case_id'] for r in baseline],[r['case_id'] for r in candidate],'ML matched sample order')
    result={}
    for key in ('wall_ns','cpu_ns','allocated_bytes'):
        a=[integer(r[key],0 if key=='allocated_bytes' else 1,key) for r in baseline]
        b=[integer(r[key],0 if key=='allocated_bytes' else 1,key) for r in candidate]
        ratios=[x/y if y else None for x,y in zip(a,b)]
        result[key]=dict(baseline_sum=sum(a),candidate_sum=sum(b),ratio=sum(a)/sum(b) if sum(b) else None,
                         per_key_ratios=ratios,losses=sum(x<1 for x in ratios if x is not None),
                         saved_per_call=(sum(a)-sum(b))/len(a))
    return result

ML_PARAMS=['ml_dsa_44','ml_dsa_65','ml_dsa_87']
ML_VARIANTS=['baseline','matrix','gamma','combined']
ML_PACKAGE='core/src/main/java/org/bouncycastle/crypto/signers/mldsa/'


def hash_map(mapping):
    return digest(json.dumps(mapping,sort_keys=True,separators=(',',':')).encode())


def method_region(content, signature):
    start=content.index(signature); opening=content.index(b'{',start); depth=1; end=opening+1
    while depth:
        require(end<len(content),'unterminated Java method')
        depth+=(content[end:end+1]==b'{')-(content[end:end+1]==b'}');end+=1
    return start,end


def restore_method(content, baseline, signature):
    start,end=method_region(content,signature); old_start,old_end=method_region(baseline,signature)
    return content[:start]+baseline[old_start:old_end]+content[end:]


def ml_source_variants(baseline,patch):
    combined=apply_patch_files(baseline,patch); matrix=dict(combined); gamma=dict(combined)
    vec=ML_PACKAGE+'PolyVec.java'; mat=ML_PACKAGE+'PolyVecMatrix.java'
    matrix[vec]=restore_method(combined[vec],baseline[vec],b'    public void uniformGamma1(')
    gamma[vec]=restore_method(combined[vec],baseline[vec],b'    void uniformBlocks(')
    gamma[mat]=baseline[mat]
    return dict(baseline=baseline,matrix=matrix,gamma=gamma,combined=combined)


def ml_derive(label,length):
    return b''.join(hashlib.sha256(('bc-ml-deep-v1/'+label+'/'+str(i)).encode()).digest()
                    for i in range((length+31)//32))[:length]


def verify_ml_confirmation(m,workspace):
    match(['baseline','combined'],m['measurement_variants'],'ML confirmation variants');match(6,m['measurement_rounds'],'ML confirmation rounds')
    parent_path=Path(m['variants']['baseline']['classes']).parent/'manifest-screen-v7.json'
    match(sha(parent_path),m['confirmation_parent_manifest_sha256'],'ML confirmation parent seal')
    parent=read_json(parent_path);original={k:v for k,v in m.items() if k not in ['measurement_variants','measurement_rounds','measurement_protocol','confirmation_parent_manifest_sha256']}
    require(set(parent['inputs'])<set(m['inputs']),'ML confirmation missing additive file bindings')
    for name,value in parent['inputs'].items():match(value,m['inputs'][name],'ML frozen input binding')
    original['inputs']=parent['inputs'];match(parent,original,'ML confirmation preserves entire prior manifest')
    protocol_path=Path(m['measurement_protocol']['path']);match(sha(protocol_path),m['measurement_protocol']['sha256'],'ML confirmation protocol seal')
    protocol=read_json(protocol_path)
    expected=dict(schema='bc-ml-deep-confirm-protocol-v1',variants=['baseline','combined'],rounds=6,fresh_jvms=72,
                  measured_keys_per_batch=128,warmup_calls_per_batch=1000,warmup_keys_per_parameter=32,warmup_measurement_seed_overlap=False,
                  keydecode_included=False,caller_copies_included=False,
                  timed_scope='fresh signer/init/message update and sign or verify; same frozen MLDeep.java',
                  primary_resource='mean allocated bytes per call, paired identical keys and rounds',
                  primary_wall_ratio='sum baseline wall ns / sum combined wall ns',
                  resource_target='at least 20% mean allocation reduction in each parameter/operation cell',
                  latency_review_trigger='aggregate wall ratio below 0.97 and at least four of six round ratios below 0.97',
                  claims='resource confirmation only; retain every loss and round; no broad speed claim',
                  jobs=ml_plan(6,False,False,['baseline','combined']))
    match(expected,protocol,'ML exact confirmation protocol')
    expected_added={'libs/bouncycastle/experiments/ml-deep-confirm/'+n for n in ['collect.py','seal.py','summarize.py']}
    expected_added.add(protocol_path.relative_to(Path(workspace).resolve()).as_posix())
    match(expected_added,set(m['inputs'])-set(parent['inputs']),'ML additive bound input coverage')
    return protocol


def verify_ml_prepared(path,workspace,upstream):
    m=read_json(path); match(PIN,m['upstream'],'ML upstream'); match(set(ML_VARIANTS),set(m['variants']),'ML variants')
    match({'JAVA_TOOL_OPTIONS':'','JDK_JAVA_OPTIONS':'','_JAVA_OPTIONS':''},m['environment'],'ML JVM environment')
    check_hashes(m['inputs'],workspace);match(sha(m['java']),m['java_sha256'],'ML Java')
    if 'measurement_variants' in m:verify_ml_confirmation(m,workspace)
    sources={}; binary_hashes={}
    for side,info in list(m['variants'].items())+[(s+'-profile',i) for s,i in m['profiles'].items()]:
        classes=Path(info['classes']); files=tree_files(classes,'.class'); binary_hashes[side]=hash_map({n:digest(v) for n,v in files.items()})
        match({n:digest(v) for n,v in files.items()},info['binaries'],'ML '+side+' binary tree')
        source=tree_files(classes.with_name(classes.name+'-src'),'.java'); sources[side]=source
        match({n:digest(v) for n,v in source.items()},info['source'],'ML '+side+' source tree')
        match(dict(operation_checks=432,negative_checks=288,inputs_preserved=True),info['correctness'],'ML correctness coverage')
        log=classes.parent/(side+'-check.log' if side.endswith('-profile') else side+'-correctness.log')
        output=log.read_text().splitlines();require(output and output[0].startswith('$ '),'ML correctness command log')
        match(info['correctness'],strict_json('\n'.join(output[1:])),'ML correctness raw log')
    verify_git_baseline(sources['baseline'],upstream)
    patches=[p for p in m['inputs'] if p.endswith('/sampling-buffers.patch')];require(len(patches)==1,'ML production patch')
    expected=ml_source_variants(sources['baseline'],(Path(workspace)/patches[0]).read_text())
    for side in ML_VARIANTS:
        match(expected[side],sources[side],'ML independently reconstructed '+side)
        changed=sorted(n for n in expected[side] if expected[side][n]!=sources['baseline'][n])
        match(changed,sorted(m['variants'][side]['changed_source_files']),'ML changed source scope')
        gate=m['variants'][side]['gate'];integer(gate['checks'],100,'ML gate checks')
        match(side in ('matrix','combined'),gate['matrix_shared'],'ML matrix gate mode')
        match(side in ('gamma','combined'),gate['gamma_shared'],'ML gamma gate mode')
        lines=(Path(m['variants'][side]['classes']).parent/(side+'-gate.log')).read_text().splitlines()
        require(lines[0].startswith('$ '),'ML gate command log');match(gate,strict_json('\n'.join(lines[1:])),'ML raw resource gate')
    require(len({tree_hash(expected[s]) for s in ML_VARIANTS})==4 and len({binary_hashes[s] for s in ML_VARIANTS})==4,'ML variants not distinct')
    profile_source=Path(workspace)/'libs/bouncycastle/experiments/ml-deep/StageProfile.java'
    for side in ['baseline','combined']:
        profile=dict(sources[side+'-profile']);stage=profile.pop(ML_PACKAGE+'StageProfile.java')
        match(profile_source.read_bytes(),stage,'ML profile helper')
        name=ML_PACKAGE+'MLDSAEngine.java'; content=profile[name]
        marks=re.findall(rb'^ *StageProfile\.mark\("[A-Za-z0-9_]+"\);\n',content,re.MULTILINE);require(len(marks)==23,'ML profile instrumentation count')
        profile[name]=re.sub(rb'^ *StageProfile\.mark\("[A-Za-z0-9_]+"\);\n',b'',content,flags=re.MULTILINE)
        match(expected[side],profile,'ML instrumented build changes only marks/helper')
    corpora={};allseeds=set();allkeys=set()
    for label,count in [('warmup',32),('measured',128)]:
        info=m['corpora'][label];match(count,info['keys_per_parameter'],'ML corpus count');match(sha(info['path']),info['sha256'],'ML corpus hash')
        rows=read_ml_corpus(info['path']);wanted=[(p,label+'/'+p+'/'+str(i)) for p in ML_PARAMS for i in range(count)]
        match(wanted,[(r['parameter'],r['id']) for r in rows],'ML corpus coverage/order')
        for row in rows:
            seed,msg,ctx,rnd,pk,sk,sig=row['fields'];i=int(row['id'].split('/')[-1])
            for name,value,length in [('seed',seed,32),('message',msg,[0,1,32,256,1024,4096][i%6]),('context',ctx,[0,1,255][i%3]),('random',rnd,0 if i%2==0 else 32)]:
                match(ml_derive(row['id']+'/'+name,length),value,'ML derived '+name)
            mode=row['parameter'].split('_')[-1];sizes={'44':(1312,2560,2420),'65':(1952,4032,3309),'87':(2592,4896,4627)}
            match(sizes[mode],(len(pk),len(sk),len(sig)),'ML key/signature sizes')
            require(seed not in allseeds and pk not in allkeys,'ML repeated warmup/measured key');allseeds.add(seed);allkeys.add(pk)
        corpora[label]=rows
    correctness=Path(m['variants']['baseline']['classes']).parent/'correctness.bin'
    match(sha(correctness),m['correctness_corpus_sha256'],'ML correctness corpus')
    cases=read_ml_corpus(correctness)
    correct_params=ML_PARAMS+[p+'_with_sha512' for p in ML_PARAMS]
    match([(p,'correctness/'+p+'/'+str(i)) for p in correct_params for i in range(12)],[(r['parameter'],r['id']) for r in cases],'ML correctness fixture coverage')
    return m,corpora


def ml_output(row,operation):
    seed,msg,ctx,rnd,pk,sk,sig=row['fields']
    if operation=='sign':return digest(sig)
    if operation=='verify':return digest(b'\1')
    if operation=='keygen':return digest(pk+sk)
    k,l={'ml_dsa_44':(4,4),'ml_dsa_65':(6,5),'ml_dsa_87':(8,7)}[row['parameter']]
    coefficients=[]
    if operation=='matrix_sample':
        for i in range(k):
            for j in range(l):
                xof=hashlib.shake_128(seed+struct.pack('<H',(i<<8)+j));length=840
                while True:
                    stream=xof.digest(length)
                    values=[int.from_bytes(stream[p:p+3],'little')&0x7fffff for p in range(0,len(stream)-2,3)]
                    accepted=[v for v in values if v<8380417]
                    if len(accepted)>=256:break
                    length+=168
                coefficients.extend(accepted[:256])
    elif operation=='gamma_sample':
        bits=18 if l==4 else 20;gamma=1<<(bits-1)
        for j in range(l):
            stream=hashlib.shake_256(seed+seed+struct.pack('<H',l*42+j)).digest(256*bits//8)
            packed=int.from_bytes(stream,'little');mask=(1<<bits)-1
            coefficients.extend(gamma-((packed>>(i*bits))&mask) for i in range(256))
    else:raise ReviewError('unknown ML operation')
    return digest(b''.join(struct.pack('>i',v) for v in coefficients))


def validate_ml_batch(data,cases,operation,round_id,output_digests=None):
    match('bc-ml-deep-batch-v1',data['schema'],'ML batch schema');match(operation,data['operation'],'ML operation')
    for name,val in [('keydecode_included',False),('caller_copies_included',False),('cpu_scope','calling_thread'),('driver_includes_checks',True)]:match(val,data[name],'ML '+name)
    match(1000,data['warmup']['iterations'],'ML fixed warmup');integer(data['warmup']['wall_ns'],1,'ML warmup time')
    for field in ['driver_process_cpu_ns','driver_gc_count','driver_gc_ms','compilation_ms_including_warmup']:integer(data[field],0,field)
    cases=[c for c in cases if c['parameter']==data['parameter']];require(len(cases)==128,'ML measured corpus count')
    expected=java_shuffle(cases,92841+round_id);match([r['id'] for r in expected],[r['case_id'] for r in data['samples']],'ML shuffled sample order')
    for row,case in zip(data['samples'],expected):
        for metric in ('wall_ns','cpu_ns','allocated_bytes'):integer(row[metric],0 if metric=='allocated_bytes' else 1,metric)
        match(True,row['checked'],'ML checked');match(True,row['inputs_unchanged'],'ML input integrity')
        expected_digest=ml_output(case,operation) if output_digests is None else output_digests[(case['id'],operation)]
        match(expected_digest,row['output_sha256'],'ML independently derived output digest')
    return data['samples']


def ml_plan(rounds,profile,sampler,variants=None):
    variants=ML_VARIANTS if variants is None else variants
    require(variants in (ML_VARIANTS,['baseline','combined']),'ML unsupported measurement variants')
    import random
    require(type(profile)is bool and type(sampler)is bool and not(profile and sampler),'ML mode')
    integer(rounds,1,'ML rounds');require(rounds%2==0 or(sampler and rounds==1),'ML balanced rounds')
    if profile:return [[0,p,o,v] for p in ML_PARAMS for o in ['sign','verify'] for v in ['baseline','combined']]
    cells=[(p,o) for p in ML_PARAMS for o in (['matrix_sample','gamma_sample'] if sampler else ['sign','verify'])]
    random.Random(384710).shuffle(cells);jobs=[]
    for rnd in range(rounds):
        for i,(p,o) in enumerate(cells):
            order=variants.copy();random.Random(384711+i+rnd//2).shuffle(order)
            if rnd%2:order.reverse()
            jobs.extend([rnd,p,o,v] for v in order)
    return jobs


def ml_independent_summary(batches,rounds,operations,variants=ML_VARIANTS):
    summary=[]
    for param in ML_PARAMS:
        for op in operations:
            for side in variants[1:]:
                pairs=[];baseline=[];candidate=[]
                for rnd in range(rounds):
                    a=batches[(rnd,param,op,'baseline')]['samples'];b=batches[(rnd,param,op,side)]['samples']
                    metrics=ml_pair(a,b);pairs.append(dict(round=rnd,metrics=metrics));baseline+=a;candidate+=b
                total=ml_pair(baseline,candidate)
                summary.append(dict(parameter=param,operation=op,variant=side,paired_rounds=rounds,samples=len(baseline),totals=total,per_round=pairs))
    return summary


def ml_claim_metrics(before,after):
    values=ml_pair(before,after);wall=values['wall_ns'];cpu=values['cpu_ns'];alloc=values['allocated_bytes'];ratios=wall['per_key_ratios']
    return dict(count=len(before),original_wall_ns_sum=wall['baseline_sum'],changed_wall_ns_sum=wall['candidate_sum'],wall_speedup=wall['ratio'],
                original_cpu_ns_sum=cpu['baseline_sum'],changed_cpu_ns_sum=cpu['candidate_sum'],thread_cpu_speedup=cpu['ratio'],
                original_alloc_bytes_sum=alloc['baseline_sum'],changed_alloc_bytes_sum=alloc['candidate_sum'],allocated_bytes_saved_per_call=alloc['saved_per_call'],
                losses=wall['losses'],ratio_median=statistics.median(ratios),ratio_min=min(ratios),ratio_max=max(ratios))


def ml_claim_summary(batches,execution,path,variants=ML_VARIANTS):
    cells=[]
    for param,op in sorted({key[1:3] for key in batches}):
        for side in variants[1:]:
            before=[];after=[];per_round=[];per_key=[]
            for rnd in range(execution['rounds']):
                a=batches[(rnd,param,op,'baseline')]['samples'];b=batches[(rnd,param,op,side)]['samples']
                per_round.append(dict(round=rnd,**ml_claim_metrics(a,b)))
                a=sorted(a,key=lambda r:r['case_id']);b=sorted(b,key=lambda r:r['case_id'])
                before+=a;after+=b
                per_key.extend(dict(round=rnd,case_id=x['case_id'],ratio=x['wall_ns']/y['wall_ns']) for x,y in zip(a,b))
            cells.append(dict(parameter=param,operation=op,variant=side,paired_rounds=execution['rounds'],**ml_claim_metrics(before,after),per_round=per_round,per_key_ratios=per_key))
    return dict(schema='bc-ml-deep-confirm-summary-v1' if variants==['baseline','combined'] else 'bc-ml-deep-summary-v1',execution_sha256=sha(path),sampler_only=execution['sampler_only'],
                primary='sum(original wall ns) / sum(changed wall ns), identical keys and rounds',cells=cells)


def review_ml(path,workspace,upstream):
    execution=read_json(path);match('bc-ml-deep-execution-v1',execution['schema'],'ML execution schema');directory=Path(path).parent
    manifest=directory/'manifest.json';match(sha(manifest),execution['manifest_sha256'],'ML manifest seal')
    m,corpora=verify_ml_prepared(manifest,workspace,upstream)
    match(0,execution['python_optimization'],'ML assertions');require(isinstance(execution['python_version'],str),'ML Python provenance')
    variants=m.get('measurement_variants',ML_VARIANTS)
    if 'measurement_variants' in m:
        match(['baseline','combined'],variants,'ML confirmation variant declaration')
        match(variants,execution['measurement_variants'],'ML execution variant declaration')
        require(execution['rounds']==6 and not execution['profile_only'] and not execution['sampler_only'],'ML confirmation scope')
        original_path=directory/'collector-execution.json';match(sha(original_path),execution['collector_execution_sha256'],'ML original collector execution seal')
        original_execution=read_json(original_path)
        match({**original_execution,'measurement_variants':variants,'measurement_protocol_sha256':m['measurement_protocol']['sha256'],'collector_execution_sha256':sha(original_path)},execution,'ML wrapper changes only declaration fields')
    jobs=ml_plan(execution['rounds'],execution['profile_only'],execution['sampler_only'],variants);match(jobs,read_json(directory/'plan.json'),'ML job plan')
    require(len(execution['runs'])==len(jobs),'ML missing/extra process')
    previous=timestamp(execution['started_at']);batches={};hashes={};profile=execution['profile_only']
    output_digests={}
    if not profile:
        for op in sorted({job[2] for job in jobs}):
            for case in corpora['measured']:output_digests[(case['id'],op)]=ml_output(case,op)
    for index,(job,record) in enumerate(zip(jobs,execution['runs'])):
        rnd,param,op,side=job;info=m['profiles' if profile else 'variants'][side]
        for key,val in [('index',index),('round',rnd),('fork',rnd),('parameter',param),('operation',op),('variant',side),('exit_code',0)]:match(val,record[key],'ML process '+key)
        command=[m['java'],*JVM,'-cp',info['classes'],'org.bouncycastle.crypto.signers.mldsa.MLDeep']
        command+=['profile',m['corpora']['measured']['path'],param,op] if profile else ['bench',m['corpora']['warmup']['path'],m['corpora']['measured']['path'],param,op,str(92841+rnd)]
        match(command,record['argv'],'ML actual command')
        start,finish=timestamp(record['started_at']),timestamp(record['completed_at']);require(previous<=start<=finish,'ML process order/overlap');previous=finish
        names={'stdout':f'{index:03d}.stdout.json','raw':f'{index:03d}.json','stderr':f'{index:03d}.stderr'}
        for key,name in names.items():
            if key!='stderr':match(name,record[key],'ML raw filename')
            actual=sha(directory/name);match(actual,record[key+'_sha256'],'ML raw '+key+' binding');hashes[name]=actual
        original=read_json(directory/names['stdout']);enriched=read_json(directory/names['raw'])
        match(param,original['parameter'],'ML raw parameter');match(op,original['operation'],'ML raw operation')
        additions=dict(variant=side,fork=rnd,round=rnd,corpus_sha256=m['corpora']['measured']['sha256'],warmup_corpus_sha256=m['corpora']['warmup']['sha256'],source_sha256=hash_map(info['source']),class_tree_sha256=hash_map(info['binaries']),java_version=m['java_version'],jvm_args=JVM)
        require(not(original.keys()&additions.keys()),'ML stdout already contains collector fields');match({**original,**additions},enriched,'ML enriched raw equals original plus provenance')
        if not profile:
            require(start<=timestamp(original['started_at'])<=timestamp(original['completed_at'])<=finish,'ML inner timestamps')
            validate_ml_batch(original,corpora['measured'],op,rnd,output_digests)
        else:
            match('bc-ml-deep-profile-v1',original['schema'],'ML profile schema');match(128,original['calls'],'ML profile count');match(True,original['instrumented'],'ML instrumented flag')
            names=[r['stage'] for r in original['stages']];require(names and len(names)==len(set(names)),'ML profile stage duplicates')
            sign_stages=['public_setup_message_hash','secret_decode_setup','rhoPrime_hash','matrix_sample','secret_ntt','gamma_sample','y_copy_ntt','matrix_product','matrix_reduce_inverse','decomposition_challenge','response_rejection','hint_rejection','signature_encode']
            verify_stages=['public_setup_message_hash','signature_decode_norm','public_key_decode','challenge_sample','matrix_sample','z_ntt','matrix_product','challenge_t1_ntt','challenge_product_subtract','inverse_canonicalize','hint_encode','challenge_hash_compare']
            match(sign_stages if op=='sign' else verify_stages,names,'ML profile exact stage coverage/order')
            entries={}
            for row in original['stages']:
                require(set(row)=={'stage','wall_ns','entries'},'ML profile row fields')
                integer(row['wall_ns'],1,'ML profile wall');entries[row['stage']]=integer(row['entries'],128,'ML profile entries')
            if op=='verify':require(set(entries.values())=={128},'ML verification stage entries')
            else:
                require(all(entries[n]==128 for n in sign_stages[:5]+['signature_encode']),'ML fixed sign stage entries')
                require(all(entries[n]==entries['gamma_sample'] for n in sign_stages[5:11]),'ML rejection-loop stage entries')
                require(128<=entries['hint_rejection']<=entries['gamma_sample'],'ML hint stage entries')
        batches[(rnd,param,op,side)]=original
    require(previous<=timestamp(execution['completed_at']),'ML incomplete execution chronology')
    match({f'{i:03d}.stdout.json' for i in range(len(jobs))},{p.name for p in directory.glob('*.stdout.json')},'ML stdout coverage')
    operations=['matrix_sample','gamma_sample'] if execution['sampler_only'] else ['sign','verify']
    summary=[] if profile else ml_independent_summary(batches,execution['rounds'],operations,variants)
    if not profile:match(ml_claim_summary(batches,execution,path,variants),read_json(directory/'summary.json'),'ML all summary claims')
    return dict(schema='bc-deep-independent-review-v1',kind='ml-profile' if profile else 'ml',complete=True,result_sha256=sha(path),manifest_sha256=sha(manifest),upstream=PIN,
                processes=len(jobs),samples=128*len(jobs),raw_hashes=hashes,summary=summary,
                confirmation_acceptance=[dict(parameter=r['parameter'],operation=r['operation'],allocation_reduction=1-r['totals']['allocated_bytes']['candidate_sum']/r['totals']['allocated_bytes']['baseline_sum'],resource_target_met=r['totals']['allocated_bytes']['candidate_sum']<=0.8*r['totals']['allocated_bytes']['baseline_sum'],latency_review_trigger=r['totals']['wall_ns']['ratio']<0.97 and sum(p['metrics']['wall_ns']['ratio']<0.97 for p in r['per_round'])>=4) for r in summary] if variants==['baseline','combined'] else [],
                limitations=['Retained classes are hash-bound, not independently recompiled; preparation text logs lack standalone exit-status records.',
                             'Calling-thread CPU excludes JVM helper threads; per-call correctness checks occur outside operation clocks and can affect later GC/JIT.',
                             'Instrumented profile mode reuses the measured corpus for warmup and emits no per-call digests; treat it only as stage diagnostics.' if profile else 'Fixed 1000-call warmup is identical across variants but does not prove steady-state JIT convergence.'])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', required=True, type=Path)
    parser.add_argument('--upstream', required=True, type=Path)
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result=read_json(args.result)
    if result.get('schema')=='bc-slh-deep-results-v1': report=review_slh(args.result,args.upstream)
    elif result.get('schema')=='bc-slh-deep-prepared-v1':
        m,hashes=verify_slh_prepared(args.result,args.upstream)
        report=dict(schema='bc-deep-preparation-review-v1',complete=True,manifest_sha256=sha(args.result),raw_hashes=hashes,parameters=m['parameters'])
    elif result.get('schema')=='bc-ml-deep-execution-v1': report=review_ml(args.result,args.workspace,args.upstream)
    elif result.get('upstream')==PIN and 'corpora' in result:
        m,corpora=verify_ml_prepared(args.result,args.workspace,args.upstream)
        report=dict(schema='bc-deep-preparation-review-v1',complete=True,manifest_sha256=sha(args.result),corpus_counts={k:len(v) for k,v in corpora.items()})
    else: raise ReviewError('unsupported evidence schema')
    report['checker_sha256']=sha(__file__)
    report['checked_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['input_path']=str(args.result.resolve())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    with args.out.open('x') as stream: json.dump(report,stream,indent=2,allow_nan=False); stream.write('\n')
    print(args.out)


if __name__ == '__main__':
    try:
        main()
    except (ReviewError, KeyError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit('REJECTED: ' + str(error))
