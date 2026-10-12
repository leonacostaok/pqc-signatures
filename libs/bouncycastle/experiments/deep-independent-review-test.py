#!/usr/bin/env python3
"""Small synthetic acceptance and rejection cases; never launches a JVM."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('deep_review', HERE / 'deep-independent-review.py')
if spec is None or spec.loader is None:
    raise RuntimeError('checker module unavailable')
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class EvidenceChecks(unittest.TestCase):
    def setUp(self):
        base = HERE.parent / 'build' / 'deep-review-tests'
        base.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=base)
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_json_rejects_ambiguous_or_nonfinite_claims(self):
        path = self.root / 'input.json'
        for text in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":1e999}', '{"x":Infinity}']:
            path.write_text(text)
            with self.subTest(text=text), self.assertRaises(review.ReviewError):
                review.read_json(path)
        path.write_text('{"x":1}')
        self.assertEqual(review.read_json(path), {'x': 1})

    def test_patch_reconstruction_rejects_wrong_baseline_and_missing_edits(self):
        baseline = {'core/A.java': b'a\nb\nc\n', 'core/B.java': b'unchanged\n'}
        patch = ('diff --git a/core/A.java b/core/A.java\nindex aaaaaaa..bbbbbbb 100644\n'
                 '--- a/core/A.java\n+++ b/core/A.java\n@@ -1,3 +1,4 @@\n a\n-b\n+B\n+extra\n c\n')
        expected = {'core/A.java': b'a\nB\nextra\nc\n', 'core/B.java': b'unchanged\n'}
        self.assertEqual(review.apply_patch_files(baseline, patch), expected)
        with self.assertRaises(review.ReviewError):
            review.apply_patch_files({**baseline, 'core/A.java': b'wrong\nb\nc\n'}, patch)
        with self.assertRaises(review.ReviewError):
            review.apply_patch_files(baseline, patch.replace('core/A.java', '../A.java'))
        with self.assertRaises(review.ReviewError):
            review.match(expected, baseline, 'actual production sources')

    def test_corpus_parser_rejects_truncation_duplicates_and_trailing_bytes(self):
        def utf(value):
            data = value.encode('ascii')
            return struct.pack('>H', len(data)) + data
        fields = [b's' * 32, b'm', b'', b'r' * 32, b'p', b'k', b'sig']
        row = utf('ml_dsa_44') + utf('measured/ml_dsa_44/0')
        row += b''.join(struct.pack('>I', len(value)) + value for value in fields)
        data = b'MLD1' + struct.pack('>I', 1) + row
        path = self.root / 'corpus.bin'
        path.write_bytes(data)
        actual = review.read_ml_corpus(path)
        self.assertEqual(actual[0]['id'], 'measured/ml_dsa_44/0')
        self.assertEqual(actual[0]['fields'], fields)
        for invalid in [data[:-1], data + b'x', b'MLD1' + struct.pack('>I', 2) + row + row]:
            path.write_bytes(invalid)
            with self.assertRaises(review.ReviewError):
                review.read_ml_corpus(path)

    def test_process_binds_command_exit_and_chronology(self):
        stem = self.root / 'run'
        command = {'command': ['java', 'Driver'], 'cwd': None, 'started_at': '2026-01-01T00:00:00+00:00'}
        status = {'exit_code': 0, 'finished_at': '2026-01-01T00:00:01+00:00'}
        Path(str(stem) + '.command.json').write_text(json.dumps(command))
        status_path = Path(str(stem) + '.status.json')
        status_path.write_text(json.dumps(status))
        Path(str(stem) + '.stdout.txt').write_text('{"ok":true}\n')
        Path(str(stem) + '.stderr.txt').write_text('')
        self.assertEqual(review.read_process(stem, ['java', 'Driver'])['rows'], [{'ok': True}])
        for invalid in [{**status, 'exit_code': 1}, {**status, 'exit_code': False},
                        {**status, 'finished_at': '2025-01-01T00:00:00+00:00'}]:
            status_path.write_text(json.dumps(invalid))
            with self.assertRaises(review.ReviewError):
                review.read_process(stem, ['java', 'Driver'])
        status_path.write_text(json.dumps(status))
        with self.assertRaises(review.ReviewError):
            review.read_process(stem, ['java', 'OtherDriver'])

    def test_slh_complete_cycles_and_metrics_fail_closed(self):
        expected = {case: str(case) * 64 for case in (0, 3, 6, 9)}
        meta = dict(side='baseline', parameter='sha2_128f', operation='verify.total', fork=0,
                    rounds=1, budget_ns=1000000, mode='bench', warmup_calls=20, classes='/sealed/classes')
        rows = [dict(variant='baseline', parameter='sha2_128f', operation='verify.total', fork=0,
                     round=0, cycle=cycle, case=case, warmup_calls=20, wall_ns=200000,
                     cpu_ns=180000, thread_cpu_ns=170000, allocated_bytes=0,
                     output_sha256=expected[case], class_source='/sealed/classes', checked=True)
                for cycle in range(2) for case in (0, 3, 6, 9)]
        result = review.validate_slh_rows(rows, expected, meta)
        self.assertEqual(result['medians']['wall_ns'], 200000)
        invalids = [rows[:-1], rows + [rows[0]], [dict(r, checked=False) for r in rows],
                    [dict(r, wall_ns=True) for r in rows], [dict(r, output_sha256='f' * 64) for r in rows],
                    [rows[1], rows[0], *rows[2:]], rows + [dict(r, cycle=2) for r in rows[:4]]]
        for invalid in invalids:
            with self.assertRaises(review.ReviewError):
                review.validate_slh_rows(invalid, expected, meta)
        with self.assertRaises(review.ReviewError):
            review.match(result, {**result, 'medians': {**result['medians'], 'wall_ns': 199000}}, 'claim')

    def test_slh_summary_recomputes_pairs_without_ratio_averaging(self):
        pairs = []
        for fork, (a, b) in enumerate([(12, 3), (6, 3)]):
            pairs.append(dict(fork=fork, parameter='sha2_128f', operation='sign.total',
                              baseline={'medians': {key: a for key in review.METRICS}},
                              candidate={'medians': {key: b for key in review.METRICS}},
                              **{key+'_ratio': a/b for key in review.METRICS}))
        out = review.slh_summary(pairs, ['sha2_128f'], ['sign.total'], 2)
        self.assertEqual(out[0]['wall_ns']['ratios'], [4.0, 2.0])
        self.assertEqual(out[0]['wall_ns']['median_ratio'], 3.0)
        with self.assertRaises(review.ReviewError):
            review.slh_summary(pairs[:-1], ['sha2_128f'], ['sign.total'], 2)

    def test_java_shuffle_and_ml_sum_ratios(self):
        self.assertEqual(review.java_shuffle(list(range(5)), 0), [4, 2, 1, 3, 0])
        baseline = [dict(case_id=str(i), wall_ns=w, cpu_ns=w, allocated_bytes=w) for i,w in enumerate([100,20])]
        candidate = [dict(case_id=str(i), wall_ns=w, cpu_ns=w, allocated_bytes=w) for i,w in enumerate([50,20])]
        result = review.ml_pair(baseline, candidate)
        self.assertAlmostEqual(result['wall_ns']['ratio'], 120/70)
        self.assertEqual(result['wall_ns']['per_key_ratios'], [2.0,1.0])
        with self.assertRaises(review.ReviewError):
            review.ml_pair(baseline, candidate[::-1])

    def test_ml_samples_reject_wrong_outputs_types_order_and_checks(self):
        cases=[dict(id='measured/ml_dsa_44/'+str(i), parameter='ml_dsa_44', fields=[bytes([i])*32,b'',b'',b'',b'p',b'k',bytes([i])]) for i in range(128)]
        ordered=review.java_shuffle(cases,92841)
        data=dict(schema='bc-ml-deep-batch-v1',parameter='ml_dsa_44',operation='sign',keydecode_included=False,caller_copies_included=False,cpu_scope='calling_thread',driver_includes_checks=True,
                  warmup={'iterations':1000,'wall_ns':1},driver_process_cpu_ns=1,driver_gc_count=0,driver_gc_ms=0,compilation_ms_including_warmup=0,
                  samples=[dict(case_id=c['id'],wall_ns=2,cpu_ns=1,allocated_bytes=3,checked=True,inputs_unchanged=True,output_sha256=review.digest(c['fields'][6])) for c in ordered])
        review.validate_ml_batch(data,cases,'sign',0)
        import copy
        for field,value in [('wall_ns',True),('cpu_ns',0),('allocated_bytes',-1),('checked',1),('output_sha256','f'*64)]:
            invalid=copy.deepcopy(data);invalid['samples'][0][field]=value
            with self.assertRaises(review.ReviewError): review.validate_ml_batch(invalid,cases,'sign',0)
        invalid=copy.deepcopy(data);invalid['samples'].reverse()
        with self.assertRaises(review.ReviewError): review.validate_ml_batch(invalid,cases,'sign',0)
        invalid=copy.deepcopy(data);invalid['samples'].pop()
        with self.assertRaises(review.ReviewError): review.validate_ml_batch(invalid,cases,'sign',0)

    def test_sampler_digest_rejection_refill_and_signed_packing(self):
        from unittest.mock import patch
        class RejectionStream:
            def digest(self,n): return b'\xff'*min(840,n)+bytes(max(0,n-840))
        class ZeroStream:
            def digest(self,n): return bytes(n)
        row=dict(parameter='ml_dsa_44',fields=[bytes(32),b'',b'',b'',b'',b'',b''])
        with patch.object(review.hashlib,'shake_128',return_value=RejectionStream()):
            self.assertEqual(review.ml_output(row,'matrix_sample'),review.digest(bytes(4*4*256*4)))
        with patch.object(review.hashlib,'shake_256',return_value=ZeroStream()):
            self.assertEqual(review.ml_output(row,'gamma_sample'),review.digest(struct.pack('>i',1<<17)*(4*256)))

    def test_ml_plan_mirrors_every_variant_and_rejects_odd_pairs(self):
        jobs=review.ml_plan(2,False,False)
        self.assertEqual(len(jobs),48)
        for parameter in review.ML_PARAMS:
            for operation in ['sign','verify']:
                orders=[[j[3] for j in jobs if j[:3]==[rnd,parameter,operation]] for rnd in [0,1]]
                self.assertEqual(set(orders[0]),set(review.ML_VARIANTS))
                self.assertEqual(orders[0],orders[1][::-1])
        with self.assertRaises(review.ReviewError): review.ml_plan(3,False,False)
        with self.assertRaises(review.ReviewError): review.ml_plan(2,True,True)
        confirmed=review.ml_plan(6,False,False,['baseline','combined'])
        self.assertEqual(len(confirmed),72)
        for parameter in review.ML_PARAMS:
            for operation in ['sign','verify']:
                orders=[[j[3] for j in confirmed if j[:3]==[rnd,parameter,operation]] for rnd in range(6)]
                self.assertEqual(sum(order[0]=='baseline' for order in orders),3)
        with self.assertRaises(review.ReviewError): review.ml_plan(6,False,False,['baseline','matrix'])

    def test_slh_zero_cpu_is_explicit_protocol_change(self):
        meta=dict(side='baseline',parameter='sha2_128f',operation='sign.prf_msg',fork=0,rounds=1,budget_ns=400,mode='bench',warmup_calls=20,classes='/sealed/classes')
        expected={case:str(case)*64 for case in [0,3,6,9]}
        rows=[dict(variant='baseline',parameter='sha2_128f',operation='sign.prf_msg',fork=0,round=0,cycle=0,case=case,warmup_calls=20,wall_ns=100,cpu_ns=0,thread_cpu_ns=0,allocated_bytes=0,output_sha256=expected[case],class_source='/sealed/classes',checked=True) for case in expected]
        with self.assertRaises(review.ReviewError): review.validate_slh_rows(rows,expected,meta)
        out=review.validate_slh_rows(rows,expected,dict(meta,allow_zero_cpu=True))
        self.assertEqual(out['medians']['thread_cpu_ns'],0)
        rows[0]['thread_cpu_ns']=-1
        with self.assertRaises(review.ReviewError): review.validate_slh_rows(rows,expected,dict(meta,allow_zero_cpu=True))


if __name__ == '__main__':
    unittest.main()
