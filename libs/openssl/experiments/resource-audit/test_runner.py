#!/usr/bin/env python3
"""Mutate retained probe outputs to check rejection without running crypto."""
import copy,importlib.util,json,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('resource_runner',Path(__file__).with_name('run.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ROOT=Path(__file__).resolve().parents[4]
class Gates(unittest.TestCase):
    def test_baseline_and_candidate_and_mutations(self):
        for side in ['baseline','candidate']:
            rows=[json.loads(s) for s in (ROOT/'results/openssl/resource-audit'/f'{side}.jsonl').read_text().splitlines()]
            m.validate(rows,side=='candidate')
            for key,value in [('net_live_bytes',1),('frees',0),('cleared_allocations',0),('allocations',True)]:
                bad=copy.deepcopy(rows);bad[0][key]=value
                with self.assertRaises(ValueError):m.validate(bad,side=='candidate')
            for bad in [rows[:-1],rows+[rows[0]],rows[::-1]]:
                with self.assertRaises(ValueError):m.validate(bad,side=='candidate')
if __name__=='__main__':unittest.main()
