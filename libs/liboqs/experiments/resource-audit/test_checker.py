#!/usr/bin/env python3
"""Reject missing, altered, duplicate and unexpected-allocation observations."""
import copy, importlib.util, json, unittest
from pathlib import Path
spec = importlib.util.spec_from_file_location('resource_check', Path(__file__).with_name('check.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
ROOT = Path(__file__).resolve().parents[4]
class Gates(unittest.TestCase):
    def test_saved_outputs_and_mutations(self):
        for side in ['baseline', 'candidate']:
            rows = [json.loads(line) for line in (ROOT / 'results/liboqs/resource-audit' / (side + '.jsonl')).read_text().splitlines()]
            m.validate(rows)
            for key, value in [('sha256', '00'*32), ('sha512', '00'*64), ('openssl_mallocs', 1), ('openssl_requested_bytes', True)]:
                bad = copy.deepcopy(rows)
                bad[0][key] = value
                with self.assertRaises(ValueError):
                    m.validate(bad)
            for bad in [rows[:-1], rows + [rows[0]], rows[::-1]]:
                with self.assertRaises(ValueError):
                    m.validate(bad)
if __name__ == '__main__':
    unittest.main()
