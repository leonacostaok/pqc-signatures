#!/usr/bin/env python3
"""Verify saved-evidence replay does not open local build paths and fails closed."""
import importlib.util, json, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

SOURCE=Path(__file__).with_name('independent-check.py').resolve()
spec=importlib.util.spec_from_file_location('indicators_independent',SOURCE)
checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
ROOT=checker.ROOT

class SavedCheck(unittest.TestCase):
    def run_check(self,provider,mutation=None):
        original_bytes=Path.read_bytes;original_text=Path.read_text
        def read_bytes(path,*args,**kwargs):
            self.assertTrue(path.resolve().is_relative_to(ROOT),'saved replay accessed an original external build')
            self.assertNotIn('build',path.resolve().relative_to(ROOT).parts,'saved replay accessed an ignored build directory')
            return original_bytes(path,*args,**kwargs)
        def read_text(path,*args,**kwargs):
            self.assertTrue(path.resolve().is_relative_to(ROOT),'saved replay accessed an original external build')
            self.assertNotIn('build',path.resolve().relative_to(ROOT).parts,'saved replay accessed an ignored build directory')
            text=original_text(path,*args,**kwargs)
            if mutation=='missing-row' and path.name=='000.jsonl' and path.parent.name=='baseline-timing':return '\n'.join(text.splitlines()[1:])+'\n'
            if mutation=='wrong-mean' and path.name=='summary.json':
                value=json.loads(text);value['baseline_timings'][0]['wall_ns']+=1;return json.dumps(value)
            if mutation=='missing-source' and path.name=='artifact-inventory.json':
                value=json.loads(text);value['entries'][0]['repository_path']='nonexistent-file';return json.dumps(value)
            return text
        build=ROOT/'libs/openssl/build/complete-indicators';build.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build) as directory:
            out=Path(directory)/'check.json'
            with patch.object(Path,'read_bytes',read_bytes),patch.object(Path,'read_text',read_text),patch.object(sys,'argv',[str(SOURCE),'--provider',provider,'--out',str(out)]):checker.main()
            report=json.loads(out.read_text());self.assertEqual(report['mode'],'saved-evidence');self.assertIsNone(report['local_original_artifacts_verified']);self.assertTrue(report['local_verification_unavailable'])
    def test_saved_replays_without_external_builds(self):
        for provider in ['liboqs','openssl']:
            with self.subTest(provider=provider):self.run_check(provider)
    def test_malformed_saved_evidence_rejected(self):
        for mutation in ['missing-row','wrong-mean','missing-source']:
            with self.subTest(mutation=mutation),self.assertRaises((ValueError,FileNotFoundError)):self.run_check('openssl',mutation)

if __name__=='__main__':unittest.main()
