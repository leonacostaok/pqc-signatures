"""Fail-closed final matrix acceptance: missing/failed/misbound batches must fail."""
import copy
import unittest
import run

class Completion(unittest.TestCase):
    def setUp(self):
        self.entries=[dict(round=i+1,variant=v,complete=True,returncode=0,ready_sha256='seal',artifact_sha256='outputs') for i,order in enumerate(run.ORDERS) for v in order]
    def test_complete(self):
        run.check_completed(self.entries,'seal','outputs')
    def test_reject_incomplete_failed_duplicate_reordered_or_changed(self):
        bad=[[],self.entries[:-1],self.entries[::-1]]
        for field,value in [('round',0),('variant','unknown'),('complete',False),('returncode',1),('ready_sha256','changed'),('artifact_sha256','changed')]:
            entries=copy.deepcopy(self.entries);entries[0][field]=value;bad.append(entries)
        entries=copy.deepcopy(self.entries);entries[0]=entries[1];bad.append(entries)
        for entries in bad:
            with self.subTest(entries=entries),self.assertRaises(ValueError):run.check_completed(entries,'seal','outputs')
    def test_valid_invocation(self):
        folder=run.E/'test-invocation'
        command=dict(command=[str(run.DRIVERS['full']),str(run.E/'inputs.bin'),str(folder/'outputs.bin'),'10'],started_utc='2026-10-12T00:00:00+00:00')
        run.check_command_status('full',folder,command,dict(returncode=0,finished_utc='2026-10-12T00:01:00+00:00'))
    def test_reject_wrong_executable_input_count_failure_or_chronology(self):
        folder=run.E/'test-invocation'
        command=dict(command=[str(run.DRIVERS['full']),str(run.E/'inputs.bin'),str(folder/'outputs.bin'),'10'],started_utc='2026-10-12T00:00:00+00:00')
        status=dict(returncode=0,finished_utc='2026-10-12T00:01:00+00:00')
        for index in range(4):
            bad=copy.deepcopy(command);bad['command'][index]='wrong'
            with self.assertRaises(ValueError):run.check_command_status('full',folder,bad,status)
        for field,value in [('returncode',1),('finished_utc','2026-10-11T00:01:00+00:00')]:
            bad=copy.deepcopy(status);bad[field]=value
            with self.assertRaises(ValueError):run.check_command_status('full',folder,command,bad)
if __name__=='__main__':unittest.main()
