#!/usr/bin/env python3
import copy, unittest
import collect

class GateTests(unittest.TestCase):
    def test_metric_gates(self):
        spec={'native_parameter':'test','records':[{'operation_sha256':['a','b','c']} for _ in range(11)]}
        job={'parameter':'test','op':1,'side':'baseline','mode':'timing','key':1,'fork':0}
        row=dict(parameter='test',operation=1,key=1,mode='timing',valid=True,input_unchanged=True,wall_ns=2,cpu_ns=1,peak_rss_pre_bytes=0,peak_rss_post_bytes=0,observed_overwritten_thread_stack_bytes=0,allocations=0,allocated_requested_bytes=0,peak_tracked_live_bytes=0,retained_at_return_bytes=0,net_after_cleanup_bytes=0,frees=0,output_sha256='b')
        collect.validate([row],job,spec)
        for field,value in [('cpu_ns',0),('wall_ns',True),('output_sha256','wrong'),('valid',False),('parameter','wrong'),('key',2)]:
            bad=copy.deepcopy(row);bad[field]=value
            with self.assertRaises(ValueError):collect.validate([bad],job,spec)
        for bad in [[],[row,row]]:
            with self.assertRaises(ValueError):collect.validate(bad,job,spec)
        for mode,values in [('allocation',dict(allocations=1,frees=0)),('rss',dict(peak_rss_pre_bytes=10,peak_rss_post_bytes=9)),('stack-a5',dict(observed_overwritten_thread_stack_bytes=0))]:
            bad=copy.deepcopy(row);bad.update(values);bad['mode']=mode;task=dict(job,mode=mode)
            with self.assertRaises(ValueError):collect.validate([bad],task,spec)
    def test_declared_coverage_and_orders(self):
        j={'parameters':[dict(parameter='SLH-DSA-SHA2-128f',baseline='baseline',paired_resource=True,baseline_timing=False),dict(parameter='ML-DSA-44',baseline='extended',paired_resource=False,baseline_timing=True)]}
        timing=collect.jobs(j,'baseline-timing');self.assertEqual(len(timing),9)
        resources=collect.jobs(j,'resources');self.assertEqual(len(resources),80)
        for mode in ['allocation','rss','stack-a5']:
            for op in range(3):
                jobs=[x for x in resources if x['mode']==mode and x['op']==op]
                self.assertEqual([x['side'] for x in jobs],['baseline','candidate','candidate','baseline','candidate','baseline','baseline','candidate'])
if __name__=='__main__':unittest.main()
