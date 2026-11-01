"""Host-only synthetic Anti-PCDN overhead benchmark; no real firewall actions."""
import argparse
import gc
import hashlib
import inspect
import json
import os
from pathlib import Path
import platform
import queue
import statistics
import sys
import tempfile
import textwrap
import time
import tracemalloc

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import netify_collector
from netify_features import FeatureBridge
from anti_pcdn.config import validate
from anti_pcdn.engine import MAX_SAMPLES
from anti_pcdn.runtime import Worker

BASE = 1800000000
REPEATS = 7
source_files = ['netify_collector.py', 'netify_features.py', 'features/anti_pcdn/engine.py', 'features/anti_pcdn/runtime.py']

def hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in source_files}

START_HASHES = hashes()

def no_accounting(_message):
    pass

class Clock:
    now = 0.0
    def monotonic(self):
        return self.now
    def wall(self):
        return BASE + self.now

class FakeFirewall:
    def __init__(self):
        self.leases = {}
        self.error = ''
        self.calls = 0
    def expire(self, now):
        self.calls += 1
    def clear(self):
        self.leases.clear()
    def install(self, *_args):
        raise AssertionError('Observe mode must not install rules')

def fixture(flows, rounds=30):
    rounds_raw, rounds_parsed = [], []
    messages = []
    for i in range(flows):
        device, peer = divmod(i, 50)
        messages.append({'type':'flow', 'internal':True, 'interface':'br-lan', 'flow':{
            'digest':str(i), 'first_seen_at':BASE*1000,
            'local_mac':'02:11:22:33:%02x:%02x' % (device // 256, device % 256),
            'local_ip':'192.168.1.%d' % (device+2),
            'other_ip':'11.0.%d.%d' % (device, peer+1),
            'local_port':40000, 'other_port':443, 'ip_protocol':17 if i%2 else 6,
            'other_type':'remote', 'detected_protocol_name':'QUIC' if i%2 else 'TLS',
            'host_server_name':'uploader.example.net', 'unneeded_metadata':'x'*256}})
    rounds_parsed.append(messages)
    for step in range(1, rounds+1):
        messages=[]
        for i in range(flows):
            upload, download = (65536, 1024) if i%3 else (4096, 32768)
            messages.append({'type':'flow_stats','internal':True,'interface':'br-lan','flow':{
                'digest':str(i),'last_seen_at':int((BASE+step*10)*1000),
                'local_bytes':upload,'other_bytes':download,'total_bytes':(upload+download)*step,
                'local_packets':50,'other_packets':5}})
        rounds_parsed.append(messages)
    for messages in rounds_parsed:
        rounds_raw.append([json.dumps(message,separators=(',',':')).encode() for message in messages])
    return rounds_raw, rounds_parsed

def collector(feature=None):
    obj=netify_collector.Collector.__new__(netify_collector.Collector)
    obj.invalid_messages=0
    obj.handle=no_accounting
    if feature is not None:
        obj.features=feature
    return obj

def enabled():
    clock=Clock()
    bridge=FeatureBridge(config_path='/tmp/betterdpi-benchmark-do-not-read.json')
    worker=Worker(validate({'enabled':True,'mode':'observe'}),firewall=FakeFirewall(),clock=clock.monotonic,wall=clock.wall)
    worker.connected=True
    bridge.worker=worker
    bridge.active=True
    return collector(bridge),worker,clock

def report_times(values, events):
    median=statistics.median(values)
    return {'repeat_seconds':values,'median_seconds':median,'events':events,
            'median_events_per_second':events/median,'median_microseconds_per_event':median*1e6/events}

def baseline():
    raw,parsed=fixture(1000)
    raw=[line for round_ in raw for line in round_]*2
    parsed=[event for round_ in parsed for event in round_]*2
    source=textwrap.dedent(inspect.getsource(netify_collector.Collector.read_message))
    snippet="        features = getattr(self, 'features', None)\n        if features and features.active:\n            features.submit(message)\n"
    assert source.count(snippet)==1
    namespace={}
    exec(source.replace(snippet,''),netify_collector.__dict__,namespace)
    pre_hook=namespace['read_message']
    current=netify_collector.Collector.read_message
    off=collector(FeatureBridge(config_path='/tmp/benchmark-no-config.json'))
    pre=collector()
    values={'read_message_no_hook':[],'read_message_disabled':[],'parsed_no_hook':[],'parsed_disabled':[]}
    parsed_namespace={}
    exec('def parsed_dispatch(self, message):\n'+textwrap.indent(textwrap.dedent(snippet),'    ')+'    self.handle(message)\n',{},parsed_namespace)
    parsed_hook=parsed_namespace['parsed_dispatch']
    def plain(self,message):
        self.handle(message)
    cases=[('read_message_no_hook',pre_hook,pre,raw),('read_message_disabled',current,off,raw),
           ('parsed_no_hook',plain,pre,parsed),('parsed_disabled',parsed_hook,off,parsed)]
    for repeat in range(REPEATS+1):
        gc.collect()
        for name,handler,obj,events in (cases if repeat%2 else list(reversed(cases))):
            start=time.perf_counter()
            for event in events:
                handler(obj,event)
            elapsed=time.perf_counter()-start
            if repeat:
                values[name].append(elapsed)
    result={name:report_times(times,len(raw)) for name,times in values.items()}
    for label in ('read_message','parsed'):
        low=result[label+'_no_hook']['median_seconds']
        high=result[label+'_disabled']['median_seconds']
        result[label+'_overhead_percent']=(high/low-1)*100
        result[label+'_added_nanoseconds_per_event']=(high-low)*1e9/len(raw)
        pairs=list(zip(values[label+'_no_hook'],values[label+'_disabled']))
        deltas=[(right-left)*1e9/len(raw) for left,right in pairs]
        result[label+'_paired_delta_ns']={'median':statistics.median(deltas),'range':[min(deltas),max(deltas)]}
        result[label+'_paired_overhead_percent_median']=statistics.median((right/left-1)*100 for left,right in pairs)
    return result

def stream(raw, include_scoring=True):
    obj,worker,clock=enabled()
    evaluations=[]
    start=time.perf_counter()
    for round_,lines in enumerate(raw):
        clock.now=round_*10
        for offset in range(0,len(lines),128):
            for line in lines[offset:offset+128]:
                obj.read_message(line)
            while not worker.queue.empty():
                worker.consume(worker.queue.get_nowait())
        if round_ and include_scoring:
            evaluation=time.perf_counter()
            worker.evaluate(clock.now)
            evaluations.append(time.perf_counter()-evaluation)
    elapsed=time.perf_counter()-start
    stats={'flows':len(worker.engine.flows),'groups':len(worker.engine.groups),'samples':worker.engine._sample_count,
           'sample_limit':MAX_SAMPLES,'counters':dict(worker.engine.counters),'worker_counters':dict(worker.counters),
           'queue_depth':worker.queue.qsize(),'invalid_messages':obj.invalid_messages,
           'candidate_rows_retained':len(worker.rows),'evaluation_seconds':sum(evaluations),
           'median_evaluation_ms':statistics.median(evaluations)*1000 if evaluations else None,
           'max_evaluation_ms':max(evaluations)*1000 if evaluations else None}
    return elapsed,stats,(obj,worker,clock)

def benchmark_enabled(flow_count):
    raw,_parsed=fixture(flow_count)
    count=sum(map(len,raw))
    values=[]
    results=[]
    for repeat in range(REPEATS+1):
        gc.collect()
        elapsed,stats,objects=stream(raw)
        if repeat:
            values.append(elapsed)
            results.append(stats)
        del objects
    result=report_times(values,count)
    result['flow_count']=flow_count
    result['simulated_seconds']=300
    result['evaluation_per_10s_median_ms']=statistics.median(item['median_evaluation_ms'] for item in results)
    result['evaluation_max_ms']=max(item['max_evaluation_ms'] for item in results)
    result['last_run']=results[-1]
    return result

def memory():
    raw,_parsed=fixture(1000)
    gc.collect()
    tracemalloc.start()
    initial=tracemalloc.get_traced_memory()[0]
    elapsed,stats,objects=stream(raw)
    gc.collect()
    current,peak=tracemalloc.get_traced_memory()
    result={'tracemalloc_retained_bytes_above_start':current-initial,'tracemalloc_peak_bytes_above_start':peak-initial,
            'instrumented_seconds_not_throughput':elapsed,'state':stats,
            'top_allocations':[str(item) for item in tracemalloc.take_snapshot().statistics('filename')[:8]]}
    tracemalloc.stop()
    return result

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('mode',choices=('baseline','250','1000','memory'))
parser.add_argument('--output-dir',type=Path,default=Path(tempfile.gettempdir()),help='Directory for JSON measurements (default: system temporary directory)')
args=parser.parse_args()
mode=args.mode
result={'mode':mode,'host':{'python':sys.version,'platform':platform.platform(),'logical_cpus':os.cpu_count()},
        'source_hashes_start':START_HASHES,
        'limitations':['Synthetic host microbenchmark; not router prediction.',
                       'Accounting handle is a no-op in every case; no SQLite or Netify socket overhead included.',
                       'Enabled path uses real collector parsing, FeatureBridge, projection, queue put/get, Worker.consume and Engine; synchronous bounded batches omit background-thread scheduling.',
                       'Observe mode and fake firewall: no kernel/firewall mutations, conntrack/neighbour commands or auto-mode cost.',
                       'No status-file publications/config polls included in per-event throughput.',
                       'Tracemalloc measures Python allocations, not RSS; fixture allocated before tracing.']}
if mode=='baseline':
    result['measurement']=baseline()
elif mode=='memory':
    result['measurement']=memory()
else:
    result['measurement']=benchmark_enabled(int(mode))
result['source_hashes_end']=hashes()
args.output_dir.mkdir(parents=True,exist_ok=True)
path=args.output_dir / ('betterdpi-pcdn-benchmark-'+mode+'.json')
path.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
