"""Regression: original TCP metadata precedes its REDIRECT map.

Run: python3 netify-stats/reproduce_late_original.py
This standalone reproducer exits nonzero on a duplicate count. No router is
contacted; all writes are confined to a temporary database that is removed.
"""
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import netify_collector as collector
from netify_proxy import RedirectMap


def reproduce():
    with tempfile.TemporaryDirectory() as directory:
        database = str(Path(directory) / 'stats.db')
        with patch.object(collector, 'DATA_DIR', directory), \
                patch.object(collector, 'RUNTIME_DIR', directory), \
                patch.object(collector, 'DB_PATH', database):
            instance = collector.Collector()
            try:
                instance.local_macs = {'aa:aa:aa:aa:aa:aa'}
                instance.proxy.refresh = lambda: None
                instance.proxy.ports = {7892}
                original = {
                    'digest': 'original', 'ip_protocol': 6,
                    'local_ip': '10.1.1.2', 'local_port': 12345,
                    'other_ip': '203.0.113.4', 'other_port': 443,
                    'local_mac': 'bb:bb:bb:bb:bb:bb',
                    'other_mac': 'aa:aa:aa:aa:aa:aa', 'other_type': 'remote',
                }
                # 1. Original metadata arrives before the cached map contains
                # this connection. It is accepted as ordinary remote traffic.
                instance.update_metadata({'interface': 'br-lan', 'internal': True, 'flow': original})
                # 2. A newer map identifies this same connection as REDIRECT.
                line = ('ipv4 2 tcp 6 100 src=10.1.1.2 dst=203.0.113.4 '
                        'sport=12345 dport=443 src=10.1.1.1 dst=10.1.1.2 '
                        'sport=7892 dport=12345')
                instance.proxy.entries = dict(RedirectMap.parse(line, {7892}))
                translated = dict(original, digest='redirect', other_ip='10.1.1.1',
                                  other_port=7892, other_type='local')
                instance.update_metadata({'interface': 'br-lan', 'internal': True, 'flow': translated})
                # 3. Mirrored counters arrive on both aliases. The established
                # policy is translated upload + original download, exactly once.
                for digest in ('original', 'redirect'):
                    instance.add_stats({'type': 'flow_stats', 'interface': 'br-lan',
                                        'internal': True, 'flow': {'digest': digest,
                                        'local_bytes': 100, 'other_bytes': 200}})
                actual = instance.db.execute('SELECT SUM(upload),SUM(download),SUM(flows) FROM hourly').fetchone()
            finally:
                instance.db.close()
    names = ('upload', 'download', 'flows')
    expected = (100, 200, 1)
    print(json.dumps({'scenario': 'original metadata before REDIRECT mapping',
                      'expected': dict(zip(names, expected)),
                      'actual': dict(zip(names, actual)),
                      'release_blocker_reproduced': actual != expected}, indent=2))
    return 1 if actual != expected else 0


if __name__ == '__main__':
    raise SystemExit(reproduce())
