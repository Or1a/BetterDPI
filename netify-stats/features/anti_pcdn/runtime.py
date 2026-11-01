"""Bounded optional worker: live observations -> scores -> short kernel leases.

This module has no database or traffic-writer dependency. Only the collector's
raw socket stream may submit events; metadata recovery must not feed this queue.
"""
from collections import Counter, deque
import json
import os
import queue
import re
import tempfile
import threading
import time

from .engine import Engine
from .firewall import Firewall

QUEUE_LIMIT = 512
EVALUATE_SECONDS = 10
STATUS_SECONDS = 3
MAX_LEASES = 128
MAX_DEVICE_LEASES = 16
MAX_ACTIONS = 4
FLOW_FIELDS = ('digest', 'first_seen_at', 'last_seen_at', 'local_mac', 'other_mac',
               'local_ip', 'other_ip', 'local_port', 'other_port', 'ip_protocol',
               'other_type', 'local_type', 'detected_application_name',
               'detected_protocol_name', 'host_server_name', 'dns_host_name',
               'local_bytes', 'other_bytes', 'total_bytes', 'local_packets', 'other_packets',
               'proxy', 'shared_transport', 'attribution')


def project(message, interface):
    """Keep only bounded scalar fields; do not retain arbitrary Netify payloads."""
    if message.get('type') not in ('flow', 'flow_stats', 'flow_purge'):
        return None
    if message.get('internal') is not True or message.get('interface') != interface:
        return None
    source = message.get('flow')
    if not isinstance(source, dict):
        raise ValueError('invalid_flow')
    flow = {}
    for key in FLOW_FIELDS:
        value = source.get(key)
        if value is None:
            continue
        if type(value) not in (str, int, float, bool) or isinstance(value, str) and len(value) > 512:
            raise ValueError('oversized_or_invalid_flow')
        if isinstance(value, int) and value.bit_length() > 64:
            raise ValueError('oversized_counter')
        flow[key] = value
    return {'type': message['type'], 'internal': True, 'interface': interface, 'flow': flow}


class Worker(threading.Thread):
    def __init__(self, settings, router_macs=(), runtime_dir='/var/run/betterdpi-anti-pcdn',
                 engine=None, firewall=None, clock=time.monotonic, wall=time.time):
        super().__init__(name='betterdpi-anti-pcdn', daemon=True)
        self.settings = settings
        self.clock, self.wall = clock, wall
        self.engine = engine if engine is not None else Engine(settings, now=clock(), router_macs=router_macs)
        self.firewall = firewall if firewall is not None else Firewall()
        self.runtime_dir = runtime_dir
        self.queue = queue.Queue(QUEUE_LIMIT)
        self.stopping = threading.Event()
        self.connected = False
        self.generation = (0, 'startup')
        self.applied_generation = -1
        self.counters = Counter()
        self.events = deque(maxlen=50)
        self.rows = []
        self.error = ''
        self.last_evaluation = clock()
        self.last_status = 0
        self.retries = {}
        self.cleanup_ready = False
        self.last_cleanup_attempt = float('-inf')

    def request_stop(self):
        self.stopping.set()

    def gap(self, reason):
        self.generation = (self.generation[0] + 1, reason)

    def submit(self, message):
        if self.stopping.is_set():
            return
        try:
            event = project(message, self.settings['interface'])
        except ValueError:
            self.counters['invalid_events'] += 1
            self.gap('invalid_event')
            return
        if event is None:
            return
        try:
            self.queue.put_nowait((self.generation[0], event, self.clock(), self.wall()))
        except queue.Full:
            self.counters['queue_dropped'] += 1
            self.gap('queue_overflow')

    def _sync_gap(self, now):
        generation, reason = self.generation
        if generation != self.applied_generation:
            self.engine.gap(now, reason)
            self.rows = []
            self.applied_generation = generation

    def consume(self, item):
        generation, message, arrived, wall = item
        now = self.clock()
        self._sync_gap(now)
        if generation != self.applied_generation:
            self.counters['discarded_queue'] += 1
            return
        if not 0 <= now - arrived <= 5:
            self.counters['stale_queue'] += 1
            self.gap('stale_queue')
            self._sync_gap(now)
            return
        # Processing and scoring share one monotonic clock. Keep source wall
        # time age accurate even if this item briefly waited in the queue.
        self.engine.observe(message, now, wall + now - arrived)
        self.counters['observed_events'] += 1

    def event(self, kind, **fields):
        self.events.append(dict(timestamp=self.wall(), kind=kind, **fields))

    def release_requests(self, now):
        path = os.path.join(self.runtime_dir, 'release.json')
        try:
            with open(path, 'rb') as handle:
                raw = handle.read(1025)
        except FileNotFoundError:
            return
        request = {}
        try:
            if len(raw) > 1024:
                raise ValueError('release_request_too_large')
            request = json.loads(raw)
            if not isinstance(request, dict):
                request = {}
                raise ValueError('invalid_release_request')
            token, request_id, stamp = request.get('id'), request.get('request_id'), request.get('timestamp')
            if not isinstance(token, str) or not re.fullmatch(r'(?:[a-f0-9]{24}|[a-f0-9]{32})', token):
                raise ValueError('invalid_lease_id')
            if not isinstance(request_id, str) or not re.fullmatch(r'[a-f0-9]{32}', request_id):
                raise ValueError('invalid_request_id')
            if type(stamp) not in (int, float) or not 0 <= self.wall() - stamp <= 30:
                raise ValueError('expired_release_request')
            if token not in self.firewall.leases:
                raise ValueError('lease_no_longer_present')
            result = self.firewall.release(token, now)
            if token in self.firewall.leases or result is False:
                raise RuntimeError(self.firewall.error or 'release_failed')
            # Manual release gives every group a fresh observation window.
            self.engine.gap(now, 'manual_release')
            self.rows = []
            self.event('released', id=token, request_id=request_id)
        except Exception as exc:
            self.event('release_failed', request_id=str(request.get('request_id', ''))[:64], error=str(exc)[:256])
        finally:
            os.unlink(path)

    def evaluate(self, now):
        self._sync_gap(now)
        self.firewall.expire(now)
        if not self.connected or self.stopping.is_set():
            self.rows = []
            return
        rows = self.engine.candidates(now)
        self.rows = rows[:50]
        if self.settings['mode'] != 'auto' or not self.cleanup_ready:
            return
        actions = 0
        suppressed = []
        generation = self.generation[0]
        current_ids = {row['id'] for row in rows}
        self.retries = {key: value for key, value in self.retries.items() if key in current_ids}
        # A pending exact identity probe gets its second fresh observation on
        # the next tick. Other failures back off so later peers are not starved.
        rows = sorted(rows, key=lambda row: not self.retries.get(row['id'], (0, False))[1])
        per_device = Counter(lease.get('mac') for lease in self.firewall.leases.values())
        for row in rows:
            if (self.stopping.is_set() or not self.connected or self.generation[0] != generation
                    or actions >= MAX_ACTIONS or len(self.firewall.leases) >= MAX_LEASES):
                break
            if row.get('decision') != 'block' or row.get('guards') or row['id'] in self.firewall.leases:
                continue
            if per_device[row['mac']] >= MAX_DEVICE_LEASES:
                self.counters['action_limit'] += 1
                continue
            action_now = self.clock()
            if self.retries.get(row['id'], (0, False))[0] > action_now:
                continue
            actions += 1
            lease = self.firewall.install(row, self.settings['ban_seconds'], action_now)
            if self.generation[0] != generation or not self.connected or self.stopping.is_set():
                if lease:
                    self.firewall.release(lease['id'], self.clock())
                break
            if lease:
                per_device[row['mac']] += 1
                self.counters['leases_installed'] += 1
                self.event('lease_installed', id=lease['id'], score=row['score'], mac=row['mac'])
                suppressed.append((row, lease['expires']))
                self.retries.pop(row['id'], None)
            else:
                self.counters['actions_deferred'] += 1
                uncertain = self.firewall.leases.get(row['id'])
                if uncertain:
                    # A timed-out write may have reached the kernel even when
                    # readback and rollback failed. Its retries are not evidence.
                    suppressed.append((row, uncertain['expires']))
                    self.event('verification_failed', id=row['id'], error=self.firewall.error)
                pending = bool(getattr(self.firewall, 'pending_identity', False))
                self.retries[row['id']] = (action_now + (EVALUATE_SECONDS if pending else 60), pending)
                row['execution_error'] = self.firewall.error
        # Plans in this one bounded batch share the same pre-action evidence.
        # Subsequent retries cannot prolong a lease or raise the group score.
        for row, until in suppressed:
            self.engine.suppress(row, until)

    def publish(self, now, stopped=False):
        leases = []
        for lease in self.firewall.leases.values():
            leases.append({key: lease[key] for key in ('id', 'mac', 'ip', 'peer', 'sport', 'dport',
                                                      'proto', 'protocol', 'score', 'state') if key in lease})
            remaining = max(0, lease['expires'] - now)
            leases[-1].update(remaining=round(remaining, 1), expires_at=self.wall() + remaining)
        state = dict(timestamp=self.wall(), enabled=not stopped,
                     mode=self.settings['mode'], connected=self.connected and not stopped,
                     interface=self.settings['interface'], candidates=self.rows[:50], leases=leases,
                     counters=dict(self.counters), engine_counters=dict(self.engine.counters),
                     error=self.error, executor_error=self.firewall.error,
                     events=list(self.events), queue_depth=self.queue.qsize())
        payload = json.dumps(state, separators=(',', ':'), allow_nan=False).encode('utf-8')
        if len(payload) > 256 * 1024:
            state.update(candidates=[], events=[], error='status_size_limit')
            payload = json.dumps(state, separators=(',', ':'), allow_nan=False).encode('utf-8')
        os.makedirs(self.runtime_dir, mode=0o700, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix='.status-', dir=self.runtime_dir)
        try:
            with os.fdopen(descriptor, 'wb') as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(payload)
            os.replace(temporary, os.path.join(self.runtime_dir, 'status.json'))
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def run(self):
        try:
            # Clean only the feature-owned table after restart, before scoring.
            self.cleanup_ready = self.firewall.clear() is not False
            self.last_cleanup_attempt = self.clock()
            while not self.stopping.is_set():
                try:
                    self.consume(self.queue.get(timeout=0.2))
                except queue.Empty:
                    pass
                now = self.clock()
                self._sync_gap(now)
                if now - self.last_status >= STATUS_SECONDS:
                    if not self.cleanup_ready and now - self.last_cleanup_attempt >= 30:
                        self.cleanup_ready = self.firewall.clear() is not False
                        self.last_cleanup_attempt = self.clock()
                        self.engine.gap(self.clock(), 'startup_cleanup')
                    self.release_requests(now)
                    self.firewall.expire(now)
                    self.publish(now)
                    self.last_status = now
                now = self.clock()
                if now - self.last_evaluation >= EVALUATE_SECONDS:
                    # Do not act while old events are waiting to be evaluated.
                    if self.queue.empty():
                        self.evaluate(now)
                        self.last_evaluation = now
        except Exception as exc:
            self.error = str(exc)[:512]
        finally:
            self.stopping.set()
            self.rows = []
            try:
                self.firewall.clear()
            except Exception as exc:
                self.error = str(exc)[:512]
            try:
                self.publish(self.clock(), stopped=True)
            except Exception:
                pass
