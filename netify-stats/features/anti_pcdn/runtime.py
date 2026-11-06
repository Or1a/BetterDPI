"""Bounded optional worker: live observations -> scores -> short kernel leases.

This module has no database or traffic-writer dependency. Only the collector's
raw socket stream may submit traffic; requested metadata recovery supplies only
identity and a cumulative baseline, never traffic samples.
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
from .scoring import REVOKING_GUARDS
from .firewall import Firewall
from .observation import ObservationJournal
from .fast import FastObserver, POLL_SECONDS

QUEUE_LIMIT = 512
EVALUATE_SECONDS = 1
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
        self.recovery_keys = ()
        self.recovery_revision = 0
        self.recovery_error = ''
        self.observations = ObservationJournal(runtime_dir) if settings['mode'] == 'observe' else None
        self.fast = (FastObserver(settings, runtime_dir=runtime_dir, router_macs=router_macs, clock=clock, wall=wall)
                     if hasattr(self.engine, 'fast_metadata') else None)
        self.last_fast = float('-inf')
        self.execution_readiness = {}

    def request_stop(self):
        self.stopping.set()

    def gap(self, reason):
        self.generation = (self.generation[0] + 1, reason)

    def reset_evidence(self, now, reason):
        self.engine.gap(now, reason)
        if self.fast is not None:
            self.fast.reset(reason)
        self.rows = []

    def clear_leases(self, failure_kind):
        """Every cleanup path must confirm both the operation and empty state."""
        self.cleanup_ready = False
        self.last_cleanup_attempt = self.clock()
        try:
            if self.firewall.clear() is False or self.firewall.leases:
                raise RuntimeError(self.firewall.error or 'Feature cleanup could not be confirmed.')
            self.cleanup_ready = True
        except Exception as exc:
            self.event(failure_kind, error=str(exc)[:240])
        return self.cleanup_ready

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
            self.reset_evidence(now, reason)
            if self.firewall.leases:
                self.clear_leases('gap_cleanup_failed')
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
        if self.firewall.leases and hasattr(self.engine, 'protection_update'):
            update = self.engine.protection_update((message['interface'], message['flow'].get('digest')))
            if update is not None:
                self.revoke_protected(now, [update])

    def revoke_protected(self, now, metadata):
        """Protection overrides an existing lease, not just a new proposal."""
        protected = [row for row in metadata if REVOKING_GUARDS.intersection(row.get('guards', ()))]
        if not protected or not self.firewall.leases:
            return True
        def identity(row):
            return tuple(row.get(name) for name in ('interface', 'mac', 'ip', 'peer', 'sport', 'dport', 'proto'))
        tokens = {row['id'] for row in protected}
        tuples = {identity(row) for row in protected}
        for token, lease in list(self.firewall.leases.items()):
            if token not in tokens and identity(lease) not in tuples:
                continue
            try:
                released = self.firewall.release(token, now)
                if released is False or token in self.firewall.leases:
                    raise RuntimeError(self.firewall.error or 'protected lease release failed')
                self.counters['protected_leases_released'] += 1
                self.event('protection_released', id=token)
            except Exception as exc:
                # An opt-out must never wait for a normal retry/TTL. If precise
                # removal fails, try removing only this feature's owned table.
                self.event('protection_release_failed', id=token, error=str(exc)[:240])
                self.clear_leases('protection_cleanup_failed')
                return False
        return True

    def seed_metadata(self, message):
        """Accept a requested export baseline without treating it as traffic."""
        if self.stopping.is_set():
            return False
        try:
            event = project(dict(message, type='flow'), self.settings['interface'])
            if event is None or (event['interface'], event['flow'].get('digest')) not in self.recovery_keys:
                return False
            event['type'] = 'flow_seed'
            self.queue.put_nowait((self.generation[0], event, self.clock(), self.wall()))
            return True
        except ValueError:
            self.counters['recovery_rejected'] += 1
            self.recovery_error = 'Recovered metadata has invalid or oversized fields.'
            return True
        except queue.Full:
            # No live increment has been lost: retry metadata next maintenance.
            self.counters['recovery_deferred'] += 1
            return False

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
            self.reset_evidence(now, 'manual_release')
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
        metadata = self.engine.fast_metadata(now) if hasattr(self.engine, 'fast_metadata') else []
        if not self.revoke_protected(now, metadata):
            self.rows = []
            return
        if self.fast is not None:
            # Prefer the independent fast evidence for a tuple, never add the
            # two byte ledgers or issue duplicate proposals for one connection.
            combined = {row['id']: row for row in rows}
            for row in self.fast.candidates(now, metadata):
                combined[row['id']] = row
            rows = sorted(combined.values(), key=lambda row: (
                not (row['threshold_met'] and not row['guards']), -row['score'], -row['upload'], row['id']))
        self.rows = rows[:50]
        if self.settings['mode'] == 'observe':
            if self.observations is not None:
                coverage = self.engine.coverage(now) if hasattr(self.engine, 'coverage') else {}
                coverage['execution_readiness'] = dict(self.execution_readiness)
                self.observations.record(rows, self.settings, now, self.wall(), coverage)
            return
        if (self.settings['mode'] != 'auto' or not self.cleanup_ready
                or self.execution_readiness.get('supported') is False):
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
                    or not self.queue.empty() or actions >= MAX_ACTIONS or len(self.firewall.leases) >= MAX_LEASES):
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
            if (self.generation[0] != generation or not self.connected or self.stopping.is_set()
                    or not self.queue.empty()):
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
            if self.fast is not None:
                self.fast.suppress(row, until)

    def check_platform(self, now):
        if hasattr(self.firewall, 'inspect'):
            self.execution_readiness = self.firewall.inspect(now)
            if self.execution_readiness.get('supported') is False and self.firewall.leases:
                self.clear_leases('capability_cleanup_failed')

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
                     execution_readiness=dict(self.execution_readiness),
                     metadata_error=self.recovery_error,
                     events=list(self.events), queue_depth=self.queue.qsize())
        if self.observations is not None:
            state['observations'] = self.observations.status()
        if self.fast is not None:
            state['fast_path'] = self.fast.status(now)
        if hasattr(self.engine, 'coverage'):
            state['coverage'] = self.engine.coverage(now)
            state['devices'] = self.engine.device_rows if self.connected and not stopped else []
            self.recovery_keys = tuple(self.engine.missing)
            self.recovery_revision = self.engine.counters['gaps']
        payload = json.dumps(state, separators=(',', ':'), allow_nan=False).encode('utf-8')
        if len(payload) > 256 * 1024:
            state.update(candidates=[], events=[], error='status_size_limit')
            if 'observations' in state:
                state['observations']['recent'] = []
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
            self.clear_leases('startup_cleanup_failed')
            while not self.stopping.is_set():
                try:
                    self.consume(self.queue.get(timeout=0.2))
                except queue.Empty:
                    pass
                now = self.clock()
                self._sync_gap(now)
                if now - self.last_status >= STATUS_SECONDS:
                    if not self.cleanup_ready and now - self.last_cleanup_attempt >= 30:
                        self.clear_leases('startup_cleanup_failed')
                        self.reset_evidence(self.clock(), 'startup_cleanup')
                    self.release_requests(now)
                    self.firewall.expire(now)
                    self.check_platform(now)
                    self.publish(now)
                    self.last_status = now
                now = self.clock()
                if now - self.last_evaluation >= EVALUATE_SECONDS:
                    # Do not act while old events are waiting to be evaluated.
                    if self.queue.empty():
                        if self.fast is not None and self.connected and now - self.last_fast >= POLL_SECONDS:
                            self.fast.poll(self.engine.fast_metadata(now), now)
                            self.last_fast = now
                        # Kernel reads are bounded but can receive new events.
                        # Apply their protection changes before considering an action.
                        if not self.queue.empty():
                            continue
                        self.evaluate(now)
                        self.last_evaluation = now
        except Exception as exc:
            self.error = str(exc)[:512]
        finally:
            self.stopping.set()
            self.rows = []
            if self.fast is not None:
                self.fast.checkpoint(self.clock(), force=True)
            if not self.clear_leases('shutdown_cleanup_failed'):
                self.error = self.error or self.firewall.error or 'Feature cleanup could not be confirmed.'
            try:
                self.publish(self.clock(), stopped=True)
            except Exception:
                pass
