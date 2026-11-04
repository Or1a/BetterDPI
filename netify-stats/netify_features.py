"""Optional live-event subscriber. Disabled mode has no worker or event copies."""
import os
import sys

# The source tree groups optional features separately; packages install the
# anti_pcdn package alongside this module on the collector's existing path.
_source_features = os.path.join(os.path.dirname(__file__), 'features')
if os.path.isdir(_source_features):
    sys.path.insert(0, _source_features)


class FeatureBridge:
    def __init__(self, router_macs=(), config_path='/etc/betterdpi-anti-pcdn.json',
                 runtime_dir='/var/run/betterdpi-anti-pcdn', factory=None):
        self.router_macs = tuple(router_macs)
        self.config_path = config_path
        self.runtime_dir = runtime_dir
        self.factory = factory
        self.worker = None
        self.active = False
        self.error = ''
        self.signature = object()
        self.settings = None
        self.connected = False

    def tick(self):
        """Called by existing 3-second collector maintenance, never per packet."""
        try:
            try:
                stat = os.stat(self.config_path)
                signature = (stat.st_ino, stat.st_mtime_ns, stat.st_size)
            except FileNotFoundError:
                signature = None
            if signature != self.signature:
                from anti_pcdn.config import load
                settings = load(self.config_path)
                self.signature, self.settings = signature, settings
                self.error = ''
                if self.worker:
                    self.worker.request_stop()
                    self.active = False
            if self.worker and not self.worker.is_alive():
                self.error = self.worker.error
                self.worker = None
            if self.worker:
                return
            if self.settings and self.settings['enabled']:
                if self.factory is None:
                    from anti_pcdn.runtime import Worker
                    factory = Worker
                else:
                    factory = self.factory
                self.worker = factory(self.settings, self.router_macs, self.runtime_dir)
                self.worker.connected = self.connected
                self.worker.start()
                self.active = True
        except Exception as exc:
            # Optional enforcement must never take down traffic accounting.
            self.error = str(exc)[:512]
            self.active = False
            if self.worker:
                self.worker.request_stop()

    def submit(self, message):
        if self.active and self.worker:
            try:
                self.worker.submit(message)
            except Exception as exc:
                self.error = str(exc)[:512]
                self.active = False
                self.worker.request_stop()

    def connection(self, connected):
        if connected != self.connected:
            self.connected = connected
            if self.worker:
                self.worker.connected = connected
                self.worker.gap('collector_reconnected' if connected else 'collector_disconnected')

    def metadata_requests(self):
        if not self.active or self.worker is None:
            return (), None
        # Immutable worker snapshots; never iterate its live engine dictionaries
        # from the collector thread.
        return self.worker.recovery_keys, (id(self.worker), self.worker.recovery_revision)

    def seed_metadata(self, message):
        if self.active and self.worker:
            return self.worker.seed_metadata(message)
        return False

    def metadata_error(self, error):
        if self.active and self.worker:
            self.worker.recovery_error = str(error)[:256]

    def close(self):
        self.active = False
        if self.worker:
            self.worker.request_stop()
            # nft calls are bounded individually. Kernel lease timeouts still
            # expire if shutdown or a system failure interrupts cleanup.
            self.worker.join(timeout=5)
