"""Read-only REDIRECT attribution. No payload inspection or proxy API access."""
import re
import subprocess
import time


class RedirectMap:
    def __init__(self):
        self.entries = {}
        self.ports = set()
        self.updated = -100
        self.ports_updated = -100
        self.error = ''

    @staticmethod
    def parse(line, ports):
        fields = line.split()
        if len(fields) < 4 or fields[2] != 'tcp':
            return []
        sides = re.findall(r'src=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)', line)
        if len(sides) != 2:
            return []
        (client, remote, cp, rp), (router, reply_client, proxy_port, reply_cp) = sides
        if (client != reply_client or cp != reply_cp or remote == router
                or int(proxy_port) not in ports):
            return []
        identity = (6, client, int(cp), remote, int(rp))
        result = []
        for role, a, ap, b, bp in (('original', client, int(cp), remote, int(rp)),
                                    ('redirect', client, int(cp), router, int(proxy_port))):
            for left, lp, right, rport, local_client in ((a, ap, b, bp, True), (b, bp, a, ap, False)):
                result.append(((6, left, lp, right, rport), {
                    'role': role, 'local_client': local_client, 'client': client,
                    'remote': remote, 'connection': identity}))
        return result

    def refresh(self):
        now = time.monotonic()
        if now - self.updated < 1:
            return
        self.updated = now
        try:
            if now - self.ports_updated >= 30:
                output = subprocess.check_output(['netstat', '-lntp'], text=True, timeout=2, stderr=subprocess.PIPE)
                ports = set()
                for line in output.splitlines():
                    fields = line.split()
                    if len(fields) >= 7 and fields[-1].split('/')[-1] in ('clash', 'mihomo', 'sing-box', 'xray'):
                        ports.add(int(fields[3].rsplit(':', 1)[1]))
                self.ports = ports
                self.ports_updated = now
            entries = {}
            if self.ports:
                with open('/proc/net/nf_conntrack') as handle:
                    for line in handle:
                        entries.update(self.parse(line, self.ports))
                        if len(entries) >= 32768:
                            break
            self.entries = entries
            self.error = ''
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            self.entries = {}
            self.error = str(exc)

    def lookup(self, flow):
        # The map only contains TCP REDIRECT entries. DNS/QUIC/ICMP metadata
        # must not trigger a full conntrack read or a listener subprocess.
        if flow.get('ip_protocol') != 6:
            return None
        self.refresh()
        key = (flow.get('ip_protocol'), flow.get('local_ip'), flow.get('local_port'),
               flow.get('other_ip'), flow.get('other_port'))
        try:
            return self.entries.get(key)
        except TypeError:
            return None

    def is_candidate(self, flow, local_macs):
        """Whether an unconfirmed LAN flow could be a proxy REDIRECT leg."""
        if flow.get('ip_protocol') != 6 or flow.get('other_type') != 'local':
            return False
        for side in ('local', 'other'):
            if ((flow.get(side + '_mac') or '').lower() in local_macs
                    and flow.get(side + '_port') in self.ports):
                return True
        return False
