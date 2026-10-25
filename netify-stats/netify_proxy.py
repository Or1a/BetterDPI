"""Read-only REDIRECT attribution. No payload inspection or proxy API access."""
import re
import os
import select
import subprocess
import time
from collections import OrderedDict



def outbound_socket_snapshot():
    """Bound the extra ownership scan to 150 ms and 512 KiB of output.

    Failure only makes WAN ownership unknown; it must not block capture while
    a router with many local sockets runs a long process listing.
    """
    command = ['netstat', '-antup']
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    deadline = time.monotonic()+.15
    output = bytearray()
    try:
        while True:
            remaining = deadline-time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                raise subprocess.TimeoutExpired(command,.15)
            chunk = os.read(process.stdout.fileno(),65536)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > 512*1024:
                raise ValueError('Socket ownership snapshot exceeded its limit')
        code = process.wait(timeout=max(.001,deadline-time.monotonic()))
        if code:
            raise subprocess.CalledProcessError(code,command)
        return output.decode('utf-8',errors='replace')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()


class RedirectMap:
    def __init__(self):
        self.entries = {}
        self.ports = set()
        self.updated = -100
        self.ports_updated = -100
        self.error = ''
        self.want_egress = False
        self.egress_entries = {}
        self.socket_owners = {}
        self.owners_updated = float('-inf')
        self.clients = OrderedDict()
        self.egress_updated = float('-inf')
        self.egress_error = ''

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

    def observe_client(self, ip, mac):
        if ip and mac:
            self.clients[ip] = (mac, time.monotonic())
            self.clients.move_to_end(ip)
            if len(self.clients) > 4096:
                self.clients.popitem(last=False)

    @staticmethod
    def socket_snapshot(output):
        ports, owners = set(), {}
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 6 or fields[0] not in ('tcp', 'tcp6', 'udp', 'udp6'):
                continue
            owner = fields[-1].split('/')[-1]
            if '/' not in fields[-1] or owner == '-':
                continue
            try:
                local, lp = fields[3].rsplit(':', 1)
                remote, rp = fields[4].rsplit(':', 1)
                if fields[0].startswith('tcp') and len(fields) >= 7 and fields[5] == 'LISTEN':
                    if owner in ('clash', 'mihomo', 'sing-box', 'xray'):
                        ports.add(int(lp))
                    continue
                # A wildcard UDP socket does not prove who owns a particular
                # remote connection. Only keep complete, exact tuples.
                if remote in ('*', '0.0.0.0', '::', '[::]') or rp == '*':
                    continue
                proto = 6 if fields[0].startswith('tcp') else 17
                key = (proto, local.strip('[]'), int(lp), remote.strip('[]'), int(rp))
                if key in owners and owners[key] != owner:
                    owners[key] = None  # Ambiguous ownership is not evidence.
                else:
                    owners[key] = owner[:64]
            except (ValueError, IndexError):
                continue
        return ports, owners

    @staticmethod
    def egress_tuple(line, clients, now):
        fields = line.split()
        if len(fields) < 4 or fields[2] not in ('tcp', 'udp'):
            return []
        sides = re.findall(r'src=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)', line)
        if len(sides) != 2:
            return []
        (client, remote, cp, rp), (reply_remote, external, reply_rp, external_cp) = sides
        observed = clients.get(client)
        # Only an observed LAN source plus an exact unretranslated destination
        # proves forwarding here. Do not infer it merely from ip_nat=true.
        if not observed or now-observed[1] > 120 or remote != reply_remote or rp != reply_rp:
            return []
        proto = 6 if fields[2] == 'tcp' else 17
        target = (client, observed[0])
        return [((proto, external, int(external_cp), remote, int(rp)), target),
                ((proto, client, int(cp), remote, int(rp)), target)]

    def refresh(self):
        now = time.monotonic()
        if now-self.updated < 1:
            return
        self.updated = now
        scan_egress = self.want_egress and now-self.egress_updated >= 30
        owner_error = ''
        if scan_egress:
            try:
                output = outbound_socket_snapshot()
                self.ports, self.socket_owners = self.socket_snapshot(output)
                self.ports_updated = self.owners_updated = now
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                self.socket_owners = {}
                self.owners_updated = float('-inf')
                owner_error = str(exc)
        try:
            if now-self.ports_updated >= 30:
                # The optional WAN ownership scan must not degrade established
                # LAN REDIRECT attribution if it times out or is unsupported.
                output = subprocess.check_output(['netstat', '-lntp'], text=True,
                                                 timeout=2, stderr=subprocess.PIPE)
                self.ports, _ = self.socket_snapshot(output)
                self.ports_updated = now
            entries, egress = {}, {}
            scan_started = time.monotonic()
            limited = False
            if self.ports or scan_egress:
                with open('/proc/net/nf_conntrack') as handle:
                    for number, line in enumerate(handle):
                        if self.ports:
                            entries.update(self.parse(line, self.ports))
                        if scan_egress:
                            for key, value in self.egress_tuple(line, self.clients, now):
                                if key in egress and egress[key] != value:
                                    egress[key] = None
                                else:
                                    egress[key] = value
                        if scan_egress and not self.ports and number % 256 == 255 and time.monotonic()-scan_started >= .05:
                            limited = True
                            break
                        if len(entries) >= 32768 or len(egress) >= 32768 or number >= 32767:
                            limited = True
                            break
            self.entries = entries
            self.error = ''
            if scan_egress:
                self.egress_entries = egress
                self.egress_updated = now
                self.egress_error = owner_error or ('Connection tracking snapshot reached its limit.' if limited else '')
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            self.entries = {}
            self.error = str(exc)
            if scan_egress:
                self.egress_entries = {}
                self.egress_updated = now
                self.egress_error = '; '.join(value for value in (owner_error,str(exc)) if value)

    def egress_lookup(self, flow):
        key = (flow.get('ip_protocol'), flow.get('local_ip'), flow.get('local_port'),
               flow.get('other_ip'), flow.get('other_port'))
        try:
            now = time.monotonic()
            owner = self.socket_owners.get(key) if now-self.owners_updated < 30 else None
            client = self.egress_entries.get(key) if now-self.egress_updated < 30 else None
            return owner, client
        except TypeError:
            return None, None

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
