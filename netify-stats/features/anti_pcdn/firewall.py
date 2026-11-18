"""Optional, expiring exact-connection leases in an exclusively owned nft table.

Installing a verified rule does not prove packets use the software forward path.
Unsupported/offloaded/proxied paths veto new actions. Never disable acceleration,
change fw4 rules, flush conntrack or turn a connection decision into a host ban.
"""
import hashlib
import json
import math
import os
import re
import selectors
import shutil
import socket
import subprocess
import time

from . import conntrack
from .fast import FRESH_SAMPLE_SECONDS, MAX_POLL_GAP

TABLE = "betterdpi_anti_pcdn"
OWNER = "BetterDPI Anti-PCDN leases v1"
MAX_LEASES = 256
MAX_DEVICE_LEASES = 32
CAPABILITY_TTL = 5
INSPECTION_TTL = 30
MAX_AGE = 15
SCOPED_FORWARD_PRIORITY = 10
DROPPED_UPLOAD = "dropped_upload"
DROPPED_DOWNLOAD = "dropped_download"
WARNING = "Rule installation is verified; actual software/hardware forwarding paths are not validated."


class FirewallError(RuntimeError):
    pass


def run_bounded(args, data=None):
    """A bounded subprocess, including output size (communicate alone is unbounded)."""
    payload = data.encode() if data is not None else None
    if payload is not None and len(payload) > 4096:
        raise FirewallError("firewall command is too large")
    process = subprocess.Popen(args, stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = bytearray()
    deadline = time.monotonic() + 1.0
    try:
        if payload is not None:
            process.stdin.write(payload)
            process.stdin.close()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise FirewallError("firewall command timed out")
                part = os.read(process.stdout.fileno(), 65536)
                if not part:
                    break
                output.extend(part)
                if len(output) > 262144:
                    raise FirewallError("firewall output exceeds safety limit")
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
        if process.returncode:
            raise FirewallError(output.decode("utf-8", "replace")[:240].strip() or "firewall command failed")
        return output.decode("utf-8", "strict")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        if process.stdin and not process.stdin.closed:
            process.stdin.close()


def read_modules():
    with open("/proc/modules", encoding="ascii") as source:
        return source.read(262145)


def objects(document):
    if not isinstance(document, dict) or not isinstance(document.get("nftables"), list):
        raise FirewallError("invalid nft JSON document")
    if any(not isinstance(item, dict) or len(item) != 1 or not isinstance(next(iter(item.values())), dict)
           for item in document["nftables"]):
        raise FirewallError("invalid nft JSON record")
    return document["nftables"]


def owned_table(document):
    matches = [obj["table"] for obj in objects(document) if isinstance(obj, dict)
               and isinstance(obj.get("table"), dict) and obj["table"].get("family") == "inet"
               and obj["table"].get("name") == TABLE]
    if not matches:
        return False
    if len(matches) != 1 or matches[0].get("comment") != OWNER:
        raise FirewallError("Anti-PCDN table name is owned by another ruleset")
    return True


def physical_wan_ifindex(name):
    # A WAN zone can include a tunnel or bridge. In proxy coexistence mode,
    # accept only a standalone netdev backed by a hardware device.
    if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,14}", name):
        return None
    path = "/sys/class/net/" + name
    if not os.path.exists(path + "/device") or os.path.lexists(path + "/master"):
        return None
    try:
        return socket.if_nametoindex(name)
    except OSError:
        return None


def wan_ifindices(records, resolve):
    indices = set()
    for item in records:
        rule = item.get("rule", {})
        if (rule.get("family"), rule.get("table"), rule.get("chain")) != ("inet", "fw4", "accept_to_wan"):
            continue
        # Read the ordinary fw4 zone accept rule. Reject conditional rules,
        # wildcards and named sets whose membership has not been resolved.
        expr = rule.get("expr", [])
        if not expr or any(not isinstance(part, dict) or len(part) != 1 for part in expr):
            continue
        matches = [part["match"] for part in expr if "match" in part]
        if (len(matches) != 1 or "accept" not in expr[-1]
                or any(not set(part) <= {"match", "counter", "accept"} for part in expr)):
            continue
        match = matches[0]
        if (not isinstance(match, dict) or match.get("left") != {"meta": {"key": "oifname"}}
                or match.get("op") not in ("==", "in")):
            continue
        value = match.get("right")
        names = value.get("set") if isinstance(value, dict) and set(value) == {"set"} else [value]
        if not isinstance(names, list) or len(names) > 32:
            continue
        for name in names:
            if isinstance(name, str):
                index = resolve(name)
                if type(index) is int and 0 < index < 2**31:
                    indices.add(index)
    return tuple(sorted(indices))


def capability(document, modules, resolve_wan=physical_wan_ifindex):
    records = objects(document)
    if not any(obj.get("table", {}).get("family") == "inet" and obj.get("table", {}).get("name") == "fw4"
               for obj in records if isinstance(obj, dict)):
        raise FirewallError("only the OpenWrt fw4 forwarding path is supported")
    if not any(obj.get("chain", {}).get("family") == "inet" and obj.get("chain", {}).get("table") == "fw4"
               and obj["chain"].get("hook") == "forward" and obj["chain"].get("type") == "filter"
               and obj["chain"].get("prio") == 0 for obj in records if isinstance(obj, dict)):
        raise FirewallError("the fw4 forward hook is unavailable or has an unsupported priority")
    def features(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ("flowtable", "flow", "tproxy", "notrack"):
                    yield key
                yield from features(item)
        elif isinstance(value, list):
            for item in value:
                yield from features(item)
    rules = set(features(records))
    if rules.intersection(("flowtable", "flow", "notrack")):
        raise FirewallError("flow offload or untracked forwarding is not supported")
    if len(modules) > 262144:
        raise FirewallError("module inventory exceeds safety limit")
    names = [line.split()[0].lower() for line in modules.splitlines() if line.split()]
    if any(any(word in name for word in ("shortcut", "fast_classifier", "ecm", "nss", "sfe", "hwnat", "hnat"))
           for name in names):
        raise FirewallError("vendor accelerated forwarding is not supported")
    proxy_modules = {name for name in names if "tproxy" in name}
    if proxy_modules - {"nft_tproxy", "nf_tproxy_ipv4", "nf_tproxy_ipv6"}:
        raise FirewallError("legacy transparent proxy forwarding is not supported")
    if "tproxy" not in rules and not proxy_modules:
        return ()
    for item in records:
        chain = item.get("chain", {})
        if (chain.get("hook") == "forward" and chain.get("family") in ("inet", "ip", "ip6")
                and (chain.get("family"), chain.get("table")) != ("inet", TABLE)
                and (type(chain.get("prio")) is not int or chain["prio"] >= SCOPED_FORWARD_PRIORITY)):
            raise FirewallError("a later forward hook could change protected traffic marks")
    indices = wan_ifindices(records, resolve_wan)
    if not indices:
        raise FirewallError("TPROXY coexistence requires a verified physical WAN interface")
    return indices


def lease_chain(token, identifier, serial):
    return "lease_" + hashlib.sha256(repr((token, identifier, serial)).encode()).hexdigest()[:24]


def lease_script(name, interface, identity, identifier, seconds, lan_direction="original", wan_index=None,
                 count_connection=False):
    version, proto, src, sport, dst, dport = identity
    family = "ip" if version == 4 else "ip6"
    lines = ["add chain inet %s %s { comment %s; }" % (TABLE, name, json.dumps(OWNER))]
    # A single ID -> verdict lookup dispatches to at most two exact guard rules.
    # Avoid ct-id concatenations: nft can lose their width metadata on readback.
    for direction, interface_key in (("original", "iifname"), ("reply", "oifname")):
        if lan_direction == "reply":
            interface_key = "oifname" if direction == "original" else "iifname"
        wan_guard = ""
        if wan_index is not None:
            wan_key = "oif" if interface_key == "iifname" else "iif"
            wan_guard = " meta %s %d meta ipsec missing rt ipsec missing" % (wan_key, wan_index)
        direction_is_upload = interface_key == "iifname"
        counter = DROPPED_UPLOAD if direction_is_upload else DROPPED_DOWNLOAD
        connection_counter = ""
        if count_connection:
            object_name = name + ("_up" if direction_is_upload else "_down")
            lines.append("add counter inet %s %s { comment %s; }" % (TABLE, object_name, json.dumps(OWNER)))
            connection_counter = " counter name " + object_name
        lines.append("add rule inet %s %s meta nfproto ipv%s meta l4proto %s ct direction %s meta %s %s%s ct original %s saddr %s ct original proto-src %s ct original %s daddr %s ct original proto-dst %s meta mark 0 ct mark 0%s counter name %s drop comment %s" %
                     (TABLE, name, version, "tcp" if proto == 6 else "udp", direction,
                      interface_key, json.dumps(interface), wan_guard, family, src, sport, family, dst, dport,
                      connection_counter, counter, json.dumps(name + ":" + direction)))
    lines.append("add element inet %s by_id { %s timeout %ss : jump %s }" % (TABLE, identifier, seconds, name))
    return "\n".join(lines) + "\n"


def has_element(document, chain, identifier):
    """Require the exact CT ID -> owned chain binding and live kernel expiry."""
    for obj in objects(document):
        record = obj.get("map", {})
        if record.get("family") != "inet" or record.get("table") != TABLE or record.get("name") != "by_id":
            continue
        if (record.get("map") != "verdict" or record.get("comment") != OWNER
                or record.get("type") != {"typeof": {"ct": {"key": "id"}}}
                or "timeout" not in record.get("flags", [])):
            raise FirewallError("kernel map did not preserve the owned expiring conntrack-ID type")
        for entry in record.get("elem", []):
            if not isinstance(entry, list) or len(entry) != 2 or not all(isinstance(item, dict) for item in entry):
                continue
            element = entry[0].get("elem", {})
            if not isinstance(element, dict) or not isinstance(entry[1].get("jump", {}), dict):
                continue
            if (element.get("val") == identifier and type(element.get("val")) is int
                    and entry[1].get("jump", {}).get("target") == chain
                    and type(element.get("expires")) in (int, float) and element["expires"] > 0):
                return True
    return False


class Firewall:
    def __init__(self, runner=run_bounded, resolver=conntrack.lookup, neighbours=conntrack.neighbour,
                 modules=read_modules, nft=None, resolve_wan=physical_wan_ifindex, ip=None,
                 audit=None, wall=time.time):
        self.runner, self.resolver, self.neighbours, self.modules = runner, resolver, neighbours, modules
        self.nft = nft or shutil.which("nft") or "/usr/sbin/nft"
        self.ip = ip or shutil.which("ip") or "/sbin/ip"
        self.resolve_wan = resolve_wan
        self.audit, self.wall = audit, wall
        self.serial = 0
        self.wan_scope = ()
        self.leases, self.probes, self.retired = {}, {}, {}
        self.ready = False
        self.last_cleanup = float("-inf")
        self.error, self.warning = "", WARNING
        self.pending_identity = False
        self.install_outcome = None
        self.attempt_chain = None
        self.checked_at = float("-inf")
        self.inspected_at = float('-inf')
        self.inspection = {}
        self.drops = {direction: {"packets": 0, "bytes": 0} for direction in ("upload", "download")}
        self.drop_baseline = {}
        self.drop_counter_error = ""

    def _json(self, *args):
        try:
            return json.loads(self.runner([self.nft, "-j", *args]))
        except (ValueError, TypeError) as error:
            raise FirewallError("invalid nft JSON readback") from error

    def _apply(self, script):
        return self.runner([self.nft, "-f", "-"], script)

    @staticmethod
    def _counts(counters, name):
        values = tuple(counters[name][key] for key in ("packets", "bytes"))
        if any(type(value) is not int or value < 0 for value in values):
            raise FirewallError("invalid drop counter")
        return values

    def sample_drops(self):
        if not self.ready:
            return False
        try:
            since = self.wall()
            counters = {item["counter"]["name"]: item["counter"]
                        for item in objects(self._json("list", "counters", "inet", TABLE))
                        if "counter" in item and item["counter"].get("table") == TABLE
                        and item["counter"].get("family") == "inet"
                        and item["counter"].get("comment") == OWNER}
            current = {}
            for direction, name in (("upload", DROPPED_UPLOAD), ("download", DROPPED_DOWNLOAD)):
                current[direction] = self._counts(counters, name)
            for direction, values in current.items():
                previous = self.drop_baseline.get(direction, (0, 0))
                for key, value, old in zip(("packets", "bytes"), values, previous):
                    if value >= old:
                        self.drops[direction][key] += value - old
            self.drop_baseline = current
            self.drop_counter_error = ""
            if self.audit is not None:
                seen_at = self.wall()
                for lease in self.leases.values():
                    self._sample_lease(lease, counters, since, seen_at)
                for lease in self.retired.values():
                    if not lease['drop_final']:
                        lease['drop_final'] = self._sample_lease(lease, counters, since, seen_at)
            return True
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
            self.drop_counter_error = str(exc)[:160]
            return False

    def _sample_lease(self, lease, counters, since, seen_at):
        zero, first, last = lease['drop_zero'], lease['drop_first'], lease['drop_last']
        complete = True
        for direction, suffix in (("upload", "_up"), ("download", "_down")):
            try:
                packets, size = self._counts(counters, lease['chain'] + suffix)
            except (KeyError, FirewallError):
                self.drop_counter_error = 'connection drop counter unavailable'
                complete = False
                continue
            last[direction] = (packets, size, seen_at)
            if packets and direction not in first:
                lower = zero.get(direction, lease['submitted_at'])
                if self.audit('first_drop', seen_at, lease, direction=direction, packets=packets,
                              bytes=size, not_before=round(lower, 3) if lower <= seen_at else None):
                    first.add(direction)
                else:
                    complete = False
            elif not packets and direction not in first:
                zero[direction] = since
        return complete

    def _retire_lease(self, lease, reason, detached=False, **fields):
        lease.update(retired_reason=reason, detached=detached)
        self.retired[lease['chain']] = lease
        if self.audit is not None:
            self.audit('lease_retired', self.wall(), lease, reason=reason, **fields)

    def _finish_lease(self, lease, reason):
        if self.audit is not None:
            wall = self.wall()
            counts = {direction: {'packets': packets, 'bytes': size, 'sampled_at': round(at, 3)}
                      for direction, (packets, size, at) in lease['drop_last'].items()}
            self.audit('lease_closed', wall, lease, reason=reason, counts=counts,
                       complete=lease['drop_final'])

    def drop_status(self):
        return {**{key: dict(values) for key, values in self.drops.items()},
                "scope": "worker_session", "error": self.drop_counter_error}

    def inspect(self, now):
        """Read-only platform precheck, including in observation mode.

        Success never claims a particular tuple or hardware path can be blocked.
        This method neither creates the feature table nor probes a connection.
        """
        if not 0 <= now - self.inspected_at < INSPECTION_TTL:
            try:
                document = self._json('-t', 'list', 'ruleset')
                scope = capability(document, self.modules(), self.resolve_wan)
                owned_table(document)
                if self.leases and scope != self.wan_scope:
                    raise FirewallError("WAN forwarding scope changed while leases are active")
                self.inspection = dict(supported=True, reason='', scope='direct_wan' if scope else 'forward')
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                self.inspection = dict(supported=False, reason=str(exc)[:240])
            self.inspected_at = now
        return dict(self.inspection, age_seconds=round(max(0, now-self.inspected_at), 1),
                    read_only=True, connection_checks_complete=False)

    def _prepare(self, now):
        if now - self.checked_at < CAPABILITY_TTL:
            return
        document = self._json("-t", "list", "ruleset")
        scope = capability(document, self.modules(), self.resolve_wan)
        present = owned_table(document)
        if present and self.ready and scope != self.wan_scope:
            if not self.clear('wan_scope_changed'):
                raise FirewallError("changed WAN forwarding scope could not be cleared: " + self.error)
            present = False
        if not present:
            for lease in self.leases.values():
                self._finish_lease(lease, 'kernel_table_missing')
            for lease in self.retired.values():
                self._finish_lease(lease, lease['retired_reason'])
            self.retired.clear()
            self.ready = False
            self.leases.clear()
            self.drop_baseline.clear()
            priority = SCOPED_FORWARD_PRIORITY if scope else -5
            script = ("add table inet %s { comment %s; }\n"
                      "add chain inet %s forward { type filter hook forward priority %d; policy accept; }\n"
                      "add counter inet %s %s { comment %s; }\n"
                      "add counter inet %s %s { comment %s; }\n"
                      "add map inet %s by_id { typeof ct id : verdict; flags timeout; gc-interval 1s; size %s; comment %s; }\n"
                      "add rule inet %s forward ct id vmap @by_id comment %s\n") % (
                          TABLE, json.dumps(OWNER), TABLE, priority,
                          TABLE, DROPPED_UPLOAD, json.dumps(OWNER), TABLE, DROPPED_DOWNLOAD, json.dumps(OWNER),
                          TABLE, MAX_LEASES, json.dumps(OWNER), TABLE, json.dumps(OWNER))
            self.runner([self.nft, "-c", "-f", "-"], script)
            self._apply(script)
            if not owned_table(self._json("list", "tables")):
                raise FirewallError("owned table creation could not be verified")
            self.ready = True
        elif not self.ready:
            raise FirewallError("leftover Anti-PCDN rules require owned-table cleanup")
        self.wan_scope = scope
        self.checked_at = now

    def _route_wan(self, identity, interface):
        version, proto, source, sport, peer, dport = identity
        args = [self.ip, "-j", "-%d" % version, "route", "get", peer, "from", source,
                "iif", interface, "mark", "0", "ipproto", "tcp" if proto == 6 else "udp",
                "sport", str(sport), "dport", str(dport)]
        routes = json.loads(self.runner(args))
        if (not isinstance(routes, list) or len(routes) != 1 or not isinstance(routes[0], dict)
                or routes[0].get("type", "unicast") != "unicast"):
            raise FirewallError("the candidate has no verified direct WAN route")
        dev = routes[0].get("dev")
        index = self.resolve_wan(dev) if isinstance(dev, str) and dev != interface else None
        if index not in self.wan_scope:
            raise FirewallError("the candidate does not use a verified direct WAN interface")
        return index

    def install(self, row, seconds, now):
        """Return a lease, or None during identity warmup/veto (see error).

        All times are monotonic. Fresh growth in two kernel samples can satisfy
        the observation requirement. Every installation still resolves the
        exact identity immediately before writing; repeat calls never renew TTL.
        """
        self.pending_identity = False
        self.install_outcome = 'invalid_candidate'
        self.attempt_chain = None
        self.checked_upload = None
        started = time.monotonic()
        try:
            self.expire(now, cleanup=False)
            if row.get("guards"):
                raise FirewallError("protected or incomplete candidate cannot be blocked")
            token = row.get("id")
            if not isinstance(token, str) or not 1 <= len(token) <= 128:
                raise FirewallError("invalid flow identity")
            if token in self.leases:
                if self.leases[token]["state"] != "installed":
                    raise FirewallError("unverified lease awaits cleanup or kernel expiry")
                return self.leases[token]
            if type(seconds) is not int or not 30 <= seconds <= 600:
                raise FirewallError("block duration must be 30 to 600 seconds")
            observed = row.get("last_observed")
            if (type(observed) not in (int, float) or not math.isfinite(observed)
                    or not 0 <= now - observed <= MAX_AGE):
                raise FirewallError("candidate observation is stale or missing")
            birth = row.get("birth")
            if type(birth) not in (int, float) or not math.isfinite(birth) or birth <= 0:
                raise FirewallError("flow birth identity is required")
            interface = row.get("interface", "")
            mac = row.get("mac", "")
            if (not isinstance(interface, str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", interface)
                    or interface in (".", "..") or not isinstance(mac, str)
                    or not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac)
                    or int(mac[:2], 16) & 1 or mac == "00:00:00:00:00:00"):
                raise FirewallError("invalid LAN interface or device MAC")
            identity = conntrack.flow_tuple(row)
            if (len(self.leases) + len(self.retired) >= MAX_LEASES
                    or sum(lease["mac"] == mac for lease in self.leases.values()) >= MAX_DEVICE_LEASES):
                self.install_outcome = 'kernel_lease_limit'
                raise FirewallError("active connection lease limit reached")
            self.install_outcome = 'platform_check_failed'
            self._prepare(now)
            self.install_outcome = 'neighbour_unverified'
            if self.neighbours(identity[2], interface) != mac:
                raise FirewallError("current neighbour MAC does not match the scored device")
            self.install_outcome = 'conntrack_unverified'
            resolved = self.resolver(row)
            identifier = resolved.get("id")
            if row.get('evidence_source') == 'conntrack_fast' and identifier != row.get('ct_id'):
                raise FirewallError('kernel counter identity changed before enforcement')
            lan_direction = resolved.get("lan_direction", "original")
            original = resolved.get("tuple")
            if (type(identifier) is not int or not 1 <= identifier <= 0xffffffff
                    or lan_direction not in ("original", "reply")
                    or original != (identity if lan_direction == "original" else conntrack.reverse(identity))):
                raise FirewallError("invalid exact conntrack identity")
            self.checked_upload = resolved.get('upload_bytes')
            self.install_outcome = 'direct_wan_unverified'
            wan_index = self._route_wan(identity, interface) if self.wan_scope else None
            fingerprint = (identifier, original, lan_direction, interface, mac, birth, wan_index)
            previous = self.probes.get(token)
            prior = row.get("prior_upload_observed")
            sampled_twice = (row.get("evidence_source") == "conntrack_fast"
                             and type(prior) in (int, float) and 0 < observed - prior <= MAX_POLL_GAP
                             and now - observed <= FRESH_SAMPLE_SECONDS)
            if not sampled_twice:
                if previous is None or previous[0] != fingerprint:
                    if len(self.probes) >= MAX_LEASES:
                        self.probes.pop(next(iter(self.probes)))
                    self.probes[token] = (fingerprint, now, observed)
                if (previous is None or previous[0] != fingerprint
                        or now - previous[1] < 2 or observed <= previous[2]):
                    self.pending_identity = True
                    self.install_outcome = 'identity_wait'
                    self.error = "waiting for a second fresh observation of the same conntrack ID"
                    return None
            self.install_outcome = 'conntrack_unverified'
            key = (identifier, original, interface)
            if any(lease["ct_id"] == identifier for lease in self.leases.values()):
                raise FirewallError("conntrack ID already has a lease under another flow identity")
            max_age = FRESH_SAMPLE_SECONDS if sampled_twice else MAX_AGE
            if now + time.monotonic() - started - observed > max_age:
                self.install_outcome = 'candidate_stale'
                raise FirewallError("candidate observation became stale during identity checks")
            self.serial += 1
            name = lease_chain(token, identifier, self.serial)
            self.attempt_chain = name
            script = lease_script(name, interface, original, identifier, seconds, lan_direction, wan_index,
                                  count_connection=self.audit is not None)
            lease = {"id": token, "mac": mac, "expires": now + seconds, "score": row.get("score", 0),
                     "state": "installed", "key": key, "chain": name, "interface": interface,
                     "ct_id": identifier, "lan_direction": lan_direction, "ip": identity[2], "peer": identity[4],
                     "sport": identity[3], "dport": identity[5], "proto": identity[1],
                     "protocol": row.get("protocol", "")}
            if self.audit is not None:
                lease.update(submitted_at=self.wall(), drop_zero={}, drop_first=set(), drop_last={}, drop_final=False)
            try:
                self.install_outcome = 'kernel_write_failed'
                self._apply(script)
                lease["expires"] = now + seconds + math.ceil(time.monotonic() - started)
                self.install_outcome = 'kernel_verification_failed'
                if not has_element(self._json("list", "map", "inet", TABLE, "by_id"), name, identifier):
                    raise FirewallError("kernel lease readback did not match the exact connection")
            except Exception:
                # A timeout can lose the acknowledgement after commit.
                lease["expires"] = now + seconds + math.ceil(time.monotonic() - started)
                if not self._rollback(lease):
                    self.install_outcome = 'rollback_pending'
                    lease["state"] = "unverified_cleanup_pending"
                    self.leases[token] = lease
                    if self.audit is not None:
                        self.audit('rollback_pending', self.wall(), lease, reason=self.install_outcome)
                    raise FirewallError("lease verification and rollback failed; kernel TTL still bounds expiry") from None
                raise
            self.leases[token] = lease
            self.probes.pop(token, None)
            self.error = ""
            self.install_outcome = 'installed'
            if self.audit is not None:
                self.audit('lease_installed', self.wall(), lease, connection_upload_bytes_at_check=self.checked_upload,
                           submitted_at=round(lease['submitted_at'], 3))
            return lease
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            self.error = str(error)[:240]
            self.checked_at = float("-inf")
            return None

    def _rollback(self, lease):
        try:
            self._delete_element(lease)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            if self.audit is None or 'No such file or directory' not in str(error):
                return False
            # A missing object may also mean a partial prior cleanup. Defer
            # removal only after proving no live verdict points at this chain.
            try:
                document = self._json('list', 'map', 'inet', TABLE, 'by_id')
                if has_element(document, lease['chain'], lease['ct_id']):
                    return False
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                return False
            self._retire_lease(lease, self.install_outcome)
            return True
        if self.audit is not None:
            self._retire_lease(lease, self.install_outcome, detached=True)
        return True

    def _delete_element(self, lease):
        self._apply("delete element inet %s by_id { %s }\ndelete chain inet %s %s\n" % (TABLE, lease["ct_id"], TABLE, lease["chain"]))

    def release(self, token, now, reason='manual_release', **fields):
        lease = self.leases.get(token)
        if lease is None:
            return False
        try:
            if owned_table(self._json("list", "tables")):
                document = self._json("list", "map", "inet", TABLE, "by_id")
                live = has_element(document, lease["chain"], lease["ct_id"])
                if live:
                    self._delete_element(lease)
                if not live or self.audit is not None:
                    self._retire_lease(lease, reason, detached=live, **fields)
            else:
                self._finish_lease(lease, 'kernel_table_missing')
            self.leases.pop(token, None)
            self.probes.pop(token, None)
            self.error = ""
            return True
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            self.error = str(error)[:240]
            return False

    def expire(self, now, cleanup=True):
        expired = [token for token, lease in self.leases.items() if lease["expires"] <= now]
        for token in expired:
            lease = self.leases.pop(token)
            self._retire_lease(lease, 'ttl_expired')
        if cleanup and self.retired and now - self.last_cleanup >= 3:
            self.last_cleanup = now
            try:
                if owned_table(self._json("list", "tables")):
                    self._reap()
                else:
                    for lease in self.retired.values():
                        self._finish_lease(lease, lease['retired_reason'])
                    self.retired.clear()
                    self.ready = False
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                self.error = "expired chain cleanup pending: " + str(error)[:180]
        self.probes = {token: probe for token, probe in self.probes.items() if now - probe[1] <= 30}
        return expired

    def _reap(self):
        if self.audit is not None and any(not lease['drop_final'] for lease in self.retired.values()):
            self.sample_drops()
        lines = []
        # A chain and both counter deletions take 219 bytes per lease.
        chains = list(self.retired)[:18 if self.audit is not None else 32]
        for chain in chains:
            if not self.retired[chain]['detached']:
                lines.append('delete chain inet %s %s\n' % (TABLE, chain))
            if self.audit is not None:
                lines.extend('delete counter inet %s %s%s\n' % (TABLE, chain, suffix) for suffix in ('_up', '_down'))
        try:
            self._apply(''.join(lines))
        except FirewallError as error:
            if 'No such file or directory' not in str(error):
                raise
            # An unacknowledged transaction may never have created the chain
            # or its counters. Reconcile once using the bounded owned table.
            records = objects(self._json('-t', 'list', 'table', 'inet', TABLE))
            names = {obj[kind].get('name') for obj in records for kind in ('counter', 'chain') if kind in obj}
            remaining = [line for line in lines if line.split()[-1] in names]
            if remaining:
                self._apply(''.join(remaining))
        for chain in chains:
            lease = self.retired.pop(chain)
            self._finish_lease(lease, lease['retired_reason'])

    def clear(self, reason='worker_cleanup'):
        try:
            present = owned_table(self._json("list", "tables"))
            if present:
                self.sample_drops()
                self._apply("delete table inet %s\n" % TABLE)
            for lease in self.leases.values():
                self._finish_lease(lease, reason if present else 'kernel_table_missing')
            for lease in self.retired.values():
                self._finish_lease(lease, lease['retired_reason'])
            self.leases.clear()
            self.probes.clear()
            self.retired.clear()
            self.ready = False
            self.wan_scope = ()
            self.drop_baseline.clear()
            self.checked_at = float("-inf")
            self.error = ""
            return True
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            self.error = str(error)[:240]
            return False
