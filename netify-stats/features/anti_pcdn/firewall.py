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
import subprocess
import time

from . import conntrack

TABLE = "betterdpi_anti_pcdn"
OWNER = "BetterDPI Anti-PCDN leases v1"
MAX_LEASES = 256
CAPABILITY_TTL = 5
MAX_AGE = 15
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


def capability(document, modules):
    records = objects(document)
    if not any(obj.get("table", {}).get("family") == "inet" and obj.get("table", {}).get("name") == "fw4"
               for obj in records if isinstance(obj, dict)):
        raise FirewallError("only the OpenWrt fw4 forwarding path is supported")
    if not any(obj.get("chain", {}).get("family") == "inet" and obj.get("chain", {}).get("table") == "fw4"
               and obj["chain"].get("hook") == "forward" and obj["chain"].get("type") == "filter"
               and obj["chain"].get("prio") == 0 for obj in records if isinstance(obj, dict)):
        raise FirewallError("the fw4 forward hook is unavailable or has an unsupported priority")
    def unsafe(value):
        if isinstance(value, dict):
            return any(str(key).lower() in ("flowtable", "flow", "tproxy", "notrack")
                       or unsafe(item) for key, item in value.items())
        if isinstance(value, list):
            return any(unsafe(item) for item in value)
        return False
    if unsafe(records):
        raise FirewallError("flow offload, TPROXY or untracked forwarding is not supported")
    if len(modules) > 262144:
        raise FirewallError("module inventory exceeds safety limit")
    names = [line.split()[0].lower() for line in modules.splitlines() if line.split()]
    if any(any(word in name for word in ("shortcut", "fast_classifier", "ecm", "nss", "sfe", "hwnat", "hnat", "tproxy"))
           for name in names):
        raise FirewallError("vendor accelerated forwarding is not supported")


def lease_chain(token, identifier):
    return "lease_" + hashlib.sha256((token + ":" + str(identifier)).encode()).hexdigest()[:24]


def lease_script(name, interface, identity, identifier, seconds, lan_direction="original"):
    version, proto, src, sport, dst, dport = identity
    family = "ip" if version == 4 else "ip6"
    lines = ["add chain inet %s %s { comment %s; }" % (TABLE, name, json.dumps(OWNER))]
    # A single ID -> verdict lookup dispatches to at most two exact guard rules.
    # Avoid ct-id concatenations: nft can lose their width metadata on readback.
    for direction, interface_key in (("original", "iifname"), ("reply", "oifname")):
        if lan_direction == "reply":
            interface_key = "oifname" if direction == "original" else "iifname"
        lines.append("add rule inet %s %s meta nfproto ipv%s meta l4proto %s ct direction %s meta %s %s ct original %s saddr %s ct original proto-src %s ct original %s daddr %s ct original proto-dst %s counter drop comment %s" %
                     (TABLE, name, version, "tcp" if proto == 6 else "udp", direction,
                      interface_key, json.dumps(interface), family, src, sport, family, dst, dport,
                      json.dumps(name + ":" + direction)))
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
                 modules=read_modules, nft=None):
        self.runner, self.resolver, self.neighbours, self.modules = runner, resolver, neighbours, modules
        self.nft = nft or shutil.which("nft") or "/usr/sbin/nft"
        self.leases, self.probes, self.retired = {}, {}, {}
        self.ready = False
        self.last_cleanup = float("-inf")
        self.error, self.warning = "", WARNING
        self.pending_identity = False
        self.checked_at = float("-inf")

    def _json(self, *args):
        try:
            return json.loads(self.runner([self.nft, "-j", *args]))
        except (ValueError, TypeError) as error:
            raise FirewallError("invalid nft JSON readback") from error

    def _apply(self, script):
        return self.runner([self.nft, "-f", "-"], script)

    def _prepare(self, now):
        if now - self.checked_at < CAPABILITY_TTL:
            return
        document = self._json("list", "ruleset")
        capability(document, self.modules())
        present = owned_table(document)
        if not present:
            self.retired.clear()
            self.ready = False
            self.leases.clear()
            script = ("add table inet %s { comment %s; }\n"
                      "add chain inet %s forward { type filter hook forward priority -5; policy accept; }\n"
                      "add map inet %s by_id { typeof ct id : verdict; flags timeout; gc-interval 1s; size %s; comment %s; }\n"
                      "add rule inet %s forward ct id vmap @by_id comment %s\n") % (TABLE, json.dumps(OWNER), TABLE, TABLE, MAX_LEASES, json.dumps(OWNER), TABLE, json.dumps(OWNER))
            self.runner([self.nft, "-c", "-f", "-"], script)
            self._apply(script)
            if not owned_table(self._json("list", "table", "inet", TABLE)):
                raise FirewallError("owned table creation could not be verified")
            self.ready = True
        elif not self.ready:
            raise FirewallError("leftover Anti-PCDN rules require owned-table cleanup")
        self.checked_at = now

    def install(self, row, seconds, now):
        """Return a lease, or None during identity warmup/veto (see error).

        All times are monotonic. A second fresh candidate observation after two
        seconds must resolve to the same kernel ID; repeat calls never renew TTL.
        """
        self.pending_identity = False
        started = time.monotonic()
        try:
            self.expire(now)
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
            if len(self.leases) + len(self.retired) >= MAX_LEASES or sum(lease["mac"] == mac for lease in self.leases.values()) >= 16:
                raise FirewallError("active connection lease limit reached")
            self._prepare(now)
            if self.neighbours(identity[2], interface) != mac:
                raise FirewallError("current neighbour MAC does not match the scored device")
            resolved = self.resolver(row)
            identifier = resolved.get("id")
            lan_direction = resolved.get("lan_direction", "original")
            original = resolved.get("tuple")
            if (type(identifier) is not int or not 1 <= identifier <= 0xffffffff
                    or lan_direction not in ("original", "reply")
                    or original != (identity if lan_direction == "original" else conntrack.reverse(identity))):
                raise FirewallError("invalid exact conntrack identity")
            fingerprint = (identifier, original, lan_direction, interface, mac, birth)
            previous = self.probes.get(token)
            if previous is None or previous[0] != fingerprint:
                if len(self.probes) >= MAX_LEASES:
                    self.probes.pop(next(iter(self.probes)))
                self.probes[token] = (fingerprint, now, observed)
                self.pending_identity = True
                self.error = "waiting for a second fresh observation of the same conntrack ID"
                return None
            if now - previous[1] < 2 or observed <= previous[2]:
                self.pending_identity = True
                self.error = "waiting for a second fresh observation of the same conntrack ID"
                return None
            name = lease_chain(token, identifier)
            key = (identifier, original, interface)
            if any(lease["ct_id"] == identifier for lease in self.leases.values()):
                raise FirewallError("conntrack ID already has a lease under another flow identity")
            if now + time.monotonic() - started - observed > MAX_AGE:
                raise FirewallError("candidate observation became stale during identity checks")
            script = lease_script(name, interface, original, identifier, seconds, lan_direction)
            lease = {"id": token, "mac": mac, "expires": now + seconds, "score": row.get("score", 0),
                     "state": "installed", "key": key, "chain": name, "interface": interface,
                     "ct_id": identifier, "lan_direction": lan_direction, "ip": identity[2], "peer": identity[4],
                     "sport": identity[3], "dport": identity[5], "proto": identity[1],
                     "protocol": row.get("protocol", "")}
            try:
                self._apply(script)
                lease["expires"] = now + seconds + math.ceil(time.monotonic() - started)
                if not has_element(self._json("list", "map", "inet", TABLE, "by_id"), name, identifier):
                    raise FirewallError("kernel lease readback did not match the exact connection")
            except Exception:
                # A command timeout can lose the acknowledgement after the
                # kernel committed. Roll back even when applying raised.
                lease["expires"] = now + seconds + math.ceil(time.monotonic() - started)
                try:
                    self._delete_element(lease)
                except Exception:
                    lease["state"] = "unverified_cleanup_pending"
                    self.leases[token] = lease
                    raise FirewallError("lease verification and rollback failed; kernel TTL still bounds expiry") from None
                raise
            self.leases[token] = lease
            self.probes.pop(token, None)
            self.error = ""
            return lease
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            self.error = str(error)[:240]
            self.checked_at = float("-inf")
            return None

    def _delete_element(self, lease):
        self._apply("delete element inet %s by_id { %s }\ndelete chain inet %s %s\n" % (TABLE, lease["ct_id"], TABLE, lease["chain"]))

    def release(self, token, now):
        self.expire(now)
        lease = self.leases.get(token)
        if lease is None:
            return False
        try:
            if owned_table(self._json("list", "ruleset")):
                document = self._json("list", "map", "inet", TABLE, "by_id")
                if has_element(document, lease["chain"], lease["ct_id"]):
                    self._delete_element(lease)
                else:
                    self.retired[lease["chain"]] = lease
            self.leases.pop(token, None)
            self.probes.pop(token, None)
            self.error = ""
            return True
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            self.error = str(error)[:240]
            return False

    def expire(self, now):
        expired = [token for token, lease in self.leases.items() if lease["expires"] <= now]
        for token in expired:
            lease = self.leases.pop(token)
            self.retired[lease["chain"]] = lease
        if self.retired and now - self.last_cleanup >= 5:
            self.last_cleanup = now
            try:
                if owned_table(self._json("list", "ruleset")):
                    for chain in list(self.retired)[:4]:
                        self._apply("delete chain inet %s %s\n" % (TABLE, chain))
                        self.retired.pop(chain, None)
                else:
                    self.retired.clear()
                    self.ready = False
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                self.error = "expired chain cleanup pending: " + str(error)[:180]
        self.probes = {token: probe for token, probe in self.probes.items() if now - probe[1] <= 30}
        return expired

    def clear(self):
        try:
            if owned_table(self._json("list", "ruleset")):
                self._apply("delete table inet %s\n" % TABLE)
            self.leases.clear()
            self.probes.clear()
            self.retired.clear()
            self.ready = False
            self.checked_at = float("-inf")
            self.error = ""
            return True
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            self.error = str(error)[:240]
            return False
