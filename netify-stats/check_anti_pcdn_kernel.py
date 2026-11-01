#!/usr/bin/env python3
"""Optional Anti-PCDN software-kernel integration check (about 45 seconds).

Requires Linux, Python 3, nft, ip, nsenter, and permission to create user/network
namespaces. Nothing is installed. Every public invocation creates fresh isolated
namespaces; isolation failure stops the check before firewall or network writes.
This is not part of unittest discovery and does not validate router acceleration.
"""

import argparse
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import time


SCRIPT = str(Path(__file__).resolve())


class CheckError(RuntimeError):
    pass


def require(condition, message):
    # Safety checks must also run under python -O.
    if not condition:
        raise CheckError(message)


def namespace(pid, kind):
    return os.readlink("/proc/%s/ns/%s" % (pid, kind))


def isolated_child(mode, nft=None, **options):
    """Pass a bounded handshake over an inherited pipe, never a namespace flag."""
    read_fd, write_fd = os.pipe()
    namespace_fds = []
    process = None
    try:
        for kind in ("net", "user"):
            namespace_fds.append(os.open("/proc/self/ns/" + kind, os.O_RDONLY))
        parent_net, parent_user = namespace("self", "net"), namespace("self", "user")
        args = ["unshare"]
        if mode == "worker":
            args.extend(["--user", "--map-root-user"])
        args.extend(["--net", sys.executable, SCRIPT, "--_" + mode, str(read_fd)])
        process = subprocess.Popen(args, pass_fds=(read_fd, *namespace_fds), **options)
        # The parent can inspect its descendant's namespaces. The reverse read
        # is denied on some kernels after crossing a user-namespace boundary.
        deadline = time.monotonic() + 2.5
        while True:
            require(process.poll() is None, "namespace launcher exited before isolation was verified")
            try:
                fresh = namespace(process.pid, "net") != parent_net
                if mode == "worker":
                    fresh = fresh and namespace(process.pid, "user") != parent_user
            except OSError:
                fresh = False
            if fresh:
                break
            require(time.monotonic() < deadline, "namespace creation was not verified")
            time.sleep(0.01)
        require(namespace("self", "net") == parent_net and namespace("self", "user") == parent_user,
                "launcher namespaces changed")
        payload = json.dumps({
            "mode": mode, "parent": os.getpid(), "netns": parent_net, "userns": parent_user,
            "namespace_fds": namespace_fds, "nft": nft,
        }).encode()
        os.write(write_fd, payload)
        return process
    except BaseException:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait()
        raise
    finally:
        os.close(read_fd)
        os.close(write_fd)
        for fd in namespace_fds:
            os.close(fd)


def verify_isolation(mode, fd):
    """Verify the live parent and both namespace boundaries before any writes."""
    try:
        require(select.select([fd], [], [], 3)[0], "missing launcher handshake")
        data = os.read(fd, 2049)
    finally:
        os.close(fd)
    require(len(data) <= 2048, "oversized launcher handshake")
    try:
        info = json.loads(data)
    except (TypeError, ValueError) as error:
        raise CheckError("invalid launcher handshake") from error
    require(isinstance(info, dict), "invalid launcher handshake")
    parent = os.getppid()
    require(info.get("mode") == mode and info.get("parent") == parent,
            "launcher parent does not match")
    descriptors = info.get("namespace_fds")
    require(isinstance(descriptors, list) and len(descriptors) == 2
            and all(type(value) is int and value >= 3 for value in descriptors)
            and len(set(descriptors)) == 2 and fd not in descriptors,
            "missing inherited parent namespace descriptors")
    try:
        for kind, descriptor in zip(("net", "user"), descriptors):
            inherited = os.readlink("/proc/self/fd/" + str(descriptor))
            require(inherited == info.get(kind + "ns") and inherited.startswith(kind + ":["),
                    "inherited parent namespace does not match launcher")
            if kind == "net" or mode == "worker":
                own = os.stat("/proc/self/ns/" + kind)
                held = os.fstat(descriptor)
                require((own.st_dev, own.st_ino) != (held.st_dev, held.st_ino),
                        "refusing to run in the parent %s namespace" % kind)
        if mode == "worker":
            require(os.geteuid() == 0, "mapped namespace root is required")
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    require({name for _index, name in socket.if_nameindex()} == {"lo"},
            "namespace is not fresh: interfaces other than lo exist")
    return info


def peer_worker(fd):
    verify_isolation("peer", fd)
    sockets = {}
    print(json.dumps({"pid": os.getpid(), "netns": namespace("self", "net")}), flush=True)
    try:
        for line in sys.stdin:
            try:
                request = json.loads(line)
                name, action = request.get("name"), request["op"]
                if action == "bind":
                    sock = socket.socket(socket.AF_INET if request["v"] == 4 else socket.AF_INET6,
                                         socket.SOCK_DGRAM if request["proto"] == "udp" else socket.SOCK_STREAM)
                    sock.settimeout(0.4)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind((request["ip"], request["port"]))
                    sockets[name] = sock
                    result = True
                elif action == "connect":
                    sockets[name].connect((request["ip"], request["port"]))
                    result = True
                elif action == "listen":
                    sockets[name].listen(8)
                    result = True
                elif action == "accept":
                    sockets[request["new"]], _address = sockets[name].accept()
                    sockets[request["new"]].settimeout(0.4)
                    result = True
                elif action == "send":
                    data = request["data"].encode()
                    if "ip" in request:
                        result = sockets[name].sendto(data, (request["ip"], request["port"]))
                    else:
                        result = sockets[name].send(data)
                elif action == "recv":
                    result = sockets[name].recv(65535).decode()
                elif action == "close":
                    sockets.pop(name).close()
                    result = True
                else:
                    raise CheckError("unknown peer action")
                print(json.dumps({"ok": result}), flush=True)
            except socket.timeout:
                print(json.dumps({"timeout": True}), flush=True)
            except Exception as error:
                print(json.dumps({"error": str(error)}), flush=True)
    finally:
        for sock in sockets.values():
            sock.close()


def receive(process):
    require(select.select([process.stdout], [], [], 3)[0], "peer response timed out")
    line = process.stdout.readline()
    require(bool(line), "isolated peer exited")
    result = json.loads(line)
    require("error" not in result, "peer failed: %s" % result.get("error"))
    return result


def peer(process, **request):
    process.stdin.write(json.dumps(request) + "\n")
    process.stdin.flush()
    return receive(process)


class Fixture:
    def __init__(self, nft):
        self.nft = nft
        self.children = []
        self.firewall = None
        self.started = time.monotonic()

    def command(self, args, data=None):
        result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=3)
        require(result.returncode == 0, result.stderr.strip() or "command failed: " + args[0])
        return result.stdout

    def apply(self, script):
        self.command([self.nft, "-f", "-"], script)

    def ruleset(self):
        return json.loads(self.command([self.nft, "-j", "list", "ruleset"]))

    def setup(self):
        # verify_isolation has already run. Read-only emptiness check is mandatory.
        records = self.ruleset().get("nftables")
        require(isinstance(records, list) and all(set(row) == {"metainfo"} for row in records),
                "refusing to modify a namespace with an existing ruleset")
        for tool in ("ip", "nsenter"):
            require(shutil.which(tool), "required command is unavailable: " + tool)
        for interface, name, base, prefix6 in (("br-lan", "client", "192.0.2", "2001:db8:1"),
                                               ("wan", "server", "198.51.100", "2001:db8:2")):
            child = isolated_child("peer", text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            self.children.append(child)
            info = receive(child)
            require(info.get("pid") == child.pid and info.get("netns") == namespace(child.pid, "net")
                    and info["netns"] != namespace("self", "net"), "peer is not isolated")
            self.command(["ip", "link", "add", interface, "type", "veth", "peer", "name", name])
            self.command(["ip", "link", "set", name, "netns", str(child.pid)])
            self.command(["ip", "addr", "add", base + ".1/24", "dev", interface])
            self.command(["ip", "link", "set", interface, "up"])
            self.command(["ip", "-6", "addr", "add", prefix6 + "::1/64", "dev", interface, "nodad"])
            ip = ["nsenter", "-t", str(child.pid), "-n", "ip"]
            suffix = "10" if name == "client" else "20"
            for args in (["link", "set", "lo", "up"],
                         ["addr", "add", base + "." + suffix + "/24", "dev", name],
                         ["link", "set", name, "up"],
                         ["route", "add", "default", "via", base + ".1"],
                         ["-6", "addr", "add", prefix6 + "::" + suffix + "/64", "dev", name, "nodad"],
                         ["-6", "route", "add", "default", "via", prefix6 + "::1"]):
                self.command(ip + args)
        # These sysctls belong to the verified new network namespace.
        for path in ("/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"):
            with open(path, "w") as stream:
                stream.write("1")
        self.apply("add table inet fw4\n"
                   "add chain inet fw4 forward { type filter hook forward priority 0; policy accept; }\n"
                   "add rule inet fw4 forward ct state established,related accept\n")
        sys.path.insert(0, str(Path(SCRIPT).parent / "features"))
        from anti_pcdn import conntrack, firewall
        self.conntrack, self.backend = conntrack, firewall
        # A synthetic software-only fixture cannot establish host/vendor safety.
        self.firewall = firewall.Firewall(nft=self.nft, modules=lambda: "")
        time.sleep(1.5)  # Allow the fresh IPv6 links to finish link-local initialization.

    def exchange(self, sender, source, receiver, target, message, destination=None):
        request = {"op": "send", "name": source, "data": message}
        if destination:
            request.update(ip=destination[0], port=destination[1])
        peer(sender, **request)
        return peer(receiver, op="recv", name=target)

    def case(self, index, version, protocol, incoming=False):
        client, server = self.children
        source = "192.0.2.10" if version == 4 else "2001:db8:1::10"
        target = "198.51.100.20" if version == 4 else "2001:db8:2::20"
        sport, dport = 12345 + index, 443 + index
        peer(server, op="bind", name="s", v=version, proto=protocol, ip=target, port=dport)
        peer(client, op="bind", name="c", v=version, proto=protocol, ip=source, port=sport)
        if protocol == "tcp":
            peer(server, op="listen", name="s")
            peer(client, op="connect", name="c", ip=target, port=dport)
            peer(server, op="accept", name="s", new="a")
            server_name, to_server, to_client = "a", None, None
        else:
            server_name, to_server, to_client = "s", (target, dport), (source, sport)

        def outgoing(message):
            return self.exchange(client, "c", server, server_name, message, to_server)

        def returning(message):
            return self.exchange(server, server_name, client, "c", message, to_client)

        first, second = (returning, outgoing) if incoming else (outgoing, returning)
        require(first("baseline") == {"ok": "baseline"}, "baseline traffic failed")
        require(second("reply") == {"ok": "reply"}, "baseline reply failed")
        row = {"ip": source, "peer": target, "sport": sport, "dport": dport,
               "proto": 17 if protocol == "udp" else 6}
        identity = self.conntrack.lookup(row)
        require(self.conntrack.lookup(row) == identity, "conntrack ID changed")
        require(identity["lan_direction"] == ("reply" if incoming else "original"),
                "conntrack direction mismatch")
        row.update(id="fixture_" + str(index), mac=self.conntrack.neighbour(source, "br-lan"),
                   interface="br-lan", birth=time.monotonic() - 5,
                   last_observed=time.monotonic(), score=99)
        fw = self.firewall
        require(fw.install(row, 30, row["last_observed"]) is None and fw.pending_identity, fw.error)

        # Simulate a stale CT-ID binding: the exact tuple guard must allow traffic.
        wrong_tuple = list(identity["tuple"])
        wrong_tuple[3] += 10
        wrong_chain = "fixture_wrong_" + str(index)
        self.apply(self.backend.lease_script(wrong_chain, "br-lan", tuple(wrong_tuple),
                                            identity["id"], 30, identity["lan_direction"]))
        require(outgoing("wrong-tuple") == {"ok": "wrong-tuple"}, "stale-ID guard blocked original traffic")
        require(returning("wrong-reply") == {"ok": "wrong-reply"}, "stale-ID guard blocked reply traffic")
        self.apply("delete element inet betterdpi_anti_pcdn by_id { %s }\n"
                   "delete chain inet betterdpi_anti_pcdn %s\n" % (identity["id"], wrong_chain))

        time.sleep(2.05)
        require(outgoing("fresh") == {"ok": "fresh"}, "fresh observation traffic failed")
        row["last_observed"] = time.monotonic()
        lease = fw.install(row, 30, row["last_observed"])
        require(lease is not None, fw.error)
        expiry = lease["expires"]
        repeated = fw.install(row, 600, time.monotonic())
        require(repeated is not None and repeated["expires"] == expiry, "repeat installation renewed TTL")
        require(outgoing("blocked-out") == {"timeout": True}, "original direction was not blocked")
        require(returning("blocked-reply") == {"timeout": True}, "reply direction was not blocked")

        peer(client, op="bind", name="other", v=version, proto=protocol, ip=source, port=sport + 1000)
        other_server = "s"
        if protocol == "tcp":
            peer(client, op="connect", name="other", ip=target, port=dport)
            peer(server, op="accept", name="s", new="b")
            other_server = "b"
        require(self.exchange(client, "other", server, other_server, "unrelated", to_server)
                == {"ok": "unrelated"}, "an unrelated source port was blocked")
        if index < 2 or incoming:
            require(fw.release(row["id"], time.monotonic()), fw.error)
            if protocol == "udp":
                require(outgoing("released") == {"ok": "released"}, "release did not restore traffic")
        for name in ("c", "other"):
            peer(client, op="close", name=name)
        if protocol == "tcp":
            for name in ("a", "b"):
                peer(server, op="close", name=name)
        peer(server, op="close", name="s")
        print("PASS IPv%s %s %s: exact identity, tuple guard, both directions, unrelated flow%s" %
              (version, protocol.upper(), "incoming" if incoming else "outgoing",
               ", release" if index < 2 or incoming else ", awaiting kernel TTL"), flush=True)

    def finish(self):
        # No backend expiration/cleanup calls while waiting: expiry must be kernel-owned.
        latest = max(lease["expires"] for lease in self.firewall.leases.values())
        deadline = latest + 3
        while True:
            document = self.ruleset()
            maps = [item["map"] for item in document["nftables"]
                    if item.get("map", {}).get("table") == "betterdpi_anti_pcdn"
                    and item["map"].get("name") == "by_id"]
            require(len(maps) == 1, "lease map disappeared")
            if not maps[0].get("elem"):
                break
            require(time.monotonic() < deadline, "kernel TTL did not expire")
            time.sleep(0.5)
        self.firewall.expire(max(time.monotonic(), latest + 0.01))
        require(not self.firewall.leases, "expired leases remain active")
        require(self.firewall.clear(), self.firewall.error)
        document = self.ruleset()
        tables = {item["table"]["name"] for item in document["nftables"] if "table" in item}
        require(tables == {"fw4"}, "cleanup changed a foreign table or left the owned table")
        print("PASS kernel-only 30s expiry, deferred cleanup, owned-table clear (%.1fs)" %
              (time.monotonic() - self.started), flush=True)

    def close(self):
        # Namespace destruction removes all fixture interfaces/rules, including failures.
        for child in self.children:
            if child.poll() is None:
                child.terminate()
        for child in self.children:
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            for stream in (child.stdin, child.stdout):
                if stream:
                    stream.close()


def worker(fd):
    info = verify_isolation("worker", fd)
    require(isinstance(info.get("nft"), str) and os.path.isabs(info["nft"]), "missing nft executable")
    fixture = Fixture(info["nft"])
    print("Isolated software fixture; synthetic fw4 and empty module inventory. "
          "Router hardware/acceleration are not validated.", flush=True)
    try:
        fixture.setup()
        for index, (version, protocol) in enumerate(((4, "udp"), (4, "tcp"), (6, "udp"), (6, "tcp"))):
            fixture.case(index, version, protocol)
        fixture.case(4, 4, "udp", incoming=True)
        fixture.case(5, 6, "udp", incoming=True)
        fixture.finish()
    finally:
        fixture.close()


def main():
    if len(sys.argv) == 3 and sys.argv[1] in ("--_worker", "--_peer"):
        action = worker if sys.argv[1] == "--_worker" else peer_worker
        action(int(sys.argv[2]))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nft", help="existing nft executable (default: search PATH); no packages are installed")
    args = parser.parse_args()
    nft = shutil.which(args.nft or "nft")
    require(nft is not None, "nft was not found; install it separately or supply --nft PATH")
    require(shutil.which("unshare"), "unshare is required; no host-namespace fallback is allowed")
    process = isolated_child("worker", nft=str(Path(nft).resolve()))
    try:
        return process.wait()
    except KeyboardInterrupt:
        process.terminate()
        process.wait()
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CheckError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("Kernel check stopped: %s" % error, file=sys.stderr)
        raise SystemExit(1)
