"""Identity parsing and firewall fail-safe tests; mocks never alter the host."""
import copy
import ipaddress
import json
import os
import socket
import struct
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "features"))
from anti_pcdn import conntrack as ct
from anti_pcdn.firewall import Firewall, FirewallError, OWNER, TABLE, capability, has_element, owned_table, run_bounded


ROW = {"id": "a" * 32, "mac": "02:00:00:00:00:01", "ip": "192.168.1.2", "peer": "8.8.8.8",
       "sport": 12345, "dport": 443, "proto": 6, "protocol": "TLS", "host": "pcdn.example.com",
       "interface": "br-lan", "birth": 1700000000000, "score": 90, "last_observed": 100}


def document(owned=False):
    records = [{"table": {"family": "inet", "name": "fw4"}},
               {"chain": {"family": "inet", "table": "fw4", "name": "forward", "type": "filter", "hook": "forward", "prio": 0}}]
    if owned:
        records += [{"table": {"family": "inet", "name": TABLE, "comment": OWNER}}]
    return {"nftables": records}


def conntrack_payload(identity, identifier=123, status=8, reply=None, zone=0):
    if reply is None:
        reply = (identity[0], identity[1], identity[4], identity[5], "203.0.113.4" if identity[0] == 4 else "2001:db8::1", 31000)
    family = socket.AF_INET if identity[0] == 4 else socket.AF_INET6
    return (bytes([family, 0, 0, 0]) + ct.attribute(0x8001, ct.tuple_attribute(identity))
            + ct.attribute(0x8002, ct.tuple_attribute(reply)) + ct.attribute(3, struct.pack("!I", status))
            + ct.attribute(12, struct.pack("!I", identifier)) + ct.attribute(18, struct.pack("!H", zone)))


class FakeNft:
    def __init__(self):
        self.document = document()
        self.calls = []
        self.elements = {}
        self.bad_readback = False
        self.bad_delete = False

    def __call__(self, args, data=None):
        self.calls.append((args, data))
        if "-j" in args:
            if "map" in args:
                entries = [[{"elem": {"val": identifier, "expires": 29, "timeout": 30}}, {"jump": {"target": name}}]
                           for identifier, name in self.elements.items()]
                return json.dumps({"nftables": [{"map": {"family": "inet", "table": TABLE, "name": "by_id",
                    "type": {"typeof": {"ct": {"key": "id"}}}, "map": "verdict", "comment": OWNER, "flags": ["timeout"],
                    "elem": [] if self.bad_readback else entries}}]})
            return json.dumps(self.document)
        if "-c" in args:
            return ""
        if data.startswith("add table"):
            self.document = document(True)
        for line in data.splitlines():
            if line.startswith("add element"):
                identifier = int(line.split("{ ", 1)[1].split()[0])
                name = line.split("jump ", 1)[1].split()[0]
                self.elements[identifier] = name
            if line.startswith("delete element"):
                if self.bad_delete:
                    raise FirewallError("delete failed")
                self.elements.pop(int(line.split("{ ", 1)[1].split()[0]), None)
        if data.startswith("delete table"):
            self.document = document()
            self.elements.clear()
        return ""


class IdentityTests(unittest.TestCase):
    def test_transport_protocol_requires_an_integer(self):
        for proto in (6.0, 17.0, True, "6"):
            with self.subTest(proto=proto), self.assertRaises(ct.IdentityError):
                ct.flow_tuple(dict(ROW, proto=proto))

    def test_subprocess_limits_output_and_elapsed_time(self):
        self.assertEqual(run_bounded([sys.executable, "-c", "print('ok')"]), "ok\n")
        with self.assertRaises(FirewallError):
            run_bounded([sys.executable, "-c", "print('x' * 300000)"])
        with self.assertRaises(FirewallError):
            run_bounded([sys.executable, "-c", "import time; time.sleep(2)"])

    def test_roundtrip_ipv4_ipv6_snat(self):
        for row in (ROW, dict(ROW, ip="fd00::2", peer="2606:4700:4700::1111", proto=17)):
            identity = ct.flow_tuple(row)
            self.assertEqual(ct.decode_conntrack(conntrack_payload(identity), identity), {"id": 123, "tuple": identity})

    def test_reject_dnat_offload_zone_and_missing_id(self):
        identity = ct.flow_tuple(ROW)
        for kwargs in ({"status": 8 | 1 << 14}, {"status": 8 | 1 << 15}, {"zone": 1}, {"identifier": 0}, {"status": 0},
                       {"reply": (4, 6, "127.0.0.1", 443, "192.168.1.2", 12345)}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ct.IdentityError):
                ct.decode_conntrack(conntrack_payload(identity, **kwargs), identity)

    def test_exact_tuple_and_invalid_attributes(self):
        identity = ct.flow_tuple(ROW)
        with self.assertRaises(ct.IdentityError):
            ct.decode_conntrack(conntrack_payload(ct.flow_tuple(dict(ROW, sport=12346))), identity)
        for data in (b"x", b"\x03\0\x01\0", b"\x08\0\x01\0", ct.attribute(1, b"a") * 2):
            with self.subTest(data=data), self.assertRaises(ct.IdentityError):
                ct.attributes(data)

    def test_message_sender_sequence_and_length(self):
        packet = struct.pack("=IHHII", 20, 0x100, 0, 55, 123) + b"abcd"
        self.assertEqual(ct.response_payload(packet, (0, 0), 0, 55, 0x100), b"abcd")
        for args in ((packet, (1, 0), 0, 55, 0x100), (packet, (0, 0), socket.MSG_TRUNC, 55, 0x100),
                     (packet, (0, 0), 0, 56, 0x100), (packet[:-1], (0, 0), 0, 55, 0x100),
                     (packet + packet, (0, 0), 0, 55, 0x100)):
            with self.subTest(args=args), self.assertRaises(ct.IdentityError):
                ct.response_payload(*args)

    def test_current_neighbour_and_incomplete_identity(self):
        ip = ipaddress.ip_address(ROW["ip"])
        def payload(state=2, index=7):
            return struct.pack("=BBHiHBB", socket.AF_INET, 0, 0, index, state, 0, 0) + ct.attribute(1, ip.packed) + ct.attribute(2, bytes.fromhex("020000000001"))
        self.assertEqual(ct.decode_neighbour(payload(), ip, 7), ROW["mac"])
        for state in (0, 1, 32):
            with self.assertRaises(ct.IdentityError):
                ct.decode_neighbour(payload(state), ip, 7)
        with self.assertRaises(ct.IdentityError):
            ct.decode_neighbour(payload(index=8), ip, 7)

    def test_inbound_non_nat_reverses_exact_get_only_on_missing_entry(self):
        identity = ct.flow_tuple(ROW)
        inbound = ct.reverse(identity)
        reply = identity
        with mock.patch.object(ct, "query", side_effect=[OSError(2, "missing"), conntrack_payload(inbound, reply=reply)]) as query:
            result = ct.lookup(ROW)
        self.assertEqual(result["tuple"], inbound)
        self.assertEqual(result["lan_direction"], "reply")
        self.assertEqual(query.call_count, 2)
        # A real kernel can match a reply tuple even in CTA_TUPLE_ORIG lookup.
        payload = conntrack_payload(inbound, reply=reply)
        with mock.patch.object(ct, "query", side_effect=[payload, payload]) as query:
            self.assertEqual(ct.lookup(ROW)["lan_direction"], "reply")
        self.assertEqual(query.call_count, 2)
        with mock.patch.object(ct, "query", side_effect=PermissionError(1, "denied")) as query:
            with self.assertRaises(PermissionError):
                ct.lookup(ROW)
        self.assertEqual(query.call_count, 1)


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.nft = FakeNft()
        self.identifier = 123
        self.firewall = Firewall(runner=self.nft, resolver=lambda row: {"id": self.identifier, "tuple": ct.flow_tuple(row)},
                                 neighbours=lambda ip, interface: ROW["mac"], modules=lambda: "nf_conntrack 123 1 - Live\n", nft="nft")

    def install(self, row=None, now=100):
        row = ROW if row is None else row
        self.assertIsNone(self.firewall.install(row, 30, now))
        return self.firewall.install(dict(row, last_observed=now + 2), 30, now + 2)

    def test_exact_two_direction_connection_and_ttl(self):
        lease = self.install()
        self.assertEqual(lease["ct_id"], 123)
        self.assertEqual(lease["key"], (123, ct.flow_tuple(ROW), "br-lan"))
        writes = "\n".join(data for args, data in self.nft.calls if data)
        self.assertIn("ct direction original meta iifname \"br-lan\"", writes)
        self.assertIn("ct direction reply meta oifname \"br-lan\"", writes)
        self.assertIn("123 timeout 30s : jump lease_", writes)
        self.assertIn("ct original ip saddr 192.168.1.2 ct original proto-src 12345 ct original ip daddr 8.8.8.8 ct original proto-dst 443", writes)
        self.assertNotIn("flush", writes)
        before = len(self.nft.calls)
        self.assertEqual(self.firewall.install(dict(ROW, last_observed=104), 600, 104), lease)
        self.assertEqual(len(self.nft.calls), before)
        self.assertGreaterEqual(lease["expires"], 132)
        self.assertLessEqual(lease["expires"], 134)
        self.assertEqual(self.firewall.expire(134), [ROW["id"]])

    def test_identity_reuse_restarts_warmup(self):
        self.firewall.install(ROW, 30, 100)
        self.identifier = 456
        self.assertIsNone(self.firewall.install(dict(ROW, last_observed=102), 30, 102))
        lease = self.firewall.install(dict(ROW, last_observed=104), 30, 104)
        self.assertEqual(lease["ct_id"], 456)

    def test_inbound_rules_use_original_remote_tuple_and_reversed_interface(self):
        self.firewall.resolver = lambda row: {"id": 123, "tuple": ct.reverse(ct.flow_tuple(row)), "lan_direction": "reply"}
        lease = self.install()
        self.assertEqual(lease["lan_direction"], "reply")
        writes = "\n".join(data for args, data in self.nft.calls if data)
        self.assertIn('ct direction original meta oifname "br-lan"', writes)
        self.assertIn('ct direction reply meta iifname "br-lan"', writes)
        self.assertIn("ct original ip saddr 8.8.8.8 ct original proto-src 443 ct original ip daddr 192.168.1.2 ct original proto-dst 12345", writes)

    def test_stale_observation_and_neighbour_change(self):
        self.assertIsNone(self.firewall.install(ROW, 30, 116))
        self.assertIn("stale", self.firewall.error)
        self.assertEqual(self.nft.calls, [])
        self.firewall.neighbours = lambda ip, interface: "02:00:00:00:00:02"
        self.assertIsNone(self.firewall.install(ROW, 30, 100))
        self.assertIn("MAC", self.firewall.error)
        self.assertFalse(self.nft.elements)

    def test_offload_tproxy_vendor_and_non_fw4_veto(self):
        for extra in ({"flowtable": {}}, {"rule": {"expr": [{"tproxy": {"port": 123}}]}},
                      {"rule": {"expr": [{"flow": {"op": "add", "flowtable": "ft"}}]}}):
            fixture = document()
            fixture["nftables"].append(extra)
            with self.assertRaises(FirewallError):
                capability(fixture, "")
        for modules in ("qca_nss_drv 0 0\n", "shortcut_fe 0 0\n", "mtk_hnat 0 0\n"):
            with self.assertRaises(FirewallError):
                capability(document(), modules)
        with self.assertRaises(FirewallError):
            capability({"nftables": []}, "")

    def test_ownership_collision_no_write(self):
        self.nft.document = document(True)
        self.nft.document["nftables"][-1]["table"]["comment"] = "another owner"
        self.assertFalse(self.firewall.clear())
        self.assertIsNone(self.firewall.install(ROW, 30, 100))
        self.assertFalse(any(data for args, data in self.nft.calls))

    def test_failed_readback_rolls_back_only_exact_element(self):
        self.nft.bad_readback = True
        self.assertIsNone(self.install())
        self.assertEqual(self.firewall.leases, {})
        writes = [data for args, data in self.nft.calls if data and data.startswith("delete")]
        self.assertEqual(len(writes), 1)
        self.assertIn("by_id { 123 }", writes[0])
        self.assertTrue(writes[0].startswith("delete element"))

    def test_timeout_after_committed_write_is_rolled_back(self):
        original = self.firewall.runner
        def timeout_after_write(args, data=None):
            result = original(args, data)
            if data and "add element" in data:
                raise FirewallError("firewall command timed out")
            return result
        self.firewall.runner = timeout_after_write
        self.assertIsNone(self.install())
        self.assertFalse(self.nft.elements)
        self.assertFalse(self.firewall.leases)

    def test_same_conntrack_id_never_rebinds_to_second_tuple(self):
        self.install()
        row = dict(ROW, id="b" * 32, sport=54321, last_observed=104)
        self.assertIsNone(self.install(row, 104))
        self.assertIn("already has a lease", self.firewall.error)
        self.assertEqual(len(self.nft.elements), 1)

    def test_failed_rollback_keeps_visible_cleanup_debt_until_ttl(self):
        self.nft.bad_readback = self.nft.bad_delete = True
        self.assertIsNone(self.install())
        self.assertEqual(self.firewall.leases[ROW["id"]]["state"], "unverified_cleanup_pending")
        self.assertIn("rollback failed", self.firewall.error)
        self.assertEqual(self.firewall.expire(134), [ROW["id"]])

    def test_readback_requires_live_expiry_and_exact_id(self):
        lease = self.install()
        fixture = json.loads(self.nft(["nft", "-j", "list", "map", "inet", TABLE, "by_id"]))
        self.assertTrue(has_element(fixture, lease["chain"], lease["ct_id"]))
        fixture["nftables"][0]["map"]["elem"][0][0]["elem"]["expires"] = 0
        self.assertFalse(has_element(fixture, lease["chain"], lease["ct_id"]))

    def test_release_and_clear_only_owned_objects(self):
        lease = self.install()
        self.assertTrue(self.firewall.release(lease["id"], 110))
        self.assertFalse(self.firewall.leases)
        self.assertTrue(self.firewall.clear())
        deleted = [data for args, data in self.nft.calls if data and data.startswith("delete table")]
        self.assertEqual(deleted, ["delete table inet " + TABLE + "\n"])

    def test_stale_owned_rules_not_adopted_after_restart(self):
        self.nft.document = document(True)
        self.nft.document["nftables"].append({"set": {"family": "inet", "table": TABLE, "name": "old"}})
        self.assertIsNone(self.firewall.install(ROW, 30, 100))
        self.assertIn("cleanup", self.firewall.error)


if __name__ == "__main__":
    unittest.main()
