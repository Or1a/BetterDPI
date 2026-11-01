"""Bounded, exact netlink identity queries; never dump or alter conntrack.

Failure to prove identity is an action veto. No shell utilities or third party
Python modules are needed on OpenWrt.
"""
import errno
import ipaddress
import secrets
import socket
import struct


class IdentityError(ValueError):
    pass


class TupleMismatch(IdentityError):
    pass


def attribute(kind, value):
    size = len(value) + 4
    return struct.pack("=HH", size, kind) + value + b"\0" * (-size % 4)


def attributes(data):
    result = {}
    while data:
        if len(data) < 4:
            raise IdentityError("truncated netlink attribute")
        size, kind = struct.unpack_from("=HH", data)
        kind &= 0x3fff
        if size < 4 or size > len(data) or kind in result:
            raise IdentityError("invalid or duplicate netlink attribute")
        result[kind] = data[4:size]
        padded = (size + 3) & ~3
        if padded > len(data):
            raise IdentityError("truncated netlink padding")
        data = data[padded:]
    return result


def integer(data, size):
    if not isinstance(data, bytes) or len(data) != size:
        raise IdentityError("missing or malformed netlink integer")
    return int.from_bytes(data, "big")


def flow_tuple(row):
    try:
        src, dst = ipaddress.ip_address(row["ip"]), ipaddress.ip_address(row["peer"])
        proto, sport, dport = row["proto"], row["sport"], row["dport"]
        if (src.version != dst.version or type(proto) is not int or proto not in (6, 17)
                or any(type(p) is not int or not 1 <= p <= 65535 for p in (sport, dport))):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise IdentityError("an exact TCP/UDP five tuple is required") from None
    return src.version, proto, str(src), sport, str(dst), dport


def tuple_attribute(identity):
    version, proto, src, sport, dst, dport = identity
    addresses = (attribute(1 if version == 4 else 3, ipaddress.ip_address(src).packed)
                 + attribute(2 if version == 4 else 4, ipaddress.ip_address(dst).packed))
    ports = attribute(1, bytes([proto])) + attribute(2, struct.pack("!H", sport)) + attribute(3, struct.pack("!H", dport))
    return attribute(0x8001, addresses) + attribute(0x8002, ports)


def decode_tuple(data, version):
    fields = attributes(data)
    if fields.get(3, b"\0\0") != b"\0\0":
        raise IdentityError("non-default conntrack zone")
    addresses, ports = attributes(fields.get(1, b"")), attributes(fields.get(2, b""))
    try:
        src = ipaddress.ip_address(addresses[1 if version == 4 else 3])
        dst = ipaddress.ip_address(addresses[2 if version == 4 else 4])
    except (KeyError, ValueError):
        raise IdentityError("invalid conntrack address") from None
    if src.version != version or dst.version != version:
        raise IdentityError("conntrack address family mismatch")
    return (version, integer(ports.get(1), 1), str(src), integer(ports.get(2), 2),
            str(dst), integer(ports.get(3), 2))


def response_payload(packet, sender, flags, sequence, expected_type):
    if not sender or sender[0] != 0 or flags & socket.MSG_TRUNC:
        raise IdentityError("untrusted or truncated netlink response")
    if len(packet) < 16:
        raise IdentityError("short netlink response")
    size, kind, message_flags, seq, _pid = struct.unpack_from("=IHHII", packet)
    if size < 16 or size > len(packet) or seq != sequence or message_flags & 0x10:
        raise IdentityError("invalid netlink response header")
    if kind == 2:
        if size < 20:
            raise IdentityError("short netlink error")
        error = struct.unpack_from("=i", packet, 16)[0]
        raise OSError(-error, "exact netlink query failed")
    if kind != expected_type or (size + 3) & ~3 != len(packet):
        raise IdentityError("unexpected or multipart netlink response")
    return packet[16:size]


def query(protocol, kind, payload, expected_type):
    sequence = secrets.randbits(32) or 1
    request = struct.pack("=IHHII", 16 + len(payload), kind, 1, sequence, 0) + payload
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, protocol) as sock:
        sock.settimeout(0.15)
        sock.bind((0, 0))
        sock.sendto(request, (0, 0))
        packet, _ancillary, flags, sender = sock.recvmsg(65536)
    return response_payload(packet, sender, flags, sequence, expected_type)


def decode_conntrack(payload, expected):
    version = expected[0]
    family = socket.AF_INET if version == 4 else socket.AF_INET6
    if len(payload) < 4 or payload[:2] != bytes([family, 0]):
        raise IdentityError("conntrack family mismatch")
    fields = attributes(payload[4:])
    if fields.get(18, b"\0\0") != b"\0\0":
        raise IdentityError("non-default conntrack zone")
    original = decode_tuple(fields.get(1, b""), version)
    reply = decode_tuple(fields.get(2, b""), version)
    if original != expected:
        raise TupleMismatch("conntrack tuple changed")
    # Reply source must be the requested peer: refuse DNAT/REDIRECT. SNAT is OK.
    if reply[1:4] != (expected[1], expected[4], expected[5]):
        raise IdentityError("translated or redirected destination")
    status = integer(fields.get(3), 4)
    if status & ((1 << 14) | (1 << 15)):
        raise IdentityError("connection is offloaded")
    if status & ((1 << 9) | (1 << 12)) or not status & (1 << 3):
        raise IdentityError("connection is unconfirmed, dying or untracked")
    identifier = integer(fields.get(12), 4)
    if not identifier:
        raise IdentityError("missing stable conntrack ID")
    return {"id": identifier, "tuple": original}


def reverse(identity):
    return identity[:2] + identity[4:6] + identity[2:4]


def lookup(row):
    identity = flow_tuple(row)
    family = socket.AF_INET if identity[0] == 4 else socket.AF_INET6
    for direction, original in (("original", identity), ("reply", reverse(identity))):
        payload = struct.pack("!BBH", family, 0, 0) + attribute(0x8001, tuple_attribute(original))
        try:
            result = decode_conntrack(query(12, 0x101, payload, 0x100), original)
        except TupleMismatch:
            # CT_GET may resolve a reply tuple even when CTA_TUPLE_ORIG was
            # supplied. Re-query the inverse and fully validate that original.
            if direction == "original":
                continue
            raise
        except OSError as error:
            if direction == "original" and error.errno == errno.ENOENT:
                continue
            raise
        result["lan_direction"] = direction
        return result


def decode_neighbour(payload, address, ifindex):
    if len(payload) < 12:
        raise IdentityError("short neighbour response")
    family, _pad1, _pad2, index, state, _flags, _kind = struct.unpack_from("=BBHiHBB", payload)
    expected_family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    fields = attributes(payload[12:])
    mac = fields.get(2, b"")
    if (family != expected_family or index != ifindex or fields.get(1) != address.packed
            or not state & (2 | 4 | 8 | 16 | 128) or state & (1 | 32)
            or len(mac) != 6 or mac[0] & 1 or not any(mac)):
        raise IdentityError("current neighbour identity is not known")
    return ":".join("%02x" % part for part in mac)


def neighbour(ip, interface):
    address = ipaddress.ip_address(ip)
    ifindex = socket.if_nametoindex(interface)
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    payload = struct.pack("=BBHiHBB", family, 0, 0, ifindex, 0, 0, 0) + attribute(1, address.packed)
    return decode_neighbour(query(0, 30, payload, 28), address, ifindex)
