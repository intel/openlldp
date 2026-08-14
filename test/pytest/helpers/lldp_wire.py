"""Raw, low-level LLDP TLV/frame construction for compliance testing.

Deliberately independent of scapy.contrib.lldp (see helpers/scapy_lldp.py
for that): its LLDPDU classes enforce a sane structure while building a
packet, which is exactly what compliance tests need to *not* have -
sending TLVs out of order, duplicated, with a lying length field, or
truncated mid-TLV all need byte-level control over the LLDPDU payload.

An LLDP TLV on the wire is a 2-byte header (7-bit type, 9-bit length)
followed by that many bytes of value - see IEEE 802.1AB clause 8.
"""

import struct

from scapy.layers.l2 import Ether

LLDP_ETHERTYPE = 0x88CC
LLDP_NEAREST_BRIDGE_MAC = "01:80:c2:00:00:0e"

# TLV type numbers (802.1AB clause 8)
END_OF_LLDPDU = 0
CHASSIS_ID = 1
PORT_ID = 2
TTL = 3
PORT_DESCRIPTION = 4
SYSTEM_NAME = 5
SYSTEM_DESCRIPTION = 6
SYSTEM_CAPABILITIES = 7
MANAGEMENT_ADDRESS = 8


def tlv(tlv_type, value=b"", declared_length=None):
    """One raw TLV: 2-byte type+length header, then value.

    declared_length overrides the header's length field independent of
    len(value) - the whole point, for building TLVs whose declared
    length doesn't match what's actually there (truncated/overflowing
    cases). Normal callers should leave it as None.
    """
    length = len(value) if declared_length is None else declared_length
    header = ((tlv_type & 0x7F) << 9) | (length & 0x1FF)
    return struct.pack("!H", header) + value


def chassis_id(subtype=4, cid=b"\x02\x00\x00\x00\x00\x01", **kw):
    """subtype 4 = MAC address (802.1AB Table 8-2)."""
    return tlv(CHASSIS_ID, bytes([subtype]) + cid, **kw)


def port_id(subtype=7, pid=b"eth-test", **kw):
    """subtype 7 = locally assigned (802.1AB Table 8-3)."""
    return tlv(PORT_ID, bytes([subtype]) + pid, **kw)


def ttl(seconds=120, **kw):
    return tlv(TTL, struct.pack("!H", seconds), **kw)


def port_description(text=b"test port", **kw):
    return tlv(PORT_DESCRIPTION, text, **kw)


def system_name(text=b"test-host", **kw):
    return tlv(SYSTEM_NAME, text, **kw)


def system_description(text=b"test system description", **kw):
    return tlv(SYSTEM_DESCRIPTION, text, **kw)


def system_capabilities(capabilities=0x0004, enabled=0x0004, **kw):
    """Default: bit 2 set = "Bridge" capable and enabled (802.1AB Table 8-4)."""
    return tlv(SYSTEM_CAPABILITIES,
               struct.pack("!HH", capabilities, enabled), **kw)


def end_of_lldpdu(**kw):
    return tlv(END_OF_LLDPDU, b"", **kw)


def mandatory_tlvs(chassis=None, port=None, life=120):
    """The three TLVs every valid LLDPDU needs, in the correct order."""
    return [
        chassis_id(cid=chassis) if chassis else chassis_id(),
        port_id(pid=port) if port else port_id(),
        ttl(seconds=life),
    ]


def build_frame(tlv_list, src_mac="02:00:00:00:00:01",
                 dst_mac=LLDP_NEAREST_BRIDGE_MAC):
    """Wrap a list of raw TLV byte strings into an Ethernet/LLDP frame."""
    payload = b"".join(tlv_list)
    return Ether(src=src_mac, dst=dst_mac, type=LLDP_ETHERTYPE) / bytes(payload)


def valid_frame(src_mac="02:00:00:00:00:01", chassis=None, port=None,
                 life=120, extra_tlvs=None):
    """A spec-valid LLDPDU: mandatory TLVs in order, optional extras,
    terminated by End Of LLDPDU.
    """
    tlvs = mandatory_tlvs(chassis=chassis, port=port, life=life)
    tlvs += list(extra_tlvs or [])
    tlvs.append(end_of_lldpdu())
    return build_frame(tlvs, src_mac=src_mac)
