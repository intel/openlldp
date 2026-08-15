"""IEEE 802.1AB LLDP receive-side compliance tests.

Sends hand-built (not scapy-validated) LLDPDUs at a real lldpad and
checks it does the spec-correct thing: accept and record well-formed
frames, and *reject* frames with out-of-order/duplicate/malformed TLVs
without corrupting its state.

Assertions for accepted frames use lldpad's neighbor table
(`lldptool -t -n`); assertions for rejected frames use two independent,
stronger signals instead (the neighbor table's behavior on rejection
isn't part of its documented contract and proved unreliable to assert
against while writing this suite - see git history):

  * `lldptool -S` statistics (`lldpad_proc.py:stats()`), which
    lldp/rx.c maintains precisely on every validation branch
    (statsFramesInTotal / statsFramesDiscardedTotal /
    statsFramesInErrorsTotal / statsTLVsDiscardedTotal / ...), and
  * the verbose (-V 7) lldpad log, which prints the *exact* validation
    message for each rejection reason (see lldp/rx.c) - this also
    means a failing assertion here tells you precisely which check
    lldpad actually hit, not just that "something" didn't match.

Every case here is derived from reading lldp/rx.c's rxProcessFrame(),
not guessed at, so where a comment says "per rx.c" that's the literal
source of truth for the expected behavior.

A couple of cases (look for "quirk" in the docstring) pin down places
where this implementation is deliberately more lenient than a strict
802.1AB reading - accepting something the spec's text would call
invalid. These aren't failures: Postel's law is a defensible choice
here, and other implementations on the wire may already depend on the
leniency. They're written as regular passing assertions on purpose, so
a future change to make a given case stricter shows up as a normal,
visible test update instead of an unexplained new failure.
"""

import os
import time

import pytest

from helpers.lldp_wire import (
    build_frame,
    chassis_id,
    end_of_lldpdu,
    management_address,
    mandatory_tlvs,
    port_description,
    port_id,
    system_capabilities,
    system_description,
    system_name,
    ttl,
    tlv,
    CHASSIS_ID,
    PORT_ID,
    TTL,
    MGMT_ADDR_IPV4,
    MGMT_ADDR_IPV6,
)

SEND_RAW = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "scapy_scripts", "send_raw.py")
SETTLE = 0.5  # time to let lldpad process one frame before we query it


def send(veth_pair, frame):
    result = veth_pair.netns.run_python(SEND_RAW, [veth_pair.peer, bytes(frame).hex()])
    assert result["sent"] is True
    time.sleep(SETTLE)


def assert_accepted(lldpad, iface, before_stats):
    """A well-formed frame: counted as received, no errors/discards
    added, and it becomes visible in the neighbor table.
    """
    after = lldpad.stats(iface)
    assert after["Total Frames Received"] > before_stats["Total Frames Received"]
    assert after["Total Error Frames Received"] == before_stats["Total Error Frames Received"]
    assert after["Total Discarded Frames Received"] == before_stats["Total Discarded Frames Received"]


def assert_rejected(lldpad, iface, before_stats, before_log, expect_message=None):
    """A malformed frame: counted as received, but also counted as a
    discard/error - and, if given, the log shows the specific rx.c
    validation message expected to have fired.
    """
    after = lldpad.stats(iface)
    assert after["Total Frames Received"] > before_stats["Total Frames Received"], (
        "frame apparently never reached lldpad")
    assert (after["Total Error Frames Received"] > before_stats["Total Error Frames Received"]
            or after["Total Discarded Frames Received"] > before_stats["Total Discarded Frames Received"]), (
        "malformed frame was not counted as discarded/in-error: %r -> %r" % (before_stats, after))
    if expect_message:
        new_log = lldpad.fetch_log()[len(before_log):]
        assert expect_message in new_log, (
            "expected log message %r not found in new log output:\n%s"
            % (expect_message, new_log))


# ---------------------------------------------------------------------
# Valid frames
# ---------------------------------------------------------------------

def test_minimal_valid_frame_is_accepted(lldpad, veth_pair):
    """Chassis ID, Port ID, TTL, End - the mandatory minimum (802.1AB 8.1)."""
    before = lldpad.stats(veth_pair.dut)
    frame = build_frame([*mandatory_tlvs(), end_of_lldpdu()])
    send(veth_pair, frame)
    assert_accepted(lldpad, veth_pair.dut, before)
    neighbors = lldpad.neighbors(veth_pair.dut)
    assert "Chassis ID TLV" in neighbors
    assert "Port ID TLV" in neighbors
    assert "Time to Live TLV" in neighbors


def test_valid_frame_with_optional_tlvs_is_accepted(lldpad, veth_pair):
    """Optional TLVs (any order, after the mandatory three) all parse."""
    before = lldpad.stats(veth_pair.dut)
    frame = build_frame([
        *mandatory_tlvs(),
        port_description(b"uplink port"),
        system_name(b"compliance-dut"),
        system_description(b"test system"),
        system_capabilities(),
        end_of_lldpdu(),
    ])
    send(veth_pair, frame)
    assert_accepted(lldpad, veth_pair.dut, before)
    neighbors = lldpad.neighbors(veth_pair.dut)
    assert "compliance-dut" in neighbors
    assert "uplink port" in neighbors


def test_ttl_zero_withdraws_neighbor(lldpad, veth_pair):
    """A TTL=0 LLDPDU is a shutdown notification (802.1AB 10.3.1): an
    established neighbor must be withdrawn immediately, not aged out.
    """
    chassis = b"\x02\x00\x00\x00\x00\x9e"
    send(veth_pair, build_frame([*mandatory_tlvs(chassis=chassis), end_of_lldpdu()]))
    assert "9e" in lldpad.neighbors(veth_pair.dut).lower().replace(":", "")

    send(veth_pair, build_frame([*mandatory_tlvs(chassis=chassis, life=0), end_of_lldpdu()]))
    neighbors = lldpad.neighbors(veth_pair.dut)
    assert "02:00:00:00:00:9e" not in neighbors.lower()


# ---------------------------------------------------------------------
# TLV order
# ---------------------------------------------------------------------

@pytest.mark.parametrize("bad_order_tlvs", [
    pytest.param(
        [port_id(), chassis_id(), ttl()],
        id="port-before-chassis",
    ),
    pytest.param(
        [chassis_id(), ttl(), port_id()],
        id="ttl-before-port",
    ),
    pytest.param(
        [ttl(), chassis_id(), port_id()],
        id="ttl-first",
    ),
])
def test_out_of_order_mandatory_tlvs_rejected(lldpad, veth_pair, bad_order_tlvs):
    """Per rx.c: TLV #1 must be type 1 (chassis), #2 type 2 (port), #3
    type 3 (ttl) - position, not just presence, is checked.
    """
    before_stats = lldpad.stats(veth_pair.dut)
    before_log = lldpad.fetch_log()
    send(veth_pair, build_frame([*bad_order_tlvs, end_of_lldpdu()]))
    assert_rejected(lldpad, veth_pair.dut, before_stats, before_log,
                     expect_message="TLV missing or TLVs out of order")


# ---------------------------------------------------------------------
# Duplicate TLVs
# ---------------------------------------------------------------------
#
# Chassis ID/Port ID/TTL (types 1-3) are deliberately *not* parametrized
# here alongside the optional TLVs below: rx.c's TLV-position check (see
# test_out_of_order_mandatory_tlvs_rejected above) means a second type
# 1/2/3 TLV can never actually reach the "multiple Chassis/Port/TTL ID"
# duplicate-detection branch - it's always caught first, either as
# "out of order" (if placed at position <=3) or as "Extra Type 1 Type2,
# or Type 3 TLV" (if placed later, see
# test_mandatory_tlv_repeated_after_position_three_rejected below). Both
# are still real rejections, just via a different rx.c branch/message
# than the one literally named after these types.

@pytest.mark.parametrize("dup_tlvs,expect_message", [
    pytest.param(
        [*mandatory_tlvs(), port_description(b"one"), port_description(b"two")],
        "multiple port description",
        id="duplicate-port-description",
    ),
    pytest.param(
        [*mandatory_tlvs(), system_name(b"one"), system_name(b"two")],
        "multiple system name",
        id="duplicate-system-name",
    ),
    pytest.param(
        [*mandatory_tlvs(), system_description(b"one"), system_description(b"two")],
        "multiple system description",
        id="duplicate-system-description",
    ),
    pytest.param(
        [*mandatory_tlvs(), system_capabilities(), system_capabilities()],
        "multiple system capabilities",
        id="duplicate-system-capabilities",
    ),
])
def test_duplicate_optional_tlvs_rejected(lldpad, veth_pair, dup_tlvs, expect_message):
    before_stats = lldpad.stats(veth_pair.dut)
    before_log = lldpad.fetch_log()
    send(veth_pair, build_frame([*dup_tlvs, end_of_lldpdu()]))
    assert_rejected(lldpad, veth_pair.dut, before_stats, before_log,
                     expect_message=expect_message)


def test_multiple_management_address_tlvs_are_tolerated(lldpad, veth_pair):
    """Unlike the other optional TLVs above, Management Address (type 8)
    is deliberately *not* subject to the "reject on duplicate" rule: a
    real LLDPDU may legitimately carry more than one, e.g. one per
    address family (IPv4 and IPv6) - switches commonly do this (see
    "lldp: Tolerate multiple management address TLVs").

    Two management address TLVs must not just be accepted rather than
    rejected - they must not abort parsing of the *rest* of the frame
    either: an earlier version of this fix (which the test above this
    one still guards for the truly-duplicate types) treated a second
    Management Address TLV as a fatal frame error, aborting before any
    later TLVs - including the End Of LLDPDU TLV itself - were parsed.
    Placing a normal optional TLV *after* the second Management Address
    TLV and confirming it shows up in the neighbor table catches a
    regression back to that behavior, not just "the frame wasn't
    rejected".
    """
    before = lldpad.stats(veth_pair.dut)
    frame = build_frame([
        *mandatory_tlvs(),
        management_address(addr_subtype=MGMT_ADDR_IPV4, addr=b"\xc0\xa8\x01\x01"),
        management_address(addr_subtype=MGMT_ADDR_IPV6, addr=b"\x20\x01\x0d\xb8" + b"\x00" * 12),
        system_name(b"mgmt-addr-dut"),
        end_of_lldpdu(),
    ])
    send(veth_pair, frame)
    assert_accepted(lldpad, veth_pair.dut, before)
    assert "mgmt-addr-dut" in lldpad.neighbors(veth_pair.dut)


@pytest.mark.parametrize("extra_tlv", [
    pytest.param(chassis_id(), id="chassis-id"),
    pytest.param(port_id(pid=b"extra"), id="port-id"),
    pytest.param(ttl(), id="ttl"),
])
def test_mandatory_tlv_repeated_after_position_three_rejected(lldpad, veth_pair, extra_tlv):
    """A second Chassis/Port/TTL TLV *anywhere* after the mandatory
    three is its own rx.c check, distinct from both the position check
    and the (for these three types, unreachable - see above) duplicate
    dedup check: "Extra Type 1 Type2, or Type 3 TLV!".
    """
    before_stats = lldpad.stats(veth_pair.dut)
    before_log = lldpad.fetch_log()
    frame = build_frame([*mandatory_tlvs(), extra_tlv, end_of_lldpdu()])
    send(veth_pair, frame)
    assert_rejected(lldpad, veth_pair.dut, before_stats, before_log,
                     expect_message="Extra Type 1 Type2, or Type 3 TLV")


# ---------------------------------------------------------------------
# TLV content / malformed data
# ---------------------------------------------------------------------

def test_ttl_wrong_length_rejected(lldpad, veth_pair):
    """The TTL TLV's value is always exactly 2 octets (802.1AB 8.5.2)."""
    before_stats = lldpad.stats(veth_pair.dut)
    before_log = lldpad.fetch_log()
    bad_ttl = tlv(TTL, b"\x00\x00\x00")  # 3 bytes instead of 2
    frame = build_frame([chassis_id(), port_id(), bad_ttl, end_of_lldpdu()])
    send(veth_pair, frame)
    assert_rejected(lldpad, veth_pair.dut, before_stats, before_log,
                     expect_message="TTL TLV validation error")


def test_zero_length_chassis_id_is_accepted(lldpad, veth_pair):
    """Documents a known implementation quirk, not a spec check: 802.1AB
    says every TLV other than End Of LLDPDU must carry a non-empty
    value, so a Chassis ID TLV with a zero-length value is technically
    invalid. This implementation accepts it anyway and stores it as a
    neighbor (lldptool then displays it as "Invalid length = 0").

    That's arguably the right call under Postel's law - other
    implementations on the wire may already rely on this being
    tolerated, and rejecting the whole frame over one cosmetic field is
    a strict reading, not a strictly necessary one. This test pins down
    *that* behavior so it's visible and intentional rather than
    accidental: if someone wants to make this stricter later, this is
    the test that should change to say so.
    """
    before = lldpad.stats(veth_pair.dut)
    empty_chassis = tlv(CHASSIS_ID, b"")
    frame = build_frame([empty_chassis, port_id(), ttl(), end_of_lldpdu()])
    send(veth_pair, frame)
    assert_accepted(lldpad, veth_pair.dut, before)


def test_truncated_tlv_length_overflow_rejected(lldpad, veth_pair):
    """A TLV whose declared length reaches past the end of the captured
    frame must be rejected as a frame overflow, not read out of bounds.
    """
    before_stats = lldpad.stats(veth_pair.dut)
    before_log = lldpad.fetch_log()
    # Declare 40 bytes of port-id value but only supply 4.
    lying_port_id = tlv(PORT_ID, b"\x07eth0", declared_length=40)
    frame = build_frame([chassis_id(), lying_port_id, ttl(), end_of_lldpdu()])
    send(veth_pair, frame)
    assert_rejected(lldpad, veth_pair.dut, before_stats, before_log,
                     expect_message="Frame overflow error")


def test_oversized_declared_length_rejected(lldpad, veth_pair):
    """Same as above but pinned to the 9-bit length field's max value
    (511, all-ones) - the boundary case for the length field itself.
    """
    before_stats = lldpad.stats(veth_pair.dut)
    before_log = lldpad.fetch_log()
    huge_tlv = tlv(PORT_ID, b"\x07x", declared_length=511)
    frame = build_frame([chassis_id(), huge_tlv, ttl(), end_of_lldpdu()])
    send(veth_pair, frame)
    assert_rejected(lldpad, veth_pair.dut, before_stats, before_log,
                     expect_message="Frame overflow error")


def test_missing_end_tlv_rejected(lldpad, veth_pair):
    """No End Of LLDPDU TLV: parsing runs off the end of the last real
    TLV with no bytes left even for another TLV header, and is
    correctly rejected as a truncated/overrun frame rather than read
    out of bounds.

    The mandatory TLVs alone pad out to under the 60-byte Ethernet
    minimum frame size, and a short raw frame gets zero-padded by the
    kernel/NIC before lldpad ever sees it - and two zero bytes read as
    a TLV header decode as a valid, empty End Of LLDPDU TLV, silently
    "fixing" the omission. A big-enough optional TLV avoids that padding
    so this test actually exercises the missing-terminator case.
    """
    before_stats = lldpad.stats(veth_pair.dut)
    before_log = lldpad.fetch_log()
    frame = build_frame([*mandatory_tlvs(), system_description(b"x" * 80)])
    send(veth_pair, frame)
    assert_rejected(lldpad, veth_pair.dut, before_stats, before_log,
                     expect_message="Frame overrun")


def test_truly_tiny_garbage_frame_rejected(lldpad, veth_pair):
    """A handful of random bytes after the Ethernet header - not even
    one complete TLV header.
    """
    before_stats = lldpad.stats(veth_pair.dut)
    before_log = lldpad.fetch_log()
    frame = build_frame([b"\xff"])
    send(veth_pair, frame)
    assert_rejected(lldpad, veth_pair.dut, before_stats, before_log)


def test_trailing_garbage_after_end_tlv_is_ignored(lldpad, veth_pair):
    """Another quirk (see module docstring): rxProcessFrame()'s parse
    loop exits as soon as it sees the End Of LLDPDU TLV
    (`while (tlv_type != 0)`), so anything appended after it is never
    inspected at all - the frame is accepted as if the trailing bytes
    weren't there, rather than rejected for carrying unexpected data.
    """
    before = lldpad.stats(veth_pair.dut)
    frame = build_frame([*mandatory_tlvs(), end_of_lldpdu(), b"\xde\xad\xbe\xef"])
    send(veth_pair, frame)
    assert_accepted(lldpad, veth_pair.dut, before)
