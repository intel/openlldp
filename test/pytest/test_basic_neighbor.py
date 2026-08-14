"""First example test built from the netns/scapy scaffolding.

Sends a hand-built LLDP frame with scapy onto one end of a veth pair and
checks that lldpad, listening on the other end, parsed it into a
neighbor entry with the expected chassis ID / port ID / system name.
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))
SEND_SCRIPT = os.path.join(HERE, "scapy_scripts", "send_lldp.py")
SNIFF_SCRIPT = os.path.join(HERE, "scapy_scripts", "sniff_lldp.py")

PEER_MAC = "02:00:00:00:00:01"


def test_lldpad_learns_neighbor_from_scapy_frame(lldpad, veth_pair):
    result = veth_pair.netns.run_python(
        SEND_SCRIPT,
        [veth_pair.peer, PEER_MAC, "--sys-name", "scapy-peer", "--port-id", "eth-test"],
    )
    assert result["sent"] is True

    neighbors = lldpad.neighbors(veth_pair.dut)

    assert PEER_MAC in neighbors
    assert "eth-test" in neighbors
    assert "scapy-peer" in neighbors


def test_lldpad_transmits_lldp_frames(lldpad, veth_pair):
    """lldpad, once enabled on an interface, sends its own LLDPDUs on it.

    lldpad's "fast start" behavior means the first transmission happens
    right after adminStatus is set, well inside the 802.1AB 30s
    msgTxInterval - no need to wait out a full interval here.
    """
    captured = veth_pair.netns.run_python(
        SNIFF_SCRIPT, [veth_pair.peer, "--timeout", "10", "--count", "1"],
        timeout=20,
    )
    assert len(captured) >= 1
    assert captured[0]["chassis_id"] is not None
