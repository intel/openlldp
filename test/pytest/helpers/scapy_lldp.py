"""LLDP frame construction helpers built on scapy.contrib.lldp.

Kept separate from the scapy_scripts/ runners so both send_lldp.py and
sniff_lldp.py (and future scripts, and tests that want to build a frame
and hand it to a script via a different route) share one definition of
"a basic LLDP frame".
"""

from scapy.contrib.lldp import (
    LLDP_NEAREST_BRIDGE_MAC,
    LLDPDUChassisID,
    LLDPDUPortID,
    LLDPDUTimeToLive,
    LLDPDUSystemName,
    LLDPDUSystemDescription,
    LLDPDUEndOfLLDPDU,
)
from scapy.layers.l2 import Ether


def build_basic_frame(src_mac, chassis_mac=None, port_id="eth-test",
                       ttl=120, sys_name=None, sys_description=None):
    """A minimal, spec-valid LLDP frame: chassis ID + port ID + TTL (+ End).

    chassis_mac defaults to src_mac. Extra optional TLVs can be layered
    on by the caller before sending; this only builds the mandatory set.
    """
    chassis_mac = chassis_mac or src_mac

    du = (
        LLDPDUChassisID(subtype="MAC address", id=chassis_mac)
        / LLDPDUPortID(subtype="locally assigned", id=port_id)
        / LLDPDUTimeToLive(ttl=ttl)
    )
    if sys_name is not None:
        du /= LLDPDUSystemName(system_name=sys_name)
    if sys_description is not None:
        du /= LLDPDUSystemDescription(description=sys_description)
    du /= LLDPDUEndOfLLDPDU()

    return Ether(src=src_mac, dst=LLDP_NEAREST_BRIDGE_MAC) / du
