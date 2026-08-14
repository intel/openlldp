#!/usr/bin/env python3
"""Capture LLDP frames on an interface, inside a NetNS.

Run via NetNS.run_python(). Usage:
    sniff_lldp.py <iface> [--timeout SEC] [--count N]

Prints a JSON list of captured frames on stdout, each as
{"src": mac, "chassis_id": str, "port_id": str, "sys_name": str|None,
 "ttl": int, "raw_hex": str}.
"""

import argparse
import json
import sys

from scapy.sendrecv import sniff

from scapy.contrib.lldp import (
    LLDPDUChassisID,
    LLDPDUPortID,
    LLDPDUTimeToLive,
    LLDPDUSystemName,
)


def summarize(pkt):
    out = {
        "src": pkt.src,
        "chassis_id": None,
        "port_id": None,
        "sys_name": None,
        "ttl": None,
        "raw_hex": bytes(pkt).hex(),
    }
    if pkt.haslayer(LLDPDUChassisID):
        cid = pkt[LLDPDUChassisID].id
        out["chassis_id"] = cid.hex() if isinstance(cid, bytes) else cid
    if pkt.haslayer(LLDPDUPortID):
        pid = pkt[LLDPDUPortID].id
        out["port_id"] = pid.decode(errors="replace") if isinstance(pid, bytes) else pid
    if pkt.haslayer(LLDPDUTimeToLive):
        out["ttl"] = pkt[LLDPDUTimeToLive].ttl
    if pkt.haslayer(LLDPDUSystemName):
        name = pkt[LLDPDUSystemName].system_name
        out["sys_name"] = name.decode(errors="replace") if isinstance(name, bytes) else name
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("iface")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--count", type=int, default=0, help="0 = unbounded until timeout")
    args = ap.parse_args()

    pkts = sniff(
        iface=args.iface,
        filter="ether proto 0x88cc",
        timeout=args.timeout,
        count=args.count,
    )
    json.dump([summarize(p) for p in pkts], sys.stdout)


if __name__ == "__main__":
    main()
