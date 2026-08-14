#!/usr/bin/env python3
"""Send one LLDP frame on an interface, inside a NetNS.

Run via NetNS.run_python(). Usage:
    send_lldp.py <iface> <src_mac> [--sys-name NAME] [--port-id ID] [--ttl SEC]

Prints {"sent": true} as JSON on success.
"""

import argparse
import json
import sys

from scapy.sendrecv import sendp

from helpers.scapy_lldp import build_basic_frame


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("iface")
    ap.add_argument("src_mac")
    ap.add_argument("--sys-name", default=None)
    ap.add_argument("--sys-description", default=None)
    ap.add_argument("--port-id", default="eth-test")
    ap.add_argument("--ttl", type=int, default=120)
    args = ap.parse_args()

    frame = build_basic_frame(
        args.src_mac,
        port_id=args.port_id,
        ttl=args.ttl,
        sys_name=args.sys_name,
        sys_description=args.sys_description,
    )
    sendp(frame, iface=args.iface, verbose=False)
    json.dump({"sent": True, "bytes": len(bytes(frame))}, sys.stdout)


if __name__ == "__main__":
    main()
