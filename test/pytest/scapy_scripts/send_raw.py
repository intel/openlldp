#!/usr/bin/env python3
"""Send one pre-built raw Ethernet frame (as a hex string) on an
interface, inside a NetNS. Used for compliance tests that need
byte-level control over an LLDPDU - see helpers/lldp_wire.py - which
build the frame bytes on the host side and just need them put on the
wire from inside the namespace.

Run via NetNS.run_python(). Usage:
    send_raw.py <iface> <hex-encoded-frame-bytes>

Prints {"sent": true, "bytes": N} as JSON on success.
"""

import json
import sys

from scapy.packet import Raw
from scapy.sendrecv import sendp


def main():
    iface, hexdata = sys.argv[1], sys.argv[2]
    frame = Raw(load=bytes.fromhex(hexdata))
    sendp(frame, iface=iface, verbose=False)
    json.dump({"sent": True, "bytes": len(frame)}, sys.stdout)


if __name__ == "__main__":
    main()
