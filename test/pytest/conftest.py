import os
import shutil

import pytest

from helpers.netns import NetNS, NetNSError
from helpers.lldpad_proc import LldpadProcess

# In an in-tree build, binaries land next to this repo's top level; for
# out-of-tree (VPATH) builds, the Makefile's check-integration target
# points us at them explicitly via these env vars.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _binary(name, env_var):
    override = os.environ.get(env_var)
    candidates = [override] if override else [os.path.join(REPO_ROOT, name)]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


@pytest.fixture(scope="session")
def lldpad_bin():
    path = _binary("lldpad", "OPENLLDP_LLDPAD")
    if not path:
        pytest.skip("lldpad is not built; run `make` first "
                     "(or set OPENLLDP_LLDPAD)")
    return path


@pytest.fixture(scope="session")
def lldptool_bin():
    path = _binary("lldptool", "OPENLLDP_LLDPTOOL")
    if not path:
        pytest.skip("lldptool is not built; run `make` first "
                     "(or set OPENLLDP_LLDPTOOL)")
    return path


@pytest.fixture(scope="session")
def require_tools():
    for tool in ("unshare", "nsenter", "ip"):
        if shutil.which(tool) is None:
            pytest.skip("%r not found on PATH" % tool)


@pytest.fixture()
def netns(require_tools, lldptool_bin):
    """A fresh, isolated net/mount/ipc/user namespace for one test."""
    ns = NetNS()
    try:
        ns.start()
    except NetNSError as e:
        pytest.skip("cannot create an unprivileged namespace: %s" % e)
    ns.lldptool_bin = lldptool_bin
    try:
        yield ns
    finally:
        ns.stop()


class VethPair:
    def __init__(self, netns, a, b):
        self.netns = netns
        self.dut = a       # the end lldpad will be bound to
        self.peer = b       # the end the test drives directly with scapy


@pytest.fixture()
def veth_pair(netns):
    """A veth pair inside `netns`, both ends up: `dut` <-> `peer`."""
    pair = VethPair(netns, "veth-dut", "veth-peer")
    netns.add_veth_pair(pair.dut, pair.peer)
    netns.link_up(pair.dut)
    netns.link_up(pair.peer)
    return pair


@pytest.fixture()
def lldpad(netns, veth_pair, lldpad_bin, lldptool_bin, tmp_path):
    """A running lldpad inside `netns`, LLDP enabled on veth_pair.dut."""
    cfg_path = str(tmp_path / "lldpad.conf")
    log_path = str(tmp_path / "lldpad.log")
    proc = LldpadProcess(netns, lldpad_bin, lldptool_bin, cfg_path, log_path=log_path)
    try:
        proc.start()
    except NetNSError as e:
        log = ""
        if os.path.exists(log_path):
            log = open(log_path, errors="replace").read()
        pytest.fail("lldpad failed to start: %s\n--- log ---\n%s" % (e, log))
    proc.enable(veth_pair.dut)
    try:
        yield proc
    finally:
        proc.stop()
