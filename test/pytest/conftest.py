import os
import re
import shutil
import tempfile

import pytest

from helpers.netns import NetNS, NetNSError
from helpers.lldpad_proc import LldpadProcess

# In an in-tree build, binaries land next to this repo's top level; for
# out-of-tree (VPATH) builds, the Makefile's check-integration target
# points us at them explicitly via these env vars.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Deliberately *not* under /tmp: NetNS mounts a private tmpfs over /tmp
# inside each test's namespace (so legacy scripts that hardcode /tmp
# paths don't collide across concurrent test cases - see helpers/netns.py),
# which means a host-side path under /tmp is invisible from inside the
# namespace. Anything a process running inside the namespace needs to
# read (lldpad's -f config file, case data, ...) has to live outside /tmp.
SCRATCH_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".scratch")


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
def vdptool_bin():
    path = _binary("vdptool", "OPENLLDP_VDPTOOL")
    if not path:
        pytest.skip("vdptool is not built; run `make` first "
                     "(or set OPENLLDP_VDPTOOL)")
    return path


@pytest.fixture(scope="session")
def qbg22sim_bin():
    # qbg22sim/vdptest are noinst_PROGRAMS, only built with --enable-debug.
    path = _binary("qbg22sim", "OPENLLDP_QBG22SIM")
    if not path:
        pytest.skip("qbg22sim is not built; configure with --enable-debug "
                     "and run `make` (or set OPENLLDP_QBG22SIM)")
    return path


@pytest.fixture(scope="session")
def vdptest_bin():
    path = _binary("vdptest", "OPENLLDP_VDPTEST")
    if not path:
        pytest.skip("vdptest is not built; configure with --enable-debug "
                     "and run `make` (or set OPENLLDP_VDPTEST)")
    return path


@pytest.fixture(scope="session")
def require_tools():
    for tool in ("unshare", "nsenter", "ip"):
        if shutil.which(tool) is None:
            pytest.skip("%r not found on PATH" % tool)


# -- pytest_runtest_makereport/case_workdir: keep failed test artifacts ----
#
# Stashes each phase's outcome on the test item (the standard pytest
# recipe) so the case_workdir fixture below can tell, at teardown time,
# whether the test it instrumented actually failed.
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, "rep_" + rep.when, rep)


def _test_failed(request):
    for when in ("setup", "call"):
        rep = getattr(request.node, "rep_" + when, None)
        if rep is not None and rep.failed:
            return True
    return False


@pytest.fixture()
def case_workdir(request):
    """A private scratch directory for one test, outside of /tmp.

    Removed on success; kept (and its path printed) if the test failed,
    so logs/configs/case output are available for post-mortem debugging.
    """
    os.makedirs(SCRATCH_ROOT, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", request.node.name)
    path = tempfile.mkdtemp(prefix=safe_name + "-", dir=SCRATCH_ROOT)
    yield path
    if _test_failed(request):
        print("\n[case_workdir] kept for debugging: %s" % path)
    else:
        shutil.rmtree(path, ignore_errors=True)


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
def lldpad(netns, veth_pair, lldpad_bin, lldptool_bin, case_workdir):
    """A running lldpad inside `netns`, LLDP enabled on veth_pair.dut."""
    cfg_path = os.path.join(case_workdir, "lldpad.conf")
    log_path = os.path.join(case_workdir, "lldpad.log")
    proc = LldpadProcess(netns, lldpad_bin, lldptool_bin, cfg_path, log_path=log_path)
    try:
        # -V 7 (LOG_DEBUG): the default level (LOG_WARNING) suppresses
        # the per-frame LLDPAD_INFO() validation messages in lldp/rx.c
        # ("TLV missing or TLVs out of order", "multiple ... TLVs", ...)
        # that compliance tests rely on to confirm *why* a malformed
        # frame was rejected, not just that it was.
        proc.start(extra_args=["-V", "7"])
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
