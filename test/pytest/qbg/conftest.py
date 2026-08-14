import pytest

from helpers.netns import NetNSError
from helpers.paired_netns import PairedNetNS
from .known_failures import KNOWN_FAILING_CASES


def pytest_addoption(parser):
    parser.addoption(
        "--qbg-known-failures", action="store_true", default=False,
        help="Also run qbg22 cases listed in qbg/known_failures.py "
             "(skipped by default).",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--qbg-known-failures"):
        return
    skip_known = pytest.mark.skip(
        reason="known failing - see qbg/known_failures.py; "
               "run with --qbg-known-failures to investigate")
    for item in items:
        if "[" not in item.name:
            continue
        case_id = item.name.split("[", 1)[1].rstrip("]")
        if case_id in KNOWN_FAILING_CASES:
            item.add_marker(skip_known)


@pytest.fixture()
def paired_netns(require_tools):
    """Two cross-linked namespaces (station role on veth0, bridge/peer
    role on veth2, each with their own netns/ipc), matching the
    interface names baked into test/qbg22/*/{*.conf,*.evb,*.ecp,*.vdp}.

    Used for *every* qbg22 case, not just VDP's dual-lldpad ones: lldpad
    auto-manages every interface it can see (config.c's init_ports()
    enumerates all of them, there's no allowlist), so even for
    EVB/ECP - where only one real lldpad instance is needed, the other
    side being qbg22sim's raw-socket peer - veth2 must live in a
    genuinely separate namespace, or lldpad starts running its own
    EVB/ECP state machine on veth2 too and the test is no longer testing
    what it claims to. See helpers/paired_netns.py.
    """
    pn = PairedNetNS()
    try:
        pn.start()
    except NetNSError as e:
        pytest.skip("cannot create paired namespaces: %s" % e)
    pn.wire_veth("veth0", "veth2")
    try:
        yield pn
    finally:
        pn.stop()
