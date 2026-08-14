"""VDP22 protocol cases, ported from test/qbg22/vdp22/.

Unlike EVB/ECP (a real lldpad against the qbg22sim simulator), every VDP
case here runs *two* real, independent lldpad instances - station role
on veth0, bridge role on veth2 (the case's own <n>.vdp file doubles as
the bridge role's lldpad config) - with the case's <n>.nlc script
driving the VDP association exchange between them via vdptest or
vdptool depending on the case.
"""

import pytest

from .cases import discover_vdp_cases, case_ids
from .runner import run_vdp_case

CASES = discover_vdp_cases()


@pytest.mark.parametrize("case", CASES, ids=case_ids(CASES))
def test_vdp22_case(case, paired_netns, lldpad_bin, lldptool_bin,
                     vdptest_bin, vdptool_bin):
    # vdptest_bin/vdptool_bin aren't referenced directly - the case's own
    # <n>.nlc script invokes them by their (fixed, repo-root-relative)
    # path - but depending on the fixtures here means cases needing them
    # skip cleanly if the debug build wasn't configured, instead of
    # failing confusingly inside the .nlc script.
    result = run_vdp_case(paired_netns, case, lldpad_bin, lldptool_bin)
    assert result.ok, result.debug
