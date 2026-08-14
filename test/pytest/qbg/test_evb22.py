"""EVB22 protocol cases, ported from test/qbg22/evb22/.

Each case is a real lldpad (station role) on veth0 exchanging EVB TLVs
with qbg22sim, acting as the bridge peer, on veth2 - both inside one
isolated namespace per test, so cases can run concurrently
(pytest -n auto) without colliding with each other.
"""

import pytest

from .cases import discover_evb_cases, case_ids
from .runner import run_qbg22sim_case

CASES = discover_evb_cases()


@pytest.mark.parametrize("case", CASES, ids=case_ids(CASES))
def test_evb22_case(case, paired_netns, lldpad_bin, lldptool_bin, qbg22sim_bin):
    result = run_qbg22sim_case(paired_netns, case, lldpad_bin, lldptool_bin, qbg22sim_bin)
    assert result.ok, result.debug
