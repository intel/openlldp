"""ECP22 protocol cases, ported from test/qbg22/ecp22/.

Same shape as test_evb22.py; some cases additionally carry a .chk script
that inspects lldpad's own (verbose) trace log for expected internal
behavior (e.g. "the ecp22 module must not have started").
"""

import pytest

from .cases import discover_ecp_cases, case_ids
from .runner import run_qbg22sim_case

CASES = discover_ecp_cases()


@pytest.mark.parametrize("case", CASES, ids=case_ids(CASES))
def test_ecp22_case(case, paired_netns, lldpad_bin, lldptool_bin, qbg22sim_bin):
    result = run_qbg22sim_case(paired_netns, case, lldpad_bin, lldptool_bin, qbg22sim_bin)
    assert result.ok, result.debug
