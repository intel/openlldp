"""Drives one evb22/ecp22 case: real lldpad (station role, veth0) against
qbg22sim acting as the bridge peer (veth2), exactly as the legacy
runevb.sh/runecp.sh did, minus the parts that assumed a single shared,
sequential, host-wide namespace.
"""

import dataclasses
import subprocess

from helpers.legacy_case import LegacyLldpad, upload_conf_with_includes
from .cases import REPO_ROOT, case_duration


@dataclasses.dataclass
class CaseResult:
    ok: bool
    summary: str
    debug: str


def run_qbg22sim_case(paired_netns, case, lldpad_bin, lldptool_bin, qbg22sim_bin):
    """Run one evb22/ecp22 case: lldpad (station role) on veth0 against
    qbg22sim (bridge role) on veth2, each in their own namespace.
    """
    station, bridge = paired_netns.station, paired_netns.bridge
    station.lldptool_bin = lldptool_bin

    remote_cfg = upload_conf_with_includes(station, case.conf_file, "/tmp")
    lldpad = LegacyLldpad(
        station, lldpad_bin, lldptool_bin, remote_cfg,
        log_name="%s-lldpad.conf.out" % case.number,
    )
    sh_proc = None
    try:
        lldpad.start(ready_iface="veth0")

        if case.sh_file:
            sh_proc = station.popen(
                ["bash", case.sh_file, REPO_ROOT],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )

        duration = case_duration(case.main_file)
        sim = bridge.run(
            [qbg22sim_bin, "-v", "-v", "-v", "-T", "5000000",
             "-d", str(duration), "veth2", case.main_file],
            check=False, timeout=duration + 30,
        )

        sh_rc, sh_out = None, ""
        if sh_proc is not None:
            try:
                sh_out_b, _ = sh_proc.communicate(timeout=15)
                sh_rc = sh_proc.returncode
                sh_out = (sh_out_b or b"").decode(errors="replace")
            except subprocess.TimeoutExpired:
                sh_proc.kill()
                sh_rc = -1
                sh_out = "<companion .sh script timed out>"

        chk_rc, chk_out = None, ""
        if case.chk_file:
            chk = station.run(["bash", case.chk_file, case.number],
                               check=False, timeout=15)
            chk_rc, chk_out = chk.returncode, chk.stdout + chk.stderr

        ok = (sim.returncode == 0
              and (sh_rc in (None, 0))
              and (chk_rc in (None, 0)))

        debug = (
            "case: %s (%s)\nconf: %s\nmain: %s\nduration: %ds\n\n"
            "--- qbg22sim (rc=%s) ---\n%s\n%s\n"
            "--- companion .sh (rc=%s) ---\n%s\n"
            "--- .chk (rc=%s) ---\n%s\n"
            "--- lldpad log ---\n%s\n"
            % (case.id, case.main_file, case.conf_file, case.main_file, duration,
               sim.returncode, sim.stdout, sim.stderr,
               sh_rc, sh_out, chk_rc, chk_out, lldpad.fetch_log())
        )
        summary = "qbg22sim rc=%s sh_rc=%s chk_rc=%s" % (sim.returncode, sh_rc, chk_rc)
        return CaseResult(ok=ok, summary=summary, debug=debug)
    finally:
        if sh_proc is not None and sh_proc.poll() is None:
            sh_proc.kill()
        lldpad.stop()


def run_vdp_case(paired_netns, case, lldpad_bin, lldptool_bin, nlc_timeout=150):
    """Run one vdp22 case: two real, independent lldpad instances - a
    station role on veth0 and a bridge role on veth2 (the case's own
    <n>.vdp file *is* the bridge role's config) - with the case's <n>.nlc
    script (itself invoking vdptest or vdptool) driving the VDP exchange
    between them.
    """
    station, bridge = paired_netns.station, paired_netns.bridge
    station.lldptool_bin = lldptool_bin
    bridge.lldptool_bin = lldptool_bin

    station_cfg = upload_conf_with_includes(station, case.conf_file, "/tmp")
    bridge_cfg = upload_conf_with_includes(bridge, case.main_file, "/tmp")

    station_lldpad = LegacyLldpad(
        station, lldpad_bin, lldptool_bin, station_cfg,
        log_name="%s-lldpad.conf.out" % case.number,
    )
    bridge_lldpad = LegacyLldpad(
        bridge, lldpad_bin, lldptool_bin, bridge_cfg,
        log_name="%s.vdp.out" % case.number,
    )
    try:
        station_lldpad.start(ready_iface="veth0")
        bridge_lldpad.start(ready_iface="veth2")

        nlc = station.run(["bash", case.nlc_file], check=False, timeout=nlc_timeout)

        ok = nlc.returncode == 0
        debug = (
            "case: %s\nstation conf: %s\nbridge conf: %s\nnlc: %s\n\n"
            "--- %s.nlc (rc=%s) ---\n%s\n%s\n"
            "--- station lldpad log ---\n%s\n"
            "--- bridge lldpad log ---\n%s\n"
            % (case.id, case.conf_file, case.main_file, case.nlc_file,
               case.number, nlc.returncode, nlc.stdout, nlc.stderr,
               station_lldpad.fetch_log(), bridge_lldpad.fetch_log())
        )
        summary = "nlc rc=%s" % nlc.returncode
        return CaseResult(ok=ok, summary=summary, debug=debug)
    finally:
        station_lldpad.stop()
        bridge_lldpad.stop()
