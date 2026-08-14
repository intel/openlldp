"""Shared plumbing for driving the legacy test/qbg22/{evb22,ecp22,vdp22}
case files against a real lldpad, inside a namespace helper (NetNS or
paired_netns.Role - anything exposing .run()/.popen()).
"""

import base64
import os
import re
import subprocess
import time

INCLUDE_RE = re.compile(r'@include\s+"([^"]+)"')


def upload_file(ns, local_path, remote_path):
    """Write local_path's content to remote_path inside the namespace.

    Goes over base64 on the nsenter'd shell's stdin/argv rather than a
    bind mount or host-side open(), since remote_path is typically under
    the namespace's private /tmp (see NetNS docstring) which the host
    process can't see directly.
    """
    with open(local_path, "rb") as f:
        content = f.read()
    b64 = base64.b64encode(content).decode()
    ns.run(["sh", "-c", "echo %s | base64 -d > %s" % (b64, remote_path)])


def upload_conf_with_includes(ns, local_conf, remote_dir):
    """Upload an lldpad libconfig file, and anything it @includes
    (libconfig resolves @include relative to the process's CWD - see
    the "cd /tmp" in start_lldpad below - so everything needs to land in
    the same remote_dir the process will be started from).

    Returns the remote path of the uploaded top-level config file.
    """
    seen = set()

    def _upload_one(local_path):
        if local_path in seen:
            return
        seen.add(local_path)
        remote_path = remote_dir + "/" + os.path.basename(local_path)
        upload_file(ns, local_path, remote_path)
        local_dir = os.path.dirname(local_path)
        with open(local_path, errors="replace") as f:
            for included in INCLUDE_RE.findall(f.read()):
                included_local = os.path.join(local_dir, included)
                if os.path.isfile(included_local):
                    _upload_one(included_local)

    _upload_one(local_conf)
    return remote_dir + "/" + os.path.basename(local_conf)


class LegacyLldpad:
    """One lldpad instance started against an uploaded case config,
    logging to a fixed /tmp path (so unmodified .chk scripts, which
    expect exactly /tmp/<n>-lldpad.conf.out, keep working).
    """

    def __init__(self, ns, lldpad_bin, lldptool_bin, remote_cfg, log_name):
        self.ns = ns
        self.lldpad_bin = lldpad_bin
        self.lldptool_bin = lldptool_bin
        self.remote_cfg = remote_cfg
        self.remote_log = "/tmp/%s" % log_name
        self.proc = None

    def start(self, extra_args="", ready_timeout=15.0, ready_iface="lo"):
        self.proc = self.ns.popen([
            "sh", "-c",
            "cd /tmp && exec %s -p -V 7 %s -f %s > %s 2>&1"
            % (self.lldpad_bin, extra_args, self.remote_cfg, self.remote_log),
        ])
        deadline = time.time() + ready_timeout
        last = None
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    "lldpad exited early during startup (rc=%s); log:\n%s"
                    % (self.proc.returncode, self.fetch_log()))
            try:
                r = self.ns.run(
                    [self.lldptool_bin, "-t", "-i", ready_iface, "-V", "sysName"],
                    check=False, timeout=2,
                )
                if "Connection refused" not in (r.stderr or ""):
                    return self
                last = r.stderr
            except subprocess.TimeoutExpired as e:
                last = e
            time.sleep(0.1)
        raise RuntimeError("lldpad did not become ready: %r" % (last,))

    def fetch_log(self):
        r = self.ns.run(["cat", self.remote_log], check=False, timeout=5)
        return r.stdout

    def stop(self):
        if self.proc is None or self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
