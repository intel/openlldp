"""Start/stop a real lldpad binary inside a NetNS for the duration of a test."""

import re
import subprocess
import time

from .netns import NetNSError

# lldptool -S output looks like:
#   Total Frames Transmitted        = 4
#   Total Discarded Frames Received = 0
#   ...
_STATS_LINE_RE = re.compile(r"^(.+?)\s*=\s*(\d+)\s*$")


class LldpadProcess:
    def __init__(self, netns, lldpad_bin, lldptool_bin, cfg_path,
                 log_path=None, start_timeout=10.0):
        self.netns = netns
        self.lldpad_bin = lldpad_bin
        self.lldptool_bin = lldptool_bin
        self.cfg_path = cfg_path
        self.log_path = log_path
        self.start_timeout = start_timeout
        self.proc = None
        self._log_fh = None

    def start(self, extra_args=None):
        # lldpad's own logging never fflush()es; redirected to a regular
        # file (not a TTY) its stdout is fully-buffered by glibc, so a
        # log read mid-run (fetch_log(), before the process exits or its
        # buffer happens to fill) can see nothing new for a long time.
        # stdbuf forces line buffering instead.
        cmd = ["stdbuf", "-oL", "-eL",
               self.lldpad_bin, "-p", "-t", "-f", self.cfg_path]
        if extra_args:
            cmd += list(extra_args)

        self._log_fh = open(self.log_path, "wb") if self.log_path else subprocess.PIPE
        self.proc = self.netns.popen(
            cmd,
            stdout=self._log_fh,
            stderr=subprocess.STDOUT,
        )
        self._wait_ready()
        return self

    def _wait_ready(self):
        """Poll via lldptool until lldpad's control socket answers."""
        deadline = time.time() + self.start_timeout
        last_err = None
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise NetNSError(
                    "lldpad exited early during startup (rc=%s); see %s"
                    % (self.proc.returncode, self.log_path or "<pipe>")
                )
            try:
                # Any request that reaches the control socket - even one
                # that errors out for other reasons - confirms lldpad is
                # up and listening.
                self.netns.run(
                    [self.lldptool_bin, "-t", "-i", "lo", "-V", "sysName"],
                    check=False,
                    timeout=2,
                )
                return
            except subprocess.TimeoutExpired as e:
                last_err = e
            time.sleep(0.1)
        raise NetNSError("lldpad did not become ready: %r" % (last_err,))

    def stop(self):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        self.proc = None
        if self._log_fh not in (None, subprocess.PIPE):
            self._log_fh.close()
        self._log_fh = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()

    # -- convenience wrappers over lldptool -----------------------------

    def enable(self, iface):
        """Enable LLDP rx+tx admin status on iface."""
        self.netns.lldptool("set-lldp", "-i", iface, "adminStatus=rxtx")

    def get_tlv(self, iface, tlv):
        """Return the string value lldptool prints for -V <tlv> on iface."""
        res = self.netns.lldptool("-t", "-i", iface, "-V", tlv, "-c")
        return res.stdout.strip()

    def neighbors(self, iface):
        """Return the raw text of `lldptool -t -n -i <iface>` (neighbor TLVs)."""
        res = self.netns.lldptool("-t", "-n", "-i", iface)
        return res.stdout

    def fetch_log(self):
        """Read back the (host-side) captured lldpad log file so far."""
        if not self.log_path:
            return ""
        try:
            with open(self.log_path, errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def stats(self, iface):
        """Parse `lldptool -S -i <iface>` into a {label: int} dict, e.g.
        {"Total Frames Received": 3, "Total Error Frames Received": 1, ...}
        - see lldp_mand_cmds.c:get_agent_stats for the full field list.
        """
        res = self.netns.lldptool("-S", "-i", iface)
        stats = {}
        for line in res.stdout.splitlines():
            m = _STATS_LINE_RE.match(line)
            if m:
                stats[m.group(1).strip()] = int(m.group(2))
        return stats
