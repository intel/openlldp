"""Two cooperating, cross-linked network namespaces ("station" and
"bridge"), for the handful of legacy VDP test cases that need two real,
independent lldpad instances talking over a veth pair - which needs
each lldpad to have both its own network namespace (lldpad's control
socket is a single fixed abstract AF_UNIX name, namespaced by netns)
and its own mount namespace (lldpad's POSIX shm segment has a single
fixed name; /dev/shm content visibility follows the mount namespace,
not any IPC namespace).

Built the same way as helpers/netns.py's NetNS - `ip netns add`/
`ip netns exec` as real root, no user namespace involved - see that
module's docstring for why. Unlike NetNS, moving a veth end between the
two real (root-owned) namespaces here needs no special handling at all:
that's an ordinary, always-permitted operation for real root, unlike
for two independently-unshared *unprivileged* user namespaces (which
is what made the old version of this file a two-level, one-shared-
outer-namespace construction - no longer needed).
"""

import os
import shutil
import subprocess
import tempfile
import time
import uuid

from .netns import NetNSError

# Same rule, and the same directory, as conftest.py's SCRATCH_ROOT:
# deliberately *not* under /tmp. self._shared_tmp below gets bind-mounted
# onto /tmp inside each role's own mount namespace, so if it were created
# under the host's real /tmp (tempfile.mkdtemp()'s default), every
# create/delete against it - including the shutil.rmtree() in stop() -
# would be operating directly on a subdirectory of the host's real /tmp,
# regardless of any mount-namespace isolation on the bind mount's target
# side. See helpers/netns.py's docstring/MOUNT_HOLDER_CMD comment for the
# separate (also real, also fixed) propagation-leak issue on that target
# side.
SCRATCH_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".scratch")

# --propagation private: see helpers/netns.py's MOUNT_HOLDER_CMD for
# why this matters here in particular - without it, the "mount --bind
# <shared_tmp> /tmp" below leaks onto the host's real /tmp (on a
# shared-propagation root, which is systemd's default), and the
# shutil.rmtree(self._shared_tmp) in stop() then deletes the host's
# actual /tmp contents through that leaked bind mount.
ROLE_CMD = ["unshare", "--mount", "--propagation", "private",
            "--", "sleep", "infinity"]


class Role:
    """One lldpad "role" (station or bridge): its own net+mount namespace."""

    def __init__(self, netns_name, pid):
        self.netns_name = netns_name
        self.pid = pid
        self.lldptool_bin = None

    def _nsenter_prefix(self):
        return ["nsenter", "--target", str(self.pid), "--mount", "--net", "--"]

    def run(self, cmd, check=True, timeout=None, **kwargs):
        return subprocess.run(
            self._nsenter_prefix() + list(cmd),
            check=check, timeout=timeout, capture_output=True, text=True, **kwargs,
        )

    def popen(self, cmd, **kwargs):
        return subprocess.Popen(self._nsenter_prefix() + list(cmd), **kwargs)

    def link_up(self, iface):
        self.run(["ip", "link", "set", iface, "up"])

    def lldptool(self, *args, check=True, timeout=10):
        if not self.lldptool_bin:
            raise NetNSError("Role.lldptool_bin was not set")
        return self.run([self.lldptool_bin, *args], check=check, timeout=timeout)


class PairedNetNS:
    def __init__(self, ready_timeout=5.0):
        self.ready_timeout = ready_timeout
        base = uuid.uuid4().hex[:10]
        self.station_ns = "pytest-%s-stn" % base
        self.bridge_ns = "pytest-%s-brg" % base
        self.station = None
        self.bridge = None
        self._station_holder = None
        self._bridge_holder = None
        # A host-side directory bind-mounted onto /tmp in both roles'
        # own private mount namespaces, so they see the *same* /tmp
        # (needed for legacy scripts - see helpers/netns.py) despite
        # each role otherwise having a fully independent mount namespace.
        self._shared_tmp = None

    def _wait_ready(self, holder):
        deadline = time.time() + self.ready_timeout
        last_err = None
        prefix = ["nsenter", "--target", str(holder.pid), "--mount", "--net", "--"]
        while time.time() < deadline:
            if holder.poll() is not None:
                stderr = holder.stderr.read().decode(errors="replace")
                raise NetNSError("role holder exited early (rc=%s): %s"
                                  % (holder.returncode, stderr.strip()))
            try:
                subprocess.run(prefix + ["true"], check=True, timeout=1,
                                capture_output=True)
                return
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                last_err = e
                time.sleep(0.05)
        raise NetNSError("role namespace never became ready: %r" % (last_err,))

    def start(self):
        try:
            for ns in (self.station_ns, self.bridge_ns):
                subprocess.run(["ip", "netns", "add", ns],
                                check=True, capture_output=True, text=True)
                subprocess.run(["ip", "-netns", ns, "link", "set", "lo", "up"],
                                check=True, capture_output=True, text=True)

            os.makedirs(SCRATCH_ROOT, exist_ok=True)
            self._shared_tmp = tempfile.mkdtemp(prefix="qbg-shared-tmp-",
                                                 dir=SCRATCH_ROOT)

            self._station_holder = subprocess.Popen(
                ["ip", "netns", "exec", self.station_ns] + ROLE_CMD,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            self._bridge_holder = subprocess.Popen(
                ["ip", "netns", "exec", self.bridge_ns] + ROLE_CMD,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            self.station = Role(self.station_ns, self._station_holder.pid)
            self.bridge = Role(self.bridge_ns, self._bridge_holder.pid)

            self._wait_ready(self._station_holder)
            self._wait_ready(self._bridge_holder)

            for role in (self.station, self.bridge):
                # Belt-and-suspenders on top of ROLE_CMD's
                # --propagation private - see helpers/netns.py's
                # matching comment for why this extra, explicit step is
                # here too.
                role.run(["mount", "--make-rprivate", "/tmp"])
                role.run(["mount", "--make-rprivate", "/dev/shm"])
                role.run(["mount", "--bind", self._shared_tmp, "/tmp"])
                role.run(["mount", "-t", "tmpfs", "tmpfs", "/dev/shm"])
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, NetNSError) as e:
            self.stop()
            raise NetNSError("paired namespace setup failed: %r" % (e,)) from e
        return self

    def wire_veth(self, station_if="veth0", bridge_if="veth2"):
        """Create a veth pair with one end in each role's netns."""
        self.station.run(["ip", "link", "add", station_if, "type", "veth",
                           "peer", "name", bridge_if])
        self.station.run(["ip", "link", "set", bridge_if, "netns", self.bridge_ns])
        self.station.link_up(station_if)
        self.bridge.link_up(bridge_if)

    def stop(self):
        for holder in (self._station_holder, self._bridge_holder):
            if holder is None:
                continue
            if holder.poll() is None:
                holder.terminate()
                try:
                    holder.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    holder.kill()
                    holder.wait(timeout=5)
        self._station_holder = None
        self._bridge_holder = None
        for ns in (self.station_ns, self.bridge_ns):
            subprocess.run(["ip", "netns", "del", ns],
                            check=False, capture_output=True)
        if self._shared_tmp:
            shutil.rmtree(self._shared_tmp, ignore_errors=True)
            self._shared_tmp = None
        self.station = None
        self.bridge = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
