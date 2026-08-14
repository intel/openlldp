"""Two cooperating, cross-linked network namespaces ("station" and
"bridge"), for the handful of legacy VDP test cases that need two real,
independent lldpad instances talking over a veth pair - which needs each
lldpad to have both its own network namespace (lldpad's control socket
is a single fixed abstract AF_UNIX name, namespaced by netns) and its
own IPC namespace (lldpad's POSIX shm segment has a single fixed name,
namespaced by IPC ns).

Moving a veth end between two namespaces requires the mover to hold
CAP_NET_ADMIN in the *owning user namespace* of both the source and
target network namespaces. Two independently-unshared `--user`
namespaces are siblings with no such relationship, so this only works
if "station" and "bridge" are both *nested inside one shared outer user
(and mount) namespace*, each with their own net+ipc namespace layered
on top. Hence the two-level structure here: one outer holder owns the
user/mount namespace (and the private /tmp - see NetNS for why), and
two inner "role" holders each get a fresh net+ipc namespace nested
inside it.
"""

import subprocess
import time

from .netns import NetNSError

OUTER_CMD = [
    "unshare", "--mount", "--user", "--map-root-user", "--", "sleep", "infinity",
]
# Each role also gets its own *mount* namespace (nested under the outer
# one, so it inherits a snapshot of the outer's already-mounted private
# /tmp - the same underlying tmpfs, so /tmp stays shared between the two
# roles for legacy-script compatibility) so that it can remount its own
# fresh /dev/shm: --ipc alone isn't enough to isolate POSIX shm objects,
# since Linux's /dev/shm is a tmpfs whose *content* visibility follows
# the mount namespace, not the IPC namespace. Without a separate
# /dev/shm, the two lldpad instances' fixed-name shm segment collides
# and the second one refuses to start ("lldpad already running").
ROLE_CMD = ["unshare", "--mount", "--net", "--ipc", "--", "sleep", "infinity"]


class Role:
    """One lldpad "role" (station or bridge): its own net+ipc namespace,
    sharing the outer PairedNetNS's mount/user namespace and /tmp.
    """

    def __init__(self, pid):
        self.pid = pid
        self.lldptool_bin = None

    def _nsenter_prefix(self):
        return [
            "nsenter",
            "--target", str(self.pid),
            "--mount", "--user", "--net", "--ipc",
            "--preserve-credentials",
            "--",
        ]

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
        self._outer = None
        self.station = None
        self.bridge = None

    def _wait_ready(self, nsenter_prefix, poll):
        deadline = time.time() + self.ready_timeout
        last_err = None
        while time.time() < deadline:
            try:
                subprocess.run(nsenter_prefix + ["true"], check=True,
                                timeout=1, capture_output=True)
                return
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                last_err = e
                time.sleep(0.05)
        raise NetNSError("namespace never became ready: %r" % (last_err,))

    def start(self):
        self._outer = subprocess.Popen(
            OUTER_CMD, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        outer_prefix = [
            "nsenter", "--target", str(self._outer.pid), "--mount", "--user",
            "--preserve-credentials", "--",
        ]
        try:
            self._wait_ready(outer_prefix, None)
            # Private /tmp shared by both roles - see NetNS for rationale.
            subprocess.run(outer_prefix + ["mount", "-t", "tmpfs", "tmpfs", "/tmp"],
                            check=True, capture_output=True)

            station_holder = subprocess.Popen(
                outer_prefix + ROLE_CMD, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            bridge_holder = subprocess.Popen(
                outer_prefix + ROLE_CMD, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            self.station = Role(station_holder.pid)
            self.bridge = Role(bridge_holder.pid)
            self._station_holder = station_holder
            self._bridge_holder = bridge_holder

            self._wait_ready(self.station._nsenter_prefix(), None)
            self._wait_ready(self.bridge._nsenter_prefix(), None)

            for role in (self.station, self.bridge):
                role.run(["mount", "-t", "tmpfs", "tmpfs", "/dev/shm"])
        except Exception:
            self.stop()
            raise
        return self

    def wire_veth(self, station_if="veth0", bridge_if="veth2"):
        """Create a veth pair with one end in each role's netns."""
        self.station.run(["ip", "link", "add", station_if, "type", "veth",
                           "peer", "name", bridge_if])
        self.station.run(["ip", "link", "set", bridge_if, "netns", str(self.bridge.pid)])
        self.station.link_up(station_if)
        self.bridge.link_up(bridge_if)

    def stop(self):
        for holder in (getattr(self, "_station_holder", None),
                       getattr(self, "_bridge_holder", None),
                       self._outer):
            if holder is None:
                continue
            if holder.poll() is None:
                holder.terminate()
                try:
                    holder.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    holder.kill()
                    holder.wait(timeout=5)
        self._outer = None
        self.station = None
        self.bridge = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
