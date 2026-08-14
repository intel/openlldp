"""Isolated network/mount/ipc/user namespace helper.

Each ``NetNS`` instance owns one fresh network, mount, ipc and user
namespace, created without requiring real root (via unprivileged user
namespaces). Everything that needs to run "inside" the namespace -
``ip link`` calls, ``lldpad`` itself, and the scapy scripts that send or
sniff frames on its interfaces - is executed with ``nsenter`` targeting
a long-lived holder process that owns the namespace set.

The holder process's namespaces are torn down (and everything in them,
e.g. veth interfaces, killed processes) as soon as the holder exits, so
cleanup is just "kill the holder".
"""

import json
import os
import subprocess
import time

UNSHARE_CMD = [
    "unshare",
    "--mount",
    "--net",
    "--ipc",
    "--user",
    "--map-root-user",
    "--",
    "sleep",
    "infinity",
]


class NetNSError(RuntimeError):
    pass


class NetNS:
    def __init__(self, ready_timeout=5.0):
        self._holder = None
        self.ready_timeout = ready_timeout
        # Set by the `netns` fixture to the built lldptool binary so that
        # self.lldptool(...) works out of the box.
        self.lldptool_bin = None

    # -- lifecycle ---------------------------------------------------

    def start(self):
        self._holder = subprocess.Popen(
            UNSHARE_CMD,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        deadline = time.time() + self.ready_timeout
        last_err = None
        while time.time() < deadline:
            if self._holder.poll() is not None:
                stderr = self._holder.stderr.read().decode(errors="replace")
                raise NetNSError(
                    "unshare exited early (rc=%s): %s"
                    % (self._holder.returncode, stderr.strip())
                )
            try:
                self.run(["true"], timeout=1)
                break
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                last_err = e
                time.sleep(0.05)
        else:
            self.stop()
            raise NetNSError("namespace never became ready: %r" % (last_err,))

        # Give /tmp its own private tmpfs: several legacy test scripts we
        # run inside this namespace (see test/qbg22/) write fixed paths
        # like /tmp/<case>-lldpad.conf.out, which would otherwise collide
        # between concurrently-running test cases sharing the host /tmp.
        self.run(["mount", "-t", "tmpfs", "tmpfs", "/tmp"])
        # Likewise for /dev/shm: lldpad keeps its runtime state in a
        # single fixed-name POSIX shm segment (LLDPAD_SHM_PATH). Content
        # visibility for /dev/shm follows the *mount* namespace, not the
        # IPC namespace, so --ipc alone does not stop two concurrently
        # running lldpad instances (in different tests, or a stale one
        # left on the host) from colliding on it - the second one finds
        # the first's still-live PID recorded there and refuses to start
        # ("lldpad already running").
        self.run(["mount", "-t", "tmpfs", "tmpfs", "/dev/shm"])
        return self

    def stop(self):
        if self._holder is None:
            return
        if self._holder.poll() is None:
            self._holder.terminate()
            try:
                self._holder.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._holder.kill()
                self._holder.wait(timeout=5)
        self._holder = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()

    @property
    def pid(self):
        if self._holder is None:
            raise NetNSError("namespace not started")
        return self._holder.pid

    # -- running things inside the namespace --------------------------

    def _nsenter_prefix(self):
        return [
            "nsenter",
            "--target", str(self.pid),
            "--mount",
            "--net",
            "--ipc",
            "--user",
            "--preserve-credentials",
            "--",
        ]

    def run(self, cmd, check=True, timeout=None, **kwargs):
        """Run cmd inside the namespace, waiting for it to finish."""
        return subprocess.run(
            self._nsenter_prefix() + list(cmd),
            check=check,
            timeout=timeout,
            capture_output=True,
            text=True,
            **kwargs,
        )

    def popen(self, cmd, **kwargs):
        """Start a long-running process inside the namespace."""
        return subprocess.Popen(self._nsenter_prefix() + list(cmd), **kwargs)

    def _nsenter_new_ipc_prefix(self):
        """Like _nsenter_prefix, but hands the command a *fresh* IPC
        namespace nested inside this NetNS's net/mount namespace, instead
        of joining the shared one.

        Used to run a second lldpad instance (e.g. VDP's bridge role)
        alongside the first inside the same NetNS: lldpad's POSIX shm
        segment has a fixed name, so two instances sharing one IPC
        namespace would collide.
        """
        return [
            "nsenter",
            "--target", str(self.pid),
            "--mount",
            "--net",
            "--preserve-credentials",
            "--",
            "unshare",
            "--ipc",
            "--",
        ]

    def popen_new_ipc(self, cmd, **kwargs):
        """Like popen(), but cmd runs in its own fresh IPC namespace."""
        return subprocess.Popen(self._nsenter_new_ipc_prefix() + list(cmd), **kwargs)

    def run_new_ipc(self, cmd, check=True, timeout=None, **kwargs):
        """Like run(), but cmd runs in its own fresh IPC namespace."""
        return subprocess.run(
            self._nsenter_new_ipc_prefix() + list(cmd),
            check=check,
            timeout=timeout,
            capture_output=True,
            text=True,
            **kwargs,
        )

    def run_python(self, script_path, args=None, extra_pythonpath=None,
                    timeout=30, check=True):
        """Run a python script inside the namespace and parse its stdout as JSON.

        The script is expected to print exactly one JSON document to
        stdout as its result; this is the convention used by the
        scapy_scripts/ helpers.
        """
        script_path = os.path.abspath(script_path)
        env = dict(os.environ)
        pypath = [os.path.dirname(os.path.dirname(script_path))]
        if extra_pythonpath:
            pypath = list(extra_pythonpath) + pypath
        env["PYTHONPATH"] = os.pathsep.join(pypath + [env.get("PYTHONPATH", "")])

        proc = self.run(
            ["python3", script_path] + [str(a) for a in (args or [])],
            check=False,
            timeout=timeout,
            env=env,
        )
        if check and proc.returncode != 0:
            raise NetNSError(
                "script %s failed (rc=%d): %s"
                % (script_path, proc.returncode, proc.stderr)
            )
        try:
            return json.loads(proc.stdout)
        except ValueError as e:
            raise NetNSError(
                "script %s did not print JSON: %s\nstdout=%r\nstderr=%r"
                % (script_path, e, proc.stdout, proc.stderr)
            )

    # -- networking convenience helpers --------------------------------

    def add_veth_pair(self, a, b):
        self.run(["ip", "link", "add", a, "type", "veth", "peer", "name", b])

    def link_up(self, iface):
        self.run(["ip", "link", "set", iface, "up"])

    def set_mac(self, iface, mac):
        self.run(["ip", "link", "set", iface, "address", mac])

    def add_addr(self, iface, cidr):
        self.run(["ip", "addr", "add", cidr, "dev", iface])

    def lldptool(self, *args, check=True, timeout=10):
        """Run lldptool inside the namespace, returning the CompletedProcess."""
        if not self.lldptool_bin:
            raise NetNSError("netns.lldptool_bin was not set")
        return self.run([self.lldptool_bin, *args], check=check, timeout=timeout)
