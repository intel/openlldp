"""Isolated network namespace helper, built on `ip netns` plus a small
per-namespace mount-namespace holder for /tmp and /dev/shm isolation.

Requires real root (CAP_SYS_ADMIN): `ip netns add` pins a namespace at
/var/run/netns/<name>, and mounting a private tmpfs needs it too. Run
the whole test process under sudo - see the Makefile's
check-integration target and this tree's README under "Privilege
model".

This deliberately does *not* use a new user namespace the way an
earlier version of this file did (mapping the caller in as
"unprivileged root" via `unshare --map-root-user`, so the suite could
run without real root at all). Two things about that turned out not to
be worth it: Ubuntu 23.10+ restricts *unprivileged* user-namespace
creation by default (kernel.apparmor_restrict_unprivileged_userns),
which blocked that path outright on some CI images; and even bypassing
that by running the unshare as real root, the resulting "root remapped
into a nested user namespace" produced its own unexplained failures
(freshly-built, real-root-owned binaries came back flat-out
"Permission denied" specifically when exec'd through that nested
namespace - not worth chasing blind).

Staying real root throughout, with only net and mount namespaces (no
CLONE_NEWUSER at all), sidesteps both: no unprivileged-userns
restriction ever applies, and there's no uid remapping to produce
surprising exec-permission behavior. This is also the same pattern
other projects doing this kind of testing already use in CI - e.g.
Open vSwitch's test suite runs under `sudo ip netns add` /
`ip netns exec`.
"""

import json
import os
import subprocess
import time
import uuid

# --propagation private detaches the new mount namespace from the
# host's propagation group. On distros where / is mounted "shared"
# (systemd's default - check with `findmnt -o PROPAGATION /`), any
# mount made *inside* the namespace below (the /tmp and /dev/shm
# tmpfs mounts in start()) would otherwise also propagate straight
# out into the host's own mount namespace, silently shadowing the
# host's real /tmp with an empty, root-owned tmpfs.
MOUNT_HOLDER_CMD = ["unshare", "--mount", "--propagation", "private",
                    "--", "sleep", "infinity"]


class NetNSError(RuntimeError):
    pass


class NetNS:
    def __init__(self, ready_timeout=5.0):
        self.ready_timeout = ready_timeout
        self.name = "pytest-%s" % uuid.uuid4().hex[:12]
        self._holder = None
        # Set by the `netns` fixture to the built lldptool binary so that
        # self.lldptool(...) works out of the box.
        self.lldptool_bin = None

    # -- lifecycle ---------------------------------------------------

    def start(self):
        try:
            subprocess.run(["ip", "netns", "add", self.name],
                            check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            raise NetNSError(
                "ip netns add failed - are you root? see this tree's "
                "README, \"Privilege model\": %s" % (e.stderr or e).strip()
            ) from e

        try:
            subprocess.run(["ip", "-netns", self.name, "link", "set", "lo", "up"],
                            check=True, capture_output=True, text=True)

            # A private mount namespace, still inside this net namespace,
            # gives /tmp and /dev/shm their own tmpfs - `ip netns exec`
            # alone only isolates the network stack, not the filesystem.
            self._holder = subprocess.Popen(
                ["ip", "netns", "exec", self.name] + MOUNT_HOLDER_CMD,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            self._wait_ready()

            # Belt-and-suspenders on top of MOUNT_HOLDER_CMD's
            # --propagation private: explicitly re-assert MS_PRIVATE on
            # the exact mountpoints we're about to replace, from
            # *inside* the namespace, right before replacing them. This
            # is the same two-step "unshare, then explicit
            # mount --make-rprivate" idiom runc/libcontainer use -
            # belt-and-suspenders because relying on unshare(1)'s
            # --propagation flag alone was not sufficient in practice
            # (observed leaking onto the host's real /tmp even with it
            # set), and `ip netns exec` itself unshares its own mount
            # namespace ahead of ours, which is one more layer than
            # --propagation private's single recursive pass accounted
            # for.
            self.run(["mount", "--make-rprivate", "/tmp"])
            self.run(["mount", "--make-rprivate", "/dev/shm"])

            # Give /tmp its own private tmpfs: several legacy test
            # scripts we run inside this namespace (see test/qbg22/)
            # write fixed paths like /tmp/<case>-lldpad.conf.out, which
            # would otherwise collide between concurrently-running test
            # cases sharing the host /tmp.
            self.run(["mount", "-t", "tmpfs", "tmpfs", "/tmp"])
            # Likewise for /dev/shm: lldpad keeps its runtime state in a
            # single fixed-name POSIX shm segment (LLDPAD_SHM_PATH), and
            # /dev/shm content visibility follows the mount namespace -
            # without this, two concurrently running lldpad instances
            # (in different tests, or a stale one left on the host)
            # would collide on it, the second one finding the first's
            # still-live PID recorded there and refusing to start
            # ("lldpad already running").
            self.run(["mount", "-t", "tmpfs", "tmpfs", "/dev/shm"])
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, NetNSError) as e:
            self.stop()
            raise NetNSError("namespace setup failed: %r" % (e,)) from e
        return self

    def _wait_ready(self):
        deadline = time.time() + self.ready_timeout
        last_err = None
        while time.time() < deadline:
            if self._holder.poll() is not None:
                stderr = self._holder.stderr.read().decode(errors="replace")
                raise NetNSError(
                    "mount namespace holder exited early (rc=%s): %s"
                    % (self._holder.returncode, stderr.strip())
                )
            try:
                self.run(["true"], timeout=1)
                return
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                last_err = e
                time.sleep(0.05)
        raise NetNSError("namespace never became ready: %r" % (last_err,))

    def stop(self):
        if self._holder is not None:
            if self._holder.poll() is None:
                self._holder.terminate()
                try:
                    self._holder.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._holder.kill()
                    self._holder.wait(timeout=5)
            self._holder = None
        subprocess.run(["ip", "netns", "del", self.name],
                        check=False, capture_output=True)

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
        return ["nsenter", "--target", str(self.pid), "--mount", "--net", "--"]

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
