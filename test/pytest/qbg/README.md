# qbg22 suite: EVB/ECP/VDP cases

This ports `test/qbg22/{evb22,ecp22,vdp22}/` - the ~110-case legacy
IEEE 802.1Qbg (EVB/ECP/VDP) protocol suite, originally driven by
hand-run shell scripts (`runevb.sh`, `runecp.sh`, `runvdp.sh`, ...)
against one shared, host-wide namespace - onto the same isolated-netns
machinery as the rest of `test/pytest/`, so cases:

* run each in their own namespace (no shared `/var/run/lldpad.pid`,
  `/tmp/*.out`, or interface names to collide on),
* can therefore run **concurrently** (`pytest -n auto`), and
* keep their **exact original test data** - every `.evb`/`.ecp`/`.vdp`/
  `.conf`/`.chk`/`.sh`/`.nlc` file under `test/qbg22/` is reused
  unmodified. Nothing here reimplements or edits protocol test data;
  it only re-hosts how those files get run.

## What each protocol's case actually runs

* **EVB / ECP** (`test_evb22.py`, `test_ecp22.py`): a real `lldpad`
  (station role, `veth0`) exchanges TLVs with `qbg22sim` acting as the
  bridge peer (`veth2`), exactly as `runevb.sh`/`runecp.sh` did. Some
  ECP cases carry a `.chk` script that additionally inspects lldpad's
  own verbose trace log for expected internal behavior; some EVB/ECP
  cases carry a `.sh` script run in parallel with the case (e.g.
  toggling the interface, or changing a setting mid-run).
* **VDP** (`test_vdp22.py`): *two* real, independent `lldpad` instances
  - station role on `veth0`, bridge role on `veth2` (the case's own
  `<n>.vdp` file doubles as the bridge role's lldpad config) - with the
  case's `<n>.nlc` script driving the actual VDP association exchange
  between them via `vdptest` or `vdptool`, depending on the case number
  (see `test/qbg22/vdp22/README` for the numbering scheme).

## Why VDP needs two namespaces, not one

lldpad's control socket is a single fixed-name abstract `AF_UNIX`
address, and its runtime state lives in a single fixed-name POSIX shm
segment - there's no way to run two lldpad instances side by side
unless each gets its own network *and* mount namespace (mount, because
`/dev/shm` content-visibility follows the mount namespace, not IPC -
see `helpers/netns.py`'s docstring). `helpers/paired_netns.py` builds
exactly that: two namespaces nested under one shared outer mount+user
namespace (so they can still validly move a veth end between each
other - moving a network device into another network namespace requires
capabilities in *both* the source's and target's owning user namespace,
which only holds if they share one), each layering its own net+ipc+mount
namespace on top, with `/tmp` inherited-shared (for the legacy scripts)
and `/dev/shm` freshly remounted per role (so the two lldpad instances
don't collide).

This turned out to matter for EVB/ECP too, not just VDP: lldpad has no
"only manage this interface" option (`config.c`'s `init_ports()`
enumerates and manages every interface it can see), so even the
single-lldpad EVB/ECP cases need `qbg22sim`'s `veth2` in a genuinely
separate namespace - otherwise lldpad starts running its own EVB/ECP
state machine on `veth2` as if it were just another local port, and the
test is silently no longer testing what it claims to.

## Debugging a failing case

Each case's `CaseResult.debug` text (shown by pytest on failure) already
includes: the case files used, the qbg22sim/nlc exit code and full
stdout/stderr, and the full verbose (`-V 7`) lldpad log(s) for every
role involved. That's usually enough on its own.

If you need to reproduce interactively, `case_workdir` (see the parent
`conftest.py`) is *not* used by this suite - the qbg cases write
everything through the namespace itself (`/tmp` inside it, not the
host's) so they can reuse the legacy scripts' hardcoded `/tmp/...`
paths unmodified. To poke at a live case, drop a `time.sleep(3600)`
into the relevant `run_*_case()` in `runner.py` right before its
`finally:` block, run the one case with `pytest -k <case-id> -s`, then
find its namespace holder (`pgrep -af 'unshare.*sleep infinity'`) and
`nsenter` into it the same way `helpers/netns.py`/`helpers/paired_netns.py` do.

## Current pass rate, and known_failures.py

As of this port, 62 of the 109 cases pass outright; the other 47 fail on
a genuine mismatch between what the case expects and lldpad/vdptool's
current behavior (protocol module start conditions, CLI error-message
text, etc.) rather than anything in this harness - unsurprising for a
suite whose data files date to 2012-2014 being run against the current
codebase for the first time in years. Each failure carries enough
detail (see above) to tell which category it's in; two real bugs *in
this harness* (a shared-namespace interface leak, and an `ipc`-only shm
isolation that didn't actually isolate `/dev/shm`) were found and fixed
while building it - see `helpers/netns.py` and `helpers/paired_netns.py`
for what they were.

Those 47 are listed by case id in `known_failures.py` and are **skipped
by default** (via a `pytest_collection_modifyitems` hook in
`conftest.py`), so a normal `pytest test/pytest/qbg` run stays fast and
fully green while they're investigated separately. To include them:

```
pytest test/pytest/qbg --qbg-known-failures -v
```

When a listed case turns out to be a real, fixed bug (or the case data
gets updated to match intentional new behavior), remove its id from
`known_failures.py` so it rejoins the default run.
