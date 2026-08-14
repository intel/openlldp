"""Discovery of the legacy test/qbg22/{evb22,ecp22,vdp22} case files.

Each case is a numbered set of files sharing a common directory:
  <n>.<ext>            - the protocol test script (qbg22sim input, or for
                          VDP cases >= 100, an lldpad bridge-role config)
  <n>-lldpad.conf       - the (station-role) lldpad config to test against
  <n>.chk   (optional)  - a pass/fail check script (ecp22 only today)
  <n>.sh    (optional)  - a companion script run in parallel with the case
  <n>.nlc   (optional)  - for VDP, a script driving vdptest/vdptool/lldptool

We reuse these files completely unmodified; this module only finds them.
"""

import dataclasses
import os
import re

QBG22_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "qbg22",
)
REPO_ROOT = os.path.dirname(os.path.dirname(QBG22_ROOT))

CASE_RE = re.compile(r"^(\d+)\.(evb|ecp|vdp)$")


@dataclasses.dataclass
class Case:
    number: str
    ext: str            # "evb", "ecp", or "vdp"
    directory: str       # absolute path to e.g. test/qbg22/evb22
    main_file: str        # absolute path to <n>.<ext>
    conf_file: str        # absolute path to <n>-lldpad.conf
    chk_file: str = None
    sh_file: str = None
    nlc_file: str = None

    @property
    def id(self):
        return "%s-%s" % (self.ext, self.number)


def _discover(subdir, ext):
    directory = os.path.join(QBG22_ROOT, subdir)
    cases = []
    if not os.path.isdir(directory):
        return cases
    for name in os.listdir(directory):
        m = CASE_RE.match(name)
        if not m or m.group(2) != ext:
            continue
        number = m.group(1)
        conf = os.path.join(directory, "%s-lldpad.conf" % number)
        if not os.path.isfile(conf):
            continue  # not a real case (e.g. a shared/support file)
        chk = os.path.join(directory, "%s.chk" % number)
        sh = os.path.join(directory, "%s.sh" % number)
        nlc = os.path.join(directory, "%s.nlc" % number)
        cases.append(Case(
            number=number,
            ext=ext,
            directory=directory,
            main_file=os.path.join(directory, name),
            conf_file=conf,
            chk_file=chk if os.path.isfile(chk) else None,
            sh_file=sh if os.access(sh, os.X_OK) else None,
            nlc_file=nlc if os.path.isfile(nlc) else None,
        ))
    cases.sort(key=lambda c: int(c.number))
    return cases


def discover_evb_cases():
    return _discover("evb22", "evb")


def discover_ecp_cases():
    return _discover("ecp22", "ecp")


def discover_vdp_cases():
    return _discover("vdp22", "vdp")


def case_ids(cases):
    return [c.id for c in cases]


_INCLUDE_RE = re.compile(r'@include\s+"([^"]+)"')


def copy_conf_with_includes(src_conf, dest_dir):
    """Copy an lldpad libconfig file, and anything it @includes, into
    dest_dir (libconfig resolves @include relative to the including
    file's own directory, so both need to live side by side).

    Returns the path to the copied top-level config file.
    """
    import shutil

    seen = set()

    def _copy_one(src):
        if src in seen:
            return
        seen.add(src)
        dst = os.path.join(dest_dir, os.path.basename(src))
        shutil.copy(src, dst)
        src_dir = os.path.dirname(src)
        with open(src, errors="replace") as f:
            for included in _INCLUDE_RE.findall(f.read()):
                included_src = os.path.join(src_dir, included)
                if os.path.isfile(included_src):
                    _copy_one(included_src)

    _copy_one(src_conf)
    return os.path.join(dest_dir, os.path.basename(src_conf))


def case_duration(case_file, cpp_bin="cpp", extra_seconds=5, default=30):
    """Replicate runevb.sh/runecp.sh's duration calculation: cpp-preprocess
    the case file, take the time field (first column) of its last
    non-blank line, and pad it by extra_seconds.
    """
    import subprocess

    try:
        out = subprocess.run(
            [cpp_bin, case_file], capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return default
    last = None
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        last = line
    if not last:
        return default
    try:
        return int(last.split()[0]) + extra_seconds
    except (ValueError, IndexError):
        return default
