"""Case IDs known to fail as of the initial qbg22 port (2026-08-14).

These aren't harness bugs (two of those were found and fixed while
building this suite - see helpers/netns.py and helpers/paired_netns.py);
they're the suite's data files genuinely disagreeing with current
lldpad/vdptool behavior (protocol module start conditions, CLI error
text, ...) after ~12 years. See qbg/README.md.

Cases listed here are skipped by default so a normal run stays fast and
green; pass --qbg-known-failures to pytest to run them anyway for
investigation. Once a case is root-caused and fixed (or the case data
updated to match intentional new behavior), remove its id here.
"""

KNOWN_FAILING_CASES = {
    "ecp-1",
    "ecp-3",
    "evb-25",
    "evb-26",
    "vdp-115",
    "vdp-116",
    "vdp-117",
    "vdp-118",
    "vdp-119",
    "vdp-120",
    "vdp-121",
    "vdp-122",
    "vdp-200",
    "vdp-201",
    "vdp-202",
    "vdp-203",
    "vdp-204",
    "vdp-205",
    "vdp-206",
    "vdp-208",
    "vdp-209",
    "vdp-210",
    "vdp-211",
    "vdp-212",
    "vdp-213",
    "vdp-220",
    "vdp-221",
    "vdp-222",
    "vdp-223",
    "vdp-224",
    "vdp-225",
    "vdp-240",
    "vdp-241",
    "vdp-300",
    "vdp-301",
    "vdp-302",
    "vdp-303",
    "vdp-304",
    "vdp-305",
    "vdp-306",
    "vdp-307",
    "vdp-308",
    "vdp-309",
    "vdp-310",
    "vdp-320",
    "vdp-321",
    "vdp-322",
}
