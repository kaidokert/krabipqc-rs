#!/usr/bin/env python3
"""Build and run krabipqc cortex-m3 examples under QEMU, parse METRIC
lines, emit a markdown footprint table to stdout (CI plumbs this into
$GITHUB_STEP_SUMMARY).

The harness exposes one example per FIPS operation:

  * ml_dsa_{44,65,87}_verify_stack — verify under measurement
  * ml_dsa_{44,65,87}_sign_stack   — sign under measurement
  * ml_kem_{512,768,1024}_decaps_stack — decaps under measurement

plus `ml_dsa_44_verify[/_traced]` and `sanity` which exercise the
harness fixture itself rather than a measurement-comparable target.
"""

import json
import re
import subprocess
import sys

TARGET = "thumbv7m-none-eabi"
TARGET_LABEL = "M3"

# (cargo example name, METRIC algo string, group label)
EXAMPLES = [
    ("ml_dsa_44_verify_stack",       "ml_dsa_44_verify_with_stack", "ml-dsa-44 verify"),
    ("ml_dsa_44_sign_stack",         "ml_dsa_44_sign",              "ml-dsa-44 sign"),
    ("ml_dsa_65_verify_stack",       "ml_dsa_65_verify",            "ml-dsa-65 verify"),
    ("ml_dsa_65_sign_stack",         "ml_dsa_65_sign",              "ml-dsa-65 sign"),
    ("ml_dsa_87_verify_stack",       "ml_dsa_87_verify",            "ml-dsa-87 verify"),
    ("ml_dsa_87_sign_stack",         "ml_dsa_87_sign",              "ml-dsa-87 sign"),
    ("ml_kem_512_decaps_stack",      "ml_kem_512_decaps",           "ml-kem-512 decaps"),
    ("ml_kem_768_decaps_stack",      "ml_kem_768_decaps",           "ml-kem-768 decaps"),
    ("ml_kem_1024_decaps_stack",     "ml_kem_1024_decaps",          "ml-kem-1024 decaps"),
]

TIMEOUT_RUN = 180   # seconds per QEMU run (ML-DSA-87 sign is the long one)
TIMEOUT_BUILD = 600


def run_cmd(args, timeout, **kwargs):
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, **kwargs
    )
    return result.returncode, result.stdout, result.stderr


def build_examples():
    rc, _out, err = run_cmd(
        ["cargo", "build", "--target", TARGET, "--release", "--examples"],
        timeout=TIMEOUT_BUILD,
    )
    if rc != 0:
        print(f"BUILD FAILED for {TARGET}:\n{err}", file=sys.stderr)
        return False
    return True


def run_qemu(example):
    rc, out, err = run_cmd(
        ["cargo", "run", "--target", TARGET, "--release", "--example", example],
        timeout=TIMEOUT_RUN,
    )
    combined = out + err
    if rc != 0 and "ACCEPT" not in combined and "REJECT" not in combined:
        print(f"  cargo run failed (rc={rc}):\n{combined}", file=sys.stderr)
    return combined


def text_size(example):
    """Return .text section size in bytes via cargo-bloat, or None."""
    try:
        rc, out, _err = run_cmd(
            [
                "cargo", "bloat",
                "--release", "--target", TARGET,
                "--example", example,
                "--message-format=json",
            ],
            timeout=TIMEOUT_BUILD,
        )
        if rc != 0:
            return None
        # cargo-bloat emits one JSON object on the last line.
        return json.loads(out.strip().split("\n")[-1]).get("text-section-size")
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, IndexError):
        return None


METRIC_RE = re.compile(
    r"METRIC stack:(\d+) cycles:(\d+) target:(\S+) algo:(\S+) backend:(\S+)"
)


def parse_metric(output):
    m = METRIC_RE.search(output)
    if not m:
        return None
    return {
        "stack": int(m.group(1)),
        "cycles": int(m.group(2)),
        "target": m.group(3),
        "algo": m.group(4),
        "backend": m.group(5),
    }


def main():
    if not build_examples():
        return 1

    rows = []
    failures = []

    for example, expected_algo, label in EXAMPLES:
        print(f"  Running {example}...", file=sys.stderr)
        try:
            output = run_qemu(example)
        except subprocess.TimeoutExpired:
            failures.append(f"Timeout: {example}")
            rows.append((label, None, None, None, "TIMEOUT"))
            continue

        accepted = f"{expected_algo} ACCEPT" in output
        metric = parse_metric(output)
        tsize = text_size(example)

        if not accepted:
            failures.append(f"REJECT: {example}")
        if metric is None:
            failures.append(f"Missing METRIC: {example}")
        elif metric["algo"] != expected_algo:
            failures.append(
                f"Algo mismatch on {example}: got {metric['algo']}, expected {expected_algo}"
            )
        if tsize is None:
            failures.append(f"Missing .text size: {example}")

        rows.append(
            (
                label,
                tsize,
                metric["stack"] if metric else None,
                metric["cycles"] if metric else None,
                "ACCEPT" if accepted else "REJECT",
            )
        )
        print(f"    {'ACCEPT' if accepted else 'REJECT'}", file=sys.stderr)

    print(f"## krabipqc {TARGET_LABEL} footprint (QEMU mps2-an385)")
    print()
    print("| Operation | .text (KiB) | Stack (bytes) | Cycles (k) | Status |")
    print("|-----------|-------------|---------------|------------|--------|")
    for label, tsize, stack, cycles, status in rows:
        tstr = f"{tsize / 1024:.1f}" if tsize is not None else "-"
        sstr = str(stack) if stack is not None else "-"
        cstr = str(cycles) if cycles is not None else "-"
        print(f"| {label} | {tstr} | {sstr} | {cstr} | {status} |")
    print()
    print(
        "Cycle counts come from the SysTick-based DWT counter in the harness "
        "and are reported in thousands. Treat them as a rough proxy, not a "
        "precise benchmark."
    )

    if failures:
        print(f"\nFailures: {len(failures)}", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
