#!/usr/bin/env python3
"""Build and run krabipqc RISC-V (riscv32imac) examples under QEMU virt,
parse METRIC lines, emit a markdown footprint table to stdout.

Uses the same METRIC format as the Cortex-M3 suite so the tables are
directly comparable. Stack measurements are stable; cycle counts from
mcycle are instruction-retired counts and should be treated as a rough
proxy, not a precise benchmark.
"""

import json
import re
import subprocess
import sys

TARGET = "riscv32imac-unknown-none-elf"
TARGET_LABEL = "RV32"

# (cargo example name, METRIC algo string, group label, feature list)
# Default group first; lowmem sign variants last so the feature flip
# triggers at most one extra rebuild.
EXAMPLES = [
    ("ml_dsa_44_verify_stack",   "ml_dsa_44_verify_with_stack", "ml-dsa-44 verify",        ()),
    ("ml_dsa_44_sign_stack",     "ml_dsa_44_sign",              "ml-dsa-44 sign",          ()),
    ("ml_dsa_65_verify_stack",   "ml_dsa_65_verify",            "ml-dsa-65 verify",        ()),
    ("ml_dsa_65_sign_stack",     "ml_dsa_65_sign",              "ml-dsa-65 sign",          ()),
    ("ml_dsa_87_verify_stack",   "ml_dsa_87_verify",            "ml-dsa-87 verify",        ()),
    ("ml_dsa_87_sign_stack",     "ml_dsa_87_sign",              "ml-dsa-87 sign",          ()),
    ("ml_kem_512_decaps_stack",  "ml_kem_512_decaps",           "ml-kem-512 decaps",       ()),
    ("ml_kem_768_decaps_stack",  "ml_kem_768_decaps",           "ml-kem-768 decaps",       ()),
    ("ml_kem_1024_decaps_stack", "ml_kem_1024_decaps",          "ml-kem-1024 decaps",      ()),
    ("ml_dsa_44_sign_stack",     "ml_dsa_44_sign",              "ml-dsa-44 sign (lowmem)", ("lowmem",)),
    ("ml_dsa_65_sign_stack",     "ml_dsa_65_sign",              "ml-dsa-65 sign (lowmem)", ("lowmem",)),
    ("ml_dsa_87_sign_stack",     "ml_dsa_87_sign",              "ml-dsa-87 sign (lowmem)", ("lowmem",)),
]


def feat_args(features):
    return ["--features", ",".join(features)] if features else []


TIMEOUT_RUN = 180   # seconds — ML-DSA-87 sign is the slow one
TIMEOUT_BUILD = 600


def run_cmd(args, timeout, **kwargs):
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, **kwargs
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"command not found: {args[0]}"


def build_examples(features=()):
    try:
        rc, out, err = run_cmd(
            ["cargo", "build", "--target", TARGET, "--release", "--examples"]
            + feat_args(features),
            timeout=TIMEOUT_BUILD,
        )
    except subprocess.TimeoutExpired:
        print(f"BUILD TIMEOUT: cargo build exceeded {TIMEOUT_BUILD}s", file=sys.stderr)
        return False
    if rc != 0:
        snippet_limit = 4000
        print(f"BUILD FAILED for {TARGET}:", file=sys.stderr)
        if out:
            print(f"--- stdout (tail) ---\n{out[-snippet_limit:]}", file=sys.stderr)
        if err:
            print(f"--- stderr (tail) ---\n{err[-snippet_limit:]}", file=sys.stderr)
        return False
    return True


def run_qemu(example, features=()):
    rc, out, err = run_cmd(
        ["cargo", "run", "--target", TARGET, "--release", "--example", example]
        + feat_args(features),
        timeout=TIMEOUT_RUN,
    )
    combined = out + err
    if rc != 0:
        print(f"  cargo run failed (rc={rc}):\n{combined}", file=sys.stderr)
    return rc, combined


def text_size(example, features=()):
    try:
        rc, out, _err = run_cmd(
            [
                "cargo", "bloat",
                "--release", "--target", TARGET,
                "--example", example,
                "--message-format=json",
            ]
            + feat_args(features),
            timeout=TIMEOUT_BUILD,
        )
        if rc != 0:
            return None
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
    rows = []
    failures = []
    built_features = None

    for example, expected_algo, label, features in EXAMPLES:
        if features != built_features:
            if not build_examples(features):
                return 1
            built_features = features

        print(f"  Running {example}...", file=sys.stderr)
        try:
            rc, output = run_qemu(example, features)
        except subprocess.TimeoutExpired:
            failures.append(f"Timeout: {example}")
            rows.append((label, None, None, None, "TIMEOUT"))
            continue

        accepted = f"{expected_algo} ACCEPT" in output
        metric = parse_metric(output)
        tsize = text_size(example, features)

        if rc != 0:
            failures.append(f"Non-zero exit: {example} (rc={rc})")
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

    print(f"## krabipqc {TARGET_LABEL} footprint (QEMU virt -m 64M, riscv32imac)")
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
        "Cycle counts come from the `mcycle` CSR (instructions retired) and are "
        "reported in thousands. Treat them as a rough proxy, not a precise benchmark."
    )

    if failures:
        print(f"\nFailures: {len(failures)}", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
