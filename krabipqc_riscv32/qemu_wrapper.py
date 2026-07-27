#!/usr/bin/env python3
"""QEMU wrapper for RISC-V (virt) — stops after the outcome record or on timeout.

The QEMU virt machine has no semihosting exit, so the binary loops forever
after printing its evidence. This wrapper monitors the UART output (routed
to stdout via -nographic) and terminates QEMU as soon as it sees the line.
"""

import subprocess
import sys
import threading

TIMEOUT = 180  # seconds — ML-DSA-87 sign with rejection sampling is the long one


def main():
    if len(sys.argv) < 2:
        print("Usage: qemu_wrapper.py <elf>", file=sys.stderr)
        return 1

    elf = sys.argv[1]
    cmd = [
        "qemu-system-riscv32",
        "-nographic",
        "-machine", "virt",
        "-m", "64M",
        "-bios", "none",
        "-kernel", elf,
    ]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    timed_out = [False]

    def on_timeout():
        timed_out[0] = True
        proc.kill()

    timer = threading.Timer(TIMEOUT, on_timeout)
    timer.start()

    accepted = False
    outcome_seen = False
    try:
        for raw_line in iter(proc.stdout.readline, b""):
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            print(line, flush=True)
            if line.startswith("EM_OUTCOME "):
                outcome_seen = True
                accepted = " status:PASS" in line
                proc.terminate()
                break
            if line.startswith(("PANIC:", "MEASUREMENT ERROR:")):
                proc.terminate()
                break
    finally:
        timer.cancel()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    if timed_out[0]:
        print("TIMEOUT", file=sys.stderr)
        return 1

    return 0 if (accepted and outcome_seen) else 1


if __name__ == "__main__":
    sys.exit(main())
