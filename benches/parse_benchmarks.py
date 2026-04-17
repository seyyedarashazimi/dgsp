#!/usr/bin/env python3
"""
Parse Criterion benchmark logs produced by all_benchmarks.sh and print timing tables.
Run on the host (not inside Docker): python3 parse_benchmarks.py [log_dir]
If log_dir is omitted, the most recent log_* directory next to this script is used.
"""
import re, sys
from pathlib import Path

VARIANTS   = ["sphincs_shake_256s", "sphincs_shake_256f"]
OPERATIONS = [
    ("keygen_manager", "DGSP.KG"),
    ("join",           "DGSP.Join"),
    ("csr",            "DGSP.RequestU"),
    ("gen_cert",       "DGSP.ResponseM"),
    ("sign",           "DGSP.Sign"),
    ("verify",         "DGSP.Verify"),
    ("open",           "DGSP.Open"),
    ("judge",          "DGSP.Judge"),
    ("revoke",         "DGSP.Revoke"),
]
STORAGES   = ("memory", "disk")
GROUP_LOGS = (10, 25)
CERT_SIZES = (1, 8)
COLS = [(st, gl, cs) for st in STORAGES for gl in GROUP_LOGS for cs in CERT_SIZES]

TIME_RE = re.compile(r"time:\s+\[[\d.]+\s+\S+\s+([\d.]+)\s+(\S+)")
UNITS   = {"s": 1e3, "ms": 1.0, "us": 1e-3, "µs": 1e-3, "ns": 1e-6}


def parse_log(path):
    results, op = {}, None
    for line in path.read_text(encoding="utf-8").splitlines():
        if "/" in line and not line.lstrip().startswith("time:"):
            op = line.rstrip().rsplit("/", 1)[-1]
        elif op:
            m = TIME_RE.search(line)
            if m:
                results[op] = float(m.group(1)) * UNITS.get(m.group(2), 1.0)
                op = None
    return results


def fmt(ms):
    if ms >= 1000: return f"{ms:.1f}"
    if ms >= 100:  return f"{ms:.2f}"
    if ms >= 10:   return f"{ms:.3f}"
    return         f"{ms:.4f}"


def print_table(log_dir, variant):
    data = {}
    for col in COLS:
        st, gl, cs = col
        f = log_dir / f"in_{st}" / f"bench_{variant}_group_log_{gl}_cert_{cs}.log"
        data[col] = parse_log(f) if f.exists() else {}

    CW = 6
    span_st = len(GROUP_LOGS) * len(CERT_SIZES) * (CW + 3) - 3
    span_gl = len(CERT_SIZES)                   * (CW + 3) - 3

    def data_row(label, vals):
        return f"| {label:<14} |" + "".join(f" {v:>{CW}} |" for v in vals)

    sep = f"| {'-'*14} |" + f" {'-'*CW} |" * len(COLS)

    print(f"\n### dgsp_{variant} (all times in ms)\n")
    print(f"| {'DB feature':<14} |" + "".join(f" {'in-'+st:^{span_st}} |" for st in STORAGES))
    print(f"| {'GROUP SIZE':<14} |" + "".join(f" {'2^'+str(gl):^{span_gl}} |" for st in STORAGES for gl in GROUP_LOGS))
    print(f"| {'BATCH SIZE':<14} |" + "".join(f" {cs:^{CW}} |" for st in STORAGES for gl in GROUP_LOGS for cs in CERT_SIZES))
    print(sep)
    for key, label in OPERATIONS:
        vals = [fmt(data[col][key]) if key in data[col] else "N/A" for col in COLS]
        print(data_row(label, vals))
    print(sep)


def main():
    script_dir = Path(__file__).parent
    log_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else max(
        script_dir.glob("log_*"), key=lambda p: p.stat().st_mtime, default=None
    )
    if log_dir is None:
        sys.exit("No log_* directory found. Usage: python3 parse_benchmarks.py <log_dir>")
    print(f"Using: {log_dir}", file=sys.stderr)
    for v in VARIANTS:
        print_table(log_dir, v)


if __name__ == "__main__":
    main()
