import re
import argparse
import statistics
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# Part C — Web access log analysis
# ---------------------------------------------------------------------------

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<date>\d{2}/\w+/\d{4}):(?P<hour>\d{2}):\d{2}:\d{2}[^\]]*\] '
    r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (?P<path>\S+) \S+" (?P<status>\d{3}) \S+'
)

# Part C — Extended attack detection patterns
ATTACK_PATTERNS = re.compile(
    r"union.*select|insert.*into|drop\s+table|select.*from"
    r"|\.\./"
    r"|<script|javascript:|onerror="
    r"|cmd=|exec=|shell="
    r"|/wp-admin|/phpmyadmin|/\.env|/etc/passwd",
    re.IGNORECASE,
)

def analyze_access_log(path: str) -> dict:
    ip_counter     = Counter()
    status_counter = Counter()
    hourly_counter = Counter()
    suspicious     = []

    for line in Path(path).open():
        m = LOG_PATTERN.match(line)
        if not m:
            continue
        ip     = m.group("ip")
        hour   = m.group("hour")
        path_  = m.group("path")
        status = m.group("status")

        ip_counter[ip]         += 1
        status_counter[status] += 1
        hourly_counter[hour]   += 1

        # Part C — flag requests matching any attack pattern
        if ATTACK_PATTERNS.search(path_):
            suspicious.append({"ip": ip, "path": path_, "status": status, "hour": hour})

    return {
        "suspicious_requests": suspicious,
        "top_ips":             ip_counter.most_common(5),
        "status_distribution": dict(status_counter),
        "hourly_counts":       hourly_counter,
    }

# ---------------------------------------------------------------------------
# Part D — 3-sigma anomaly detection on hourly request counts
# ---------------------------------------------------------------------------

def detect_anomalies(hourly_counts: Counter, sigma_threshold: float = 3.0) -> list[str]:
    counts = list(hourly_counts.values())
    if len(counts) < 2:
        return []
    mean  = statistics.mean(counts)
    stdev = statistics.stdev(counts)
    anomalies = []
    for hour, count in sorted(hourly_counts.items()):
        z = (count - mean) / stdev
        if z > sigma_threshold:
            anomalies.append(
                f"[ANOMALY] {hour}:00 — {count} requests "
                f"(z={z:.1f}σ, threshold={sigma_threshold:.1f}σ)"
            )
    return anomalies

def main():
    parser = argparse.ArgumentParser(description="Analyze web access log for attacks and anomalies")
    parser.add_argument("--input", default="access.log")
    parser.add_argument("--sigma", type=float, default=3.0)
    args = parser.parse_args()

    results = analyze_access_log(args.input)

    print(f"\n{'='*55}")
    print(f"  ACCESS LOG ANALYSIS — {args.input}")
    print(f"{'='*55}")

    # Part C — suspicious requests
    print(f"\n[+] Suspicious requests detected: {len(results['suspicious_requests'])}")
    for req in results["suspicious_requests"][:10]:
        print(f"    [{req['status']}] {req['ip']:<18} {req['path']}")
    if len(results["suspicious_requests"]) > 10:
        print(f"    ... and {len(results['suspicious_requests']) - 10} more")

    # Part C — top IPs
    print(f"\n[+] Top 5 IPs by request volume:")
    for ip, count in results["top_ips"]:
        print(f"    {ip:<20} {count} requests")

    # Part C — status distribution
    print(f"\n[+] HTTP status code distribution:")
    for status, count in sorted(results["status_distribution"].items()):
        print(f"    HTTP {status}  →  {count}")

    # Part D — 3-sigma anomaly detection
    print(f"\n[+] Hourly anomaly detection (threshold={args.sigma}σ):")
    anomalies = detect_anomalies(results["hourly_counts"], args.sigma)
    if anomalies:
        for a in anomalies:
            print(f"    {a}")
    else:
        print("    No anomalies detected.")
    print()

if __name__ == "__main__":
    main()
