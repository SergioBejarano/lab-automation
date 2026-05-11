import re
import argparse
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# Part A — SSH authentication log analysis
# ---------------------------------------------------------------------------

FAIL_PATTERN    = re.compile(r"Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)")
SUCCESS_PATTERN = re.compile(r"Accepted \S+ for (\S+) from (\d+\.\d+\.\d+\.\d+)")

def analyze_auth_log(path: str, threshold: int = 10) -> dict:
    failed_by_ip   = Counter()
    targeted_users = Counter()
    total_failed   = 0
    total_success  = 0

    for line in Path(path).open():
        # Part A — count failed attempts per IP and track targeted usernames
        if m := FAIL_PATTERN.search(line):
            user, ip = m.group(1), m.group(2)
            failed_by_ip[ip] += 1
            targeted_users[user] += 1
            total_failed += 1
        # Part A — count successful logins for the fail/success ratio
        elif SUCCESS_PATTERN.search(line):
            total_success += 1

    brute_force_ips = [
        {"ip": ip, "attempts": count}
        for ip, count in failed_by_ip.most_common()
        if count >= threshold
    ]
    ratio = round(total_failed / total_success, 2) if total_success > 0 else float("inf")

    return {
        "brute_force_ips":    brute_force_ips,
        "targeted_users":     targeted_users.most_common(),
        "total_failed":       total_failed,
        "total_success":      total_success,
        "fail_success_ratio": ratio,
    }

def main():
    parser = argparse.ArgumentParser(description="Analyze SSH auth log for brute-force activity")
    parser.add_argument("--input",     default="auth.log")
    parser.add_argument("--threshold", type=int, default=10)
    args = parser.parse_args()

    results = analyze_auth_log(args.input, args.threshold)

    print(f"\n{'='*55}")
    print(f"  AUTH LOG ANALYSIS — {args.input}")
    print(f"{'='*55}")
    print(f"\n[+] IPs with >= {args.threshold} failed attempts (brute-force suspects):")
    for entry in results["brute_force_ips"]:
        print(f"    {entry['ip']:<20} {entry['attempts']} attempts")
    print(f"\n[+] Targeted usernames:")
    for user, count in results["targeted_users"]:
        print(f"    {user:<15} {count} times")
    print(f"\n[+] Login summary:")
    print(f"    Failed logins  : {results['total_failed']}")
    print(f"    Successful     : {results['total_success']}")
    print(f"    Fail/success   : {results['fail_success_ratio']}:1")
    print()

if __name__ == "__main__":
    main()
