import socket
import json
import sys
import time
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

def parse_ports(ports_arg: str) -> list[int]:
    ports = []
    for part in ports_arg.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def scan_port(args: tuple) -> int | None:
    host, port, timeout = args
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return port
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

def main():
    parser = argparse.ArgumentParser(description="Concurrent TCP port scanner")
    parser.add_argument("target",                                help="IP address to scan")
    parser.add_argument("--ports",   default="1-1024",          help="Port range or list (e.g. 1-1024 or 22,80,443)")
    parser.add_argument("--rate",    type=int,   default=200,   help="Max concurrent connections (default: 200)")
    parser.add_argument("--timeout", type=float, default=0.5,   help="Timeout per port in seconds (default: 0.5)")
    parser.add_argument("--output",  default=None,              help="Output JSON file (default: stdout)")
    args = parser.parse_args()

    ports = parse_ports(args.ports)

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.rate) as executor:
        results = executor.map(scan_port, [(args.target, p, args.timeout) for p in ports])
    elapsed = time.perf_counter() - start

    open_ports = sorted(p for p in results if p is not None)

    output = {
        "target":            args.target,
        "scan_time_seconds": round(elapsed, 4),
        "timestamp":         datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "open_ports":        open_ports,
    }

    json_output = json.dumps(output, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(json_output)
        print(f"Results saved to {args.output}")
    else:
        print(json_output)

if __name__ == "__main__":
    main()
