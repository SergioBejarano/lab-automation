import socket
import time
from concurrent.futures import ThreadPoolExecutor

def scan_port(args: tuple) -> int | None:
    host, port = args
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.connect((host, port))
            return port
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

if __name__ == "__main__":
    host = "127.0.0.1"
    ports = range(1, 1025)

    for workers in [50, 200, 500]:
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = executor.map(scan_port, [(host, p) for p in ports])
        open_ports = sorted(p for p in results if p is not None)
        elapsed = time.perf_counter() - start
        print(f"workers={workers:>4} | Open ports: {open_ports} | Time: {elapsed:.4f}s")
