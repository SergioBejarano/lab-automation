import socket
import time

def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

if __name__ == "__main__":
    host = "127.0.0.1"
    start = time.perf_counter()
    open_ports = [p for p in range(1, 1025) if scan_port(host, p)]
    elapsed = time.perf_counter() - start
    print(f"Open ports: {open_ports}")
    print(f"Time: {elapsed:.4f}s")
