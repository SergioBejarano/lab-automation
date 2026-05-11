import asyncio
import time

async def scan_port(host: str, port: int, semaphore: asyncio.Semaphore) -> int | None:
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=1.0
            )
            writer.close()
            await writer.wait_closed()
            return port
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

async def scan_host(host: str, ports: range, max_concurrent: int) -> list[int]:
    semaphore = asyncio.Semaphore(max_concurrent)
    tasks = [scan_port(host, p, semaphore) for p in ports]
    results = await asyncio.gather(*tasks)
    return sorted(p for p in results if p is not None)

if __name__ == "__main__":
    host = "127.0.0.1"

    for limit in [50, 200, 500]:
        start = time.perf_counter()
        open_ports = asyncio.run(scan_host(host, range(1, 1025), limit))
        elapsed = time.perf_counter() - start
        print(f"limit={limit:>4} | Open ports: {open_ports} | Time: {elapsed:.4f}s")
