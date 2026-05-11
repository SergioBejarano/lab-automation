import argparse
import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime


# ---------------------------------------------------------------------------
# Part B — Parse nmap XML output into structured Python dictionaries
# ---------------------------------------------------------------------------

def parse_ports(host_elem: ET.Element) -> list[dict]:
    """Extract all open ports with service name and version from a host element."""
    ports = []
    for port in host_elem.findall(".//port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        entry = {
            "port": int(port.get("portid")),
            # service name comes from the <service name="..."> attribute
            "service": service.get("name", "unknown") if service is not None else "unknown",
            # version is assembled from product + version + extrainfo fields
            "version": " ".join(filter(None, [
                service.get("product", ""),
                service.get("version", ""),
                f'({service.get("extrainfo", "")})' if service.get("extrainfo") else "",
            ])).strip() if service is not None else "",
        }
        ports.append(entry)
    return ports


# ---------------------------------------------------------------------------
# Part C — Enrich hosts with SSH host key type via ssh-keyscan subprocess
# ---------------------------------------------------------------------------

def get_ssh_key_type(ip: str, timeout: int = 5) -> str | None:
    """
    Run ssh-keyscan against the given IP and return the first key type found.
    Returns None if the host does not respond or the subprocess times out.
    Comment lines (starting with #) are skipped — they contain metadata,
    not key data, and were causing a parsing bug before this fix.
    """
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-T", str(timeout), ip],
            capture_output=True, text=True, timeout=timeout + 2
        )
        for line in result.stdout.splitlines():
            # Skip comment lines and blank lines in ssh-keyscan output
            if line.startswith("#") or not line.strip():
                continue
            # Each key line format: <ip> <key-type> <base64-key>
            parts = line.strip().split()
            if len(parts) >= 2:
                return parts[1]   # e.g. ecdsa-sha2-nistp256, ssh-ed25519
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def parse_scan(xml_path: str) -> list[dict]:
    """
    Parse the nmap XML file and return a list of host dictionaries.
    Only hosts that are 'up' and have at least one open port are included.
    Hosts with port 22 open are enriched with SSH key type (Part C).
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts = []

    for host in root.findall("host"):
        # Skip hosts that did not respond
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        # Extract IPv4 address from <address addrtype="ipv4"> element
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr")

        # Hostname is optional — nmap may leave this empty
        hostname_elem = host.find(".//hostname")
        hostname = hostname_elem.get("name", "") if hostname_elem is not None else ""

        # Part B — build the open ports list for this host
        open_ports = parse_ports(host)
        if not open_ports:
            continue

        entry = {
            "ip":         ip,
            "hostname":   hostname,
            "open_ports": open_ports,
        }

        # Part C — if port 22 is open, run ssh-keyscan to get the host key type
        has_ssh = any(p["port"] == 22 for p in open_ports)
        if has_ssh:
            print(f"  [*] Running ssh-keyscan on {ip} ...")
            key_type = get_ssh_key_type(ip)
            entry["ssh_host_key_type"] = key_type if key_type else "unavailable"

        hosts.append(entry)

    return hosts


# ---------------------------------------------------------------------------
# Part D — CLI interface and JSON output
# ---------------------------------------------------------------------------

def main():
    # argparse provides --input and --output flags with sensible defaults
    parser = argparse.ArgumentParser(description="Parse nmap XML and enrich with SSH key info")
    parser.add_argument("--input",  default="scan.xml",   help="nmap XML input file")
    parser.add_argument("--output", default="hosts.json", help="JSON output file")
    args = parser.parse_args()

    print(f"[*] Parsing {args.input} ...")
    hosts = parse_scan(args.input)
    print(f"[*] Found {len(hosts)} active host(s) with open ports")

    # Wrap results with metadata before writing to disk
    output = {
        "timestamp":   datetime.now().isoformat(timespec="seconds"),
        "total_hosts": len(hosts),
        "hosts":       hosts,
    }

    # Part D — write enriched host list to JSON file
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[*] Results written to {args.output}")


if __name__ == "__main__":
    main()
