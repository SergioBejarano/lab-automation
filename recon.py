import argparse
import ipaddress
import json
import logging
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


# ===========================================================================
# Utilities — logging, subprocess wrapper, mode detection
# ===========================================================================

def setup_logging(output_dir: Path, verbose: bool) -> logging.Logger:
    """Configure audit logger that writes to audit.log and optionally stderr."""
    output_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("recon.audit")
    logger.setLevel(logging.DEBUG)

    # File handler — always on
    fh = logging.FileHandler(output_dir / "audit.log")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)

    # Stderr handler — only when --verbose
    if verbose:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(sh)

    return logger


def run(cmd: list[str], logger: logging.Logger, timeout: int = 30) -> tuple[str, str, int]:
    """
    Run a subprocess command, log it, and return (stdout, stderr, returncode).
    Never raises — errors are logged and returned as non-zero returncode.
    Each step fails independently without crashing the tool.
    """
    cmd_str = " ".join(cmd)
    logger.info(f"RUN: {cmd_str}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0:
            logger.info(f"OK:  {cmd_str} (exit 0)")
        else:
            logger.warning(f"ERR: {cmd_str} (exit {result.returncode}) — {result.stderr.strip()[:120]}")
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        logger.error(f"TIMEOUT: {cmd_str} after {timeout}s")
        return "", "timeout", 1
    except FileNotFoundError:
        logger.error(f"NOT FOUND: {cmd[0]} — is it installed?")
        return "", "command not found", 1


def detect_mode(target: str) -> str:
    """Return 'ip' if target is a valid IP address, otherwise 'domain'."""
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


# ===========================================================================
# Domain mode — whois, dig (A/MX/NS/TXT), curl -IL
# ===========================================================================

def run_whois_domain(target: str, logger: logging.Logger) -> dict:
    stdout, stderr, rc = run(["whois", target], logger, timeout=20)

    # FIX 3 — always return structured dict, never just an error string
    if rc != 0 or not stdout:
        reason = "timeout" if "timeout" in stderr else "error"
        return {
            "status":            "unavailable",
            "reason":            reason,
            "registrar":         "",
            "registration_date": "",
            "expiry_date":       "",
            "registrant_org":    "",
        }

    def extract(patterns: list[str]) -> str:
        for pattern in patterns:
            m = re.search(pattern, stdout, re.IGNORECASE | re.MULTILINE)
            if m:
                return m.group(1).strip()
        return ""

    return {
        "status":            "ok",
        "registrar":          extract([r"Registrar:\s*(.+)", r"registrar:\s*(.+)"]),
        "registration_date":  extract([r"Creation Date:\s*(.+)", r"created:\s*(.+)"]),
        "expiry_date":        extract([r"Expir\w+ Date:\s*(.+)", r"Expiry Date:\s*(.+)"]),
        "registrant_org":     extract([r"Registrant Organization:\s*(.+)", r"org:\s*(.+)"]),
    }


def run_dig(target: str, logger: logging.Logger) -> dict:
    records = {}
    for rtype in ["A", "MX", "NS", "TXT"]:
        stdout, _, rc = run(["dig", "+short", rtype, target], logger)
        records[rtype] = [l.strip() for l in stdout.splitlines() if l.strip()] if rc == 0 else []
    return records


def run_curl_headers(target: str, logger: logging.Logger) -> dict:
    """
    FIX 1 — use -IL (follow redirects) to capture headers from the final
    destination, not from a 301 redirect response. This ensures CSP, HSTS,
    and X-Frame-Options are read from the actual page, not the redirect.
    """
    url = target if target.startswith("http") else f"https://{target}"
    stdout, _, rc = run(["curl", "-IL", "-s", "--max-time", "10", url], logger, timeout=15)
    if rc != 0:
        # Fallback to http
        url = f"http://{target}"
        stdout, _, rc = run(["curl", "-IL", "-s", "--max-time", "10", url], logger, timeout=15)
    if not stdout:
        return {
            "status": "unavailable",
            "headers": {},
            "missing_security_headers": [],
        }

    # When -L follows redirects, stdout contains all response headers separated
    # by blank lines. We only want the LAST response block (final destination).
    blocks = re.split(r"\r?\n\r?\n", stdout.strip())
    last_block = blocks[-1] if blocks else stdout

    headers = {}
    for line in last_block.splitlines():
        if ":" in line and not line.startswith("HTTP/"):
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()

    security_headers = {
        "server":                    headers.get("server", ""),
        "x-powered-by":              headers.get("x-powered-by", ""),
        "content-security-policy":   headers.get("content-security-policy", ""),
        "strict-transport-security": headers.get("strict-transport-security", ""),
        "x-frame-options":           headers.get("x-frame-options", ""),
        "x-content-type-options":    headers.get("x-content-type-options", ""),
    }
    missing = [
        k for k, v in security_headers.items()
        if k not in ("server", "x-powered-by") and not v
    ]
    return {
        "status":                  "ok",
        "headers":                 security_headers,
        "missing_security_headers": missing,
    }


# ===========================================================================
# IP mode — nmap, dig -x, whois on IP
# ===========================================================================

def run_nmap(target: str, output_dir: Path, logger: logging.Logger) -> dict:
    xml_path = output_dir / "nmap.xml"
    _, _, rc = run(
        ["nmap", "-sV", "--open", "--top-ports", "100", "-oX", str(xml_path), target],
        logger, timeout=120
    )
    if rc != 0 or not xml_path.exists():
        return {"status": "unavailable", "reason": "nmap failed", "hosts": []}

    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        logger.error(f"XML parse error: {e}")
        return {"status": "unavailable", "reason": str(e), "hosts": []}

    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            continue
        ports = []
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            ports.append({
                "port":    int(port.get("portid")),
                "service": svc.get("name", "") if svc is not None else "",
                "version": " ".join(filter(None, [
                    svc.get("product", "") if svc is not None else "",
                    svc.get("version", "") if svc is not None else "",
                ])).strip(),
            })
        hosts.append({"ip": addr.get("addr"), "open_ports": ports})

    return {"status": "ok", "hosts": hosts}


def run_reverse_dns(target: str, logger: logging.Logger) -> dict:
    stdout, _, rc = run(["dig", "-x", target, "+short"], logger)
    hostnames = [l.strip().rstrip(".") for l in stdout.splitlines() if l.strip()]
    return {
        "status":    "ok" if rc == 0 else "unavailable",
        "hostnames": hostnames,
    }


def run_whois_ip(target: str, logger: logging.Logger) -> dict:
    stdout, stderr, rc = run(["whois", target], logger, timeout=20)

    # FIX 3 — always return structured dict with consistent keys
    if rc != 0 or not stdout:
        reason = "timeout" if "timeout" in stderr else "error"
        return {
            "status":       "unavailable",
            "reason":       reason,
            "organization": "",
            "country":      "",
            "cidr":         "",
        }

    def extract(patterns: list[str]) -> str:
        for pattern in patterns:
            m = re.search(pattern, stdout, re.IGNORECASE | re.MULTILINE)
            if m:
                return m.group(1).strip()
        return ""

    return {
        "status":       "ok",
        "organization": extract([r"OrgName:\s*(.+)", r"org-name:\s*(.+)", r"owner:\s*(.+)"]),
        "country":      extract([r"Country:\s*(.+)", r"country:\s*(.+)"]),
        "cidr":         extract([r"CIDR:\s*(.+)", r"route:\s*(.+)"]),
    }


# ===========================================================================
# Report generation — results.json + report.md
# ===========================================================================

def _whois_section(lines: list, whois: dict):
    """
    FIX 2 — render WHOIS section cleanly whether data is available or not.
    Never shows raw error keys in the markdown table.
    """
    lines.append("\n## WHOIS\n")
    if whois.get("status") == "unavailable":
        lines.append(f"> ⚠️ WHOIS data unavailable ({whois.get('reason', 'unknown reason')}). "
                     "The tool continued with remaining steps.\n")
        return
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    skip = {"status", "reason", "raw_lines"}
    for k, v in whois.items():
        if k not in skip and v:
            lines.append(f"| {k.replace('_', ' ').title()} | {v} |")


def generate_report(results: dict, output_dir: Path, target: str, mode: str):
    """Write results.json and report.md to the output directory."""

    # results.json — structured data, no raw text
    (output_dir / "results.json").write_text(json.dumps(results, indent=2))

    lines = []
    a = lines.append
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    a("# Recon Report")
    a(f"\n**Target:** `{target}`  ")
    a(f"**Mode:** {mode}  ")
    a(f"**Generated:** {ts}\n")
    a("---\n")

    # ------------------------------------------------------------------ #
    a("## Summary\n")
    a("| Category | Status |")
    a("|----------|--------|")

    if mode == "domain":
        whois = results.get("whois", {})
        dns   = results.get("dns",   {})
        http  = results.get("http",  {})

        a(f"| Registrar       | {whois.get('registrar', '—') or '—'} |")
        a(f"| Expiry date     | {whois.get('expiry_date', '—') or '—'} |")
        a(f"| A records       | {', '.join(dns.get('A', [])) or '—'} |")
        a(f"| MX records      | {len(dns.get('MX', []))} found |")
        missing = http.get("missing_security_headers", [])
        a(f"| Missing security headers | {len(missing)} |")

        a("\n---\n")
        _whois_section(lines, whois)

        a("\n## DNS Records\n")
        for rtype, recs in dns.items():
            a(f"### {rtype}\n")
            if recs:
                for r in recs:
                    a(f"- `{r}`")
            else:
                a("_No records found_")
            a("")

        a("## HTTP Headers\n")
        headers = http.get("headers", {})
        if not headers:
            a("> ⚠️ Could not retrieve HTTP headers.\n")
        else:
            a("| Header | Value |")
            a("|--------|-------|")
            for k, v in headers.items():
                display = v if v else "❌ not present"
                a(f"| `{k}` | {display} |")

            if missing:
                a("\n### ⚠️ Missing Security Headers\n")
                for h in missing:
                    a(f"- `{h}`")

    else:  # ip mode
        nmap  = results.get("nmap",        {})
        rdns  = results.get("reverse_dns", {})
        whois = results.get("whois",       {})
        hosts = nmap.get("hosts", [])
        total_ports = sum(len(h["open_ports"]) for h in hosts)

        a(f"| Organization | {whois.get('organization', '—') or '—'} |")
        a(f"| Country      | {whois.get('country', '—') or '—'} |")
        a(f"| CIDR         | {whois.get('cidr', '—') or '—'} |")
        a(f"| Reverse DNS  | {', '.join(rdns.get('hostnames', [])) or '—'} |")
        a(f"| Open ports   | {total_ports} found |")

        a("\n---\n")
        _whois_section(lines, whois)

        a("\n## Reverse DNS\n")
        hostnames = rdns.get("hostnames", [])
        if hostnames:
            for h in hostnames:
                a(f"- `{h}`")
        else:
            a("_No PTR records found_")

        a("\n## Open Ports\n")
        if not hosts:
            a("_No hosts with open ports detected_")
        for host in hosts:
            a(f"### `{host['ip']}`\n")
            a("| Port | Service | Version |")
            a("|------|---------|---------|")
            for p in host["open_ports"]:
                a(f"| {p['port']} | {p['service']} | {p['version'] or '—'} |")
            a("")

    a("\n---\n")
    a(f"_Audit log: `{output_dir}/audit.log`_")

    (output_dir / "report.md").write_text("\n".join(lines))


# ===========================================================================
# Main — CLI via argparse
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Multi-stage reconnaissance tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # Required: target domain or IP
    parser.add_argument("target",
                        help="Domain name or IP address to recon")
    # Optional: force mode, auto-detected if omitted
    parser.add_argument("--mode", choices=["domain", "ip"], default=None,
                        help="Force recon mode (auto-detected from target if omitted)")
    # Optional: output directory
    parser.add_argument("--output", default=None,
                        help="Output directory (default: ./recon_<target>_<timestamp>/)")
    # Optional: verbose stderr logging
    parser.add_argument("--verbose", action="store_true",
                        help="Print progress to stderr as the tool runs")
    args = parser.parse_args()

    target = args.target
    mode   = args.mode or detect_mode(target)
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe   = re.sub(r"[^\w\-.]", "_", target)
    outdir = Path(args.output) if args.output else Path(f"recon_{safe}_{ts}")

    logger = setup_logging(outdir, args.verbose)
    logger.info(f"=== recon.py started | target={target} mode={mode} output={outdir} ===")

    results = {"target": target, "mode": mode, "timestamp": ts}

    if mode == "domain":
        print(f"[*] Mode: domain | Target: {target}")
        print("[*] Running whois ...")
        results["whois"] = run_whois_domain(target, logger)

        print("[*] Running dig (A, MX, NS, TXT) ...")
        results["dns"] = run_dig(target, logger)

        print("[*] Running curl -IL (follow redirects) ...")
        results["http"] = run_curl_headers(target, logger)

    else:
        print(f"[*] Mode: ip | Target: {target}")
        print("[*] Running nmap ...")
        results["nmap"] = run_nmap(target, outdir, logger)

        print("[*] Running reverse DNS lookup ...")
        results["reverse_dns"] = run_reverse_dns(target, logger)

        print("[*] Running whois ...")
        results["whois"] = run_whois_ip(target, logger)

    print("[*] Writing results.json and report.md ...")
    generate_report(results, outdir, target, mode)
    logger.info(f"=== recon.py finished | output={outdir} ===")

    print(f"\n[✓] Done — output in: {outdir}/")
    print(f"    ├── results.json")
    print(f"    ├── report.md")
    print(f"    ├── audit.log")
    if mode == "ip":
        print(f"    └── nmap.xml")


if __name__ == "__main__":
    main()
