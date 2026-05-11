# Security Automation Lab — README

**Course topic:** Automation (Lab 15)
**Environment:** Kali Linux
**Language:** Python 3.10+
**External tools required:** `nmap`, `whois`, `dnsutils` (`dig`), `curl`, `ssh-keyscan`

---

## Table of Contents

1. [Setup](#setup)
2. [Repository Structure](#repository-structure)
3. [Part 1 — Concurrent Port Scanner](#part-1--concurrent-port-scanner)
4. [Part 2 — nmap XML Parser and Enricher](#part-2--nmap-xml-parser-and-enricher)
5. [Part 3 — Log Analysis and Anomaly Detection](#part-3--log-analysis-and-anomaly-detection)
6. [Part 4 — Integrated Reconnaissance Tool](#part-4--integrated-reconnaissance-tool)
7. [Files — Submitted Deliverables](#files--submitted-deliverables)

---

## Setup

Install system dependencies:

```bash
sudo apt update
sudo apt install -y nmap whois dnsutils curl python3 python3-pip
```

No third-party Python packages are required. All scripts use the standard library only
(`socket`, `asyncio`, `concurrent.futures`, `subprocess`, `xml.etree.ElementTree`,
`re`, `statistics`, `collections`, `argparse`, `json`, `logging`, `pathlib`).

---

## Repository Structure

```
lab-auto/
├── scanner_v1.py              # Part 1A — sequential baseline scanner
├── scanner_v2_threads.py      # Part 1A — ThreadPoolExecutor version
├── scanner_v3_asyncio.py      # Part 1B — asyncio + Semaphore version
├── scanner_final.py           # Part 1C/D — final scanner with CLI + JSON output
├── parse_scan.py              # Part 2   — nmap XML parser + ssh-keyscan enricher
├── auth_analysis.py           # Part 3A  — SSH brute-force log analysis
├── log_analysis.py            # Part 3C/D — web access log analysis + 3σ anomaly detection
├── recon.py                   # Part 4   — integrated multi-stage recon tool
│
├── scan.xml                   # nmap output used in Part 2
├── hosts.json                 # parse_scan.py output
├── report.md                  # combined findings report (Part 3E)
│
├── recon_192.168.145.128_*/   # recon.py output — IP mode run
│   ├── audit.log
│   ├── nmap.xml
│   ├── report.md
│   └── results.json
│
└── recon_google.com_*/        # recon.py output — domain mode run
    ├── audit.log
    ├── report.md
    └── results.json
```

---

## Part 1 — Concurrent Port Scanner

### What was built

Three progressive versions of a TCP port scanner, each improving on the previous:

**`scanner_v1.py` — Sequential baseline**
Scans ports one at a time using Python's `socket` module. Simple and correct, but
slow: each closed port blocks until `ConnectionRefusedError` or timeout. Used to
establish the timing baseline for comparison.

```bash
python3 scanner_v1.py
# Target hardcoded to 127.0.0.1, ports 1–1024
```

**`scanner_v2_threads.py` — ThreadPoolExecutor**
Replaces the sequential loop with `concurrent.futures.ThreadPoolExecutor`. All
connection attempts are dispatched in parallel. Benchmarked at three concurrency
levels (50, 200, 500 workers) against a baseline with `iptables DROP` rules on
ports 100–300 to produce measurable timeouts.

```bash
python3 scanner_v2_threads.py
```

Benchmark results (localhost, ports 1–1024, 200 filtered ports at 1s timeout):

| Mode | Workers | Time | Speedup |
|------|---------|------|---------|
| Sequential | — | 201.3s | 1× |
| ThreadPool | 50 | 2.53s | 79× |
| ThreadPool | 200 | 1.02s | 197× |
| ThreadPool | 500 | 0.56s | 362× |

**`scanner_v3_asyncio.py` — asyncio + Semaphore**
Rewrites the scanner using `asyncio.open_connection` and `asyncio.Semaphore` for
concurrency control. Uses a single-threaded event loop instead of OS threads.
Faster in theory for high host counts, but slower than threads on localhost
because the event loop overhead exceeds the I/O wait when connections are
near-instantaneous.

```bash
python3 scanner_v3_asyncio.py
```

asyncio vs. threads comparison (same conditions):

| Workers | ThreadPool | asyncio | Faster |
|---------|-----------|---------|--------|
| 50 | 2.53s | 5.03s | Threads 2× |
| 200 | 1.02s | 2.02s | Threads 2× |
| 500 | 0.56s | 1.02s | Threads 1.8× |

**`scanner_final.py` — Full CLI with argparse and JSON output (Part 1C/D)**
The production version. Adds a complete `argparse` interface and structured JSON output.

```bash
# Scan top ports with default settings
python3 scanner_final.py 192.168.145.128

# Custom port range (comma list or range)
python3 scanner_final.py 192.168.145.128 --ports 22,80,443,8080
python3 scanner_final.py 192.168.145.128 --ports 1-1024

# Tune concurrency and timeout
python3 scanner_final.py 192.168.145.128 --rate 500 --timeout 0.5

# Save results to file
python3 scanner_final.py 192.168.145.128 --output results.json
```

Output format:
```json
{
  "target": "192.168.145.128",
  "scan_time_seconds": 1.2,
  "timestamp": "2026-05-09T10:00:00",
  "open_ports": [22, 80]
}
```

CLI flags:

| Flag | Description | Default |
|------|-------------|---------|
| `target` | IP address to scan | required |
| `--ports` | Port range (`1-1024`) or list (`22,80,443`) | `1-1024` |
| `--rate` | Max concurrent connections | `200` |
| `--timeout` | Per-port timeout in seconds | `0.5` |
| `--output` | JSON output file path | stdout |

---

## Part 2 — nmap XML Parser and Enricher

### What was built

**`parse_scan.py`** — reads the XML output of `nmap -sV --open -oX` and produces
a structured JSON file. Optionally enriches hosts that have port 22 open by running
`ssh-keyscan` via subprocess to extract the SSH host key algorithm.

```bash
# Generate the nmap scan first
sudo nmap -sV --open -oX scan.xml 192.168.145.0/24

# Parse and enrich
python3 parse_scan.py --input scan.xml --output hosts.json
```

Key implementation decisions:
- Uses `xml.etree.ElementTree` only — no third-party nmap libraries.
- Version string is assembled from `product + version + extrainfo` nmap fields.
- `ssh-keyscan` output comment lines (starting with `#`) are skipped to avoid
  a parsing bug where metadata was mistaken for the key type.
- Each step is wrapped in try/except so a timeout on one host does not abort the run.

Output format per host:
```json
{
  "ip": "192.168.145.128",
  "hostname": "",
  "open_ports": [
    {"port": 22, "service": "ssh", "version": "OpenSSH 10.2p1 Debian 3 (protocol 2.0)"},
    {"port": 80, "service": "http", "version": "Apache httpd 2.4.66 (Debian)"}
  ],
  "ssh_host_key_type": "ssh-rsa"
}
```

---

## Part 3 — Log Analysis and Anomaly Detection

### What was built

Three scripts that analyze SSH authentication logs and web access logs for attack
patterns and statistical anomalies.

**`auth_analysis.py` — SSH brute-force detection (Part 3A)**

Reads `/var/log/auth.log` (or a synthetic equivalent) and extracts:
- IPs with more than N failed login attempts, sorted descending
- Usernames being targeted by attackers
- Overall failed-to-successful login ratio

```bash
python3 auth_analysis.py --input auth.log --threshold 10
```

Results from the synthetic log (500 failed, 20 successful):

| IP | Attempts | Risk |
|----|----------|------|
| 185.220.101.5 | 268 | High |
| 45.33.32.156 | 199 | High |
| 10.0.0.2 | 22 | Medium |

Fail/success ratio: **25:1** — consistent with automated credential stuffing.

**`log_analysis.py` — Web attack detection + 3σ anomaly detection (Part 3C/D)**

Parses Apache/Nginx combined log format and produces:
- All requests matching attack signatures (SQLi, XSS, path traversal, command injection)
- Top 5 IPs by request volume
- HTTP status code distribution
- Hourly traffic anomalies using the 3-sigma rule

```bash
python3 log_analysis.py --input access.log --sigma 3.0
```

Attack patterns detected (extended from the theory section):

| Category | Pattern examples |
|----------|-----------------|
| SQL injection | `UNION SELECT`, `DROP TABLE`, `INSERT INTO` |
| Path traversal | `../`, `..\` |
| XSS | `<script`, `javascript:`, `onerror=` |
| Command injection | `cmd=`, `exec=`, `shell=` |
| Probing | `/wp-admin`, `/phpmyadmin`, `/.env`, `/etc/passwd` |

Anomaly detected:
```
[ANOMALY] 03:00 — 946 requests (z=4.7σ, threshold=3.0σ)
```

**`report.md` — Combined findings report (Part 3E)**

Consolidates all findings from the SSH auth analysis, web attack detection,
anomaly detection, and nmap enrichment into a single structured markdown document
with sections for each finding category, including summary tables, brute-force
suspects, targeted usernames, suspicious HTTP requests, status code distribution,
and anomalous traffic hours.

---

## Part 4 — Integrated Reconnaissance Tool

### What was built

**`recon.py`** — a single-file, multi-stage reconnaissance tool with full audit logging.

```bash
# IP mode (auto-detected)
python3 recon.py 192.168.145.128 --verbose

# Domain mode (auto-detected)
python3 recon.py google.com --verbose

# Force mode and custom output directory
python3 recon.py google.com --mode domain --output my_output/ --verbose
```

CLI flags:

| Flag | Description | Default |
|------|-------------|---------|
| `target` | Domain or IP to recon | required |
| `--mode` | `domain` or `ip` | auto-detected |
| `--output` | Output directory | `./recon_<target>_<timestamp>/` |
| `--verbose` | Print progress to stderr | off |

**Domain mode** runs: `whois` → `dig` (A, MX, NS, TXT) → `curl -IL` (HTTP headers)

**IP mode** runs: `nmap -sV --top-ports 100` → `dig -x` (reverse DNS) → `whois`

Each step is wrapped in a `try/except` with timeout handling. A failure in any single
step is logged and does not abort the remaining steps.

**Output files per run:**

| File | Contents |
|------|----------|
| `results.json` | All findings in a structured dict keyed by tool name |
| `report.md` | Human-readable markdown with tables and security header analysis |
| `audit.log` | Timestamped record of every command run, its result, and any errors |
| `nmap.xml` | Raw nmap XML output (IP mode only) |

**Security header analysis** (domain mode): the tool explicitly flags missing headers:
- `content-security-policy`
- `strict-transport-security`
- `x-frame-options`
- `x-content-type-options`

Results from the two test runs:

| Target | Mode | Open ports | Missing headers | WHOIS |
|--------|------|-----------|-----------------|-------|
| 192.168.145.128 | ip | 2 (SSH, HTTP) | n/a | timeout (no internet) |
| google.com | domain | n/a | 3 (CSP, HSTS, X-Content-Type) | timeout (no internet) |

---

## Files — Submitted Deliverables

### ✅ Keep

| File | Why |
|------|-----|
| `scanner_final.py` | Final version of Part 1 with full CLI and JSON output |
| `scanner_v1.py` | Required for Part 1A benchmark comparison |
| `scanner_v2_threads.py` | Required for Part 1A benchmark comparison |
| `scanner_v3_asyncio.py` | Required for Part 1B asyncio implementation |
| `parse_scan.py` | Part 2 deliverable |
| `auth_analysis.py` | Part 3A deliverable |
| `log_analysis.py` | Part 3C/D deliverable |
| `report.md` | Part 3E output — combined findings report |
| `recon.py` | Part 4 deliverable |
| `scan.xml` | Input data for Part 2 |
| `hosts.json` | Output of parse_scan.py — documents Part 2 result |
| `recon_192.168.145.128_*/` | Sample output directory for Part 4 (IP mode) |
| `recon_google.com_*/` | Sample output directory for Part 4 (domain mode) |


