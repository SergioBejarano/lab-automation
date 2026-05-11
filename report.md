# Security Analysis Report

**Generated:** 2026-05-09 10:01:14  
**Scope:** 192.168.145.0/24  
**Analyst:** Kali Linux automated pipeline

---

## 1. Network Reconnaissance (nmap -sV)

Nmap service-version scan identified **2 active host(s)** with open ports.

### Host: `192.168.145.2`

| Port | Service | Version |
|------|---------|---------|
| 53 | domain | (generic dns response: NXDOMAIN) |

### Host: `192.168.145.128`

| Port | Service | Version |
|------|---------|---------|
| 22 | ssh | OpenSSH 10.2p1 Debian 3 (protocol 2.0) |
| 80 | http | Apache httpd 2.4.66 ((Debian)) |
| 8080 | http | SimpleHTTPServer 0.6 (Python 3.13.11) |
| 8888 | http | SimpleHTTPServer 0.6 (Python 3.13.11) |
| 9000 | http | SimpleHTTPServer 0.6 (Python 3.13.11) |
| 9090 | http | SimpleHTTPServer 0.6 (Python 3.13.11) |

**SSH host key type:** `ssh-rsa`

---

## 2. SSH Brute-Force Analysis (auth.log)

Analyzed **520 log entries** — 500 failed and 20 successful logins.

### 2.1 Brute-Force IPs (≥ 10 failed attempts)

| IP Address | Failed Attempts | Risk |
|------------|-----------------|------|
| `185.220.101.5` | 268 | 🔴 High |
| `45.33.32.156` | 199 | 🔴 High |
| `10.0.0.2` | 22 | 🟡 Medium |

### 2.2 Targeted Usernames

| Username | Times Targeted |
|----------|---------------|
| `ubuntu` | 136 |
| `daniel` | 124 |
| `root` | 123 |
| `admin` | 117 |

### 2.3 Login Ratio

| Metric | Value |
|--------|-------|
| Failed logins | 500 |
| Successful logins | 20 |
| Fail / success ratio | **25.0:1** |

> A ratio of 25.0:1 strongly indicates automated brute-force activity.

---

## 3. Web Attack Detection (access.log)

### 3.1 Suspicious Requests

**136 requests** matched attack signatures (SQL injection, path traversal, XSS, command injection).

| Status | Source IP | Path |
|--------|-----------|------|
| 200 | `66.249.66.1` | `/wp-admin/` |
| 403 | `10.0.0.1` | `/admin/../../../etc/passwd` |
| 200 | `185.220.101.5` | `/search?q=<script>alert(1)</script>` |
| 200 | `10.0.0.1` | `/admin/../../../etc/passwd` |
| 403 | `192.168.145.128` | `/admin/../../../etc/passwd` |
| 403 | `10.0.0.1` | `/wp-admin/` |
| 200 | `10.0.0.1` | `/search?q=<script>alert(1)</script>` |
| 403 | `10.0.0.1` | `/cgi-bin/test.cgi?cmd=id` |
| 200 | `10.0.0.1` | `/wp-admin/` |
| 403 | `10.0.0.1` | `/cgi-bin/test.cgi?cmd=id` |
| 200 | `66.249.66.1` | `/search?q=<script>alert(1)</script>` |
| 200 | `45.33.32.156` | `/wp-admin/` |
| 200 | `192.168.145.128` | `/wp-admin/` |
| 500 | `10.0.0.1` | `/admin/../../../etc/passwd` |
| 403 | `66.249.66.1` | `/admin/../../../etc/passwd` |

*... and 121 more suspicious requests.*


### 3.2 Top 5 IPs by Request Volume

| Rank | IP Address | Requests |
|------|-----------|----------|
| 1 | `10.0.0.1` | 1834 |
| 2 | `66.249.66.1` | 641 |
| 3 | `45.33.32.156` | 309 |
| 4 | `185.220.101.5` | 292 |
| 5 | `192.168.145.128` | 201 |

### 3.3 HTTP Status Code Distribution

| Status Code | Count | Meaning |
|-------------|-------|---------|
| HTTP 200 | 3190 | OK |
| HTTP 403 | 48 | Forbidden |
| HTTP 500 | 39 | Server Error |

---

## 4. Anomaly Detection — Hourly Traffic (3σ rule)

| Hour | Detail |
|------|--------|
| 🔴 | [ANOMALY] 03:00 — 946 requests (z=4.7σ, threshold=3.0σ) |

---

## 5. Summary & Recommendations

| # | Finding | Severity | Recommendation |
|---|---------|----------|----------------|
| 1 | SSH brute-force from external IPs | 🔴 High | Block offending IPs with `fail2ban`; disable password auth, enforce key-only login |
| 2 | Version strings exposed in banners | 🟡 Medium | Set `ServerTokens Prod` and `ServerSignature Off`; keep services patched |
| 3 | Web attacks detected (SQLi, XSS, path traversal) | 🔴 High | Deploy WAF; sanitize all user input; audit HTTP 200 responses to attack paths |
| 4 | Traffic spike anomaly at 03:00 | 🟡 Medium | Investigate source IPs in that window; apply rate limiting |
| 5 | Privileged usernames targeted (`root`, `admin`) | 🟡 Medium | Set `PermitRootLogin no` in sshd_config |