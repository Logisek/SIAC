# SIAC

**Sharing Isn't Always Caring!**

SIAC identifies and correlates websites sharing the same hosting IP address to reveal shared infrastructure and potential exposure risks. It is a reverse IP lookup tool that queries multiple independent data sources, deduplicates results, and assesses the likelihood of shared hosting.

---

## Features

- **Multi-source lookups**: Queries multiple independent data sources (APIs, Certificate Transparency, TLS) for comprehensive coverage
- **Deduplication**: Merges and normalizes domains across all sources
- **Shared hosting assessment**: Estimates confidence based on base domain count and source agreement
- **Zero external dependencies**: Uses Python standard library only
- **Robust error handling**: Continues with other sources if one fails

---

## Requirements

- **Python 3.10+** (for type hints such as `set[str]`, `str | None`)
- **No external packages required.** SIAC uses Python standard library only (`urllib.request`, `json`, `ssl`, `socket`, `argparse`, `ipaddress`, `re`, `os`). No `pip install` needed.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Logisek/SIAC.git
   cd SIAC
   ```
2. Run directly (no installation required):
   ```bash
   python siac.py --target 8.8.8.8
   ```

---

## Usage

### Basic usage

Look up domains sharing the IP address `8.8.8.8`:

```bash
python siac.py --target 8.8.8.8
```

Results are displayed in a matrix in the console by default.

### Export to file

Save results to a file (in addition to console output):

```bash
python siac.py --target 8.8.8.8 --output results.txt
```

### Specifying a directory

Create output in a subdirectory (parent directories are created automatically):

```bash
python siac.py --target 192.168.1.1 --output reports/reverse_ip_192.168.1.1.txt
```

### Multiple targets (--targets)

Look up multiple IPs from a text file (one IP per line). You must use exactly one of `--target` or `--targets`:

```bash
python siac.py --targets ips.txt
```

With multiple targets, the console shows a clear section per IP (e.g. `========== Target: 8.8.8.8 ==========`) and a **Confidence by target** table at the end listing assessment and confidence for each IP.

### Consolidated report (multiple targets + --output)

When you use `--targets` and `--output` together, SIAC writes a single consolidated report file: one section per IP (header `# Target: <IP>` followed by domains, one per line), then a summary section with assessment and confidence for each IP.

```bash
python siac.py --targets ips.txt --output report.txt
```

### More examples

```bash
# Lookup Google DNS IP
python siac.py --target 8.8.8.8

# Lookup Cloudflare DNS and save to custom path
python siac.py --target 1.1.1.1 --output cloudflare_domains.txt

# Lookup a private IP (may return few or no results)
python siac.py --target 192.168.1.100 --output private_scan.txt

# Lookup multiple IPs from file and save consolidated report
python siac.py --targets ips.txt --output report.txt
```

---

## Command-line options

| Option      | Required | Default | Description                                                                 |
| -----------| -------- | ------- | --------------------------------------------------------------------------- |
| `--target` | One of these | —   | Single IP address to lookup (IPv4 only). Use exactly one of `--target` or `--targets`. |
| `--targets`| One of these | —   | Path to a text file with one IP per line. Use exactly one of `--target` or `--targets`. |
| `--output` | No       | —       | Export to file. Single target: one domain per line. Multiple: consolidated report.     |
| `--no-crt` | No       | —       | Disable crt.sh lookup (avoids rate limiting/ban).                             |
| `--no-hackertarget` | No | —       | Disable HackerTarget API (e.g. when rate limited).                             |
| `--no-robtex` | No       | —       | Disable Robtex API (e.g. when hitting 10 req/hour limit).                     |

---

## Data sources

SIAC queries multiple independent sources and merges the results:

1. **HackerTarget API** — `https://api.hackertarget.com/reverseiplookup/`  
   - Plain text, newline-separated domains  
   - Filters out PTR-style and `*.ip6.arpa` records  
   - Rate limited; use `--no-hackertarget` to disable  

2. **Robtex Free API** — `https://freeapi.robtex.com/` (ipquery + pdns/reverse)  
   - JSON/NDJSON: active and passive DNS domains pointing to the IP  
   - Rate limit: 10 requests per hour per client IP; use `--no-robtex` to disable  

3. **RIPE NCC (stat.ripe.net)** — `https://stat.ripe.net/data/reverse-dns-ip/data.json`  
   - Single PTR (reverse DNS) result per IP; no API key required  

4. **crt.sh (Certificate Transparency)** — `https://crt.sh/?q={IP}&output=json`  
   - JSON with `name_value` fields (domains from SSL certificates)  
   - Normalizes wildcard entries (e.g., `*.example.com` → `example.com`)  
   - Use `--no-crt` to disable (avoids rate limiting/ban)  

5. **TLS SAN (Direct connection)** — Connects to `{IP}:443`  
   - Extracts Subject Alternative Names from the server certificate  
   - Skipped gracefully if port 443 is unreachable (firewall, no HTTPS)  

### Optional / key-based alternatives

For higher volume or additional coverage, you can integrate (e.g. via environment or config):  
- **ViewDNS.info** — Reverse IP API at `https://api.viewdns.info/reverseip/` (API key required; free tier available).  
- **NetworksDB** — “Domains on IP” style API; free tier ~1,000 requests/month.  

---

## Output

### Console output (default)

By default, SIAC prints domain results in a multi-column matrix to the console, followed by a summary (total domains, assessment, confidence).

### File output (with `--output`)

- **Single target**: Domains are written **one per line**, sorted alphabetically. Domains are normalized (lowercase, trailing dots removed).
- **Multiple targets**: A **consolidated report** is written: for each IP, a `# Target: <IP>` header followed by its domains (one per line), then a `# Summary` section with assessment and confidence per IP.  

### Shared hosting assessment

Confidence is based on **base domain count** (not raw domain count). Multiple subdomains of the same domain (e.g., mail.example.com, www.example.com) count as one tenant and indicate dedicated hosting. Multiple distinct base domains indicate shared hosting.

| Base domain count | Assessment                          | Confidence (base) |
| ----------------- | ----------------------------------- | ----------------- |
| 0                 | No reverse IP data found            | N/A               |
| 1                 | Likely dedicated hosting            | 95–99%            |
| 2–5               | Possibly shared hosting             | 50–65%            |
| 6–20              | Likely shared hosting                | 75–90%            |
| 21+               | Strong indicator of shared hosting   | 95–99%            |

Confidence is boosted by **+5% per additional source** that returned data (beyond the first).

---

## Error handling

- **Invalid IP** (e.g. `--target xyz`): Exits with a clear error message  
- **Targets file**: Invalid lines are skipped with a warning to stderr; empty lines are ignored. If no valid IPs remain, the program exits.  
- **Source timeout/failure**: Logs a warning to stderr and continues with other sources  
- **TLS connection errors** (timeout, connection refused): Skips the TLS SAN source and reports in the summary  
- **File write errors**: Exits with an error message  

---

## Limitations

- **IPv4 only**: IPv6 is not supported  
- **Rate limits**: HackerTarget and crt.sh may enforce rate limits; Robtex allows 10 req/hour. Use `--no-crt`, `--no-hackertarget`, or `--no-robtex` to disable individual sources when needed.  
- **Public IPs**: Best results for public IPs; private ranges may return no data  

---

## License

GPL-3.0 — see [LICENSE](LICENSE) for details.

---

## Links

- **Project**: https://github.com/Logisek/SIAC  
- **Logisek**: https://logisek.com | info@logisek.com  
