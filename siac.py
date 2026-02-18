#     SIAC - Sharing Isn't Always Caring!
#     Copyright (C) 2026 Logisek
#     https://github.com/Logisek/SIAC
#
#     This program identifies and correlates websites sharing the same hosting IP address to reveal shared infrastructure and potential exposure risks.
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.

#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.

#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#    For more see the file 'LICENSE' for copying permission.
#

import argparse
import ipaddress
import json
import os
import re
import ssl
import socket
import sys
import time
import urllib.error
import urllib.request
from typing import Callable

# User-Agent for HTTP requests; some APIs (e.g. Robtex) return 403 without it
HTTP_HEADERS = {"User-Agent": "SIAC/1.0 (https://github.com/Logisek/SIAC)"}


def print_ascii_banner() -> None:
    """Display ASCII art banner and Logisek/GitHub/license attribution."""
    banner = r"""
  _____ ___    _    ____
 / ___ |__ \  / \  / ___|
 \___ \  / / / _ \| |
  ___) ||_| / ___ \ |___
 |____/ (_)/_/   \_\____|
 Sharing Isn't Always Caring!

 https://logisek.com | info@logisek.com
 Project: https://github.com/Logisek/SIAC
 License: GPL-3.0 (see LICENSE)
"""
    print(banner)


def validate_ip(value: str) -> str:
    """Validate IPv4 address and return it if valid. Exit with error otherwise."""
    try:
        addr = ipaddress.ip_address(value)
        if addr.version != 4:
            sys.exit(f"Error: IPv6 is not supported. Got: {value}")
        return str(addr)
    except ValueError:
        sys.exit(f"Error: Invalid IP address: {value}")


def validate_ip_optional(value: str) -> str | None:
    """Validate IPv4 address and return it if valid, or None if invalid. Does not exit."""
    try:
        addr = ipaddress.ip_address(value.strip())
        if addr.version != 4:
            return None
        return str(addr)
    except ValueError:
        return None


def load_targets_file(path: str) -> list[str]:
    """Read targets file (one IP per line). Skip empty lines; invalid lines emit warning and are skipped."""
    if not os.path.isfile(path):
        sys.exit(f"Error: Targets file not found: {path}")
    targets: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            raw = line.strip()
            if not raw:
                continue
            ip = validate_ip_optional(raw)
            if ip is not None:
                targets.append(ip)
            else:
                print(f"Warning: Skipping invalid line {line_num} in {path}: {raw!r}", file=sys.stderr)
    if not targets:
        sys.exit(f"Error: No valid IP addresses in targets file: {path}")
    return targets


def parse_args() -> argparse.Namespace:
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Reverse IP lookup - identify domains sharing the same hosting IP address.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--target",
        help="Single IP address to lookup (e.g., 8.8.8.8). Use exactly one of --target or --targets.",
    )
    group.add_argument(
        "--targets",
        metavar="FILE",
        help="Path to a text file with one IP address per line. Use exactly one of --target or --targets.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Export domains to file (one per line). With multiple targets, writes a consolidated report.",
    )
    parser.add_argument(
        "--no-crt",
        action="store_true",
        help="Disable crt.sh Certificate Transparency lookup (avoids rate limiting/ban).",
    )
    parser.add_argument(
        "--no-hackertarget",
        action="store_true",
        help="Disable HackerTarget API (e.g. when rate limited).",
    )
    parser.add_argument(
        "--no-robtex",
        action="store_true",
        help="Disable Robtex API (e.g. when hitting 10 req/hour limit).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=1500,
        metavar="MS",
        help="Delay in milliseconds between each target when using --targets (default: 1500). Use 0 to disable.",
    )
    args = parser.parse_args()

    if args.timeout < 0:
        sys.exit("Error: --timeout must be >= 0")

    if args.target is not None:
        args.targets_list = [validate_ip(args.target)]
    else:
        args.targets_list = load_targets_file(args.targets)

    return args


def fetch_hackertarget(ip: str, timeout: int = 10) -> set[str]:
    """Fetch reverse IP lookup results from HackerTarget API.
    Returns a set of domain names, or empty set on failure.
    """
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    domains: set[str] = set()

    try:
        req = urllib.request.Request(url, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")

        for line in body.splitlines():
            domain = line.strip()
            if not domain or "." not in domain:
                continue
            # Exclude PTR-style / ip6.arpa records for cleaner website domain output
            if ".ip6.arpa" in domain:
                continue
            domains.add(domain.lower().rstrip("."))

    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"Warning: HackerTarget API failed: {e}", file=sys.stderr)

    return domains


def fetch_robtex(ip: str, timeout: int = 10) -> set[str]:
    """Fetch reverse IP lookup from Robtex Free API (ipquery + pdns/reverse).
    Returns a set of domain names, or empty set on failure or rate limit (429).
    Rate limit: 10 requests per hour per client IP.
    """
    base = "https://freeapi.robtex.com"
    domains: set[str] = set()

    def add_domain(raw: str) -> None:
        if not raw or ".ip6.arpa" in raw:
            return
        norm = _normalize_domain(raw)
        if norm:
            domains.add(norm)

    # 1) ipquery: act (active PTR) and pas (passive DNS domains pointing to this IP)
    try:
        url = f"{base}/ipquery/{ip}"
        req = urllib.request.Request(url, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        data = json.loads(body)
        if isinstance(data, dict) and data.get("status") == "ratelimited":
            print("Warning: Robtex API rate limited (10 req/hour). Skipping.", file=sys.stderr)
            return domains
        if isinstance(data, dict) and data.get("status") == "ok":
            for key in ("act", "pas"):
                for item in data.get(key) or []:
                    if isinstance(item, dict) and "o" in item:
                        add_domain(str(item["o"]))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            print("Warning: Robtex API rate limited (HTTP 429). Skipping.", file=sys.stderr)
        else:
            print(f"Warning: Robtex API failed: {e}", file=sys.stderr)
        return domains
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
        print(f"Warning: Robtex API failed: {e}", file=sys.stderr)
        return domains

    # 2) pdns/reverse: NDJSON with rrname (domain) and rrdata (IP)
    try:
        url = f"{base}/pdns/reverse/{ip}"
        req = urllib.request.Request(url, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if isinstance(entry, dict) and "rrname" in entry:
                    add_domain(str(entry["rrname"]))
            except json.JSONDecodeError:
                continue
    except urllib.error.HTTPError as e:
        if e.code == 429:
            print("Warning: Robtex pdns/reverse rate limited (HTTP 429).", file=sys.stderr)
        else:
            print(f"Warning: Robtex pdns/reverse failed: {e}", file=sys.stderr)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"Warning: Robtex pdns/reverse failed: {e}", file=sys.stderr)

    return domains


def fetch_ripe_reverse_dns(ip: str, timeout: int = 10) -> set[str]:
    """Fetch single PTR (reverse DNS) from RIPE NCC stat.ripe.net.
    Returns a set of zero or one domain name, or empty set on failure.
    """
    url = f"https://stat.ripe.net/data/reverse-dns-ip/data.json?resource={ip}"
    try:
        req = urllib.request.Request(url, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        data = json.loads(body)
        if not isinstance(data, dict):
            return set()
        result = data.get("data", {}).get("result")
        if result is None:
            return set()
        # result can be a single string or a list of strings (e.g. ["dns.google"])
        if isinstance(result, str):
            names = [result] if "." in result else []
        elif isinstance(result, list):
            names = [x for x in result if isinstance(x, str) and "." in x]
        else:
            return set()
        out: set[str] = set()
        for raw in names:
            if ".ip6.arpa" in raw:
                continue
            norm = _normalize_domain(raw)
            if norm:
                out.add(norm)
        return out
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
        print(f"Warning: RIPE reverse-dns-ip API failed: {e}", file=sys.stderr)
        return set()


def _normalize_domain(raw: str) -> str | None:
    """Strip wildcard prefix, lowercase, strip trailing dots. Returns None if invalid."""
    s = raw.strip()
    if not s or "." not in s:
        return None
    # Strip *. prefix (e.g., *.example.com -> example.com)
    if s.startswith("*."):
        s = s[2:]
    s = s.lower().rstrip(".")
    if not s or "." not in s:
        return None
    return s


def fetch_crtsh(ip: str, timeout: int = 10) -> set[str]:
    """Fetch reverse IP lookup from crt.sh Certificate Transparency.
    Returns a set of domain names, or empty set on failure.
    """
    url = f"https://crt.sh/?q={ip}&output=json"
    domains: set[str] = set()

    try:
        req = urllib.request.Request(url, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")

        entries = json.loads(body)
        if not isinstance(entries, list):
            return domains

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name_value = entry.get("name_value")
            if not name_value:
                continue
            # name_value can be comma- or newline-separated
            for part in re.split(r"[\n,]", name_value):
                norm = _normalize_domain(part)
                if norm:
                    domains.add(norm)

    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
        print(f"Warning: crt.sh API failed: {e}", file=sys.stderr)

    return domains


def _get_base_domain(domain: str) -> str:
    """Extract registered (base) domain. Handles common 2-part TLDs like .co.uk."""
    parts = domain.lower().split(".")
    # Common second-level TLDs (e.g., example.co.uk)
    SECOND_LEVEL_TLDS = (
        "co.uk", "com.au", "co.nz", "com.br", "co.za", "co.jp", "com.mx", "co.in"
    )
    if len(parts) >= 3 and ".".join(parts[-2:]) in SECOND_LEVEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def fetch_tls_san(ip: str, timeout: int = 10) -> set[str]:
    """Connect to IP:443, perform TLS handshake, extract Subject Alternative Names.
    Returns a set of domain names, or empty set on failure.
    """
    domains: set[str] = set()

    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # Connect by IP; skip cert verification to extract SANs for reconnaissance
        with context.wrap_socket(sock, server_hostname=ip) as conn:
            cert = conn.getpeercert()
            if cert and "subjectAltName" in cert:
                for name_type, name_value in cert["subjectAltName"]:
                    if name_type == "DNS":
                        norm = _normalize_domain(name_value)
                        if norm:
                            domains.add(norm)
    except (ssl.SSLError, socket.timeout, socket.error, OSError) as e:
        print(f"Warning: TLS SAN fetch failed: {e}", file=sys.stderr)

    return domains


def calculate_confidence(
    domains: set[str], sources_used: int
) -> tuple[str, int | None]:
    """Compute shared-hosting assessment and confidence percentage.
    Uses base domain count: multiple subdomains of same domain indicate dedicated
    hosting; multiple distinct base domains indicate shared hosting.
    Returns (assessment_string, confidence_pct) where confidence_pct is None if N/A.
    """
    base_domains = {_get_base_domain(d) for d in domains}
    num_base = len(base_domains)
    # Boost: +5% per additional source beyond the first
    source_boost = max(0, sources_used - 1) * 5

    if num_base == 0:
        return ("No reverse IP data found", None)
    if num_base == 1:
        base = 95
        confidence = min(99, base + source_boost)
        return ("Likely dedicated hosting", confidence)
    if num_base <= 5:
        base = 57
        confidence = min(99, base + source_boost)
        return ("Possibly shared hosting", confidence)
    if num_base <= 20:
        base = 82
        confidence = min(99, base + source_boost)
        return ("Likely shared hosting", confidence)
    base = 95
    confidence = min(99, base + source_boost)
    return ("Strong indicator of shared hosting", confidence)


def print_matrix(domains: list[str], cols: int = 4) -> None:
    """Print domains in a multi-column matrix layout with header and column separators."""
    if not domains:
        return
    pad = 2
    max_len = max(len(d) for d in domains) + pad
    # Ensure column width doesn't exceed terminal-friendly size
    col_width = min(max_len, 50)
    sep = " | "
    # Header row: column labels #1, #2, ...
    header_cells = [f"#{j + 1}".ljust(col_width) for j in range(cols)]
    print(sep.join(header_cells).rstrip())
    # Separator line
    print("-" * (col_width * cols + len(sep) * (cols - 1)))
    # Data rows with column separators
    for i in range(0, len(domains), cols):
        row = domains[i : i + cols]
        line = sep.join(d.ljust(col_width) for d in row)
        print(line.rstrip())
    sys.stdout.flush()


def write_output(domains: list[str], output_path: str) -> None:
    """Write domains to file (one per line). Creates parent dirs if needed."""
    parent = os.path.dirname(output_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for domain in domains:
            f.write(domain + "\n")


def print_summary(
    domains: set[str],
    assessment: str,
    confidence: int | None,
    output_path: str | None,
) -> None:
    """Print summary to console: total domains, assessment, confidence %, output path."""
    total = len(domains)
    print(f"Total unique domains: {total}")
    print(f"Assessment: {assessment}")
    if confidence is not None:
        print(f"Confidence: {confidence}%")
    else:
        print("Confidence: N/A")
    if output_path is not None:
        print(f"Output written to: {output_path}")


def print_progress(step: int, total: int, message: str) -> None:
    """Print a progress step indicator."""
    print(f"[{step}/{total}] {message}")
    sys.stdout.flush()


def run_single_target(
    ip: str,
    no_crt: bool,
    no_hackertarget: bool,
    no_robtex: bool,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> tuple[set[str], list[str], str, int | None]:
    """Run full lookup for one IP: fetch all sources, dedupe, assess. Returns (domains_set, sorted_domains_list, assessment, confidence)."""
    domains: set[str] = set()
    sources_used = 0

    def progress(step: int, total: int, message: str) -> None:
        if progress_cb:
            progress_cb(step, total, message)
        else:
            print_progress(step, total, message)

    progress(1, 5, "Querying reverse IP APIs...")
    if not no_hackertarget:
        r = fetch_hackertarget(ip)
        if r:
            domains |= r
            sources_used += 1
            print(f"  -> HackerTarget: {len(r)} domain(s)")
        else:
            print("  -> HackerTarget: No results (failed or empty)")
    if not no_robtex:
        r = fetch_robtex(ip)
        if r:
            domains |= r
            sources_used += 1
            print(f"  -> Robtex: {len(r)} domain(s)")
        else:
            print("  -> Robtex: No results (failed or empty)")
    r = fetch_ripe_reverse_dns(ip)
    if r:
        domains |= r
        sources_used += 1
        print(f"  -> RIPE: {len(r)} domain(s)")
    else:
        print("  -> RIPE: No results (failed or empty)")
    print()

    if no_crt:
        progress(2, 5, "Skipping crt.sh (disabled by --no-crt)...")
        print("  -> Skipped")
    else:
        progress(2, 5, "Querying crt.sh (Certificate Transparency)...")
        r = fetch_crtsh(ip)
        if r:
            domains |= r
            sources_used += 1
            print(f"  -> Found {len(r)} domain(s)")
        else:
            print("  -> No results (source failed or returned nothing)")
    print()

    progress(3, 5, "Connecting to IP:443 for TLS SAN extraction...")
    r = fetch_tls_san(ip)
    if r:
        domains |= r
        sources_used += 1
        print(f"  -> Found {len(r)} domain(s)")
    else:
        print("  -> No results (port unreachable or no DNS SANs)")
    print()

    progress(4, 5, "Deduplicating and assessing shared hosting...")
    assessment, confidence = calculate_confidence(domains, sources_used)
    sorted_domains = sorted(domains)
    print(f"  -> {len(domains)} unique domain(s), {assessment}")
    print()

    return domains, sorted_domains, assessment, confidence


def write_consolidated_report(
    results_by_ip: dict[str, tuple[list[str], str, int | None]],
    output_path: str,
) -> None:
    """Write one file with a section per IP (domains) and a summary with assessment/confidence per IP."""
    parent = os.path.dirname(output_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for ip, (sorted_domains, assessment, confidence) in results_by_ip.items():
            f.write(f"# Target: {ip}\n")
            for domain in sorted_domains:
                f.write(domain + "\n")
            f.write("\n")
        f.write("# Summary\n")
        f.write("# IP             | Assessment                      | Confidence\n")
        for ip, (_, assessment, confidence) in results_by_ip.items():
            conf_str = f"{confidence}%" if confidence is not None else "N/A"
            f.write(f"# {ip:<14} | {assessment:<30} | {conf_str}\n")


def print_confidence_by_target(
    results_by_ip: dict[str, tuple[list[str], str, int | None]],
) -> None:
    """Print a table of assessment and confidence for each target IP."""
    print("--- Confidence by target ---")
    for ip, (_, assessment, confidence) in results_by_ip.items():
        conf_str = f"{confidence}%" if confidence is not None else "N/A"
        print(f"  {ip:<14} | {assessment:<30} | {conf_str}")
    sys.stdout.flush()


if __name__ == "__main__":
    try:
        print_ascii_banner()
        args = parse_args()
        targets = args.targets_list
        num_targets = len(targets)

        results_by_ip: dict[str, tuple[list[str], str, int | None]] = {}

        for i, ip in enumerate(targets):
            print("=" * 10 + f" Target: {ip} " + "=" * 10)
            print()

            target_prefix = f"[Target {i + 1}/{num_targets}] {ip} - " if num_targets > 1 else ""

            def progress_cb(step: int, total: int, message: str) -> None:
                print_progress(step, total, target_prefix + message)

            _, sorted_domains, assessment, confidence = run_single_target(
                ip,
                args.no_crt,
                args.no_hackertarget,
                args.no_robtex,
                progress_cb=progress_cb,
            )
            results_by_ip[ip] = (sorted_domains, assessment, confidence)

            if args.output and num_targets == 1:
                print_progress(5, 5, target_prefix + f"Writing results to {args.output}...")
            else:
                print_progress(5, 5, target_prefix + "Printing results in matrix format...")
            print_matrix(sorted_domains)
            print("  -> Done")
            print()

            if i < num_targets - 1 and args.timeout > 0:
                print(f"Rate limit: waiting {args.timeout} ms before next target...")
                time.sleep(args.timeout / 1000.0)

        print_confidence_by_target(results_by_ip)

        if args.output:
            if num_targets == 1:
                ip = targets[0]
                write_output(results_by_ip[ip][0], args.output)
                print(f"Output written to: {args.output}")
            else:
                write_consolidated_report(results_by_ip, args.output)
                print(f"Consolidated report written to: {args.output}")
    except KeyboardInterrupt:
        print("Interrupted by user (Ctrl+C).", file=sys.stderr)
        sys.exit(130)
