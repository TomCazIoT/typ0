#!/usr/bin/env python3
"""Find DNS, web, and certificate information for likely typosquatted domains."""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import ssl
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Callable
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


DEFAULT_STEPS = ("generate", "dns", "geo", "http", "cert")
STEP_NAMES = ("generate", "dns", "geo", "http", "cert")
CONFUSABLES_URL = "https://www.unicode.org/Public/security/latest/confusables.txt"
TLD_LIST_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
KEYBOARD_NEIGHBORS = {
    "q": "was", "w": "qes", "e": "wrs", "r": "etf", "t": "rgy",
    "y": "tuh", "u": "yij", "i": "uko", "o": "ipl", "p": "ol",
    "a": "qwsz", "s": "awedx", "d": "serfc", "f": "drtg",
    "g": "ftyhb", "h": "gyujn", "j": "huikm", "k": "jiol",
    "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv",
    "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
ProgressCallback = Callable[[int, int], None]


@dataclass
class DomainResult:
    domain: str
    unicode_domain: str | None = None
    records: dict[str, list[str]] = field(default_factory=dict)
    locations: dict[str, dict[str, Any]] = field(default_factory=dict)
    http: dict[str, Any] = field(default_factory=dict)
    certificate: dict[str, Any] = field(default_factory=dict)


class TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.in_title = tag.lower() == "title"

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)


def normalize_domain(value: str) -> str:
    candidate = value.strip()
    if "://" not in candidate:
        candidate = f"//{candidate}"
    parsed = urlparse(candidate)
    domain = (parsed.hostname or "").rstrip(".").lower()
    if not domain or "." not in domain:
        raise ValueError("the domain must contain a hostname and a TLD")
    if len(domain) > 253 or any(len(part) > 63 for part in domain.split(".")):
        raise ValueError("the domain name is too long")
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("the domain contains invalid internationalized characters") from exc


def load_confusables(url: str = CONFUSABLES_URL) -> dict[str, set[str]]:
    request = Request(url, headers={"User-Agent": "typ0/1.0"})
    with urlopen(request, timeout=15) as response:
        content = response.read(8_000_000).decode("utf-8")

    mappings: dict[str, set[str]] = {}
    for line in content.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("#", 1)[0].split(";")
        if len(fields) < 2:
            continue
        try:
            source = "".join(chr(int(value, 16)) for value in fields[0].split())
            target = "".join(chr(int(value, 16)) for value in fields[1].split())
        except ValueError:
            continue
        if (len(source) == 1 and len(target) == 1 and target.isascii()
                and target.isalnum() and source != target
                and all(character.isprintable() for character in source)):
            mappings.setdefault(target, set()).add(source)
    if not mappings:
        raise ValueError("Unicode confusables source did not contain valid mappings")
    return mappings


def to_idna_domain(domain: str) -> str:
    try:
        return ".".join(label.encode("idna").decode("ascii") for label in domain.split("."))
    except UnicodeError as exc:
        raise ValueError(f"invalid generated internationalized domain: {domain}") from exc


def load_tlds(url: str = TLD_LIST_URL) -> list[str]:
    request = Request(url, headers={"User-Agent": "typ0/1.0"})
    with urlopen(request, timeout=15) as response:
        content = response.read(500_000).decode("utf-8")
    tlds = [
        line.strip().lower()
        for line in content.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if not tlds:
        raise ValueError("TLD source did not contain valid TLDs")
    return tlds


def generate_candidates(
    domain: str,
    tlds: list[str],
    confusables_url: str = CONFUSABLES_URL,
    progress: ProgressCallback | None = None,
) -> list[str]:
    labels = domain.split(".")
    name = labels[0]
    candidates: set[str] = set()
    confusables = load_confusables(confusables_url)

    for index in range(len(name)):
        candidates.add(name[:index] + name[index + 1:])
        candidates.add(name[:index] + name[index] + name[index:])
        if name[index].isalpha():
            for replacement in KEYBOARD_NEIGHBORS.get(name[index], ""):
                candidates.add(name[:index] + replacement + name[index + 1:])
        if index + 1 < len(name) and name[index] != name[index + 1]:
            swapped = list(name)
            swapped[index], swapped[index + 1] = swapped[index + 1], swapped[index]
            candidates.add("".join(swapped))
    for index in range(1, len(name)):
        candidates.add(name[:index] + "-" + name[index:])
    for character in "0123456789":
        candidates.add(name + character)
    for index, character in enumerate(name):
        for replacement in confusables.get(character, ()):
            candidates.add(name[:index] + replacement + name[index + 1:])

    valid: dict[str, str] = {}
    total_candidates = len(candidates) * len(tlds)
    if progress:
        progress(0, total_candidates)
    processed = 0
    for candidate in candidates:
        if (not candidate or len(candidate) > 63 or candidate.startswith("-")
                or candidate.endswith("-")):
            continue
        for tld in tlds:
            unicode_domain = f"{candidate}.{tld}"
            try:
                valid[to_idna_domain(unicode_domain)] = unicode_domain
            except ValueError:
                pass
            processed += 1
            if progress:
                progress(processed, total_candidates)
    valid.pop(domain, None)
    return sorted(valid)


def run_dig(domain: str, record_type: str) -> list[str]:
    if not shutil.which("dig"):
        raise RuntimeError("dig was not found in PATH")
    completed = subprocess.run(
        ["dig", "+short", record_type, domain],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"dig failed for {domain}")
    values = []
    for line in completed.stdout.splitlines():
        value = line.strip().rstrip(".")
        if value and not value.startswith(";"):
            values.append(value)
    return values


def resolve_dns(
    domains: list[str],
    unicode_domains: dict[str, str],
    progress: ProgressCallback | None = None,
) -> list[DomainResult]:
    results = [DomainResult(domain, unicode_domains.get(domain)) for domain in domains]
    for index, result in enumerate(results, 1):
        for record_type in ("A", "AAAA", "CNAME"):
            try:
                values = run_dig(result.domain, record_type)
            except (RuntimeError, subprocess.SubprocessError, OSError) as exc:
                result.records.setdefault("_error", []).append(str(exc))
                break
            if values:
                result.records[record_type] = values
        if result.records.get("A") or result.records.get("AAAA") or result.records.get("CNAME"):
            print(f"DNS found: {result.domain} -> {result.records}")
        if progress:
            progress(index, len(results))
    return [result for result in results if result.records.get("A") or result.records.get("AAAA")
            or result.records.get("CNAME")]


def lookup_location(ip: str) -> dict[str, Any]:
    request = Request(f"https://ipwho.is/{ip}", headers={"User-Agent": "typ0/1.0"})
    with urlopen(request, timeout=10) as response:
        payload = json.load(response)
    if not payload.get("success", False):
        raise RuntimeError(str(payload.get("message", "location lookup failed")))
    return {
        key: payload.get(key)
        for key in ("country", "region", "city", "latitude", "longitude", "isp", "org")
    }


def collect_locations(results: list[DomainResult], progress: ProgressCallback | None = None) -> None:
    total_ips = sum(
        len(result.records.get(record_type, []))
        for result in results
        for record_type in ("A", "AAAA")
    )
    processed_ips = 0
    for result in results:
        for record_type in ("A", "AAAA"):
            for ip in result.records.get(record_type, []):
                try:
                    result.locations[ip] = lookup_location(str(ip_address(ip)))
                except (URLError, OSError, RuntimeError, ValueError) as exc:
                    result.locations[ip] = {"error": str(exc)}
                processed_ips += 1
                if progress:
                    progress(processed_ips, total_ips)


def fetch_site(domain: str) -> dict[str, Any]:
    request = Request(f"https://{domain}/", headers={"User-Agent": "typ0/1.0"})
    with urlopen(request, timeout=10) as response:
        content = response.read(512_000)
        parser = TitleParser()
        parser.feed(content.decode(response.headers.get_content_charset() or "utf-8", errors="replace"))
        return {
            "status": response.status,
            "url": response.geturl(),
            "title": " ".join(" ".join(parser.title_parts).split()) or None,
        }


def collect_http(results: list[DomainResult], progress: ProgressCallback | None = None) -> None:
    for index, result in enumerate(results, 1):
        try:
            result.http = fetch_site(result.domain)
            print(f"HTTPS site found: {result.domain} ({result.http.get('title') or 'no title'})")
        except (URLError, OSError, ValueError) as exc:
            result.http = {"error": str(exc)}
        if progress:
            progress(index, len(results))


def extract_certificate(domain: str) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=10) as connection:
        with context.wrap_socket(connection, server_hostname=domain) as tls_socket:
            certificate = tls_socket.getpeercert()
    return {
        "subject": dict(item[0] for item in certificate.get("subject", ())),
        "issuer": dict(item[0] for item in certificate.get("issuer", ())),
        "not_before": certificate.get("notBefore"),
        "not_after": certificate.get("notAfter"),
        "subject_alt_names": [value for kind, value in certificate.get("subjectAltName", ())
                              if kind == "DNS"],
    }


def collect_certificates(results: list[DomainResult], progress: ProgressCallback | None = None) -> None:
    for index, result in enumerate(results, 1):
        if "error" in result.http:
            if progress:
                progress(index, len(results))
            continue
        try:
            result.certificate = extract_certificate(result.domain)
        except (OSError, ssl.SSLError, ValueError) as exc:
            result.certificate = {"error": str(exc)}
        if progress:
            progress(index, len(results))


def write_report(path: Path, source: str, candidates: list[str],
                 results: list[DomainResult], steps: tuple[str, ...],
                 confusables_url: str, tlds: list[str]) -> None:
    report = {
        "tool": "typ0",
        "source_domain": source,
        "steps": list(steps),
        "confusables_source": confusables_url,
        "tlds": tlds,
        "candidate_count": len(candidates),
        "candidates": candidates,
        "discovered_domains": [asdict(result) for result in results],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect likely typosquatted domains.")
    parser.add_argument("domain", help="Domain to test, with or without a scheme")
    parser.add_argument("-o", "--output", required=True, type=Path, help="JSON report path")
    parser.add_argument(
        "--steps", nargs="+", choices=STEP_NAMES, default=list(DEFAULT_STEPS),
        help="Steps to run (default: all discovery steps)",
    )
    parser.add_argument(
        "--confusables-url", default=CONFUSABLES_URL,
        help="Unicode confusables.txt URL (default: official Unicode source)",
    )
    parser.add_argument(
        "--all-tlds", action="store_true",
        help="test candidates against all TLDs from the official IANA list",
    )
    parser.add_argument(
        "--tlds", default=None,
        help="comma-separated TLDs to test instead of the source TLD (for example: com,fr,net)",
    )
    parser.add_argument(
        "--tld-list-url", default=TLD_LIST_URL,
        help="IANA TLD list URL used with --all-tlds",
    )
    return parser.parse_args()


def print_step(step_number: int, total_steps: int, name: str, message: str) -> None:
    print(f"[{step_number}/{total_steps}] {name}: {message}")


class ProgressBar:
    def __init__(self, label: str, total: int, width: int = 30) -> None:
        self.label = label
        self.total = total
        self.width = width
        self.last_rendered = -1

    def update(self, current: int, total: int | None = None) -> None:
        if total is not None:
            self.total = total
        completed = min(current, self.total)
        render_interval = max(self.total // 100, 1)
        if (completed != self.total and completed != 0
                and completed - self.last_rendered < render_interval):
            return
        ratio = completed / self.total if self.total else 1
        filled = int(self.width * ratio)
        bar = "#" * filled + "-" * (self.width - filled)
        print(
            f"\r    {self.label}: [{bar}] {completed}/{self.total}",
            end="",
            flush=True,
        )
        self.last_rendered = completed

    def finish(self) -> None:
        self.update(self.total)
        print()


def run_with_progress(
    label: str,
    total: int,
    operation: Callable[[ProgressCallback], Any],
) -> Any:
    progress_bar = ProgressBar(label, total)
    result = operation(lambda current, total: progress_bar.update(current, total))
    progress_bar.finish()
    return result


def main() -> int:
    args = parse_args()
    try:
        source = normalize_domain(args.domain)
        steps = tuple(step for step in STEP_NAMES if step in args.steps)
        total_steps = len(steps) + 1
        current_step = 0

        def start_step(name: str, message: str) -> None:
            nonlocal current_step
            current_step += 1
            print_step(current_step, total_steps, name, message)

        if "generate" in steps:
            start_step("Generate", "loading Unicode confusables and generating candidates")
            source_tld = ".".join(source.split(".")[1:])
            if args.tlds:
                tlds = [tld.strip().lstrip(".").lower() for tld in args.tlds.split(",") if tld.strip()]
            elif args.all_tlds:
                tlds = load_tlds(args.tld_list_url)
            else:
                tlds = [source_tld]
            if not tlds:
                raise ValueError("at least one TLD must be provided")
            unicode_candidates = run_with_progress(
                "Candidates",
                0,
                lambda progress: generate_candidates(
                    source, tlds, args.confusables_url, progress
                ),
            )
        else:
            unicode_candidates = [source]
            tlds = [".".join(source.split(".")[1:])]
        unicode_domains = {to_idna_domain(candidate): candidate for candidate in unicode_candidates}
        candidates = sorted(unicode_domains)
        if "generate" in steps:
            print(f"    Generated {len(candidates)} candidate domain(s).")
        results = [DomainResult(domain, unicode_domains.get(domain)) for domain in candidates]
        if "dns" in steps:
            start_step("DNS", f"checking {len(candidates)} candidate domain(s)")
            results = run_with_progress(
                "DNS candidates",
                len(candidates),
                lambda progress: resolve_dns(candidates, unicode_domains, progress),
            )
            print(f"    Found DNS records for {len(results)} domain(s).")
        if "geo" in steps:
            start_step("Geolocation", f"looking up IP addresses for {len(results)} domain(s)")
            location_total = sum(
                len(result.records.get(record_type, []))
                for result in results
                for record_type in ("A", "AAAA")
            )
            run_with_progress(
                "IP addresses",
                location_total,
                lambda progress: collect_locations(results, progress),
            )
            location_count = sum(len(result.locations) for result in results)
            print(f"    Processed {location_count} IP address(es).")
        if "http" in steps:
            start_step("HTTPS", f"checking {len(results)} discovered domain(s)")
            run_with_progress(
                "HTTPS candidates",
                len(results),
                lambda progress: collect_http(results, progress),
            )
            available_count = sum("error" not in result.http for result in results)
            print(f"    Found {available_count} HTTPS site(s).")
        if "cert" in steps:
            start_step("Certificates", f"retrieving certificates for {len(results)} domain(s)")
            run_with_progress(
                "Certificates",
                len(results),
                lambda progress: collect_certificates(results, progress),
            )
            certificate_count = sum(
                bool(result.certificate) and "error" not in result.certificate
                for result in results
            )
            print(f"    Retrieved {certificate_count} certificate(s).")
        start_step("Report", f"writing results to {args.output}")
        write_report(
            args.output, source, candidates, results, steps,
            args.confusables_url, tlds,
        )
        print(f"Report written to {args.output}")
        return 0
    except (ValueError, OSError, URLError) as exc:
        print(f"typ0: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
