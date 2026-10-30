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
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from html.parser import HTMLParser
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

DEFAULT_STEPS = ("generate", "dns", "geo", "http", "cert")
STEP_NAMES = ("generate", "dns", "geo", "http", "cert")
CONFUSABLES_URL = "https://www.unicode.org/Public/security/latest/confusables.txt"
TLD_LIST_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
DEFAULT_MAX_WORKERS = 8
# Common generic and country-code TLDs used for broad typosquatting checks.
TOP_TLDS = (
    "com",
    "fr",
    "net",
    "org",
    "de",
    "uk",
    "cn",
    "ru",
    "nl",
    "eu",
    "info",
    "xyz",
    "io",
    "co",
    "app",
)
KEYBOARD_NEIGHBORS = {
    "q": "was",
    "w": "qes",
    "e": "wrs",
    "r": "etf",
    "t": "rgy",
    "y": "tuh",
    "u": "yij",
    "i": "uko",
    "o": "ipl",
    "p": "ol",
    "a": "qwsz",
    "s": "awedx",
    "d": "serfc",
    "f": "drtg",
    "g": "ftyhb",
    "h": "gyujn",
    "j": "huikm",
    "k": "jiol",
    "l": "kop",
    "z": "asx",
    "x": "zsdc",
    "c": "xdfv",
    "v": "cfgb",
    "b": "vghn",
    "n": "bhjm",
    "m": "njk",
}
# Common substitutions where a letter and a digit look similar in a domain
# name. Each replacement is applied one character at a time.
CHARACTER_LOOKALIKES = {
    "a": "4",
    "e": "3",
    "g": "9",
    "i": "1",
    "l": "1",
    "o": "0",
    "s": "5",
    "t": "7",
    "b": "8",
}
# These terms are common in deceptive lookalike domains. They are kept small
# and explicit so candidate generation remains predictable.
COMMON_DOMAIN_TERMS = ("account", "login", "secure", "support", "verify")
ProgressCallback = Callable[[int, int], None]


@dataclass
class DomainResult:
    """All observations collected for one generated domain."""

    domain: str
    unicode_domain: str | None = None
    records: dict[str, list[str]] = field(default_factory=dict)
    email_capable: bool | None = None
    locations: dict[str, dict[str, Any]] = field(default_factory=dict)
    http: dict[str, Any] = field(default_factory=dict)
    certificate: dict[str, Any] = field(default_factory=dict)
    review_score: int | None = None
    review_priority: str | None = None
    review_reasons: list[str] = field(default_factory=list)


class TitleParser(HTMLParser):
    """Extract the text inside an HTML document's ``title`` element."""

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
    """Return a lowercase ASCII (IDNA) hostname from user input.

    Prefixing a schemeless value with ``//`` lets ``urlparse`` treat it as a
    network location, so inputs such as ``example.com`` and
    ``https://example.com/path`` can share the same parsing code.
    """

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
        # IDNA converts internationalized hostnames to the ASCII form accepted
        # by DNS tools and network libraries.
        return domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(
            "the domain contains invalid internationalized characters"
        ) from exc


def load_confusables(url: str = CONFUSABLES_URL) -> dict[str, set[str]]:
    """Download Unicode's confusables data and keep useful single characters.

    The source is a semi-colon-separated file with hexadecimal code points.
    We only keep mappings that can replace one source character with one
    printable ASCII letter or digit; this bounds the number of candidates.
    """

    request = Request(url, headers={"User-Agent": "typ0/1.0"})
    with urlopen(request, timeout=15) as response:
        content = response.read(8_000_000).decode("utf-8")

    mappings: dict[str, set[str]] = {}
    for line in content.splitlines():
        # Comments and blank lines are not mapping records.
        if not line or line.startswith("#"):
            continue
        fields = line.split("#", 1)[0].split(";")
        if len(fields) < 2:
            continue
        try:
            # A mapping may contain several code points, hence the join.
            source = "".join(chr(int(value, 16)) for value in fields[0].split())
            target = "".join(chr(int(value, 16)) for value in fields[1].split())
        except ValueError:
            continue
        if (
            len(source) == 1
            and len(target) == 1
            and target.isascii()
            and target.isalnum()
            and source != target
            and all(character.isprintable() for character in source)
        ):
            mappings.setdefault(target, set()).add(source)
    if not mappings:
        raise ValueError("Unicode confusables source did not contain valid mappings")
    return mappings


def to_idna_domain(domain: str) -> str:
    """Encode every hostname label separately because dots are separators."""

    try:
        return ".".join(
            label.encode("idna").decode("ascii") for label in domain.split(".")
        )
    except UnicodeError as exc:
        raise ValueError(
            f"invalid generated internationalized domain: {domain}"
        ) from exc


def load_tlds(url: str = TLD_LIST_URL) -> list[str]:
    """Load one TLD per line from an IANA-compatible text resource."""

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


def parse_tlds(value: str) -> list[str]:
    """Parse a comma-separated TLD argument and preserve its input order."""

    tlds = [
        tld
        for raw_tld in value.split(",")
        if (tld := raw_tld.strip().lstrip(".").lower())
    ]
    if not tlds:
        raise ValueError("at least one TLD must be provided")
    return list(dict.fromkeys(tlds))


def generate_candidates(
    domain: str,
    tlds: list[str],
    confusables_url: str = CONFUSABLES_URL,
    progress: ProgressCallback | None = None,
) -> list[str]:
    """Generate valid IDNA candidates for the first label of ``domain``.

    The mutation rules deliberately operate on the name only. The suffix is
    then combined with each requested TLD, allowing the same typo pattern to
    be checked across several namespaces.
    """

    labels = domain.split(".")
    name = labels[0]
    candidates: set[str] = set()
    confusables = load_confusables(confusables_url)

    for index in range(len(name)):
        # Deletion, duplication, keyboard-neighbor replacement, and swapping
        # model common typing mistakes.
        candidates.add(name[:index] + name[index + 1 :])
        candidates.add(name[:index] + name[index] + name[index:])
        if name[index].isalpha():
            for replacement in KEYBOARD_NEIGHBORS.get(name[index], ""):
                candidates.add(name[:index] + replacement + name[index + 1 :])
            for replacement in CHARACTER_LOOKALIKES.get(name[index], ""):
                candidates.add(name[:index] + replacement + name[index + 1 :])
        if index + 1 < len(name) and name[index] != name[index + 1]:
            swapped = list(name)
            swapped[index], swapped[index + 1] = swapped[index + 1], swapped[index]
            candidates.add("".join(swapped))
    for index in range(1, len(name)):
        candidates.add(name[:index] + "-" + name[index:])
    for character in "0123456789":
        candidates.add(name + character)
    for term in COMMON_DOMAIN_TERMS:
        candidates.add(f"{term}-{name}")
        candidates.add(f"{name}-{term}")
    for index, character in enumerate(name):
        for replacement in confusables.get(character, ()):
            candidates.add(name[:index] + replacement + name[index + 1 :])

    valid: dict[str, str] = {}
    total_candidates = len(candidates) * len(tlds)
    if progress:
        progress(0, total_candidates)
    processed = 0
    for candidate in candidates:
        # DNS labels cannot start or end with a hyphen and are limited to
        # 63 characters, so reject those before trying every TLD.
        if (
            not candidate
            or len(candidate) > 63
            or candidate.startswith("-")
            or candidate.endswith("-")
        ):
            continue
        for tld in tlds:
            unicode_domain = f"{candidate}.{tld}"
            try:
                valid[to_idna_domain(unicode_domain)] = unicode_domain
            except ValueError:
                # Some Unicode substitutions cannot be represented as IDNA.
                pass
            processed += 1
            if progress:
                progress(processed, total_candidates)
    valid.pop(domain, None)
    return sorted(valid)


def resolve_dns_record(domain: str, record_type: str) -> list[str]:
    """Query one DNS record type using ``dig`` or the standard library.

    ``dig`` is preferred when installed because it exposes all requested
    record types consistently. ``socket`` is used as a dependency-free
    fallback.
    """

    if record_type not in {"A", "AAAA", "CNAME", "MX"}:
        raise ValueError(f"unsupported DNS record type: {record_type}")
    if shutil.which("dig"):
        completed = subprocess.run(
            ["dig", "+short", record_type, domain],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or f"dig failed for {domain}")
        return sorted(
            {
                line.strip().rstrip(".")
                for line in completed.stdout.splitlines()
                if line.strip() and not line.strip().startswith(";")
            }
        )

    if record_type == "A":
        family = socket.AF_INET
    elif record_type == "AAAA":
        family = socket.AF_INET6
    elif record_type == "CNAME":
        _hostname, aliases, _addresses = socket.gethostbyname_ex(domain)
        return sorted({alias.rstrip(".") for alias in aliases if alias})
    elif record_type == "MX":
        raise RuntimeError(
            "MX lookup requires dig when the external resolver is unavailable"
        )
    values = {
        sockaddr[0].rstrip(".")
        for _family, _kind, _protocol, _canonname, sockaddr in socket.getaddrinfo(
            domain, None, family=family, type=socket.SOCK_STREAM
        )
    }
    return sorted(values)


def resolve_dns(
    domains: list[str],
    unicode_domains: dict[str, str],
    progress: ProgressCallback | None = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    verbose: bool = False,
) -> list[DomainResult]:
    """Resolve candidates and retain only domains with at least one record."""

    results = [DomainResult(domain, unicode_domains.get(domain)) for domain in domains]
    if not results:
        return []

    def resolve_one(result: DomainResult) -> DomainResult:
        for record_type in ("A", "AAAA", "CNAME", "MX"):
            try:
                values = resolve_dns_record(result.domain, record_type)
            except (
                OSError,
                RuntimeError,
                ValueError,
                subprocess.SubprocessError,
            ) as exc:
                # A failed query is recorded, but one unavailable record type
                # should not prevent the remaining candidates from being used.
                result.records.setdefault("_error", []).append(str(exc))
                continue
            if values:
                result.records[record_type] = values
            if record_type == "MX":
                result.email_capable = bool(values)
        return result

    completed = 0
    with ThreadPoolExecutor(max_workers=min(max_workers, len(results))) as executor:
        futures = {
            executor.submit(resolve_one, result): index
            for index, result in enumerate(results)
        }
        for future in as_completed(futures):
            index = futures[future]
            results[index] = future.result()
            result = results[index]
            if verbose and (
                result.records.get("A")
                or result.records.get("AAAA")
                or result.records.get("CNAME")
                or result.records.get("MX")
            ):
                print(f"DNS found: {result.domain} -> {result.records}")
            completed += 1
            if progress:
                progress(completed, len(results))
    return [
        result
        for result in results
        if result.records.get("A")
        or result.records.get("AAAA")
        or result.records.get("CNAME")
        or result.records.get("MX")
    ]


def lookup_location(ip: str) -> dict[str, Any]:
    """Look up public IP metadata using the ipwho.is JSON API."""

    request = Request(f"https://ipwho.is/{ip}", headers={"User-Agent": "typ0/1.0"})
    with urlopen(request, timeout=10) as response:
        payload = json.load(response)
    if not payload.get("success", False):
        raise RuntimeError(str(payload.get("message", "location lookup failed")))
    return {
        key: payload.get(key)
        for key in ("country", "region", "city", "latitude", "longitude", "isp", "org")
    }


def collect_locations(
    results: list[DomainResult],
    progress: ProgressCallback | None = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> None:
    """Add geolocation data to each A and AAAA address found by DNS."""

    total_ips = sum(
        len(result.records.get(record_type, []))
        for result in results
        for record_type in ("A", "AAAA")
    )
    tasks = [
        (result, ip)
        for result in results
        for record_type in ("A", "AAAA")
        for ip in result.records.get(record_type, [])
    ]
    if not tasks:
        return

    def lookup(
        item: tuple[DomainResult, str],
    ) -> tuple[DomainResult, str, dict[str, Any]]:
        result, ip = item
        try:
            location = lookup_location(str(ip_address(ip)))
        except (URLError, OSError, RuntimeError, ValueError) as exc:
            # Keep the failure beside the address so the report remains useful
            # and the rest of the batch can continue.
            location = {"error": str(exc)}
        return result, ip, location

    with ThreadPoolExecutor(max_workers=min(max_workers, len(tasks))) as executor:
        futures = [executor.submit(lookup, task) for task in tasks]
        for processed_ips, future in enumerate(as_completed(futures), 1):
            result, ip, location = future.result()
            result.locations[ip] = location
            if progress:
                progress(processed_ips, total_ips)


def fetch_site(domain: str) -> dict[str, Any]:
    """Fetch a site's HTTPS homepage and return its status, URL, and title."""

    request = Request(f"https://{domain}/", headers={"User-Agent": "typ0/1.0"})
    with urlopen(request, timeout=10) as response:
        content = response.read(512_000)
        parser = TitleParser()
        # Use the server-declared charset when available; replacement keeps a
        # malformed page from aborting the entire discovery run.
        parser.feed(
            content.decode(
                response.headers.get_content_charset() or "utf-8", errors="replace"
            )
        )
        return {
            "status": response.status,
            "url": response.geturl(),
            "title": " ".join(" ".join(parser.title_parts).split()) or None,
        }


def collect_http(
    results: list[DomainResult],
    progress: ProgressCallback | None = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    verbose: bool = False,
) -> None:
    """Probe the HTTPS endpoint for every DNS-discovered domain."""

    if not results:
        return

    def fetch(result: DomainResult) -> tuple[DomainResult, dict[str, Any]]:
        try:
            response = fetch_site(result.domain)
        except (URLError, OSError, ValueError) as exc:
            response = {"error": str(exc)}
        return result, response

    with ThreadPoolExecutor(max_workers=min(max_workers, len(results))) as executor:
        futures = [executor.submit(fetch, result) for result in results]
        for index, future in enumerate(as_completed(futures), 1):
            result, response = future.result()
            result.http = response
            if verbose and "error" not in response:
                print(
                    f"HTTPS site found: {result.domain} ({response.get('title') or 'no title'})"
                )
            if progress:
                progress(index, len(results))


def extract_certificate(domain: str) -> dict[str, Any]:
    """Perform a verified TLS handshake and return selected certificate fields."""

    context = ssl.create_default_context()
    # Passing ``server_hostname`` enables SNI, which is required by many
    # hosting providers to return the certificate for the requested domain.
    with (
        socket.create_connection((domain, 443), timeout=10) as connection,
        context.wrap_socket(connection, server_hostname=domain) as tls_socket,
    ):
        certificate = tls_socket.getpeercert()
    return {
        "subject": dict(item[0] for item in certificate.get("subject", ())),
        "issuer": dict(item[0] for item in certificate.get("issuer", ())),
        "not_before": certificate.get("notBefore"),
        "not_after": certificate.get("notAfter"),
        "subject_alt_names": [
            value
            for kind, value in certificate.get("subjectAltName", ())
            if kind == "DNS"
        ],
    }


def collect_certificates(
    results: list[DomainResult],
    progress: ProgressCallback | None = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> None:
    """Collect certificates only for domains whose HTTPS probe succeeded."""

    eligible = [result for result in results if "error" not in result.http]
    if not eligible:
        if progress:
            for index in range(1, len(results) + 1):
                progress(index, len(results))
        return

    def fetch(result: DomainResult) -> tuple[DomainResult, dict[str, Any]]:
        try:
            certificate = extract_certificate(result.domain)
        except (OSError, ssl.SSLError, ValueError) as exc:
            certificate = {"error": str(exc)}
        return result, certificate

    completed = 0
    with ThreadPoolExecutor(max_workers=min(max_workers, len(eligible))) as executor:
        futures = {executor.submit(fetch, result): result for result in eligible}
        for future in as_completed(futures):
            result, certificate = future.result()
            result.certificate = certificate
            completed += 1
            if progress:
                progress(completed, len(results))
    if progress:
        for _ in range(len(results) - len(eligible)):
            completed += 1
            progress(completed, len(results))


def score_domain(source: str, result: DomainResult) -> None:
    """Assign a heuristic review-priority score without comparing site content."""

    source_name = source.split(".", 1)[0]
    candidate_name = result.domain.split(".", 1)[0]
    similarity = SequenceMatcher(None, source_name, candidate_name).ratio()
    score = round(similarity * 35)
    reasons = [f"name similarity: {round(similarity * 100)}%"]

    mutation_score = 0
    if any(character in candidate_name for character in "0123456789"):
        mutation_score += 4
        reasons.append("letter/digit lookalike or appended digit")
    if any(term in candidate_name.split("-") for term in COMMON_DOMAIN_TERMS):
        mutation_score += 4
        reasons.append("common security-related term")
    if "-" in candidate_name:
        mutation_score += 2
        reasons.append("hyphen insertion")
    if result.unicode_domain and result.unicode_domain != result.domain:
        mutation_score += 4
        reasons.append("Unicode lookalike")
    if len(candidate_name) == len(source_name) and candidate_name != source_name:
        mutation_score += 3
        reasons.append("character substitution or transposition")
    score += min(mutation_score, 15)

    if result.records.get("A") or result.records.get("AAAA"):
        score += 10
        reasons.append("A/AAAA record found")
    if result.records.get("CNAME"):
        score += 5
        reasons.append("CNAME record found")
    if result.records.get("MX"):
        score += 8
        reasons.append("MX record found: domain can receive email")
    if result.http and "error" not in result.http:
        score += 10
        reasons.append("HTTPS site reachable")
    if result.certificate and "error" not in result.certificate:
        score += 2
        reasons.append("TLS certificate retrieved")
        subject_alt_names = result.certificate.get("subject_alt_names", [])
        if source in subject_alt_names:
            score += 8
            reasons.append("source domain appears in certificate SANs")

    result.review_score = min(score, 100)
    result.review_priority = (
        "very_high"
        if score >= 75
        else "high" if score >= 50 else "medium" if score >= 25 else "low"
    )
    result.review_reasons = reasons


def score_results(source: str, results: list[DomainResult]) -> None:
    """Score each result after all requested discovery steps have completed."""

    for result in results:
        score_domain(source, result)


def write_report(
    path: Path,
    source: str,
    candidates: list[str],
    results: list[DomainResult],
    steps: tuple[str, ...],
    confusables_url: str,
    tlds: list[str],
) -> None:
    """Serialize the run in a stable, human-readable JSON report."""

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
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )


def parse_args() -> argparse.Namespace:
    """Build the command-line interface and parse its arguments."""

    parser = argparse.ArgumentParser(description="Detect likely typosquatted domains.")
    parser.add_argument("domain", help="Domain to test, with or without a scheme")
    parser.add_argument(
        "-o", "--output", required=True, type=Path, help="JSON report path"
    )
    parser.add_argument(
        "--steps",
        nargs="+",
        choices=STEP_NAMES,
        default=list(DEFAULT_STEPS),
        help="Steps to run (default: all discovery steps)",
    )
    parser.add_argument(
        "--confusables-url",
        default=CONFUSABLES_URL,
        help="Unicode confusables.txt URL (default: official Unicode source)",
    )
    tld_group = parser.add_mutually_exclusive_group()
    tld_group.add_argument(
        "--top-tlds",
        action="store_true",
        help="test the source TLD plus the 15 most common TLDs",
    )
    tld_group.add_argument(
        "--tlds",
        help="comma-separated TLDs to test instead of the source TLD (for example: com,fr,net)",
    )
    tld_group.add_argument(
        "--all-tlds",
        action="store_true",
        help="test candidates against all TLDs from the official IANA list",
    )
    parser.add_argument(
        "--tld-list-url",
        default=TLD_LIST_URL,
        help="IANA TLD list URL used with --all-tlds",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help=f"maximum number of concurrent network tasks (default: {DEFAULT_MAX_WORKERS})",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="display intermediate results and the final summary",
    )
    return parser.parse_args()


def print_step(step_number: int, total_steps: int, name: str, message: str) -> None:
    """Print a consistently formatted workflow step heading."""

    print(f"[{step_number}/{total_steps}] {name}: {message}")


class ProgressBar:
    """Render a lightweight terminal progress bar without extra dependencies."""

    def __init__(self, label: str, total: int, width: int = 30) -> None:
        self.label = label
        self.total = total
        self.width = width
        self.last_rendered = -1

    def update(self, current: int, total: int | None = None) -> None:
        if total is not None:
            self.total = total
        completed = min(current, self.total)
        # Rendering every item can be expensive for a large TLD set, so cap
        # updates at roughly one percent while always showing the endpoints.
        render_interval = max(self.total // 100, 1)
        if (
            completed != self.total
            and completed != 0
            and completed - self.last_rendered < render_interval
        ):
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
    """Run an operation with a callback that updates one shared progress bar."""

    progress_bar = ProgressBar(label, total)
    result = operation(lambda current, total: progress_bar.update(current, total))
    progress_bar.finish()
    return result


def print_summary(
    source: str,
    candidates: list[str],
    results: list[DomainResult],
    steps: tuple[str, ...],
) -> None:
    """Print the small set of findings most useful at the end of a run."""

    dns_domains = [
        result
        for result in results
        if result.records.get("A")
        or result.records.get("AAAA")
        or result.records.get("CNAME")
        or result.records.get("MX")
    ]
    email_domains = [result for result in results if result.records.get("MX")]
    https_domains = [
        result for result in results if result.http and "error" not in result.http
    ]
    certificate_domains = [
        result
        for result in results
        if result.certificate and "error" not in result.certificate
    ]

    print("\nSummary")
    print(f"  Source domain: {source}")
    print(f"  Candidates generated: {len(candidates)}")
    if "dns" in steps:
        print(f"  Domains with DNS records: {len(dns_domains)}")
        print(f"  Domains with mail records (MX): {len(email_domains)}")
    if "http" in steps:
        print(f"  HTTPS sites found: {len(https_domains)}")
    if "cert" in steps:
        print(f"  TLS certificates retrieved: {len(certificate_domains)}")
    if dns_domains:
        print("  Domains requiring review:")
        for result in sorted(
            dns_domains, key=lambda item: item.review_score or 0, reverse=True
        )[:10]:
            print(
                f"    - {result.domain} "
                f"(score: {result.review_score}/100, {result.review_priority})"
            )
        if len(dns_domains) > 10:
            print(f"    ... and {len(dns_domains) - 10} more")
    print("  Note: these findings indicate possibilities, not proof of typosquatting.")


def main() -> int:
    """Coordinate generation, discovery steps, and report creation."""

    args = parse_args()
    try:
        source = normalize_domain(args.domain)
        if args.workers < 1:
            raise ValueError("--workers must be at least 1")
        steps = tuple(step for step in STEP_NAMES if step in args.steps)
        total_steps = len(steps) + 1
        current_step = 0

        def start_step(name: str, message: str) -> None:
            nonlocal current_step
            current_step += 1
            print_step(current_step, total_steps, name, message)

        if "generate" in steps:
            start_step(
                "Generate", "loading Unicode confusables and generating candidates"
            )
            source_tld = ".".join(source.split(".")[1:])
            # The options are mutually exclusive in argparse; this branch
            # chooses the requested TLD source while preserving the default.
            if args.tlds:
                tlds = parse_tlds(args.tlds)
            elif args.top_tlds:
                tlds = list(dict.fromkeys([source_tld, *TOP_TLDS]))
            elif args.all_tlds:
                tlds = load_tlds(args.tld_list_url)
            else:
                tlds = [source_tld]
            unicode_candidates = run_with_progress(
                "Candidates",
                0,
                lambda progress: generate_candidates(
                    source, tlds, args.confusables_url, progress
                ),
            )
        else:
            # Without generation, later steps operate only on the supplied
            # domain. This makes ``--steps dns`` useful for a direct check.
            unicode_candidates = [source]
            tlds = [".".join(source.split(".")[1:])]
        # The IDNA form is used for network operations; the original Unicode
        # form is retained for readers of the report.
        unicode_domains = {
            to_idna_domain(candidate): candidate for candidate in unicode_candidates
        }
        candidates = sorted(unicode_domains)
        if "generate" in steps:
            print(
                "    Candidates after IDNA conversion, deduplication, and "
                f"source removal: {len(candidates)}"
            )
        if args.verbose and "generate" in steps:
            print(f"    Generated {len(candidates)} candidate domain(s).")
        results = [
            DomainResult(domain, unicode_domains.get(domain)) for domain in candidates
        ]
        if "dns" in steps:
            start_step("DNS", f"checking {len(candidates)} candidate domain(s)")
            results = run_with_progress(
                "DNS candidates",
                len(candidates),
                lambda progress: resolve_dns(
                    candidates, unicode_domains, progress, args.workers, args.verbose
                ),
            )
            if args.verbose:
                print(f"    Found DNS records for {len(results)} domain(s).")
        if "geo" in steps:
            start_step(
                "Geolocation", f"looking up IP addresses for {len(results)} domain(s)"
            )
            location_total = sum(
                len(result.records.get(record_type, []))
                for result in results
                for record_type in ("A", "AAAA")
            )
            run_with_progress(
                "IP addresses",
                location_total,
                lambda progress: collect_locations(results, progress, args.workers),
            )
            location_count = sum(len(result.locations) for result in results)
            if args.verbose:
                print(f"    Processed {location_count} IP address(es).")
        if "http" in steps:
            start_step("HTTPS", f"checking {len(results)} discovered domain(s)")
            run_with_progress(
                "HTTPS candidates",
                len(results),
                lambda progress: collect_http(
                    results, progress, args.workers, args.verbose
                ),
            )
            available_count = sum("error" not in result.http for result in results)
            if args.verbose:
                print(f"    Found {available_count} HTTPS site(s).")
        if "cert" in steps:
            start_step(
                "Certificates", f"retrieving certificates for {len(results)} domain(s)"
            )
            run_with_progress(
                "Certificates",
                len(results),
                lambda progress: collect_certificates(results, progress, args.workers),
            )
            certificate_count = sum(
                bool(result.certificate) and "error" not in result.certificate
                for result in results
            )
            if args.verbose:
                print(f"    Retrieved {certificate_count} certificate(s).")
        score_results(source, results)
        start_step("Report", f"writing results to {args.output}")
        write_report(
            args.output,
            source,
            candidates,
            results,
            steps,
            args.confusables_url,
            tlds,
        )
        print(f"Report written to {args.output}")
        print_summary(source, candidates, results, steps)
        return 0
    except (ValueError, OSError, URLError) as exc:
        print(f"typ0: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
