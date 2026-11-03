# typ0
Typosquatting detection tool to identify potentially malicious lookalike domains.

## Usage

`typ0` is a standard-library Python 3.10+ CLI that generates common lookalike domains,
including Unicode confusables from the official Unicode [confusables.txt](https://www.unicode.org/Public/security/latest/confusables.txt) data,
resolves them with `dig` when available (and otherwise Python's standard-library
DNS resolver), checks whether domains can receive email through MX records,
optionally looks up IP geolocation, checks HTTPS pages,
and extracts TLS certificate information.

```bash
python3 typ0.py example.com --output report.json
```

By default, variants keep the TLD of the input domain. To test the input TLD
plus the 15 most common TLDs, use:

```bash
python3 typ0.py example.com --output report.json --top-tlds
```

To test a selected list of TLDs, use a comma-separated argument:

```bash
python3 typ0.py example.com --output report.json --tlds com,net,org,fr
```

To use every public TLD in the official IANA list, opt in explicitly:

```bash
python3 typ0.py example.com --output report.json --all-tlds
```

This can create a very large number of candidates and DNS/HTTPS requests. Use
`--tld-list-url` to provide a compatible mirror of the IANA TLD list.

The report is JSON. The `--steps` option selects the operations to run:

```bash
python3 typ0.py example.com --output report.json \
  --steps generate dns http cert
```

Available steps are `generate`, `dns`, `geo`, `http`, and `cert`. By default all
steps are enabled. The TLD selection options (`--top-tlds`, `--tlds`, and
`--all-tlds`) require `generate` to be included in `--steps`. DNS lookups use
`dig` when it is installed and fall back to the operating system resolver
through Python's standard library otherwise. The `MX` record is used to identify
domains that could receive email and to add that signal to the review score. MX
lookups require `dig`; when it is absent, the other DNS checks still use the
`socket` fallback, but email capability cannot be determined. The `geo` step
sends discovered public IP addresses to the public `https://ipwho.is/` API for
geolocation; non-public addresses are skipped. The generation step downloads
the official Unicode source over HTTPS; use `--confusables-url` to provide a
mirror or a local HTTP server.
Network operations use a ten-second timeout, except the Unicode source download,
which uses fifteen seconds. The `socket` resolver fallback is subject to the
operating system resolver's timeouts and may exceed ten seconds.

Network checks run concurrently with a bounded worker pool. Use `--workers` to
control the maximum number of simultaneous tasks; it defaults to 8:

```bash
python3 typ0.py example.com --output report.json --top-tlds --workers 4
```

By default, the console displays the workflow steps, their progress bars, and
the final summary. Intermediate findings are hidden. Use `--verbose` to display
those findings as they are collected:

```bash
python3 typ0.py example.com --output report.json --verbose
```

During execution, typ0 displays the current step, its position in the workflow,
and a progress bar based on the number of candidates, IPs, or certificates
processed. The report-writing step is always displayed as the final step.

Only the first label of the supplied domain is mutated; its suffix is preserved
unless `--top-tlds`, `--tlds`, or `--all-tlds` is used. The TLD selection
options are mutually exclusive.
The generated mutations include character omissions, repetitions, adjacent
keyboard substitutions, letter/digit lookalikes such as `o/0` and `l/1`,
transpositions, hyphen insertion, appended digits, common security-related
prefixes and suffixes, and Unicode confusable substitutions. Unicode
candidates are converted to IDNA (punycode) before DNS and HTTPS requests;
both forms are included in the report.

## How the score is computed

Every discovered domain receives a `review_score` from 0 to 100. The score is
computed once, after all requested steps have run, by adding points from several
independent signals. Signals from steps that were not run (or that failed)
simply contribute nothing. The score never inspects page content, so two
domains with different web pages but identical network and certificate
findings receive the same score.

| Signal | Points |
| --- | --- |
| Name similarity (see below) | 0–35 |
| Mutation pattern (capped) | 0–15 |
| `A` or `AAAA` record found | +10 |
| `CNAME` record found | +5 |
| `MX` record found (domain can receive email) | +8 |
| HTTPS site reachable | +10 |
| TLS certificate retrieved | +2 |
| Source domain appears in certificate SANs | +8 |

**Name similarity.** The first label of the source domain is compared with the
first label of the candidate (in Unicode display form when available) using
Python's `difflib.SequenceMatcher`. The similarity ratio, from 0 to 1, is
multiplied by 35 and rounded, so an identical label scores 35 and an unrelated
one scores close to 0.

**Mutation pattern.** These signals are added together, then capped at 15:

| Pattern | Points |
| --- | --- |
| Contains a digit (letter/digit lookalike or appended digit) | +4 |
| Contains a hyphen-separated common security term (`account`, `login`, `secure`, `support`, `verify`) | +4 |
| Contains a hyphen | +2 |
| Unicode lookalike (IDNA and Unicode forms differ) | +4 |
| Same length as the source but different (substitution or transposition) | +3 |

**Network and certificate signals.** An `A`/`AAAA` record adds 10, a `CNAME`
adds 5, and an `MX` record adds 8. A reachable HTTPS page adds 10. A retrieved
TLS certificate adds 2, and 8 more if one of its subject alternative names
covers the source domain (including wildcard matches).

The raw total is capped at 100. The `review_priority` label is derived from the
final score:

| Score | Priority |
| --- | --- |
| 75–100 | `very_high` |
| 50–74 | `high` |
| 25–49 | `medium` |
| 0–24 | `low` |

Each result also includes `review_reasons`, the human-readable list of signals
that contributed to its score.
=======
## Score calculation

The score is calculated independently for each discovered domain. It starts
with the similarity between the first label of the source domain and the first
label of the candidate, measured with `SequenceMatcher`:

| Signal | Points |
| --- | ---: |
| Name similarity | 0 to 35, based on the similarity ratio |
| Digit lookalike or appended digit | +4 |
| Common security-related term (`account`, `login`, `secure`, `support`, or `verify`) | +4 |
| Hyphen in the candidate name | +2 |
| Unicode lookalike | +4 |
| Same-length character substitution or transposition | +3 |
| Mutation subtotal | Maximum +15 |
| `A` or `AAAA` DNS record | +10 |
| `CNAME` DNS record | +5 |
| `MX` DNS record | +8 |
| Reachable HTTPS site | +10 |
| TLS certificate retrieved | +2 |
| Source domain present in the certificate SANs | +8 |

The final total is capped at 100. The review priority is assigned from that
total: `low` below 25, `medium` from 25 to 49, `high` from 50 to 74, and
`very_high` from 75 to 100. A signal only contributes points when the
corresponding observation is available; for example, skipping the `http` step
means that HTTPS availability cannot add points. The score is a triage aid,
not a probability, a verdict, or proof that a domain is malicious.

## Interpreting the results

The results are indicators, not proof that typosquatting exists or that a
domain is malicious. A generated lookalike domain, DNS record, web page, or
certificate only shows that the domain may exist and deserves further
investigation. Domains can be registered for legitimate reasons, and the
absence of a DNS or HTTPS result does not prove that no typosquatting is
occurring. Always validate findings with additional context and, where
appropriate, manual or legal investigation.

## Run the automated tests with:

```bash
python3 -m unittest discover -s tests -v
```
