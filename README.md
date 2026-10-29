# typ0
Typosquatting detection tool to identify potentially malicious lookalike domains.

## Usage

`typ0` is a standard-library Python CLI that generates common lookalike domains,
including Unicode confusables from the official Unicode [confusables.txt](https://www.unicode.org/Public/security/latest/confusables.txt) data,
checks them with `dig`, optionally looks up IP geolocation, checks HTTPS pages,
and extracts TLS certificate information.

## Interpreting the results

The results are indicators, not proof that typosquatting exists or that a
domain is malicious. A generated lookalike domain, DNS record, web page, or
certificate only shows that the domain may exist and deserves further
investigation. Domains can be registered for legitimate reasons, and the
absence of a DNS or HTTPS result does not prove that no typosquatting is
occurring. Always validate findings with additional context and, where
appropriate, manual or legal investigation.

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
steps are enabled. `dns` requires the `dig` command to be installed and
available in `PATH`. The `geo` step sends discovered public IP addresses to the
public `https://ipwho.is/` API for geolocation. The generation step downloads
the official Unicode source over HTTPS; use `--confusables-url` to provide a
mirror or a local HTTP server.
Network operations use a ten-second timeout, except the Unicode source download,
which uses fifteen seconds.

Network checks run concurrently with a bounded worker pool. Use `--workers` to
control the maximum number of simultaneous tasks; it defaults to 8:

```bash
python3 typ0.py example.com --output report.json --top-tlds --workers 4
```

Each discovered domain receives a heuristic review-priority score from 0 to
100. The score combines name similarity, mutation patterns, DNS records,
HTTPS availability, and certificate metadata. It does not compare website
content, and it is not a risk determination or proof of typosquatting; use it
only to prioritize manual review.

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
