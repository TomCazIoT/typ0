# typ0
Typosquatting detection tool to identify potentially malicious lookalike domains.

## Usage

`typ0` is a standard-library Python CLI that generates common lookalike domains,
including Unicode confusables from the official Unicode `confusables.txt` data,
checks them with `dig`, optionally looks up IP geolocation, checks HTTPS pages,
and extracts TLS certificate information.

```bash
python3 typ0.py example.com --output report.json
```

By default, variants keep the TLD of the input domain. To test a selected set
of TLDs, use a comma-separated list:

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
public `ipwho.is` API. The generation step downloads the official Unicode source
over HTTPS; use `--confusables-url` to provide a mirror or a local HTTP server.
Network operations use a ten-second timeout, except the Unicode source download,
which uses fifteen seconds.

During execution, typ0 displays the current step, its position in the workflow,
and a progress bar based on the number of candidates, IPs, or certificates
processed. The report-writing step is always displayed as the final step.

Only the first label of the supplied domain is mutated; its suffix is preserved
unless `--tlds` or `--all-tlds` is used.
The generated mutations include character omissions, repetitions, adjacent
keyboard substitutions, transpositions, hyphen insertion, appended digits, and
Unicode confusable substitutions. Unicode candidates are converted to IDNA
(punycode) before DNS and HTTPS requests; both forms are included in the report.
