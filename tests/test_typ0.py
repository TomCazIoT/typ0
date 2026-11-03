import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))

import typ0


class DomainParsingTests(unittest.TestCase):
    def test_normalize_domain_accepts_schemeless_and_url_inputs(self) -> None:
        self.assertEqual(typ0.normalize_domain(" Example.COM. "), "example.com")
        self.assertEqual(
            typ0.normalize_domain("https://Example.COM/path"),
            "example.com",
        )

    def test_normalize_domain_converts_internationalized_domain(self) -> None:
        self.assertEqual(
            typ0.normalize_domain("münich.de"),
            "xn--mnich-kva.de",
        )

    def test_normalize_domain_rejects_missing_tld(self) -> None:
        with self.assertRaisesRegex(ValueError, "hostname and a TLD"):
            typ0.normalize_domain("localhost")

    def test_normalize_domain_rejects_invalid_hostnames(self) -> None:
        for value in (
            "ex ample.com",
            "exa_mple.com",
            "-foo.com",
            "foo-.com",
            "1.2.3.4",
            "foo.c",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                typ0.normalize_domain(value)

    def test_parse_tlds_strips_dots_and_deduplicates(self) -> None:
        self.assertEqual(
            typ0.parse_tlds(" .com, fr, .com,net. "),
            ["com", "fr", "net"],
        )

    def test_parse_tlds_rejects_empty_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least one TLD"):
            typ0.parse_tlds(" , . ")

    def test_parse_tlds_rejects_invalid_tld(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid TLD"):
            typ0.parse_tlds("com, bad tld")


class DNSResolutionTests(unittest.TestCase):
    @patch.object(typ0.shutil, "which", return_value="/usr/bin/dig")
    @patch.object(
        typ0.subprocess,
        "run",
        return_value=type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": "192.0.2.1.\n",
                "stderr": "",
            },
        )(),
    )
    def test_prefers_dig_when_available(self, run, which) -> None:
        self.assertEqual(
            typ0.resolve_dns_record("example.com", "A"),
            ["192.0.2.1"],
        )
        which.assert_called_once_with("dig")
        run.assert_called_once()

    @patch.object(typ0.shutil, "which", return_value="/usr/bin/dig")
    @patch.object(
        typ0.subprocess,
        "run",
        return_value=type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": "10 mail.example.com.\n",
                "stderr": "",
            },
        )(),
    )
    def test_resolves_mx_records_with_dig(self, run, _which) -> None:
        self.assertEqual(
            typ0.resolve_dns_record("example.com", "MX"),
            ["10 mail.example.com"],
        )
        run.assert_called_once()

    @patch.object(typ0.shutil, "which", return_value="/usr/bin/dig")
    @patch.object(typ0, "resolve_dns_record")
    def test_marks_domain_as_email_capable_when_mx_exists(
        self, resolve_record, _which
    ) -> None:
        resolve_record.side_effect = lambda _domain, record_type, _dig_available: {
            "A": ["192.0.2.1"],
            "AAAA": [],
            "CNAME": [],
            "MX": ["10 mail.example.com"],
        }[record_type]

        results = typ0.resolve_dns(["example.com"], {"example.com": "example.com"})

        self.assertTrue(results[0].email_capable)
        self.assertEqual(results[0].records["MX"], ["10 mail.example.com"])

    @patch.object(typ0.shutil, "which", return_value=None)
    @patch.object(typ0, "resolve_dns_record", return_value=[])
    def test_skips_mx_without_dig(self, resolve_record, _which) -> None:
        typ0.resolve_dns(["example.com"], {"example.com": "example.com"})

        record_types = [call.args[1] for call in resolve_record.call_args_list]
        self.assertNotIn("MX", record_types)

    @patch.object(
        typ0.shutil,
        "which",
        return_value=None,
    )
    @patch.object(
        typ0.socket,
        "getaddrinfo",
        return_value=[
            (typ0.socket.AF_INET, 1, 6, "", ("192.0.2.1", 0)),
            (typ0.socket.AF_INET, 1, 6, "", ("192.0.2.1", 0)),
        ],
    )
    def test_resolves_a_records_without_dig(self, _getaddrinfo, _which) -> None:
        self.assertEqual(
            typ0.resolve_dns_record("example.com", "A"),
            ["192.0.2.1"],
        )

    @patch.object(
        typ0.shutil,
        "which",
        return_value=None,
    )
    @patch.object(
        typ0.socket,
        "gethostbyname_ex",
        return_value=("example.com", ["alias.example.com."], ["192.0.2.1"]),
    )
    def test_resolves_cname_aliases_from_standard_library(
        self, _gethostbyname_ex, _which
    ) -> None:
        self.assertEqual(
            typ0.resolve_dns_record("example.com", "CNAME"),
            ["alias.example.com"],
        )

    def test_rejects_unsupported_record_type(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported DNS record type"):
            typ0.resolve_dns_record("example.com", "TXT")

    @patch.object(typ0.shutil, "which", return_value=None)
    def test_mx_requires_dig_for_socket_fallback(self, _which) -> None:
        with self.assertRaisesRegex(RuntimeError, "MX lookup requires dig"):
            typ0.resolve_dns_record("example.com", "MX")


class DiscoveryTests(unittest.TestCase):
    @patch.object(typ0, "lookup_location", return_value={"country": "US"})
    def test_collect_locations_skips_private_and_deduplicates(self, lookup) -> None:
        first = typ0.DomainResult(
            "first.com",
            records={"A": ["192.168.1.1", "8.8.8.8"]},
        )
        second = typ0.DomainResult("second.com", records={"A": ["8.8.8.8"]})

        typ0.collect_locations([first, second])

        lookup.assert_called_once_with("8.8.8.8")
        self.assertNotIn("192.168.1.1", first.locations)
        self.assertEqual(first.locations["8.8.8.8"], {"country": "US"})
        self.assertEqual(second.locations["8.8.8.8"], {"country": "US"})

    @patch.object(typ0, "fetch_site", side_effect=typ0.HTTPException("bad response"))
    def test_collect_http_records_http_exception(self, _fetch_site) -> None:
        result = typ0.DomainResult("example.com")

        typ0.collect_http([result])

        self.assertIn("bad response", result.http["error"])

    @patch.object(typ0, "urlopen", return_value=io.BytesIO(b"[]"))
    def test_lookup_location_rejects_non_object_payload(self, _urlopen) -> None:
        with self.assertRaisesRegex(TypeError, "invalid response"):
            typ0.lookup_location("8.8.8.8")


class CandidateGenerationTests(unittest.TestCase):
    @patch.object(typ0, "load_confusables", return_value={})
    def test_generates_multiple_mutation_families(self, _load_confusables) -> None:
        candidates = typ0.generate_candidates("example.com", ["com", "fr"])

        self.assertIn("examp1e.com", candidates)
        self.assertIn("login-example.fr", candidates)
        self.assertIn("example-login.com", candidates)
        self.assertIn("example0.com", candidates)
        self.assertNotIn("example.com", candidates)

    @patch.object(typ0, "load_confusables", return_value={"e": {"é"}})
    def test_converts_unicode_candidates_to_idna(self, _load_confusables) -> None:
        candidates = typ0.generate_candidates("example.com", ["com"])

        self.assertIn("xn--xample-9ua.com", candidates)

    @patch.object(typ0, "load_confusables", return_value={"e": {"é"}})
    def test_preserves_unicode_candidate_mapping(self, _load_confusables) -> None:
        candidates = typ0.generate_candidates("example.com", ["com"])

        self.assertEqual(candidates["xn--xample-9ua.com"], "éxample.com")


class ScoringTests(unittest.TestCase):
    def test_score_uses_observations_and_assigns_priority(self) -> None:
        result = typ0.DomainResult(
            "examp1e-login.com",
            records={"A": ["192.0.2.1"]},
            http={"status": 200},
            certificate={"subject_alt_names": []},
        )

        typ0.score_domain("example.com", result)

        self.assertIsNotNone(result.review_score)
        self.assertGreaterEqual(result.review_score, 50)
        self.assertEqual(result.review_priority, "high")
        self.assertTrue(any("HTTPS" in reason for reason in result.review_reasons))

    def test_score_does_not_compare_page_content(self) -> None:
        first = typ0.DomainResult("example0.com", http={"title": "Original"})
        second = typ0.DomainResult("example0.com", http={"title": "Unrelated"})

        typ0.score_domain("example.com", first)
        typ0.score_domain("example.com", second)

        self.assertEqual(first.review_score, second.review_score)
        self.assertEqual(first.review_reasons, second.review_reasons)

    def test_score_uses_unicode_name_for_similarity(self) -> None:
        result = typ0.DomainResult(
            "xn--xample-9ua.com",
            unicode_domain="éxample.com",
        )

        typ0.score_domain("example.com", result)

        self.assertEqual(result.review_reasons[0], "name similarity: 86%")
        self.assertIn("Unicode lookalike", result.review_reasons)

    def test_score_decodes_punycode_source_label(self) -> None:
        from_idna = typ0.DomainResult(
            "xn--mnich0-3ya.de",
            unicode_domain="münich0.de",
        )
        from_unicode = typ0.DomainResult(
            "xn--mnich0-3ya.de",
            unicode_domain="münich0.de",
        )

        typ0.score_domain("xn--mnich-kva.de", from_idna)
        typ0.score_domain("münich.de", from_unicode)

        self.assertEqual(from_idna.review_score, from_unicode.review_score)
        self.assertEqual(from_idna.review_reasons, from_unicode.review_reasons)

    def test_certificate_covers_wildcard_subdomain(self) -> None:
        self.assertTrue(typ0.certificate_covers("www.example.com", ["*.example.com"]))
        self.assertFalse(typ0.certificate_covers("example.com", ["*.example.com"]))


class OutputTests(unittest.TestCase):
    def test_summary_lists_review_priority(self) -> None:
        result = typ0.DomainResult(
            "example0.com",
            records={"A": ["192.0.2.1"]},
        )
        typ0.score_domain("example.com", result)
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            typ0.print_summary(
                "example.com",
                ["example0.com"],
                [result],
                ("generate", "dns"),
            )

        text = output.getvalue()
        self.assertIn("example0.com", text)
        self.assertIn("score:", text)
        self.assertIn("not proof of typosquatting", text)

    def test_write_report_sorts_locations_and_creates_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "report.json"
            result = typ0.DomainResult(
                "example0.com",
                locations={
                    "8.8.8.8": {"city": "B"},
                    "1.1.1.1": {"city": "A"},
                },
            )

            typ0.write_report(
                path,
                "example.com",
                ["example0.com"],
                [result],
                ("dns",),
                "https://example.test/confusables.txt",
                ["com"],
            )
            report = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(
            list(report["discovered_domains"][0]["locations"]),
            ["1.1.1.1", "8.8.8.8"],
        )

    @patch.object(
        sys,
        "argv",
        [
            "typ0.py",
            "example.com",
            "-o",
            "report.json",
            "--steps",
            "generate",
            "--tlds",
            "",
        ],
    )
    def test_main_rejects_empty_tlds(self) -> None:
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(typ0.main(), 2)

    @patch.object(
        sys,
        "argv",
        ["typ0.py", "example.com", "-o", "report.json", "--steps", "dns", "--top-tlds"],
    )
    def test_main_rejects_tld_selection_without_generate(self) -> None:
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(typ0.main(), 2)


if __name__ == "__main__":
    unittest.main()
