import contextlib
import io
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[1]))

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

    def test_parse_tlds_strips_dots_and_deduplicates(self) -> None:
        self.assertEqual(
            typ0.parse_tlds(" .com, fr, .com,net "),
            ["com", "fr", "net"],
        )

    def test_parse_tlds_rejects_empty_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least one TLD"):
            typ0.parse_tlds(" , . ")


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

    @patch.object(typ0, "resolve_dns_record")
    def test_marks_domain_as_email_capable_when_mx_exists(self, resolve_record) -> None:
        resolve_record.side_effect = lambda _domain, record_type: {
            "A": ["192.0.2.1"],
            "AAAA": [],
            "CNAME": [],
            "MX": ["10 mail.example.com"],
        }[record_type]

        results = typ0.resolve_dns(["example.com"], {"example.com": "example.com"})

        self.assertTrue(results[0].email_capable)
        self.assertEqual(results[0].records["MX"], ["10 mail.example.com"])

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


if __name__ == "__main__":
    unittest.main()
