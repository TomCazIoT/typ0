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
