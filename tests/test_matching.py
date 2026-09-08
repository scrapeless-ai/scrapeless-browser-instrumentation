"""Offline tests for sbi.matching comparison modes."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbi.verify.matching import compare, mode_names
from sbi.verify.oracle import _equal


class TestExact(unittest.TestCase):
    CASES = [
        ({"a": [1, "x"], "b": None}, {"b": None, "a": [1, "x"]}, True),
        ([1, [2, {"k": True}]], [1, [2, {"k": True}]], True),
        ("sig", "sig", True),
        (1, 1.0, False),                 # int vs float: type-strict
        ("1", 1, False),
        ([1, 2], [2, 1], False),
        ({"a": 1}, {"a": 1, "b": 2}, False),
        (None, False, False),
    ]

    def test_matches_oracle_semantics(self):
        for a, b, want in self.CASES:
            self.assertEqual(compare(a, b)["match"], want, (a, b))
            self.assertEqual(_equal(a, b), want, (a, b))

    def test_bool_never_equals_one(self):
        self.assertFalse(compare(True, 1)["match"])
        self.assertFalse(compare(0, False)["match"])

    def test_detail_set_on_mismatch(self):
        r = compare("a", "b")
        self.assertFalse(r["match"])
        self.assertTrue(r["detail"])


class TestLooseString(unittest.TestCase):
    def test_structure_match(self):
        r = compare("tok_abc123", "tok_xyz789", "loose_string")
        self.assertTrue(r["match"], r)

    def test_case_insensitive_alpha(self):
        self.assertTrue(compare("Tok-Abc", "tOK-aBC", "loose_string")["match"])

    def test_length_mismatch(self):
        r = compare("tok_abc", "tok_abcd", "loose_string")
        self.assertFalse(r["match"])
        self.assertIn("length", r["detail"])

    def test_class_mismatch(self):
        r = compare("tok_a1", "tok_ab", "loose_string")
        self.assertFalse(r["match"])
        self.assertIn("index 5", r["detail"])

    def test_non_strings_fall_back_strict(self):
        self.assertTrue(compare(5, 5, "loose_string")["match"])
        self.assertFalse(compare("5", 5, "loose_string")["match"])


class TestNumeric(unittest.TestCase):
    def test_tolerance(self):
        self.assertTrue(compare(10.0, 10.4, "numeric", tol=0.5)["match"])
        self.assertFalse(compare(10.0, 10.6, "numeric", tol=0.5)["match"])

    def test_relative(self):
        self.assertTrue(compare(1000, 1019, "numeric", rel=0.02)["match"])
        self.assertFalse(compare(1000, 1030, "numeric", rel=0.02)["match"])

    def test_combined(self):
        self.assertTrue(compare(0.0, 0.9, "numeric", tol=0.5, rel=10.0)["match"])

    def test_bool_excluded(self):
        self.assertFalse(compare(True, 1, "numeric", tol=10)["match"])

    def test_non_numbers_fall_back_strict(self):
        self.assertFalse(compare("10", 10, "numeric")["match"])


class TestTimeTolerant(unittest.TestCase):
    def test_within_window(self):
        r = compare("signed at 2026-09-04T10:00:00Z id=42",
                    "signed at 2026-09-04T10:00:31Z id=42", "time_tolerant", seconds=60)
        self.assertTrue(r["match"], r)

    def test_outside_window(self):
        r = compare("t=2026-09-04T10:00:00Z", "t=2026-09-04T10:05:00Z",
                    "time_tolerant", seconds=60)
        self.assertFalse(r["match"])
        self.assertIn("beyond", r["detail"])

    def test_count_mismatch(self):
        r = compare("2026-09-04T10:00:00Z and 2026-09-04T11:00:00Z",
                    "2026-09-04T10:00:00Z", "time_tolerant")
        self.assertFalse(r["match"])
        self.assertIn("timestamps", r["detail"])

    def test_non_ts_text_must_match(self):
        r = compare("a 2026-09-04T10:00:00Z", "b 2026-09-04T10:00:00Z", "time_tolerant")
        self.assertFalse(r["match"])
        self.assertIn("non-timestamp", r["detail"])

    def test_space_separator_and_offset_forms(self):
        self.assertTrue(compare("x 2026-09-04 10:00:00+02:00",
                                "x 2026-09-04 08:00:30+00:00", "time_tolerant",
                                seconds=60)["match"])


class TestMisc(unittest.TestCase):
    def test_unknown_mode_raises(self):
        with self.assertRaises(ValueError):
            compare(1, 1, "fuzzy")

    def test_mode_names(self):
        self.assertEqual(mode_names(),
                         ["exact", "loose_string", "numeric", "time_tolerant"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
