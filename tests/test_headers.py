"""
Headers class conformance tests.
RFC 9110 §5: Header Fields (case-insensitivity, multiple values, etc.)
"""
from __future__ import annotations

import pytest
from kaede.models import Headers


class TestCaseInsensitivity:
    """RFC 9110 §5.1: Field names are case-insensitive"""

    def test_get_lowercase(self):
        h = Headers({"Content-Type": "text/html"})
        assert h.get("content-type") == "text/html"

    def test_get_uppercase(self):
        h = Headers({"Content-Type": "text/html"})
        assert h.get("CONTENT-TYPE") == "text/html"

    def test_get_mixed_case(self):
        h = Headers({"Content-Type": "text/html"})
        assert h.get("Content-Type") == "text/html"

    def test_set_case_insensitive_lookup(self):
        h = Headers({})
        h.set("Content-Type", "text/html")
        assert h.get("CONTENT-TYPE") == "text/html"

    def test_contains_case_insensitive(self):
        h = Headers({"X-Custom": "value"})
        assert "x-custom" in h
        assert "X-Custom" in h
        assert "X-CUSTOM" in h

    def test_set_merges_case_variants(self):
        h = Headers({})
        h.set("X-Test", "first")
        h.set("x-test", "second")
        assert h.get("X-Test") == "second"


class TestMultipleValues:
    """RFC 9110 §5.2: Multiple header field lines with same name"""

    def test_append_two_values(self):
        h = Headers({})
        h.append("Accept", "text/html")
        h.append("Accept", "application/json")
        result = h.get("Accept")
        assert "text/html" in result
        assert "application/json" in result

    def test_combined_with_comma(self):
        """RFC 9110 §5.2: Combined field values are comma-separated"""
        h = Headers({})
        h.append("Accept", "text/html")
        h.append("Accept", "application/json")
        result = h.get("Accept")
        assert isinstance(result, str)
        assert "," in result

    def test_set_cookie_returned_as_list(self):
        """RFC 6265 §4.1.3: Set-Cookie headers MUST NOT be combined"""
        h = Headers({})
        h.append("Set-Cookie", "a=1; Path=/")
        h.append("Set-Cookie", "b=2; Path=/")
        result = h.get("Set-Cookie")
        assert isinstance(result, list)
        assert "a=1; Path=/" in result
        assert "b=2; Path=/" in result

    def test_items_returns_all_pairs(self):
        h = Headers({})
        h.append("Accept", "text/html")
        h.append("Accept", "application/json")
        pairs = h.items()
        accept_values = [v for k, v in pairs if k == "accept"]
        assert "text/html" in accept_values
        assert "application/json" in accept_values


class TestSetBehavior:
    def test_set_override_true_replaces(self):
        h = Headers({"X-Test": "old"})
        h.set("X-Test", "new", override=True)
        assert h.get("X-Test") == "new"

    def test_set_override_false_preserves(self):
        h = Headers({"X-Test": "old"})
        h.set("X-Test", "new", override=False)
        assert h.get("X-Test") == "old"

    def test_set_override_false_sets_when_absent(self):
        h = Headers({})
        h.set("X-Test", "value", override=False)
        assert h.get("X-Test") == "value"

    def test_set_default_is_override(self):
        h = Headers({"X-Test": "old"})
        h.set("X-Test", "new")
        assert h.get("X-Test") == "new"


class TestRemove:
    def test_remove_existing(self):
        h = Headers({"X-Test": "value"})
        h.remove("X-Test")
        assert h.get("X-Test") is None
        assert "X-Test" not in h

    def test_remove_case_insensitive(self):
        h = Headers({"X-Test": "value"})
        h.remove("x-test")
        assert "X-Test" not in h

    def test_remove_nonexistent_no_error(self):
        h = Headers({})
        h.remove("X-Missing")  # should not raise


class TestGetDefault:
    def test_missing_key_returns_none(self):
        h = Headers({})
        assert h.get("X-Missing") is None

    def test_missing_key_returns_default(self):
        h = Headers({})
        assert h.get("X-Missing", "fallback") == "fallback"


class TestVaryHeader:
    """RFC 7231 §7.1.4: Vary header management"""

    def test_append_vary_adds_field(self):
        h = Headers({})
        h.append_vary("Accept-Encoding")
        assert "Accept-Encoding" in h.get("Vary")

    def test_append_vary_no_duplicate(self):
        h = Headers({})
        h.append_vary("Accept-Encoding")
        h.append_vary("Accept-Encoding")
        vary = h.get("Vary")
        assert vary.count("Accept-Encoding") == 1

    def test_append_vary_multiple_fields(self):
        h = Headers({})
        h.append_vary("Accept-Encoding")
        h.append_vary("Origin")
        vary = h.get("Vary")
        assert "Accept-Encoding" in vary
        assert "Origin" in vary

    def test_vary_star_cannot_be_extended(self):
        """RFC 7231 §7.1.4: * means vary on everything; no further fields needed"""
        h = Headers({"Vary": "*"})
        h.append_vary("Accept-Encoding")
        assert h.get("Vary") == "*"

    def test_set_vary_star(self):
        h = Headers({})
        h.append_vary("*")
        assert h.get("Vary") == "*"

    def test_case_insensitive_dedup(self):
        h = Headers({})
        h.append_vary("accept-encoding")
        h.append_vary("Accept-Encoding")
        vary = h.get("Vary")
        assert vary.count("ncoding") == 1


# ---------------------------------------------------------------------------
# RFC 9110 §5.1: items() and __getitem__ / __setitem__
# ---------------------------------------------------------------------------

class TestItemsMethod:
    def test_items_returns_lowercase_keys(self):
        """headers dict stores keys lowercase; items() must emit lowercase names"""
        h = Headers({"Content-Type": "text/html", "X-Custom": "val"})
        keys = [k for k, v in h.items()]
        assert all(k == k.lower() for k in keys)

    def test_items_returns_all_set_cookie_separately(self):
        """RFC 6265 §4.1.3: Each Set-Cookie is a separate header; items() must emit both"""
        h = Headers({})
        h.append("Set-Cookie", "a=1; Path=/")
        h.append("Set-Cookie", "b=2; Path=/")
        pairs = [(k, v) for k, v in h.items() if k == "set-cookie"]
        assert len(pairs) == 2

    def test_items_order_preserves_insertion(self):
        """items() must return headers in insertion order"""
        h = Headers({})
        h.set("X-First", "1")
        h.set("X-Second", "2")
        h.set("X-Third", "3")
        keys = [k for k, v in h.items()]
        assert keys == ["x-first", "x-second", "x-third"]


class TestGetitemSetitem:
    def test_getitem_case_insensitive(self):
        """h[key] must behave case-insensitively like h.get(key)"""
        h = Headers({"Content-Type": "text/html"})
        assert h["Content-Type"] == "text/html"
        assert h["content-type"] == "text/html"
        assert h["CONTENT-TYPE"] == "text/html"

    def test_setitem_stores_value(self):
        """h[key] = value must store the header"""
        h = Headers({})
        h["X-Test"] = "hello"
        assert h.get("X-Test") == "hello"

    def test_setitem_overrides_existing(self):
        """h[key] = value must override any existing value"""
        h = Headers({"X-Test": "old"})
        h["X-Test"] = "new"
        assert h.get("X-Test") == "new"


class TestHeadersInitialization:
    def test_empty_headers_dict(self):
        h = Headers({})
        assert h.items() == []
        assert h.get("X-Missing") is None

    def test_init_from_dict_with_multiple_keys(self):
        h = Headers({"A": "1", "B": "2", "C": "3"})
        assert h.get("A") == "1"
        assert h.get("B") == "2"
        assert h.get("C") == "3"

    def test_contains_after_remove(self):
        h = Headers({"X-Test": "value"})
        assert "X-Test" in h
        h.remove("X-Test")
        assert "X-Test" not in h
        assert "x-test" not in h


class TestVaryEdgeCases:
    def test_append_vary_to_existing_multi_value_vary(self):
        """append_vary on a Vary already containing comma-separated values"""
        h = Headers({"Vary": "Origin, Accept-Encoding"})
        h.append_vary("Accept-Language")
        vary = h.get("Vary")
        assert "Origin" in vary
        assert "Accept-Encoding" in vary
        assert "Accept-Language" in vary

    def test_append_vary_dedup_against_pre_existing(self):
        """append_vary must not duplicate a field already in an existing Vary"""
        h = Headers({"Vary": "Origin, Accept-Encoding"})
        h.append_vary("Accept-Encoding")
        vary = h.get("Vary")
        assert vary.count("Accept-Encoding") == 1
