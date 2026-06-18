"""
Structured Field Values conformance tests (RFC 8941).

Parsing/serialization must follow the §4 algorithms exactly; §1.1 mandates
strict processing where the only error handling is to fail. Examples are taken
from the RFC. Tests assert the spec, not Kaede's prior behavior.
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from kaede.http import structured as sf
from kaede.http.structured import Item, InnerList, Token, StructuredFieldError, parse, serialize

class TestBareItems:
    def test_integer(self):
        assert parse("42", "item").value == 42

    def test_negative_integer(self):
        assert parse("-42", "item").value == -42

    def test_integer_range_max(self):
        assert parse("999999999999999", "item").value == 999999999999999

    def test_integer_too_long_fails(self):
        with pytest.raises(StructuredFieldError):
            parse("9999999999999999", "item")  # 16 digits

    def test_decimal(self):
        assert parse("4.5", "item").value == Decimal("4.5")

    def test_decimal_must_have_fraction(self):
        with pytest.raises(StructuredFieldError):
            parse("4.", "item")

    def test_decimal_max_three_fraction_digits(self):
        with pytest.raises(StructuredFieldError):
            parse("1.2345", "item")

    def test_string(self):
        assert parse('"hello world"', "item").value == "hello world"

    def test_string_escapes(self):
        assert parse('"a\\"b\\\\c"', "item").value == 'a"b\\c'

    def test_string_rejects_unescaped_control(self):
        with pytest.raises(StructuredFieldError):
            parse('"a\tb"', "item")

    def test_string_only_double_quote_delimits(self):
        with pytest.raises(StructuredFieldError):
            parse("'single'", "item")

    def test_token(self):
        v = parse("foo123/456", "item").value
        assert v == "foo123/456"
        assert isinstance(v, Token)

    def test_token_vs_string_type_preserved(self):
        assert isinstance(parse("abc", "item").value, Token)
        assert not isinstance(parse('"abc"', "item").value, Token)

    def test_byte_sequence(self):
        v = parse(":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:", "item").value
        assert v == b"pretend this is binary content."

    def test_boolean_true(self):
        assert parse("?1", "item").value is True

    def test_boolean_false(self):
        assert parse("?0", "item").value is False

class TestLists:
    def test_token_list(self):
        members = parse("sugar, tea, rum", "list")
        assert [m.value for m in members] == ["sugar", "tea", "rum"]

    def test_trailing_comma_fails(self):
        with pytest.raises(StructuredFieldError):
            parse("a, b,", "list")

    def test_inner_lists(self):
        members = parse('("foo" "bar"), ("baz"), ("bat" "one"), ()', "list")
        assert isinstance(members[0], InnerList)
        assert [it.value for it in members[0].items] == ["foo", "bar"]
        assert members[3].items == []  # empty inner list

    def test_parameters_at_both_levels(self):
        members = parse('("foo"; a=1;b=2);lvl=5, ("bar" "baz");lvl=1', "list")
        assert members[0].items[0].params == {"a": 1, "b": 2}
        assert members[0].params == {"lvl": 5}
        assert members[1].params == {"lvl": 1}

class TestDictionaries:
    def test_mixed_dictionary(self):
        d = parse("en=\"Applepie\", da=:w4ZibGV0w6ZydGU=:", "dictionary")
        assert d["en"].value == "Applepie"
        assert isinstance(d["da"].value, bytes)

    def test_boolean_true_omitted_value(self):
        d = parse("a=?0, b, c; foo=bar", "dictionary")
        assert d["a"].value is False
        assert d["b"].value is True
        assert d["c"].value is True
        assert d["c"].params == {"foo": "bar"}

    def test_duplicate_keys_keep_last(self):
        d = parse("a=1, b=2, a=3", "dictionary")
        assert d["a"].value == 3
        assert list(d.keys()) == ["a", "b"]

class TestParameters:
    def test_item_parameters(self):
        item = parse("abc;a=1;b=2; cde_456", "item")
        assert item.value == "abc"
        assert item.params == {"a": 1, "b": 2, "cde_456": True}

class TestSerialization:
    def test_round_trip_list(self):
        assert serialize(parse("sugar, tea, rum", "list")) == "sugar, tea, rum"

    def test_round_trip_inner_list_params(self):
        # Input may include optional whitespace after ";"; the canonical
        # re-serialization (RFC 8941 §4.1.1.2) omits it.
        src = '("foo"; a=1;b=2);lvl=5, ("bar" "baz");lvl=1'
        canonical = '("foo";a=1;b=2);lvl=5, ("bar" "baz");lvl=1'
        assert serialize(parse(src, "list")) == canonical

    def test_round_trip_dictionary(self):
        src = "a=?0, b, c;foo=bar"
        assert serialize(parse(src, "dictionary")) == src

    def test_serialize_string_escapes(self):
        assert sf.serialize_item(Item('a"b\\c')) == '"a\\"b\\\\c"'

    def test_serialize_boolean_param_true_omitted(self):
        assert sf.serialize_item(Item(Token("x"), {"a": True})) == "x;a"

    def test_decimal_rounds_half_even(self):
        # §4.1.5: round to three decimal places, ties to even.
        assert sf.serialize_item(Item(Decimal("1.0005"))) == "1.0"
        assert sf.serialize_item(Item(Decimal("1.0015"))) == "1.002"

    def test_integer_out_of_range_fails(self):
        with pytest.raises(StructuredFieldError):
            sf.serialize_item(Item(10 ** 15))

    def test_empty_list_serializes_empty(self):
        assert serialize([]) == ""
