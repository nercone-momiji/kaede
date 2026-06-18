"""
Generic HTTP field-value parsing tests (RFC 9110 §5.6, §12.4).

The compliance-critical behavior is that quoted-strings are honored: a comma or
semicolon inside DQUOTEs is data, not a delimiter. Tests assert the RFC.
"""
from __future__ import annotations

from kaede.http.fields import split_list, unquote, parse_parameters, parse_qlist, parse_qvalue, is_token

class TestSplitList:
    def test_simple(self):
        assert split_list("a, b, c") == ["a", "b", "c"]

    def test_drops_empty_elements(self):
        # RFC 9110 §5.6.1: empty list elements are ignored.
        assert split_list("a,, b, ,c,") == ["a", "b", "c"]

    def test_comma_inside_quotes_is_data(self):
        # An entity-tag or quoted value may contain a comma.
        assert split_list('"a,b", "c"') == ['"a,b"', '"c"']

    def test_escaped_quote_inside_quotes(self):
        assert split_list('"a\\",b", "c"') == ['"a\\",b"', '"c"']

    def test_empty_string(self):
        assert split_list("") == []

class TestUnquote:
    def test_plain_quoted(self):
        assert unquote('"hello"') == "hello"

    def test_escaped(self):
        assert unquote('"a\\"b"') == 'a"b'

    def test_token_unchanged(self):
        assert unquote("token") == "token"

class TestParseParameters:
    def test_head_and_params(self):
        head, params = parse_parameters("text/html; charset=utf-8; q=0.8")
        assert head == "text/html"
        assert params == {"charset": "utf-8", "q": "0.8"}

    def test_quoted_param_value(self):
        head, params = parse_parameters('form-data; name="a;b"')
        assert head == "form-data"
        assert params == {"name": "a;b"}

    def test_param_name_lowercased(self):
        _, params = parse_parameters("x; Charset=UTF-8")
        assert params == {"charset": "UTF-8"}

class TestParseQList:
    def test_accept_encoding(self):
        result = parse_qlist("gzip, br;q=0.5, *;q=0")
        assert result == [("gzip", 1.0, {}), ("br", 0.5, {}), ("*", 0.0, {})]

    def test_q_clamped(self):
        assert parse_qlist("a;q=5")[0][1] == 1.0
        assert parse_qlist("a;q=-1")[0][1] == 0.0

    def test_default_q_is_one(self):
        assert parse_qlist("deflate")[0][1] == 1.0

class TestQValue:
    def test_parse(self):
        assert parse_qvalue("0.7") == 0.7

    def test_invalid_is_zero(self):
        assert parse_qvalue("abc") == 0.0

class TestIsToken:
    def test_valid(self):
        assert is_token("gzip")

    def test_invalid(self):
        assert not is_token("a b")
        assert not is_token("")
