"""
HTTP-date conformance tests (RFC 9110 §5.6.7).

A recipient that parses a timestamp MUST accept all three formats: IMF-fixdate,
the obsolete RFC 850 format, and the asctime() format. Senders generate only
IMF-fixdate. These tests assert the RFC, not Kaede's prior behavior.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from kaede.http.date import parse_http_date, format_http_date, http_date_to_timestamp

# RFC 9110 §5.6.7 gives these three as equivalent representations of the same
# instant: Sunday, November 6, 1994, 08:49:37 GMT.
IMF = "Sun, 06 Nov 1994 08:49:37 GMT"
RFC850 = "Sunday, 06-Nov-94 08:49:37 GMT"
ASCTIME = "Sun Nov  6 08:49:37 1994"

EXPECTED = datetime(1994, 11, 6, 8, 49, 37, tzinfo=timezone.utc)

class TestAcceptThreeFormats:
    def test_imf_fixdate(self):
        assert parse_http_date(IMF) == EXPECTED

    def test_rfc850(self):
        assert parse_http_date(RFC850) == EXPECTED

    def test_asctime(self):
        assert parse_http_date(ASCTIME) == EXPECTED

    def test_all_three_equal(self):
        assert parse_http_date(IMF) == parse_http_date(RFC850) == parse_http_date(ASCTIME)

class TestParsedValueIsUTC:
    def test_timezone_aware_utc(self):
        dt = parse_http_date(IMF)
        assert dt.tzinfo is not None
        assert dt.utcoffset().total_seconds() == 0

class TestRoundTrip:
    def test_format_is_imf_fixdate(self):
        assert format_http_date(EXPECTED) == IMF

    def test_parse_then_format(self):
        assert format_http_date(parse_http_date(RFC850)) == IMF

    def test_format_from_timestamp(self):
        assert format_http_date(EXPECTED.timestamp()) == IMF

    def test_weekday_names_round_trip(self):
        # Every weekday must serialize to the correct three-letter day-name.
        for day in range(1, 8):  # 2024-01-01 is a Monday
            dt = datetime(2024, 1, day, 12, 0, 0, tzinfo=timezone.utc)
            assert parse_http_date(format_http_date(dt)) == dt

class TestTwoDigitYearRule:
    """RFC 9110 §5.6.7: a two-digit year more than 50 years in the future is
    the most recent past year with the same last two digits."""

    def test_recent_past_not_shifted(self):
        # A year a few years in the past stays in the current century.
        now = datetime.now(timezone.utc)
        two = (now.year - 3) % 100
        parsed = parse_http_date(f"Monday, 01-Jan-{two:02d} 00:00:00 GMT")
        assert parsed.year == now.year - 3

    def test_far_future_shifted_to_past(self):
        now = datetime.now(timezone.utc)
        # Construct a two-digit year ~60 years ahead; it must resolve to the past.
        future = now.year + 60
        two = future % 100
        parsed = parse_http_date(f"Monday, 01-Jan-{two:02d} 00:00:00 GMT")
        assert parsed.year <= now.year
        assert parsed.year % 100 == two

class TestRejectsMalformed:
    @pytest.mark.parametrize("value", [
        "",
        "not a date",
        "Sun, 06 Nov 1994 08:49:37",          # missing GMT
        "Sun, 06 Nov 1994 08:49:37 UTC",       # wrong zone token
        "Xxx, 06 Nov 1994 08:49:37 GMT",       # bad day-name
        "Sun, 06 Zzz 1994 08:49:37 GMT",       # bad month
        "Sun, 32 Nov 1994 08:49:37 GMT",       # impossible day
        "Sun, 06 Nov 1994 25:49:37 GMT",       # impossible hour
        "Sun, 6 Nov 1994 08:49:37 GMT",        # day not 2 digits (IMF)
        "Sun, 06 Nov 94 08:49:37 GMT",         # 2-digit year in IMF form
    ])
    def test_invalid(self, value):
        assert parse_http_date(value) is None

class TestTimestampHelper:
    def test_timestamp(self):
        assert http_date_to_timestamp(IMF) == EXPECTED.timestamp()

    def test_timestamp_none_on_invalid(self):
        assert http_date_to_timestamp("garbage") is None
