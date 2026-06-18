from __future__ import annotations

from datetime import datetime, timezone

# RFC 9110 §5.6.7: HTTP-date. Three formats must be accepted on input
# (IMF-fixdate, the obsolete RFC 850 format, and asctime). Output is always
# IMF-fixdate. The literal day/month/"GMT" tokens are case-sensitive.

DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
DAY_NAMES_LONG = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

_MONTHS: dict[str, int] = {name: i + 1 for i, name in enumerate(MONTH_NAMES)}

def _parse_time(token: str) -> tuple[int, int, int] | None:
    parts = token.split(":")
    if len(parts) != 3:
        return None
    if not all(len(p) == 2 and p.isdigit() for p in parts):
        return None

    hour, minute, second = int(parts[0]), int(parts[1]), int(parts[2])
    if hour > 23 or minute > 59 or second > 60:
        return None

    return hour, minute, second

def _build(year: int, month: int, day: int, hour: int, minute: int, second: int) -> datetime | None:
    if second == 60:  # leap second; datetime cannot represent it
        second = 59
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None

def _expand_two_digit_year(two: int) -> int:
    # RFC 9110 §5.6.7: a two-digit year that appears to be more than 50 years
    # in the future is the most recent past year with the same last two digits.
    now = datetime.now(timezone.utc).year
    year = now - (now % 100) + two
    while year > now + 50:
        year -= 100
    return year

def _parse_imf_fixdate(rest: str) -> datetime | None:
    parts = rest.split(" ")
    if len(parts) != 5 or parts[4] != "GMT":
        return None

    day_s, month_s, year_s, time_s, _ = parts
    if len(day_s) != 2 or not day_s.isdigit() or len(year_s) != 4 or not year_s.isdigit():
        return None

    month = _MONTHS.get(month_s)
    tod = _parse_time(time_s)
    if month is None or tod is None:
        return None

    return _build(int(year_s), month, int(day_s), *tod)

def _parse_rfc850(rest: str) -> datetime | None:
    parts = rest.split(" ")
    if len(parts) != 3 or parts[2] != "GMT":
        return None

    date2, time_s, _ = parts
    date_parts = date2.split("-")
    if len(date_parts) != 3:
        return None

    day_s, month_s, year_s = date_parts
    if len(day_s) != 2 or not day_s.isdigit() or len(year_s) != 2 or not year_s.isdigit():
        return None

    month = _MONTHS.get(month_s)
    tod = _parse_time(time_s)
    if month is None or tod is None:
        return None

    return _build(_expand_two_digit_year(int(year_s)), month, int(day_s), *tod)

def _parse_asctime(value: str) -> datetime | None:
    # date3 uses either "2DIGIT" or "SP 1DIGIT" for the day; splitting on runs
    # of whitespace collapses the padding, yielding five tokens.
    parts = value.split()
    if len(parts) != 5:
        return None

    day_name, month_s, day_s, time_s, year_s = parts
    if day_name not in DAY_NAMES:
        return None
    if not (1 <= len(day_s) <= 2) or not day_s.isdigit():
        return None
    if len(year_s) != 4 or not year_s.isdigit():
        return None

    month = _MONTHS.get(month_s)
    tod = _parse_time(time_s)
    if month is None or tod is None:
        return None

    return _build(int(year_s), month, int(day_s), *tod)

def parse_http_date(value: str) -> datetime | None:
    """Parse an HTTP-date in any of the three RFC 9110 §5.6.7 formats.

    Returns a timezone-aware UTC datetime, or None if the value is not a
    well-formed HTTP-date.
    """
    if not value:
        return None
    value = value.strip()

    comma = value.find(",")
    if comma == -1:
        return _parse_asctime(value)

    day_name = value[:comma]
    rest = value[comma + 1:]
    if not rest.startswith(" "):
        return None
    rest = rest[1:]

    if day_name in DAY_NAMES_LONG:
        return _parse_rfc850(rest)
    if day_name in DAY_NAMES:
        # The short day-name is shared by IMF-fixdate and (rarely) appears with
        # a dash-delimited date2; disambiguate on the date separator.
        head = rest.split(" ", 1)[0]
        if "-" in head:
            return _parse_rfc850(rest)
        return _parse_imf_fixdate(rest)
    return None

def format_http_date(when: datetime | float | int | None = None) -> str:
    """Format a timestamp as an IMF-fixdate (RFC 9110 §5.6.7), e.g.
    "Sun, 06 Nov 1994 08:49:37 GMT". Accepts a datetime, a POSIX timestamp,
    or None (meaning "now")."""
    if when is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(when, (int, float)):
        dt = datetime.fromtimestamp(when, tz=timezone.utc)
    else:
        dt = when.astimezone(timezone.utc)

    return "%s, %02d %s %04d %02d:%02d:%02d GMT" % (
        DAY_NAMES[dt.weekday()],
        dt.day,
        MONTH_NAMES[dt.month - 1],
        dt.year,
        dt.hour,
        dt.minute,
        dt.second,
    )

def http_date_to_timestamp(value: str) -> float | None:
    """Parse an HTTP-date and return POSIX seconds (UTC), or None."""
    dt = parse_http_date(value)
    return dt.timestamp() if dt is not None else None
