from ..common import unquote, split_list, split_semicolons

class ETag:
    @staticmethod
    def parse(value: str) -> tuple[bool, str] | None:
        value = value.strip()
        weak = False

        if value.startswith("W/"):
            weak = True
            value = value[2:]

        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            return weak, value

        return None

    @staticmethod
    def strong_match(a: str, b: str) -> bool:
        pa, pb = ETag.parse(a), ETag.parse(b)
        if pa is None or pb is None:
            return False
        return (not pa[0]) and (not pb[0]) and pa[1] == pb[1]

    @staticmethod
    def weak_match(a: str, b: str) -> bool:
        pa, pb = ETag.parse(a), ETag.parse(b)
        if pa is None or pb is None:
            return False
        return pa[1] == pb[1]

class AcceptEncoding:
    @staticmethod
    def parse(value: str) -> dict[str, float]:
        out: dict[str, float] = {}

        for element in split_list(value):
            head, params = AcceptEncoding.parse_params(element)
            head = head.lower()
            if not head:
                continue

            q = 1.0
            if "q" in params:
                try:
                    q = max(0.0, min(1.0, float(params["q"])))
                except (ValueError, TypeError):
                    q = 0.0

            params.pop("q", None)
            out[head] = q

        return out

    @staticmethod
    def parse_params(value: str) -> tuple[str, dict[str, str]]:
        segments = split_semicolons(value)
        head = segments[0].strip()
        params: dict[str, str] = {}

        for seg in segments[1:]:
            seg = seg.strip()
            if not seg:
                continue

            name, eq, raw = seg.partition("=")
            name = name.strip().lower()
            if not name:
                continue

            params[name] = unquote(raw.strip()) if eq else ""

        return head, params
