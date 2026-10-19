"""Git diff parser and changed file extractor."""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class ChangedFile:
    file_path: str
    added_lines: List[int] = field(default_factory=list)
    raw_hunks: List[str] = field(default_factory=list)


def parse_unified_diff(diff_text: str) -> Dict[str, ChangedFile]:
    """Parse a unified git diff into changed files with line numbers and patch hunks."""
    files: Dict[str, ChangedFile] = {}
    current_file = None
    current_line = 0

    lines = diff_text.splitlines()
    for line in lines:
        if line.startswith("diff --git"):
            match = re.search(r"b/(.+)$", line)
            if match:
                current_file = match.group(1)
                files[current_file] = ChangedFile(file_path=current_file)
        elif line.startswith("+++ b/"):
            current_file = line[6:].strip()
            if current_file not in files:
                files[current_file] = ChangedFile(file_path=current_file)
        elif line.startswith("@@"):
            # Parse @@ -a,b +c,d @@
            hunk_match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if hunk_match and current_file:
                current_line = int(hunk_match.group(1))
                files[current_file].raw_hunks.append(line)
        elif line.startswith("+") and not line.startswith("+++"):
            if current_file and current_file in files:
                files[current_file].added_lines.append(current_line)
            current_line += 1
        elif not line.startswith("-"):
            current_line += 1

    return files


def extract_changed_filenames(diff_text: str) -> Set[str]:
    """Extract set of relative file paths modified in the diff."""
    return set(parse_unified_diff(diff_text).keys())
