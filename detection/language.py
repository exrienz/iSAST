"""Language detection from source extensions with LOC counting
(blueprint sections 11 and 12)."""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

from core.models import LanguageInfo

DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "coverage",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".idea",
    ".vscode",
    "Pods",
}

EXTENSION_MAP: Dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hppx": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
}

# Languages CodeQL can extract without executing the project build.
CODEQL_SOURCE_ONLY = {"python", "javascript", "typescript", "go", "ruby", "html", "cpp"}
CODEQL_SUPPORT = {
    "python": "python",
    "javascript": "javascript-typescript",
    "typescript": "javascript-typescript",
    "java": "java-kotlin",
    "kotlin": "java-kotlin",
    "go": "go",
    "csharp": "csharp",
    "c": "c-cpp",
    "cpp": "c-cpp",
    "ruby": "ruby",
    "swift": "swift",
}

MAX_SCAN_FILE_SIZE = 20 * 1024 * 1024


def iter_source_files(root: Path, excluded: Optional[set] = None) -> List[Path]:
    """Walk the tree, skipping excluded/hidden/build directories."""
    skip = set(excluded) if excluded else set(DEFAULT_EXCLUDED_DIRS)
    files: List[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in skip or entry.name.startswith("."):
                        continue
                    stack.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    files.append(Path(entry.path))
            except OSError:
                continue
    return files


def _count_lines(path: Path) -> int:
    """Count source lines, tolerating a missing trailing newline."""
    try:
        if path.stat().st_size > MAX_SCAN_FILE_SIZE:
            return 0
        with path.open("rb") as handle:
            data = handle.read()
    except OSError:
        return 0
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)


class LanguageDetector:
    """Detect languages and LOC from the source tree."""

    def detect(self, source_root: Path, excluded: Optional[set] = None) -> List[LanguageInfo]:
        source_root = Path(source_root).resolve()
        if not source_root.exists():
            return []
        loc_by_language: Dict[str, int] = Counter()
        for path in iter_source_files(source_root, excluded):
            language = EXTENSION_MAP.get(path.suffix.lower())
            if language:
                loc_by_language[language] += _count_lines(path)
        languages = [
            LanguageInfo(name=name, loc=loc)
            for name, loc in sorted(loc_by_language.items(), key=lambda kv: -kv[1])
        ]
        return languages


def codeql_language_for(name: str) -> Optional[str]:
    """Map an internal language name to CodeQL's --language flag value."""
    return CODEQL_SUPPORT.get(name)


def codeql_source_only_language(name: str) -> bool:
    """True when CodeQL does not need the project build for this language."""
    return name in CODEQL_SOURCE_ONLY