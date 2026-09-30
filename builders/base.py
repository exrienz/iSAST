"""Base builder primitives.

Every builder produces a BuildPlan whose command is a strict argv list
(blueprint section 15: never raw shell strings).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class BuildPlan:
    """A resolved build execution plan."""

    required: bool
    ecosystem: Optional[str] = None
    command: Optional[List[str]] = None
    language: Optional[str] = None
    manifest_path: Optional[str] = None
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "required": self.required,
            "ecosystem": self.ecosystem,
            "command": list(self.command) if self.command else None,
            "language": self.language,
            "manifest_path": self.manifest_path,
            "reason": self.reason,
        }


class BaseBuilder:
    """Interface for ecosystem-specific build resolvers."""

    ecosystem: str = ""

    def plan(self, manifest_path, source_root):  # pragma: no cover - interface
        raise NotImplementedError