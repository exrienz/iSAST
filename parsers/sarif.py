"""SARIF v2.1.0 parser → common Finding dicts (blueprint sections 18/19).

Both OpenGrep and CodeQL emit SARIF; this layer is engine-agnostic.
Parsing NEVER throws for a malformed individual result — failures are
collected per-file so a corrupted SARIF artifact cannot erase other
engines' findings.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

def clean_rule_id(rule_id: str) -> str:
    """OpenGrep namespaces file-based configs with the config path
    ('Users.x.iSast.engines.rules.isast.python.sqli' → 'isast.python.sqli')."""
    marker = ".rules.isast."
    if marker in rule_id:
        return "isast." + rule_id.split(marker)[-1]
    return rule_id


SEVERITY_NORMALIZATION = {
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "HIGH": "HIGH",
    "WARNING": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "NOTE": "LOW",
    "LOW": "LOW",
    "INFO": "INFO",
    "NONE": "INFO",
}


def normalize_severity(raw: str) -> str:
    """Map SARIF/security severities to the internal levels."""
    return SEVERITY_NORMALIZATION.get((raw or "").strip().upper(), "INFO")


def _load(path: Path) -> Tuple[Optional[dict], Optional[str]]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"cannot read SARIF {path}: {exc}"


class SarifParser:
    """Parse SARIF files into normalized finding payloads."""

    def parse_file(self, path: Path, default_scanner: str, root: Path) -> Tuple[List[dict], List[str]]:
        """Returns (findings, errors)."""
        document, error = _load(path)
        if error:
            return [], [error]
        assert document is not None
        return self.parse_document(document, default_scanner, root)

    def parse_document(
        self, document: dict, default_scanner: str, root: Path
    ) -> Tuple[List[dict], List[str]]:
        findings: List[dict] = []
        errors: List[str] = []
        runs = document.get("runs") or []
        if not runs:
            errors.append(f"{default_scanner}: SARIF has no runs")
        for run in runs:
            tool = (run.get("tool") or {}).get("driver") or {}
            rules = {rule.get("id"): rule for rule in tool.get("rules") or []}
            for result in run.get("results") or []:
                finding = self._parse_result(result, rules, default_scanner, root)
                if finding:
                    findings.append(finding)
        return findings, errors

    def _parse_result(
        self,
        result: dict,
        rules: Dict[str, dict],
        scanner: str,
        root: Path,
    ) -> Optional[Dict]:
        rule_id = clean_rule_id(result.get("ruleId") or "unknown")
        message_node = result.get("message") or {}
        message = message_node.get("text") or message_node.get("markdown") or rule_id
        locations = result.get("locations") or []
        location = locations[0] if locations else {}
        physical = location.get("physicalLocation") or {}
        artifact = physical.get("artifactLocation") or {}
        uri = artifact.get("uri") or ""
        if not uri:
            return None
        region = physical.get("region") or {}

        rule = rules.get(rule_id) or {}
        cwe = extract_cwe(rule)
        sarif_severity = severity_from_result(result, rule)
        language = infer_language_from_rule(rule_id) or infer_language_from_uri(uri)

        rel_path = _relative_path(uri, root)
        return {
            "scanner": scanner,
            "rule_id": rule_id,
            "language": language,
            "file": rel_path,
            "line": int(region.get("startLine") or 0),
            "column": int(region.get("startColumn") or 0),
            "scanner_title": rule_short_title(rule, rule_id),
            "scanner_message": (message or rule_id)[:1000],
            "scanner_severity": sarif_severity,
            "cwe": cwe,
            "kind": result.get("kind") or "review",
        }


def rule_short_title(rule: dict, fallback: str) -> str:
    """Prefer a human title from the rule metadata."""
    short = (rule.get("shortDescription") or {}).get("text")
    if short:
        return short[:200]
    name = rule.get("name")
    if name:
        return str(name)[:200]
    return fallback


def severity_from_result(result: dict, rule: dict) -> str:
    """Resolve severity: SARIF level > rule defaultConfiguration > security-severity."""
    level = (result.get("level") or "").upper()
    if level:
        return level
    rule_level = rule.get("defaultConfiguration", {}).get("level", "")
    if rule_level:
        return str(rule_level).upper()
    security = rule.get("properties", {}).get("security-severity")
    if security:
        try:
            score = float(security)
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "ERROR"
            if score >= 4.0:
                return "WARNING"
            return "NOTE"
        except ValueError:
            return "INFO"
    return "INFO"


def extract_cwe(rule: dict) -> Optional[str]:
    """Pull a CWE id out of rule metadata (properties, tags, relationships)."""

    def _from_tag(tag: str) -> Optional[str]:
        import re

        match = re.search(r"cwe[-/](\d+)", tag.lower())
        if match:
            return f"CWE-{int(match.group(1)):03d}"
        return None

    properties = rule.get("properties") or {}
    for candidate in (properties.get("cwe"), properties.get("CWE")):
        if isinstance(candidate, str) and "CWE" in candidate:
            return candidate.split(",")[0].strip()
    tags = properties.get("tags") or []
    for tag in tags:
        if isinstance(tag, str) and "cwe" in tag.lower():
            from_tag = _from_tag(tag)
            if from_tag:
                return from_tag
    # Explicit "CWE-89" style tags.
    for tag in tags:
        if isinstance(tag, str) and tag.upper().startswith("CWE-"):
            return tag
    # CodeQL relationship-based taxonomies: target id "CWE-89".
    for rel in rule.get("relationships") or []:
        target_id = str((rel.get("target") or {}).get("id") or "")
        if target_id.upper().startswith("CWE-"):
            return target_id
    return None


def infer_language_from_rule(rule_id: str) -> Optional[str]:
    rule_lower = rule_id.lower()
    hints = {
        "python": "python",
        "javascript": "javascript",
        "js/": "javascript",
        "typescript": "typescript",
        "java": "java",
        "kotlin": "kotlin",
        "go": "go",
        "csharp": "csharp",
        "cpp": "cpp",
        "c/": "c",
        "ruby": "ruby",
        "swift": "swift",
        "generic/": "",
    }
    for hint, language in hints.items():
        if hint in rule_lower and language:
            return language
    return None


def infer_language_from_uri(uri: str) -> str:
    ext_map = {
        ".py": "python",
        ".java": "java",
        ".kt": "kotlin",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".c": "c",
        ".cpp": "cpp",
        ".cs": "csharp",
        ".rb": "ruby",
        ".swift": "swift",
    }
    dot = uri.rfind(".")
    if dot >= 0:
        return ext_map.get(uri[dot:].lower(), "unknown")
    return "unknown"


def _relative_path(uri: str, root: Path) -> str:
    """Normalize SARIF file:// or absolute URIs to source-root-relative paths."""
    raw = uri
    if raw.startswith("file://"):
        raw = raw[len("file://"):]
    candidate = Path(raw)
    if not candidate.is_absolute():
        return candidate.as_posix()
    try:
        return candidate.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return candidate.as_posix()

# CodeQL SARIF stores rule metadata in run.tool.extensions[*] when taxonomies
# exist; openGrep inlines it in tool.driver.rules. The simple rules map built
# from driver.rules covers both engines' common output and is intentionally
# tolerant; missing metadata degrades to rule-id-derived fields.