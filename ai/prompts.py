"""Prompt templates (blueprint sections 22-26).

Hard anti-hallucination rules (section 24) are embedded in every prompt:
never invent code behavior, never claim exploitation without evidence,
never invent files/functions, never change scanner evidence, and say
INSUFFICIENT_EVIDENCE when the evidence is thin.
"""

SYSTEM_VALIDATION = """You are iSAST, a senior static analysis finding reviewer.
You review findings produced by SAST scanners (OpenGrep, CodeQL) against real code.

STRICT RULES:
- Never invent code behavior.
- Never claim exploitation without evidence in the provided code.
- Never invent a vulnerable data flow.
- Never invent files or functions that are not shown.
- Never change scanner evidence; report what is present.
- If evidence is insufficient, say so (status INSUFFICIENT_EVIDENCE).

OUTPUT: a single JSON object, no prose, matching the requested schema exactly.
"""

SYSTEM_DEDUP = """You are iSAST's duplicate detector. You receive a group of SAST
findings (possibly from different scanners/rule ids) and decide which describe
the SAME underlying vulnerability (same source/sink pair at the same location).

STRICT RULES:
- Merge findings only with strong evidence: same file, same sink, same flow.
- Never merge findings merely because rule names look similar.
- When in doubt, do not merge: report them as separate.

OUTPUT: a single JSON object, no prose.
"""

VALIDATION_SCHEMA_EXAMPLE = """{
  "results": [
    {
      "finding_id": "abc12345",
      "validation": {
        "status": "CONFIRMED|LIKELY|INSUFFICIENT_EVIDENCE|FALSE_POSITIVE",
        "confidence": 0.0-1.0,
        "reason": "one or two sentences grounded in the shown code only"
      },
      "canonical": {
        "title": "short canonical name, e.g. 'SQL Injection'",
        "category": "e.g. Injection",
        "cwe": "CWE-89 (only when justified)",
        "owasp": "A03:2021-Injection (only when justified)"
      },
      "risk": {
        "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
        "exploitability": "HIGH|MEDIUM|LOW",
        "impact": "HIGH|MEDIUM|LOW"
      },
      "description": "professional 2-3 sentence description grounded ONLY in shown evidence",
      "recommendation": "concrete remediation advice"
    }
  ]
}
"""


def build_validation_payload(group_finding: dict) -> str:
    """Render one candidate-group representative as the user prompt."""
    code_context = group_finding.get("code_context") or {}
    lines = [
        "Analyze this SAST finding. Return the JSON object described in the schema.",
        "",
        f"finding_id: {group_finding.get('finding_id', '')}",
        f"scanner: {group_finding.get('scanner', '')}",
        f"language: {group_finding.get('language', '')}",
        f"rule_id: {group_finding.get('rule_id', '')}",
        f"file: {group_finding.get('file', '')}",
        f"line: {group_finding.get('line', '')}",
        f"scanner_severity: {group_finding.get('scanner_severity', '')}",
        f"scanner_message: {group_finding.get('scanner_message', '')}",
        "",
        "code_context:",
        f"before:\n{code_context.get('before', '')}",
        f"target:\n{code_context.get('target', '')}",
        f"after:\n{code_context.get('after', '')}",
    ]
    return "\n".join(lines)


def schema_reminder() -> str:
    return (
        VALIDATION_SCHEMA_EXAMPLE
        + "\nIMPORTANT: output complete valid JSON only — keep reason/description/recommendation concise (max 300 characters each) so the reply never gets cut off before closing braces."
    )


def build_dedup_payload(members: List[dict]) -> str:
    """Render a candidate group of findings for dedup decision."""
    lines = [
        "Decide which of these findings describe the SAME underlying vulnerability.",
        "Return JSON:",
        '{"duplicates": [{"canonical_finding_id": "<id>", "duplicates": ["<id>", "<id>"]}], "reason": "short basis"}',
        "Every finding id you received must appear exactly once in the output group ids.",
        "",
        "findings:",
    ]
    for member in members:
        lines.append(
            "- id={id} scanner={scanner} rule_id={rule_id} file={file} line={line} "
            "message={message}".format(
                id=member.get("finding_id", "")[:8],
                scanner=member.get("scanner", ""),
                rule_id=member.get("rule_id", ""),
                file=member.get("file", ""),
                line=member.get("line", ""),
                message=(member.get("scanner_message") or "")[:160],
            )
        )
    return "\n".join(lines)