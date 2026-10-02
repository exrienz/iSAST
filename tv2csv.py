#!/usr/bin/env python3
"""
tv2csv.py — Fetch ThreatVault findings from the export API and convert to CSV.

Produces output in the exact format of ProjectPulsev2-finalx.csv (ThreatVault
VAPT schema, every field quoted, CRLF line endings, multi-line evidence
preserved inside quoted fields):

    cve, risk, host, port, name, description, remediation, evidence, vpr_score

Equivalent curl:
    curl -X 'GET' \\
      'http://localhost:8000/api/v2/findings/export?product_id=...&plugin_id=...&label=...&status=NEW,OPEN' \\
      -H 'accept: */*' \\
      -H 'Authorization: <token>'

Usage:
    python tv2csv.py --pluginid=82335b52-... --productid=ec4faa05-... \
        --label=projectpulse/v2:master --output=xxxx.csv

    Optional:
        --status=NEW,OPEN        (default: NEW,OPEN)
        --url=http://localhost:8000
        --token=<token>        (or THREATVAULT_KEY env var / .env)

Auth token resolution order: --token flag > THREATVAULT_KEY env var > THREATVAULT_KEY in .env.
Create a .env file next to this script (or in the working directory):

    THREATVAULT_BASEURL=http://localhost:8000
    THREATVAULT_KEY=<token>

.env is git-ignored and holds only the ThreatVault settings.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import polars as pl

VAULT_SCHEMA = [
    "cve",
    "risk",
    "host",
    "port",
    "name",
    "description",
    "remediation",
    "evidence",
    "vpr_score",
]

VALID_RISKS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

THREATVAULT_BASEURL = "http://localhost:8000"
DEFAULT_ENDPOINT = "/api/v2/findings/export"
DEFAULT_STATUS = "NEW,OPEN"


# ---------------------------------------------------------------------------
# HTTP fetch
# ---------------------------------------------------------------------------

def _load_env() -> None:
    """
    Populate os.environ from .env files without overriding variables already
    set in the environment. Checked in order: script directory, then cwd.
    Supports KEY=VALUE lines, comments (#) and surrounding quotes.
    """
    for directory in (os.path.dirname(os.path.abspath(__file__)), os.getcwd()):
        path = os.path.join(directory, ".env")
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                value = value.strip().strip("\"'")
                if not value.strip():
                    continue  # empty entry must not shadow a real value elsewhere
                os.environ.setdefault(key.strip(), value)


def _token(token: str | None) -> str:
    """Resolve the API token from the flag, THREATVAULT_KEY env var, or .env file."""
    _load_env()
    value = token or os.environ.get("THREATVAULT_KEY", "").strip()
    if not value:
        raise SystemExit(
            "Missing API token. Pass --token=..., export THREATVAULT_KEY=<token>, "
            "or add THREATVAULT_KEY=<token> to .env next to tv2csv.py"
        )
    return value


def _baseurl() -> str:
    """Resolve the base URL from the THREATVAULT_BASEURL env var or .env file."""
    _load_env()
    return os.environ.get("THREATVAULT_BASEURL", "").strip() or THREATVAULT_BASEURL


def fetch(
    url: str,
    token: str,
    page: int | None = None,
    timeout: int = 30,
) -> tuple[bytes, str]:
    """
    GET the export endpoint and return (response body, content type).

    Args:
        url: Fully-encoded export URL with query string
        token: Authorization token (sent raw, matching the curl example)
        page: Optional page number appended for paginated JSON APIs
        timeout: Request timeout in seconds

    Raises:
        SystemExit: On any non-2xx response or connection error
    """
    request_url = url
    if page is not None:
        request_url = f"{url}&page={page}"

    req = urllib.request.Request(
        request_url,
        headers={
            "accept": "*/*",
            "Authorization": token,
            "User-Agent": "tv2csv/1.0",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return body, resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:500]
        raise SystemExit(f"HTTP {exc.code} from {request_url}: {detail}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"Could not reach {request_url}: {exc.reason}")


def fetch_all(url: str, token: str, timeout: int = 30) -> tuple[bytes, str]:
    """
    Fetch the export endpoint, following pagination if the JSON response
    advertises a 'next' page (DefectDojo-style). Returns the concatenated
    JSON bytes ('{"results": [...], "next": ...}' merged) or the raw body
    for non-paginated responses.
    """
    body, content_type = fetch(url, token, timeout=timeout)

    if "json" not in content_type.lower() and "text" not in content_type.lower():
        return body, content_type

    try:
        first = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return body, content_type

    if not isinstance(first, dict) or "next" not in first:
        return body, content_type

    results: list[Any] = list(first.get("results") or [])
    nxt = first.get("next")
    while nxt:
        page_url = nxt if isinstance(nxt, str) else None
        page_no = int(
            urllib.parse.parse_qs(urllib.parse.urlparse(page_url).query).get("page", [0])[0]
        )
        body, _ct = fetch(url, token, page=page_no or None, timeout=timeout)
        chunk = json.loads(body)
        results.extend(chunk.get("results") or [])
        nxt = chunk.get("next") if isinstance(chunk, dict) else None

    merged = json.dumps({"results": results}).encode()
    return merged, "application/json"


# ---------------------------------------------------------------------------
# Parsing: API response -> raw rows
# ---------------------------------------------------------------------------

# JSON field candidates per ThreatVault column, in priority order
FIELD_CANDIDATES = {
    "cve": ["cve", "cve_id", "vulnerability_id", "vuln_id"],
    "risk": ["risk", "severity"],
    "host": ["host", "hostname", "target", "project", "repository"],
    "port": ["port"],
    "name": ["name", "title", "finding_name"],
    "description": ["description"],
    "remediation": ["remediation", "mitigation", "fix", "recommendation"],
    "evidence": ["evidence"],
    "vpr_score": ["vpr_score", "vpr", "vulnerability_priority_rating"],
}


def _extract(row: dict, column: str) -> str:
    """Pull the first matching candidate field out of a finding dict."""
    for key in FIELD_CANDIDATES[column]:
        value = row.get(key)
        if value is not None and value != "":
            if isinstance(value, (dict, list)):
                # Empty containers (e.g. cve returned as []) mean no data —
                # fall through to the next candidate instead of "[]"
                serialized = json.dumps(value)
                if serialized in ("[]", "{}"):
                    continue
                value = serialized
            return str(value)
    return ""


def parse_json(body: bytes) -> list[dict[str, str]]:
    """
    Convert a JSON findings response into raw rows keyed by the ThreatVault
    columns. Handles list responses, {'results': [...]} and {'data': [...]}.
    """
    data = json.loads(body)
    if isinstance(data, dict):
        for key in ("results", "data", "findings", "items"):
            if isinstance(data.get(key), list):
                data = data[key]
                break

    if not isinstance(data, list):
        raise SystemExit(
            "Unexpected JSON structure from export API; expected a list of findings "
            f"(got top-level {type(data).__name__})"
        )

    rows = []
    for item in data:
        if not isinstance(item, dict):
            continue
        row = {col: _extract(item, col) for col in VAULT_SCHEMA}
        rows.append(row)
    return rows


def parse_csv(body: bytes) -> list[dict[str, str]]:
    """
    Parse a CSV export into raw rows keyed by the ThreatVault columns.
    Handles the UTF-8 BOM and normalizes header names (lowercase).
    """
    if body.startswith(b"\xef\xbb\xbf"):
        body = body[3:]

    df = pl.read_csv(body, infer_schema_length=0, truncate_ragged_lines=True)
    df = df.rename({c: c.strip().strip('"').lower() for c in df.columns})

    missing = set(VAULT_SCHEMA) - set(df.columns)
    if missing:
        raise SystemExit(
            f"CSV export is missing required columns: {', '.join(sorted(missing))}. "
            f"Found columns: {', '.join(df.columns)}"
        )

    return df.select(VAULT_SCHEMA).to_dicts()


def parse_response(body: bytes, content_type: str) -> list[dict[str, str]]:
    """Dispatch to the JSON or CSV parser based on the response content type."""
    ctype = content_type.lower()
    if "csv" in ctype:
        return parse_csv(body)
    if "json" in ctype:
        return parse_json(body)

    # Ambiguous content type ('text/plain', '*/*' echo, missing) — sniff it
    head = body[:256].lstrip()
    if head.startswith((b"[", b"{")):
        return parse_json(body)
    return parse_csv(body)


# ---------------------------------------------------------------------------
# Normalization: raw rows -> ThreatVault VAPT schema (mirrors isast.py)
# ---------------------------------------------------------------------------

def normalize(rows: list[dict[str, str]]) -> pl.DataFrame:
    """
    Normalize raw rows to the ThreatVault VAPT schema, matching the style of
    ProjectPulsev2-finalx.csv: risk uppercased, invalid-risk rows dropped,
    numeric ports cast to int (empty ports kept empty), text fields trimmed,
    and multi-line content preserved as raw newlines inside quoted fields.
    """
    df = pl.DataFrame(rows, schema=VAULT_SCHEMA, strict=False)

    text_fields = ["cve", "host", "name", "description", "remediation", "evidence", "vpr_score"]

    df = (
        df
        # Normalize text fields: fill nulls, trim surrounding whitespace
        .with_columns([
            pl.col(c).fill_null("").cast(pl.String).str.strip_chars()
            for c in text_fields
        ])
        # Normalize risk to the expected CRITICAL/HIGH/MEDIUM/LOW values
        .with_columns(
            pl.col("risk").fill_null("").cast(pl.String).str.strip_chars().str.to_uppercase()
        )
        # Drop rows with an invalid or missing risk value
        .filter(pl.col("risk").is_in(VALID_RISKS))
        # Cast port to int when numeric; non-numeric/empty ports are preserved
        # as-is (e.g. "" stays "" like in ProjectPulsev2-finalx.csv).
        # Port 0 means "no port" for SAST findings — emit "" like the expected
        # ProjectPulsev2-finalx.csv style
        .with_columns(
            pl.col("port").cast(pl.Int64, strict=False).cast(pl.String).fill_null("")
        )
        .with_columns(
            pl.when(pl.col("port") == "0").then(pl.lit("")).otherwise(pl.col("port")).alias("port")
        )
        # The stored findings were ingested through isast.py, which converts
        # newlines to <br/> at upload time. Invert that so evidence /
        # description / remediation keep real multi-line quoted fields like
        # ProjectPulsev2-finalx.csv. Replace double breaks first so blank
        # lines come back as "\n\n" instead of two single breaks
        .with_columns([
            pl.col(c)
            .str.replace_all("<br/><br/>", "\n\n")
            .str.replace_all("<br/>", "\n")
            for c in ("description", "remediation", "evidence")
        ])
        # Note: newlines inside description/remediation/evidence are kept raw
        # (multi-line quoted fields), matching ProjectPulsev2-finalx.csv style
        # Emit columns in the exact ThreatVault schema order
        .select(VAULT_SCHEMA)
    )

    return df


def write_output(df: pl.DataFrame, path: str) -> None:
    """
    Write the normalized findings to CSV in the same style as
    ProjectPulsev2-finalx.csv: every field quoted, CRLF line endings.

    Handles both polars API spellings: 'line_terminator' (newer) and
    'eol' (older versions). Prepends the UTF-8 BOM like
    ProjectPulsev2-finalx.csv (Excel-style export).
    """
    try:
        df.write_csv(path, quote_style="always", line_terminator="\r\n")
    except TypeError:
        df.write_csv(path, quote_style="always", eol="\r\n")

    with open(path, "rb") as fh:
        body = fh.read()
    if not body.startswith(b"\xef\xbb\xbf"):
        with open(path, "wb") as fh:
            fh.write(b"\xef\xbb\xbf" + body)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_url(args: argparse.Namespace) -> str:
    """Compose the fully-encoded export URL from base URL + query params."""
    params = {
        "product_id": args.productid,
        "plugin_id": args.pluginid,
        "label": args.label,
        "status": args.status,
    }
    query = urllib.parse.urlencode(params)
    base = args.url.rstrip("/")
    return f"{base}/{DEFAULT_ENDPOINT.lstrip('/')}?{query}"


def main() -> int:
    baseurl = _baseurl()
    parser = argparse.ArgumentParser(
        description="Fetch ThreatVault findings export and convert to ThreatVault CSV."
    )
    parser.add_argument("--pluginid", required=True, help="plugin_id filter (required)")
    parser.add_argument("--productid", required=True, help="product_id filter (required)")
    parser.add_argument("--label", required=True, help="label filter, e.g. projectpulse/v2:master (required)")
    parser.add_argument("--output", required=True, help="Output CSV path (e.g. xxxx.csv)")
    parser.add_argument("--url", default=baseurl, help=f"Base URL (default: {baseurl})")
    parser.add_argument("--token", default=None, help="API token (or set THREATVAULT_KEY env var / .env)")
    parser.add_argument("--status", default=DEFAULT_STATUS, help="Comma-separated status filter (default: NEW,OPEN)")
    args = parser.parse_args()

    token = _token(args.token)
    url = build_url(args)

    print(f"GET {url}")
    body, content_type = fetch_all(url, token)
    print(f"Received {len(body)} bytes ({content_type or 'unknown content type'})")

    rows = parse_response(body, content_type)
    if not rows:
        raise SystemExit("No findings returned by the export API.")

    df = normalize(rows)
    write_output(df, args.output)
    print(f"Wrote {df.height} findings to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())