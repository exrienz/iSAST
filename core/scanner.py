"""core.scanner: the full 8-stage scan orchestration (blueprint section 32).

Stages:
  1 dependencies  2 source validation  3 project detection
  4 OpenGrep      5 CodeQL             6 normalization/fingerprint/grouping
  7 AI analysis   8 reports (final.csv, raw-findings.json)
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ai.analyzer import AIAnalyzer
from ai.checkpoint import AICheckpoint
from ai.error_report import summarize_ai_errors
from ai.progress import AIDashboard
from ai.provider import AIConfig
from core.dependency import DependencyManager, DependencyError
from core.executor import ExecutorError
from core.models import (
    CanonicalFinding,
    DetectionResult,
    Finding,
    LanguageInfo,
    ScanStats,
    ValidationStatus,
)
from core.workspace import ScanWorkspace, WorkspaceError, find_resumable
from detection.build import BuildResolver
from detection.language import CODEQL_SUPPORT, LanguageDetector
from detection.manifest import ManifestDetector
from engines.codeql import CodeqlEngine
from engines.opengrep import OpenGrepEngine
from findings.grouping import CandidateGrouper
from findings.normalizer import FindingNormalizer
from output.csv import CSVWriter
from output.json import JSONWriter, findings_payload
from parsers.sarif import SarifParser
from core.textclamp import clamp_text
from sandbox.manager import SandboxManager

# Language → primary manifest ecosystem when several manifests exist.
_PRIMARY_ECOSYSTEM = {
    "python": "pip",
    "javascript": "npm",
    "typescript": "npm",
    "java": "maven",
    "kotlin": "maven",
    "go": "go",
    "c": "cmake",
    "cpp": "cmake",
    "csharp": "dotnet",
    "ruby": "bundler",
    "php": "composer",
}

# Safety clamps on the evidence snippet (the normalizer already clamps its
# per-line context; scanner_message and unknown future sources are not
# pre-clamped, so re-clamping here keeps the evidence block bounded).
MAX_EVIDENCE_SNIPPET_CHARS = 2000


@dataclass
class ScanConfig:
    """CLI-derived scan options."""

    source: Path
    report: Path
    # Repository locator (e.g. paynet-login/applications/sso-v3:master) written
    # into the CSV host column; None/empty leaves host blank.
    repo: Optional[str] = None
    threads: int = 4
    timeout: int = 3600
    keep_workdir: bool = False
    offline: bool = False
    non_interactive: bool = False
    verbose: bool = False
    quiet: bool = False
    allow_unsafe_build: bool = False
    resume: bool = False
    resume_scan_id: Optional[str] = None  # "" → most recent resumable


@dataclass
class ScanOutcome:
    """Terminal state of one scan run."""

    success: bool
    exit_code: int
    message: str = ""
    stats: ScanStats = field(default_factory=ScanStats)
    workspace: Optional[ScanWorkspace] = None
    raw_findings_json: Optional[Path] = None
    final_csv: Optional[Path] = None
    per_language_findings: Dict[str, int] = field(default_factory=dict)


class Scanner:
    """Owns the deterministic part: detect → scan → normalize → report."""

    def __init__(self, config: ScanConfig, settings) -> None:
        self.config = config
        self.settings = settings
        self.stats = ScanStats()
        self.ai_errors: List[str] = []
        self.engine_failures: List[str] = []
        self.codeql_per_lang: Dict[str, int] = {}
        self.workspace: Optional[ScanWorkspace] = None
        # Resume bookkeeping: completed stages (mirrored to state.json) and
        # whether no engine re-ran this session (→ normalized file reusable).
        self._completed: Dict[str, Dict[str, Any]] = {}
        self._normalized_valid = True

    # ------------------------------------------------------------------
    # Main flow
    # ------------------------------------------------------------------

    def run(self, on_progress=None) -> ScanOutcome:
        progress = on_progress or (lambda stage, label, detail: None)

        # Fresh scans create a brand-new workspace; --resume reopens one kept
        # by an earlier (failed/interrupted) run and validates its metadata.
        if self.config.resume:
            try:
                scan_id, metadata = find_resumable(self.settings.workdir, self.config.resume_scan_id or "")
                workspace = ScanWorkspace(self.settings.workdir, scan_id=scan_id)
                self.workspace = workspace
                self._validate_resume(workspace, metadata)
                workspace.create()  # exist_ok: also recreates missing subdirs
                workspace.write_metadata(
                    self._metadata(), created_at=metadata.get("created_at")
                )
                try:
                    state = workspace.read_json(workspace.state_file, default=None)
                except WorkspaceError:
                    state = None
                self._completed = dict((state or {}).get("stages") or {})
                if self._completed.get("reports") is not None:
                    raise WorkspaceError(
                        f"scan '{scan_id}' already completed ({metadata.get('created_at', 'earlier')}) "
                        "— re-run without --resume"
                    )
            except WorkspaceError as exc:
                return ScanOutcome(
                    False, 4, f"resume declined: {exc}", stats=self.stats
                )
        else:
            self._completed = {}
            self._normalized_valid = True
            workspace = ScanWorkspace(self.settings.workdir, scan_id=f"scan-{uuid.uuid4().hex[:12]}")
            workspace.create()
            workspace.write_metadata(self._metadata())
        self.workspace = workspace

        try:
            progress(1, "Checking dependencies", "")
            dependencies = self._stage_dependencies()
            progress(1, "Checking dependencies", dependencies["detail"])

            progress(2, "Validating source", "")
            source = self._stage_validate_source()
            progress(2, "Validating source", "OK")

            progress(3, "Detecting project", "")
            detection = None
            if "detect" in self._completed:
                detection = self._load_detection(workspace)
            if detection is None:
                detection = self._stage_detect(source, workspace)
                self._checkpoint(workspace, "detect", {})
            progress(
                3,
                "Detecting project",
                ", ".join(f"{lang.name} {lang.loc:,} LOC" for lang in detection.languages),
            )

            progress(4, "Running OpenGrep", "")
            opengrep_ok = "opengrep" in self._completed and workspace.raw_opengrep.exists()
            opengrep_findings = self._load_opengrep(workspace, source) if opengrep_ok else None
            if opengrep_findings is None:
                opengrep_ok, opengrep_findings = self._stage_opengrep(
                    dependencies["opengrep"], source, workspace, progress
                )
                self._normalized_valid = False  # fresh evidence → regroup
                if opengrep_ok:
                    self._checkpoint(workspace, "opengrep", {})
            progress(4, "Running OpenGrep", f"{len(opengrep_findings)} findings" if opengrep_ok else "failed")

            progress(5, "Running CodeQL", "")
            codeql_findings = self._stage_codeql(
                dependencies["codeql"],
                source,
                workspace,
                detection,
                progress,
                saved_langs=((self._completed.get("codeql") or {}).get("langs") or {}),
            )
            detail = ",".join(f"{name} {count}" for name, count in self.codeql_per_lang.items())
            progress(5, "Running CodeQL", detail or ("failed" if self.engine_failures else "no findings"))

            progress(6, "Normalizing findings", "")
            all_findings, groups = None, None
            if self._normalized_valid and "normalize" in self._completed:
                all_findings, groups = self._load_normalized_groups(workspace)
            if all_findings is None:
                all_findings, groups = self._stage_normalize(
                    source, workspace, opengrep_findings, codeql_findings
                )
                self._checkpoint(workspace, "normalize", {})
            progress(
                6,
                "Normalizing findings",
                f"Raw findings: {self.stats.raw_findings}, Candidate groups: {self.stats.candidate_groups}",
            )

            progress(7, "AI analysis", "")
            ai_results, links = self._stage_ai(groups, workspace)
            progress(7, "AI analysis", self._ai_brief(ai_results, links))

            canonical_map = self._canonical_map(all_findings, links)

            progress(8, "Writing reports", "")
            final_csv, raw_json = self._stage_reports(
                source, workspace, all_findings, ai_results, canonical_map, detection
            )
            progress(8, "Writing reports", "OK")
            self._checkpoint(workspace, "reports", {})
        except DependencyError as exc:
            return self._failed_outcome(
                3, f"dependency installation failed: {exc}", workspace
            )
        except (ValueError, WorkspaceError) as exc:
            return self._failed_outcome(4, f"invalid source: {exc}", workspace)
        except KeyboardInterrupt as exc:
            return self._failed_outcome(
                130, f"interrupted — resumable: --resume {workspace.scan_id}", workspace
            )
        except Exception as exc:  # noqa: BLE001 — top-level scan guard
            return self._failed_outcome(1, f"scan runtime failure: {exc}", workspace)

        if not self.config.keep_workdir:
            workspace.cleanup()

        exit_code = self._exit_code(opengrep_ok, bool(codeql_findings) or not self._codeql_failed())
        self.stats.canonical = len(set(canonical_map.values()))
        ok = exit_code == 0
        message = (
            "Scan completed successfully."
            if ok
            else "Scan completed with partial results (some engines failed)."
        )
        return ScanOutcome(
            success=ok,
            exit_code=exit_code,
            message=message,
            stats=self.stats,
            workspace=workspace if self.config.keep_workdir else None,
            final_csv=final_csv,
            raw_findings_json=raw_json,
            per_language_findings=self.codeql_per_lang,
        )

    # ------------------------------------------------------------------
    # Stages
    # ------------------------------------------------------------------

    def _stage_dependencies(self) -> Dict[str, str]:
        deps = DependencyManager({})
        deps.opengrep_version = self.settings.opengrep_version
        deps.codeql_version = self.settings.codeql_version
        opengrep = deps.ensure_opengrep(
            interactive=not self.config.non_interactive, offline=self.config.offline
        )
        codeql = deps.ensure_codeql(
            interactive=not self.config.non_interactive, offline=self.config.offline
        )
        versions = deps.status()
        detail = (
            f"OpenGrep {versions['opengrep']['version']} | CodeQL {versions['codeql']['version']}"
        )
        return {"opengrep": opengrep, "codeql": codeql, "detail": detail}

    def _stage_validate_source(self) -> Path:
        source = self.config.source.expanduser().resolve()
        if not source.exists() or not source.is_dir():
            raise ValueError(f"invalid source directory: {self.config.source}")
        return source

    # ------------------------------------------------------------------
    # Resume plumbing
    # ------------------------------------------------------------------

    def _metadata(self) -> Dict[str, Any]:
        return {
            "source": str(self.config.source.expanduser().resolve()),
            "report": str(self.config.report.expanduser().resolve()),
            "threads": self.config.threads,
            "timeout": self.config.timeout,
            "opengrep_version": self.settings.opengrep_version,
            "codeql_version": self.settings.codeql_version,
            "ai_model": self.settings.ai_model if self.settings.ai_enabled else "",
        }

    def _validate_resume(self, workspace: ScanWorkspace, metadata: Dict[str, Any]) -> None:
        """Refuse workspaces that belong to another source; warn on drift."""
        expected_source = str(self.config.source.expanduser().resolve())
        saved_source = str(metadata.get("source") or "")
        if saved_source != expected_source:
            raise WorkspaceError(
                f"workspace '{workspace.scan_id}' was for source {saved_source!r}, "
                f"not {expected_source!r} — pass the original --source or a different workspace"
            )
        for key, label in (
            ("opengrep_version", "OpenGrep"),
            ("codeql_version", "CodeQL"),
            ("ai_model", "AI model"),
        ):
            saved = str(metadata.get(key) or "")
            current = {
                "opengrep_version": self.settings.opengrep_version,
                "codeql_version": self.settings.codeql_version,
                "ai_model": self.settings.ai_model if self.settings.ai_enabled else "",
            }[key]
            if saved and current and saved != current:
                print(f"[resume] warning: {label} changed since this workspace "
                      f"was created ({saved!r} → {current!r})")

    def _checkpoint(self, workspace: ScanWorkspace, stage: str, info: Dict[str, Any]) -> None:
        """Record a completed stage durably (crash mid-scan keeps progress)."""
        self._completed[stage] = dict(info, completed_at=int(time.time()))
        self._persist_state(workspace)

    def _persist_state(self, workspace: ScanWorkspace) -> None:
        try:
            workspace.write_json_atomic(
                workspace.state_file,
                {"stages": self._completed, "updated_at": int(time.time())},
            )
        except WorkspaceError:
            pass  # diagnostics only; the outcome already carries the hint

    def _failed_outcome(
        self, exit_code: int, message: str, workspace: Optional[ScanWorkspace]
    ) -> ScanOutcome:
        if workspace is not None:
            self._persist_state(workspace)
            message = f"{message} (resumable: --resume {workspace.scan_id})"
        return ScanOutcome(
            False, exit_code, message, stats=self.stats, workspace=workspace
        )

    def _load_detection(self, workspace: ScanWorkspace) -> Optional[DetectionResult]:
        payload = None
        try:
            payload = workspace.read_json(workspace.detection_file, default=None)
        except WorkspaceError:
            return None
        if not isinstance(payload, dict):
            return None
        try:
            detection = DetectionResult.from_dict(payload)
        except Exception:  # noqa: BLE001 — corrupt file → re-run the stage
            return None
        return detection if detection.languages else None

    def _load_opengrep(self, workspace: ScanWorkspace, source: Path) -> Optional[List[Dict]]:
        try:
            return self._parse_engine_sarif(workspace.raw_opengrep, "opengrep", source)
        except Exception:  # noqa: BLE001 — corrupt SARIF → re-run the stage
            return None

    def _load_normalized_groups(
        self, workspace: ScanWorkspace
    ) -> Tuple[Optional[List[Finding]], Optional[list]]:
        """Rebuild findings + deterministic groups from normalized/findings.json."""
        try:
            entries = workspace.read_json(workspace.normalized_findings, default=None)
        except WorkspaceError:
            return None, None
        if not isinstance(entries, list) or not entries:
            return None, None
        try:
            all_findings = [Finding.from_dict(e) for e in entries if isinstance(e, dict)]
            groups = CandidateGrouper().group(all_findings)
        except Exception:  # noqa: BLE001 — corrupt file → re-normalize
            return None, None
        self.stats.raw_findings = len(all_findings)
        self.stats.candidate_groups = len(groups)
        return all_findings, groups

    def _parse_engine_sarif(self, sarif_path: Path, scanner_name: str, source: Path):
        """Shared SARIF→dict parsing used by both engine stages and resume."""
        parsed, parse_errors = SarifParser().parse_file(sarif_path, scanner_name, source)
        for finding in parsed:
            finding["scanner"] = scanner_name
        if parse_errors and self.config.verbose:
            for error in parse_errors:
                print(f"    [sarif] {error}")
        return parsed

    def _stage_detect(self, source: Path, workspace: ScanWorkspace) -> DetectionResult:
        detector = LanguageDetector()
        languages = detector.detect(source)
        manifests = ManifestDetector().detect(source)
        ecosystem_for_manifest: Dict[str, str] = {}
        for manifest in manifests:
            ecosystem_for_manifest[manifest["ecosystem"]] = manifest["ecosystem"]
        enriched: List[LanguageInfo] = []
        for lang in languages:
            build_system = _PRIMARY_ECOSYSTEM.get(lang.name)
            resolved = ecosystem_for_manifest.get(build_system or "", build_system)
            enriched.append(
                LanguageInfo(
                    name=lang.name,
                    loc=lang.loc,
                    build_system=resolved,
                    codeql_supported=lang.name in CODEQL_SUPPORT,
                )
            )
        detection = DetectionResult(
            languages=enriched,
            manifests=[{k: str(v) if k == "path" else v for k, v in m.items()} for m in manifests],
        )
        workspace.write_detection(detection.to_dict())
        return detection

    def _stage_opengrep(self, binary: str, source: Path, workspace: ScanWorkspace, progress):
        engine = OpenGrepEngine(binary)
        try:
            result = engine.scan(
                source,
                workspace.raw_opengrep,
                threads=self.config.threads,
                timeout=self.config.timeout,
            )
        except ExecutorError as exc:
            self.engine_failures.append(f"opengrep: {exc}")
            return False, []
        if not result.ok or not workspace.raw_opengrep.exists():
            self.engine_failures.append(f"opengrep: exit {result.exit_code}: {result.stderr[-300:]}")
            return False, []
        return True, self._parse_engine_sarif(workspace.raw_opengrep, "opengrep", source)

    def _stage_codeql(
        self,
        binary: str,
        source: Path,
        workspace: ScanWorkspace,
        detection,
        progress,
        saved_langs: Optional[Dict[str, int]] = None,
    ):
        """CodeQL per language. Checkpointed languages with a saved SARIF are
        replayed from the workspace; the rest re-run (never delete evidence)."""
        supported = [lang for lang in detection.languages if lang.codeql_supported]
        findings: List[Dict] = []
        if not supported:
            return findings
        sandbox_manager = SandboxManager(self.settings)
        engine = CodeqlEngine(binary, sandbox_manager)
        resolver = BuildResolver(self._real_manifests(detection))
        re_ran = False
        for lang in supported:
            codeql_name = CODEQL_SUPPORT.get(lang.name)
            if not codeql_name:
                continue
            per_lang_sarif = workspace.raw_codeql / f"{lang.name}.sarif"
            if lang.name in saved_langs and per_lang_sarif.exists():
                try:
                    parsed = self._parse_engine_sarif(per_lang_sarif, "codeql", source)
                except Exception:  # noqa: BLE001 — corrupt leftover → re-run
                    parsed = None
                if parsed is not None:
                    findings.extend(parsed)
                    self.codeql_per_lang[lang.name] = len(parsed)
                    continue
            plan = resolver.plan_for_language(lang.name, source)
            re_ran = True
            try:
                ok, message = engine.scan_language(
                    source,
                    lang.name,
                    codeql_name,
                    workspace.raw_codeql,
                    per_lang_sarif,
                    plan,
                    threads=self.config.threads,
                    allow_unsafe_build=self.config.allow_unsafe_build,
                    timeout=self.config.timeout,
                )
            except ExecutorError as exc:
                self.engine_failures.append(f"codeql[{lang.name}]: {exc}")
                continue
            if not ok or not per_lang_sarif.exists():
                self.engine_failures.append(f"codeql[{lang.name}]: {message}")
                continue
            parsed = self._parse_engine_sarif(per_lang_sarif, "codeql", source)
            findings.extend(parsed)
            self.codeql_per_lang[lang.name] = len(parsed)
            self._checkpoint(workspace, "codeql", {"langs": dict(self.codeql_per_lang)})
        if re_ran:
            self._normalized_valid = False  # fresh evidence → regroup
        return findings

    def _stage_normalize(self, source: Path, workspace: ScanWorkspace, opengrep_findings, codeql_findings):
        normalizer = FindingNormalizer(self.settings)
        opengrep_normalized = normalizer.normalize(opengrep_findings, source)
        codeql_normalized = normalizer.normalize(codeql_findings, source)
        all_findings = opengrep_normalized + codeql_normalized
        self.stats.raw_findings = len(all_findings)
        groups = CandidateGrouper().group(all_findings)
        self.stats.candidate_groups = len(groups)
        workspace.write_json(
            workspace.normalized_findings, [f.to_dict() for f in all_findings]
        )
        return all_findings, groups

    def _stage_ai(self, groups, workspace):
        try:
            if not self.settings.ai_enabled or not self.settings.ai_configured:
                self.ai_errors = ["AI disabled or not configured; findings marked UNPROCESSED"]
                return {}, []
            try:
                analyzer = AIAnalyzer(
                    AIConfig(
                        base_url=self.settings.ai_base_url,
                        api_key=self.settings.ai_api_key,
                        model=self.settings.ai_model,
                        timeout=self.settings.ai_timeout,
                        max_retries=self.settings.ai_max_retries,
                        temperature=self.settings.ai_temperature,
                        max_tokens=self.settings.ai_max_tokens or None,
                        group_budget=self.settings.ai_group_budget,
                    ),
                    batch_size=self.settings.ai_batch_size,
                    concurrency=self.settings.ai_concurrency,
                    error_dump_dir=workspace.ai_dir,
                    checkpoint=AICheckpoint(workspace.validation_partial, workspace.dedup_file),
                )
            except Exception as exc:  # defensive: AI never blocks raw evidence
                self.ai_errors = [f"AI analyzer unavailable: {exc}"]
                return {}, []
            if self.config.verbose:
                print(f"    [ai] {len(groups)} candidate groups — one model call each", flush=True)

            dashboard = None
            try:
                dashboard = AIDashboard(
                    len(groups),
                    quiet=self.config.quiet,
                    verbose=self.config.verbose,
                )
                dashboard.start()
                results, links, errors = analyzer.analyze_groups(
                    groups, on_event=dashboard.on_event
                )
            finally:
                # Every completed verdict is already on disk within seconds;
                # an interrupt mid-phase keeps the whole decided prefix.
                analyzer.flush_checkpoint()
                if dashboard is not None:
                    dashboard.stop()
            self.ai_errors = errors or []
            return results, links
        finally:
            self._persist_ai_errors(workspace)

    def _persist_ai_errors(self, workspace) -> None:
        """Persist the failure-kind histogram to ai/errors.json (diagnostics)."""
        try:
            workspace.write_json(
                workspace.ai_dir / "errors.json",
                summarize_ai_errors(self.ai_errors),
            )
        except Exception as exc:  # diagnostics only; never block the scan
            if self.config.verbose:
                print(f"    [ai] could not persist ai/errors.json: {exc}")

    def _stage_reports(self, source, workspace, all_findings, ai_results, canonical_map, detection):
        findings = self._build_canonical_findings(all_findings, ai_results, canonical_map)
        raw_entries = findings_payload(all_findings, ai_results, canonical_map)
        report = self.config.report.expanduser().resolve()
        writer = CSVWriter()
        final_csv = writer.write(report, findings, host=self.config.repo)
        raw_writer = JSONWriter()
        raw_json = raw_writer.write(report.parent / "raw-findings.json", raw_entries)
        workspace.reports_dir.mkdir(parents=True, exist_ok=True)
        writer.write(workspace.reports_dir / report.name, findings, host=self.config.repo)
        raw_writer.write(
            workspace.reports_dir / "raw-findings.json",
            raw_entries,
        )
        self.stats.canonical = len(findings)
        self.stats.deduplicated = max(0, len(all_findings) - len(findings))
        try:
            workspace.write_json(
                workspace.root / "ai" / "validation.json",
                {
                    finding.finding_id[:8]: {
                        "status": result.status.value,
                        "confidence": result.confidence,
                        "reason": result.reason,
                        "severity": result.ai_severity,
                    }
                    for finding, result in _zip_results(all_findings, ai_results)
                },
            )
        except Exception as exc:  # diagnostics only; never block the scan
            if self.config.verbose:
                print(f"    [ai] could not persist validation.json: {exc}")
        return final_csv, raw_json

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _real_manifests(self, detection: DetectionResult):
        """Re-read manifests as Path objects for the BuildResolver."""
        manifests = []
        for manifest in detection.manifests:
            manifests.append(
                {
                    "path": manifest["path"],
                    "relative": manifest["relative"],
                    "ecosystem": manifest["ecosystem"],
                }
            )
        return manifests

    def _canonical_map(self, all_findings, links) -> Dict[str, str]:
        """Assign F-XXX ids; duplicates share the canonical row id."""
        short_to_full = {f.finding_id[:8]: f.finding_id[:8] for f in all_findings}
        duplicate_of: Dict[str, str] = {}
        for link in links:
            for member in link.duplicates:
                if member in short_to_full and member != link.canonical_finding_id:
                    duplicate_of[member] = link.canonical_finding_id
        mapping: Dict[str, str] = {}
        assigned: Dict[str, str] = {}
        counter = 1
        for finding in all_findings:
            short_id = finding.finding_id[:8]
            if short_id in mapping:
                continue
            root = short_id
            seen = {root}
            while root in duplicate_of and duplicate_of[root] not in seen:
                root = duplicate_of[root]
                seen.add(root)
            if root in assigned:
                mapping[short_id] = assigned[root]
            else:
                canonical_id = f"F-{counter:03d}"
                counter += 1
                assigned[root] = canonical_id
                mapping[short_id] = canonical_id
        self.stats.deduplicated = max(0, len(all_findings) - counter + 1)
        return mapping

    def _build_canonical_findings(self, all_findings, ai_results, canonical_map):
        """One CanonicalFinding per AI-CONFIRMED canonical id.

        final.csv carries only verified positive findings:
        - status must be CONFIRMED (LIKELY/INSUFFICIENT_EVIDENCE/
          FALSE_POSITIVE/UNPROCESSED stay in raw-findings.json only);
        - the final risk must land in {CRITICAL, HIGH, MEDIUM, LOW} —
          scanner severities fall back through ERROR→HIGH, WARNING→MEDIUM,
          NOTE→LOW, and INFO (or unknown) is dropped.
        """
        by_id: Dict[str, list] = {}
        for finding in all_findings:
            by_id.setdefault(canonical_map[finding.finding_id[:8]], []).append(finding)
        findings: List[CanonicalFinding] = []
        for canonical_id in sorted(by_id):
            members = by_id[canonical_id]
            primary = members[0]
            result = ai_results.get(primary.finding_id[:8])
            if result is None:
                # Representative verdict missing: fall back to any member's
                # verdict within this group (never another group's).
                result = next(
                    (ai_results.get(m.finding_id[:8]) for m in members
                     if ai_results.get(m.finding_id[:8]) is not None),
                    None,
                )
            status = result.status if result else ValidationStatus.UNPROCESSED
            if status is not ValidationStatus.CONFIRMED:
                continue
            severity = result.ai_severity if result and result.ai_severity else primary.scanner_severity
            severity = _risk_severity(severity)
            if severity is None:
                continue
            target = primary.code_context.get("target", "")
            end_line = primary.line
            if target.strip():
                end_line = primary.line + max(1, len(target.splitlines())) - 1
            scanners = sorted({m.scanner for m in members})
            findings.append(
                CanonicalFinding(
                    canonical_id=canonical_id,
                    title=(result.title if result and result.title else primary.scanner_title),
                    severity=severity,
                    confidence=(result.confidence if result else 0.0),
                    language=primary.language,
                    file=primary.file,
                    line=primary.line,
                    column=primary.column,
                    category=(result.category if result and result.category else "Uncategorized"),
                    cwe=(result.cwe if result and result.cwe else (primary.cwe or "")),
                    owasp=(result.owasp if result and result.owasp else ""),
                    description=(result.description if result and result.description else primary.scanner_message),
                    recommendation=(result.recommendation if result and result.recommendation else "Review manually."),
                    exploitability=(result.exploitability if result and result.exploitability else ""),
                    impact=(result.impact if result and result.impact else ""),
                    scanner_count=len(scanners),
                    scanners=";".join(scanners),
                    validation_status=status.value,
                    member_ids=[m.finding_id[:8] for m in members],
                    end_line=end_line,
                    evidence=(
                        self._build_evidence(primary, end_line, target)
                    ),
                )
            )
        return findings

    @staticmethod
    def _build_evidence(primary: Finding, end_line: int, target: str) -> str:
        """Structured evidence block: file path, line range, blank line, snippet."""
        snippet = clamp_text(
            (target or "").strip() or primary.scanner_message,
            MAX_EVIDENCE_SNIPPET_CHARS,
        )
        return (
            f"Affected File: {primary.file}\n"
            f"Affected Line: {primary.line} - {end_line}\n"
            f"\n"
            f"{snippet}"
        )

    def _ai_brief(self, ai_results, links) -> str:
        if not ai_results:
            return f"UNPROCESSED ({self.stats.raw_findings} raw findings retained)"
        validated = sum(
            1 for r in ai_results.values() if r.status in (ValidationStatus.CONFIRMED, ValidationStatus.LIKELY)
        )
        false_positive = sum(1 for r in ai_results.values() if r.status == ValidationStatus.FALSE_POSITIVE)
        return (
            f"Validated: {validated}, False positive: {false_positive}, "
            f"Duplicate links: {len(links)}"
        )

    def _codeql_failed(self) -> bool:
        return any(f.startswith("codeql") for f in self.engine_failures)

    def _exit_code(self, opengrep_ok: bool, codeql_ok: bool) -> int:
        if not opengrep_ok and not codeql_ok:
            return 1
        if not opengrep_ok or self._codeql_failed() or self.ai_errors:
            return 5
        return 0


_RISK_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def _risk_severity(value) -> Optional[str]:
    """Map a scanner severity to the final.csv risk vocabulary, or None.

    AI severities already come validated from the validator; this normalizes
    raw scanner severities when the AI verdict lacks one. INFO never keeps a
    row — the ThreatVault format has no slot for it.
    """
    if not isinstance(value, str):
        return None
    upper = value.strip().upper()
    mapping = {"ERROR": "HIGH", "WARNING": "MEDIUM", "NOTE": "LOW"}
    upper = mapping.get(upper, upper)
    return upper if upper in _RISK_LEVELS else None


def _zip_results(all_findings, ai_results):
    """Yield (finding, result) pairs actually present in ai_results."""
    paired = []
    for finding in all_findings:
        result = ai_results.get(finding.finding_id[:8])
        if result:
            paired.append((finding, result))
    return paired