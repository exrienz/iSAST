#!/usr/bin/env python3
"""iSAST — zero-configuration CLI-first SAST orchestrator.

Primary UX (blueprint section 4):
    python isast.py --source=/path/to/source --report=final.csv

Everything else — dependency installation, language detection, build
detection, CodeQL databases, OpenGrep execution, sandboxing, SARIF
parsing, finding grouping, AI validation/dedup/wording and CSV
generation — is automatic.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.dependency import DependencyError  # noqa: E402

VERSION = "1.0.0"

EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_INVALID_ARGS = 2
EXIT_DEPS = 3
EXIT_INVALID_SOURCE = 4
EXIT_PARTIAL = 5

# repo locator: project[/path…][:ref] — e.g. paynet-login/applications/sso-v3:master
REPO_PATTERN = re.compile(r"^[\w.\-]+(/[\w.\-]+)*(:[\w.\-]+)?$")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="isast.py",
        description="iSAST — zero-configuration SAST orchestrator (OpenGrep + CodeQL + AI).",
    )
    parser.add_argument("--source", type=str, help="source directory to scan")
    parser.add_argument("--report", type=str, help="path of the final.csv report to write")
    parser.add_argument(
        "--repo",
        type=str,
        default=None,
        help="repository locator (e.g. paynet-login/applications/sso-v3:master); written into the CSV host column",
    )
    parser.add_argument("--threads", type=int, default=4, help="scanner parallelism (default 4)")
    parser.add_argument("--timeout", type=int, default=3600, help="scan timeout in seconds (default 3600)")
    parser.add_argument("--workdir", type=str, default=None, help="override scan working directory")
    parser.add_argument(
        "--resume",
        nargs="?",
        const="",
        default=None,
        metavar="SCAN_ID",
        help="resume an interrupted scan (no value: most recent resumable workspace)",
    )
    parser.add_argument("--keep-workdir", action="store_true", help="keep the scan workspace for auditing")
    parser.add_argument("--verbose", action="store_true", help="detailed progress output")
    parser.add_argument("--quiet", action="store_true", help="suppress non-essential output")
    parser.add_argument("--offline", action="store_true", help="do not download anything (fail if engines missing)")
    parser.add_argument("--non-interactive", action="store_true", help="never prompt (CI/CD mode)")
    parser.add_argument("--config", type=str, default=None, help="optional YAML config file")
    parser.add_argument("--allow-unsafe-build", action="store_true", help="trusted repos only: run required builds on host when no sandbox is available")
    parser.add_argument("--update", action="store_true", help="install/refresh the pinned engine versions")
    parser.add_argument("--version", action="store_true", help="print iSAST version")
    parser.add_argument("--doctor", action="store_true", help="diagnose installation and configuration")
    return parser


def _banner() -> None:
    print(f"iSAST v{VERSION}")
    print("=" * 48)


def cmd_version() -> int:
    print(f"iSAST v{VERSION}")
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    from core.dependency import DependencyManager
    from core.resources import ensure_layout, isast_home
    from core.settings import load_settings
    from ai.provider import AIConfig
    from ai.openai_compatible import AIProvider

    print(f"iSAST v{VERSION} — doctor")
    print("=" * 48)
    ensure_layout()
    settings = load_settings(Path(__file__).resolve().parent, Path(args.config) if args.config else None)
    if args.workdir:
        settings.workdir = Path(args.workdir).expanduser()

    print(f"\n[home] {isast_home()}")

    print("\n[python]")
    print(f"    {sys.version.split()[0]} (requires 3.10+)")

    print("\n[engines]")
    deps = DependencyManager({})
    deps.opengrep_version = settings.opengrep_version
    deps.codeql_version = settings.codeql_version
    status = deps.status()
    for engine, info in status.items():
        state = "OK" if info["installed"] == "yes" else "MISSING"
        print(f"    {engine:<10} {state:<8} version={info['version']} path={info['path']}")

    print("\n[ai]")
    if not settings.ai_enabled:
        print("    AI disabled (AI_ENABLED=false)")
    elif not settings.ai_configured:
        print("    NOT CONFIGURED — set AI_BASE_URL, AI_API_KEY, AI_MODEL in .env")
    else:
        print(f"    base_url={settings.ai_base_url}")
        print(f"    model={settings.ai_model}")
        provider = AIProvider(
            AIConfig(
                base_url=settings.ai_base_url,
                api_key=settings.ai_api_key,
                model=settings.ai_model,
                timeout=min(settings.ai_timeout, 60),
            )
        )
        reachable = provider.ping()
        print("    connectivity: " + ("OK" if reachable else "FAILED"))

    print("\n[exit] doctor done")
    return EXIT_OK


def cmd_update(args: argparse.Namespace) -> int:
    from core.dependency import DependencyManager
    from core.resources import ensure_layout
    from core.settings import load_settings

    _banner()
    ensure_layout()
    settings = load_settings(Path(__file__).resolve().parent, Path(args.config) if args.config else None)
    deps = DependencyManager({})
    deps.opengrep_version = settings.opengrep_version
    deps.codeql_version = settings.codeql_version
    try:
        paths = deps.install_all(interactive=not args.non_interactive)
    except DependencyError as exc:
        print(f"\n[-] engine update failed: {exc}")
        return EXIT_DEPS
    for engine, path in paths.items():
        print(f"    {engine:<10} {path}")
    print("\n[i] engines installed/verified at pinned versions.")
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    from core.scanner import ScanConfig, Scanner
    from core.settings import load_settings
    from core.workspace import WorkspaceError, find_resumable

    resuming = args.resume is not None
    if not resuming and (not args.source or not args.report):
        print("error: --source and --report are required (see python isast.py --help)", file=sys.stderr)
        return EXIT_INVALID_ARGS
    if args.threads < 1 or args.timeout < 1:
        print("error: --threads and --timeout must be positive integers", file=sys.stderr)
        return EXIT_INVALID_ARGS
    if args.quiet and args.verbose:
        print("error: --quiet and --verbose are mutually exclusive", file=sys.stderr)
        return EXIT_INVALID_ARGS
    if args.repo and not REPO_PATTERN.match(args.repo):
        print(
            f"error: --repo must look like project/path[:ref] (got: {args.repo!r});"
            " e.g. paynet-login/applications/sso-v3:master",
            file=sys.stderr,
        )
        return EXIT_INVALID_ARGS

    settings = load_settings(Path(__file__).resolve().parent, Path(args.config) if args.config else None)
    if args.workdir:
        settings.workdir = Path(args.workdir).expanduser()

    # Resume resolves the workspace before anything else: --source/--report
    # may be omitted and fall back to what the original scan recorded.
    source_arg = args.source
    report_arg = args.report
    resume_scan_id = args.resume or ""
    if resuming:
        try:
            scan_id, metadata = find_resumable(settings.workdir, resume_scan_id)
        except WorkspaceError as exc:
            print(f"error: --resume: {exc}", file=sys.stderr)
            return EXIT_INVALID_SOURCE
        resume_scan_id = scan_id
        source_arg = source_arg or metadata.get("source")
        report_arg = report_arg or metadata.get("report")
        if not source_arg or not report_arg:
            print(
                "error: resumable workspace lacks recorded --source/--report; pass them explicitly",
                file=sys.stderr,
            )
            return EXIT_INVALID_ARGS
        if not args.quiet:
            print(f"[resume] continuing scan '{scan_id}' (skipping completed stages)")

    config = ScanConfig(
        source=Path(source_arg),
        report=Path(report_arg),
        repo=args.repo,
        threads=args.threads,
        timeout=args.timeout,
        keep_workdir=args.keep_workdir,
        offline=args.offline,
        non_interactive=args.non_interactive,
        verbose=args.verbose,
        quiet=args.quiet,
        allow_unsafe_build=args.allow_unsafe_build,
        resume=resuming,
        resume_scan_id=resume_scan_id,
    )

    if not args.quiet:
        if not resuming:
            _banner()
            print()

    scanner = Scanner(config, settings)

    def progress(stage: int, label: str, detail: str) -> None:
        """Blueprint-style banner: start line, then the result on completion."""
        if args.quiet:
            return
        if detail:
            print("OK" if detail == "OK" else detail, flush=True)
        else:
            dots = "." * max(0, 32 - len(label))
            print(f"[{stage}/8] {label} {dots} ", end="", flush=True)

    outcome = scanner.run(on_progress=progress)

    if not args.quiet:
        print()
        print(f"      {config.report}")
        print("      raw-findings.json")
        print()
        print("=" * 48)
        print(outcome.message)
        if outcome.exit_code == EXIT_PARTIAL:
            for failure in scanner.engine_failures:
                print(f"    [engine] {failure}")
            for error in scanner.ai_errors[:5]:
                print(f"    [ai] {error}")
        if outcome.exit_code not in (EXIT_OK, EXIT_INVALID_ARGS) and resuming:
            print(
                f"[i] still resumable: python isast.py --resume {resume_scan_id} "
                f"--source {source_arg} --report {report_arg}"
            )
    return outcome.exit_code


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.version:
            return cmd_version()
        if args.doctor:
            return cmd_doctor(args)
        if args.update:
            return cmd_update(args)
        return cmd_scan(args)
    except KeyboardInterrupt:
        print("\n[i] interrupted by user", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())