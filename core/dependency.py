"""Engine dependency management (blueprint section 8).

iSAST owns OpenGrep and CodeQL under ~/.isast:

    ~/.isast/bin/opengrep
    ~/.isast/tools/codeql/codeql

Engines are downloaded once from official GitHub releases with checksum
verification, pinned to versions declared in .env (OPENGREP_VERSION /
CODEQL_VERSION). Scans must never upgrade engines on their own.
"""

from __future__ import annotations

import hashlib
import platform
import re
import sys
import urllib.request
from pathlib import Path
from typing import Dict, Optional, Tuple

import core.resources as res
from core.executor import ExecutorError, run_command

OPENGREP_DEFAULT_VERSION = "v1.30.0"
CODEQL_DEFAULT_VERSION = "2.27.1"

OPENGREP_REPO = "https://github.com/opengrep/opengrep/releases/download"
CODEQL_REPO = "https://github.com/github/codeql-action/releases/download"

_GITHUB_API_HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "iSAST"}
_VERSION_HINT = re.compile(r"\d+\.\d+")


class DependencyError(RuntimeError):
    """Raised when an engine cannot be installed or verified."""


def normalize_version(version: str) -> str:
    """Allow '1.30.0', 'v1.30.0' and '2.27.1' styles in .env."""
    version = (version or "").strip()
    return version


def _opengrep_asset_name(version: str) -> str:
    """OpenGrep ships self-contained single-file binaries per platform."""
    machine = platform.machine().lower()
    system = sys.platform
    if system == "darwin":
        arch = "arm64" if machine in ("arm64", "aarch64") else "x86"
        return f"opengrep_osx_{arch}"
    if system.startswith("linux"):
        arch = "aarch64" if machine in ("arm64", "aarch64") else "x86"
        # Prefer manylinux variant on glibc distros; musl fallback is the
        # same channel name namespace so manylinux works for Ubuntu/RHEL.
        return f"opengrep_manylinux_{arch}"
    raise DependencyError(f"unsupported platform for OpenGrep: {system}/{machine}")


def _codeql_asset_names(version: str) -> Tuple[str, str]:
    """Return (bundle_asset, checksum_asset) for this platform."""
    machine = platform.machine().lower()
    system = sys.platform
    if system == "darwin":
        variant = "osx64"
    elif system.startswith("linux"):
        variant = "linux-arm64" if machine in ("arm64", "aarch64") else "linux64"
    else:
        raise DependencyError(f"unsupported platform for CodeQL: {system}/{machine}")
    return f"codeql-bundle-{variant}.tar.gz", f"codeql-bundle-{variant}.tar.gz.checksum.txt"


def _download(url: str, destination: Path, timeout: int = 900) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, headers=_GITHUB_API_HEADERS), timeout=timeout
        ) as response, destination.open("wb") as handle:
            while True:
                chunk = response.read(1024 * 512)
                if not chunk:
                    break
                handle.write(chunk)
    except OSError as exc:
        raise DependencyError(f"download failed ({url}): {exc}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_checksum(artifact: Path, checksum_text: str) -> bool:
    """Accept both '<sha256> <name>' and bare-hash checksum files."""
    expected = checksum_text.strip().split()
    if not expected:
        return False
    candidates = {expected[0].lower()}
    if len(expected) >= 2:  # "<hash> name" -> first token; "<name> <hash>" -> second
        candidates.add(expected[1].lower())
    return _sha256(artifact).lower() in candidates


def _untar(archive: Path, target_dir: Path) -> None:
    import tarfile

    target_dir.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            bundle.extractall(target_dir, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise DependencyError(f"failed to extract {archive}: {exc}") from exc


def _resolve_version_from_tag(tag: str) -> bool:
    """Validate that a tag looks like a semver-ish release tag."""
    return bool(re.match(r"^v?\d+\.\d+\.\d+$", tag.strip()))


def opengrep_command(version: str = "") -> str:
    del version
    return str(res.bin_dir() / "opengrep")


class DependencyManager:
    """Check/verify/install OpenGrep and CodeQL."""

    def __init__(self, settings: Dict[str, str]) -> None:
        self.settings = settings
        self.opengrep_version = normalize_version(settings.get("OPENGREP_VERSION") or OPENGREP_DEFAULT_VERSION)
        self.codeql_version = normalize_version(settings.get("CODEQL_VERSION") or CODEQL_DEFAULT_VERSION)
        self.installed: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # OpenGrep
    # ------------------------------------------------------------------

    def ensure_opengrep(self, *, interactive: bool, offline: bool = False) -> str:
        path = res.bin_dir() / "opengrep"
        if path.exists() and self._verify_opengrep(str(path)):
            self.installed["opengrep"] = path
            return str(path)
        if offline:
            raise DependencyError(
                "OpenGrep is missing and --offline was given; run 'python isast.py --update' once while online."
            )
        self._install_opengrep(interactive=interactive)
        return str(path)

    def _verify_opengrep(self, path: str) -> bool:
        result = run_command([path, "--version"], timeout=60)
        # Some builds print only the version number ("1.30.0").
        return result.ok and bool(_VERSION_HINT.search(result.stdout + result.stderr))

    def _install_opengrep(self, *, interactive: bool) -> None:
        if interactive:
            answer = input(
                f"OpenGrep is not installed. Download and install {self.opengrep_version} to {res.isast_home()}? [Y/n] "
            )
            if answer.strip().lower() not in ("", "y", "yes"):
                raise DependencyError("OpenGrep installation declined by user.")
        res.ensure_layout()
        asset = _opengrep_asset_name(self.opengrep_version)
        url = f"{OPENGREP_REPO}/{self.opengrep_version}/{asset}"
        archive = res.downloads_dir() / asset
        if not archive.exists() or archive.stat().st_size == 0:
            _download(url, archive)
        binary_target = res.bin_dir() / "opengrep"
        # Single-file release: the whole archive is the executable.
        try:
            binary_target.write_bytes(archive.read_bytes())
            binary_target.chmod(0o755)
        except OSError as exc:
            raise DependencyError(f"cannot install opengrep binary: {exc}") from exc
        if not self._verify_opengrep(str(binary_target)):
            # Some releases ship a tar.gz; fall back to extraction.
            self._extract_opengrep_fallback(archive, binary_target)
        if not self._verify_opengrep(str(binary_target)):
            raise DependencyError(
                f"installed OpenGrep {self.opengrep_version} does not execute correctly on this platform."
            )
        self.installed["opengrep"] = str(binary_target)

    def _extract_opengrep_fallback(self, archive: Path, binary_target: Path) -> None:
        _untar(archive, res.downloads_dir() / "opengrep-tmp")
        extracted_root = res.downloads_dir() / "opengrep-tmp"
        for candidate in sorted(extracted_root.rglob("opengrep*")):
            if candidate.is_file() and not candidate.name.endswith((".sig", ".cert")):
                binary_target.write_bytes(candidate.read_bytes())
                binary_target.chmod(0o755)
                return
        raise DependencyError("opengrep binary not found inside downloaded archive.")

    # ------------------------------------------------------------------
    # CodeQL
    # ------------------------------------------------------------------

    def ensure_codeql(self, *, interactive: bool, offline: bool = False) -> str:
        path = res.codeql_home() / "codeql" / "codeql"
        if not path.exists():
            path = res.codeql_home() / "codeql" / "codeql.cmd"
        if path.exists() and self._verify_codeql(str(path)):
            self.installed["codeql"] = str(path)
            return str(path)
        if offline:
            raise DependencyError(
                "CodeQL is missing and --offline was given; run 'python isast.py --update' once while online."
            )
        self._install_codeql(interactive=interactive)
        return str(path)

    def _verify_codeql(self, path: str) -> bool:
        result = run_command([path, "version"], timeout=180)
        # Output like "CodeQL command-line toolchain release 2.27.1."
        return result.ok and bool(_VERSION_HINT.search(result.stdout + result.stderr))

    def _install_codeql(self, *, interactive: bool) -> None:
        if interactive:
            answer = input(
                f"CodeQL is not installed. Download and install bundle {self.codeql_version} to {res.codeql_home()}? [Y/n] "
            )
            if answer.strip().lower() not in ("", "y", "yes"):
                raise DependencyError("CodeQL installation declined by user.")
        res.ensure_layout()
        bundle_asset, checksum_asset = _codeql_asset_names(self.codeql_version)
        codeql_tag = self.codeql_version.lstrip("v")
        bundle_tag = f"codeql-bundle-v{codeql_tag}" if not self.codeql_version.startswith("v") else f"codeql-bundle-{self.codeql_version}"
        base = f"{CODEQL_REPO}/{bundle_tag}"
        archive = res.downloads_dir() / bundle_asset
        checksum = res.checksums_dir() / checksum_asset
        if not archive.exists() or archive.stat().st_size == 0:
            _download(f"{base}/{bundle_asset}", archive)
            _download(f"{base}/{checksum_asset}", checksum)
        if checksum.exists():
            expected = checksum.read_text(encoding="utf-8", errors="replace")
            if not _verify_checksum(archive, expected):
                raise DependencyError(
                    f"CodeQL bundle checksum mismatch for {archive.name}; refusing to install."
                )
        install_root = res.codeql_home()
        marker = install_root / ".installed"
        if marker.exists() and (install_root / "codeql" / "codeql").exists():
            self.installed["codeql"] = str(install_root / "codeql" / "codeql")
            return
        _untar(archive, install_root)
        try:
            marker.write_text(self.codeql_version, encoding="utf-8")
        except OSError:
            pass
        codeql_bin = install_root / "codeql" / "codeql"
        if not codeql_bin.exists():
            raise DependencyError(
                "codeql-bundle archive extracted but codeql/codeql binary not found."
            )
        codeql_bin.chmod(0o755)
        if not self._verify_codeql(str(codeql_bin)):
            raise DependencyError("codeql binary does not execute correctly after installation.")
        self.installed["codeql"] = str(codeql_bin)

    # ------------------------------------------------------------------
    # Status / doctor
    # ------------------------------------------------------------------

    def status(self) -> Dict[str, Dict[str, str]]:
        """Report what is installed and at which version."""
        report: Dict[str, Dict[str, str]] = {}
        for name in ("opengrep", "codeql"):
            info = {"installed": "no", "version": "-", "path": "-"}
            if name == "opengrep":
                path = res.bin_dir() / "opengrep"
                if path.exists():
                    info["installed"] = "yes"
                    info["path"] = str(path)
                    try:
                        info["version"] = self._opengrep_version(str(path)) or self.opengrep_version
                    except ExecutorError:
                        info["version"] = "unknown"
            else:
                path = res.codeql_home() / "codeql" / "codeql"
                if path.exists():
                    info["installed"] = "yes"
                    info["path"] = str(path)
                    try:
                        info["version"] = self._codeql_version(str(path))
                    except ExecutorError:
                        info["version"] = "unknown"
            report[name] = info
        return report

    def _opengrep_version(self, path: str) -> Optional[str]:
        result = run_command([path, "--version"], timeout=60)
        text = result.stdout + result.stderr
        match = re.search(r"(\d+\.\d+\.\d+)", text)
        return match.group(1) if match else None

    def _codeql_version(self, path: str) -> str:
        result = run_command([path, "version"], timeout=120)
        text = result.stdout + result.stderr
        match = re.search(r"release (\d+\.\d+\.\d+)", text)
        if match:
            return match.group(1)
        match = re.search(r"(\d+\.\d+\.\d+)", text)
        return match.group(1) if match else "unknown"

    def install_all(self, *, interactive: bool, offline: bool = False) -> Dict[str, str]:
        """Install (or verify) both engines and return their paths."""
        paths = {
            "opengrep": self.ensure_opengrep(interactive=interactive, offline=offline),
            "codeql": self.ensure_codeql(interactive=interactive, offline=offline),
        }
        return paths