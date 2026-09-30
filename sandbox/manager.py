"""SandboxManager: decide whether a build can run safely
(blueprint sections 16 and 17).

The sandbox exists ONLY to execute project-controlled build steps. If no
sandboxing mechanism is available on this host and a build is required,
iSAST FAILS SAFE: the build is skipped and CodeQL runs source-only.
A build never happens silently on the host unless the operator passes
--allow-unsafe-build for trusted internal repositories.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Optional

from builders.base import BuildPlan


@dataclass
class SandboxDecision:
    """Outcome of the sandbox availability check."""

    mode: str  # "docker" | "native-limits" | "host" | "none"
    available: bool
    runner_path: Optional[str] = None
    reason: str = ""
    restricted_network: bool = False
    resource_limits: dict = field(default_factory=lambda: {"cpu": 2, "memory_mb": 8192})


class SandboxManager:
    """Detect a usable sandbox mechanism for build execution."""

    def __init__(self, settings) -> None:
        self.settings = settings
        self.decision = self._detect()

    def _detect(self) -> SandboxDecision:
        docker = shutil.which("docker")
        if docker:
            probe = _probe_docker(docker)
            if probe:
                return SandboxDecision(
                    mode="docker",
                    available=True,
                    runner_path=docker,
                    reason=f"docker engine available ({probe})",
                    restricted_network=True,
                )
            return SandboxDecision(
                mode="none",
                available=False,
                reason="docker CLI found but engine not reachable; refusing to build on host",
            )
        return SandboxDecision(
            mode="none",
            available=False,
            reason="no sandboxing mechanism available on this host",
        )

    def gate(self, plan: BuildPlan, allow_unsafe_build: bool = False) -> "SandboxDecision":
        """Decide how (or whether) a required build may run.

        Priority (blueprint section 16):
          1. docker sandbox (restricted network, no host creds)
          2. explicit host escape hatch (--allow-unsafe-build)
          3. refuse: FAIL SAFE — the scan continues without the build
        """
        if not plan.required:
            return SandboxDecision(mode="none", available=True, reason=plan.reason)
        if self.decision.available:
            return self.decision
        if allow_unsafe_build:
            return SandboxDecision(
                mode="host",
                available=True,
                reason="--allow-unsafe-build: executing build on host (trusted repo)",
            )
        return SandboxDecision(
            mode="none",
            available=False,
            reason=(
                "build sandbox unavailable; failing safe and skipping the project build "
                "(use --allow-unsafe-build to override)"
            ),
        )


def _probe_docker(docker_path: str) -> Optional[str]:
    """Return docker server version string, or None when the daemon is down."""
    from core.executor import run_command

    result = run_command([docker_path, "info", "--format", "{{.ServerVersion}}"], timeout=30)
    if result.ok and result.stdout.strip():
        return result.stdout.strip()
    return None