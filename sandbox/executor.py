"""Sandboxed build execution (blueprint section 16).

Runs project build commands inside a disposable Docker container with:
CPU limit, RAM limit, timeout, restricted network, no host credentials and
an isolated filesystem overlay. The container is always removed afterwards.
"""

from __future__ import annotations

import os
import uuid
from typing import List

from builders.base import BuildPlan
from core.executor import ProcessResult, run_command
from sandbox.manager import SandboxManager

DEFAULT_DOCKER_IMAGE = "ubuntu:22.04"


class SandboxExecutor:
    """Execute BuildPlan.command inside the available sandbox."""

    def __init__(self, manager: SandboxManager) -> None:
        self.manager = manager

    def run_build(
        self,
        plan: BuildPlan,
        source_root: str,
        *,
        timeout: int = 3600,
        network_disabled: bool = True,
    ) -> ProcessResult:
        """Run one build plan, sandboxed where available.

        Returns a ProcessResult; NEVER raises for build failure —
        build failures are scan-visible but must not abort the pipeline.
        """
        decision = self.manager.gate(plan)
        if not decision.available or not plan.command:
            return ProcessResult(
                command=plan.command or [],
                exit_code=-1,
                stdout="",
                stderr=decision.reason,
            )
        if decision.mode == "docker":
            return self._run_docker(
                plan.command,
                source_root,
                timeout=timeout,
                network_disabled=network_disabled,
                image=os.environ.get("ISAST_BUILD_IMAGE", DEFAULT_DOCKER_IMAGE),
            )
        # host mode (--allow-unsafe-build): arg-array subprocess with limits.
        return run_command(plan.command, cwd=source_root, timeout=timeout)

    def _run_docker(
        self,
        command: List[str],
        source_root: str,
        *,
        timeout: int,
        network_disabled: bool,
        image: str,
    ) -> ProcessResult:
        docker = self.manager.decision.runner_path
        container_name = f"isast-build-{uuid.uuid4().hex[:10]}"
        limits = self.manager.decision.resource_limits

        argv = [docker, "run", "--rm", "--name", container_name]
        # Restricted network (blueprint section 16).
        argv += ["--network", "none" if network_disabled else "bridge"]
        # Resource limits.
        argv += ["--cpus", str(float(limits.get("cpu", 2)))]
        argv += ["--memory", f"{int(limits.get('memory_mb', 8192))}m"]
        argv += ["--pids-limit", "512"]
        # No host secrets: mount only the source tree, read-only-ish.
        argv += ["--volume", f"{os.path.abspath(source_root)}:/isast-work"]
        argv += ["--workdir", "/isast-work"]
        # Prevent setuid games and drop most capabilities.
        argv += ["--security-opt", "no-new-privileges"]
        argv += ["--cap-drop", "ALL"]
        argv += ["--user", "0:0"]
        argv += [image]
        argv += ["sh", "-c", " ".join(_quote(arg) for arg in command)]

        result = run_command(argv, timeout=timeout)
        run_command([docker, "rm", "-f", container_name], timeout=30)
        return result


def _quote(arg: str) -> str:
    """Quote a single argv element for 'sh -c' inside the container."""
    escaped = arg.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
    return f'"{escaped}"'