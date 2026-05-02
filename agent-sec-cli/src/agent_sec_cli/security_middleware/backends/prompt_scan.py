"""prompt_scan backend — delegates to the prompt_scanner package."""

import json
from typing import Any

from agent_sec_cli.prompt_scanner.config import ScanMode
from agent_sec_cli.prompt_scanner.result import Verdict
from agent_sec_cli.prompt_scanner.scanner import PromptScanner
from agent_sec_cli.security_middleware.backends.base import BaseBackend
from agent_sec_cli.security_middleware.context import RequestContext
from agent_sec_cli.security_middleware.result import ActionResult


class PromptScanBackend(BaseBackend):
    """Scan prompt text for injection / jailbreak attempts using the prompt_scanner engine."""

    def execute(self, ctx: RequestContext, **kwargs: Any) -> ActionResult:
        text: str = kwargs.get("text", "")
        mode_str: str = kwargs.get("mode", "standard")
        source: str = kwargs.get("source", "")

        if not text or not text.strip():
            return ActionResult(
                success=False,
                error="prompt_scan error: no input text provided",
                exit_code=1,
            )

        try:
            scan_mode = ScanMode(mode_str.lower())
        except ValueError:
            return ActionResult(
                success=False,
                error=f"prompt_scan error: invalid mode '{mode_str}'. Choose from: fast, standard, strict",
                exit_code=1,
            )

        scanner = PromptScanner(mode=scan_mode)
        result = scanner.scan(text, source=source if source else None)

        has_error = result.verdict == Verdict.ERROR
        d = result.to_dict()

        return ActionResult(
            success=not has_error,
            data=d,
            stdout=json.dumps(d, indent=2, ensure_ascii=False),
            exit_code=1 if has_error else 0,
        )
