"""Intent backend — future stub for intent-level security analysis."""

from typing import Any

from agent_sec_cli.security_middleware.backends.base import BaseBackend
from agent_sec_cli.security_middleware.context import RequestContext
from agent_sec_cli.security_middleware.result import ActionResult


class IntentBackend(BaseBackend):
    """Placeholder for intent-level security evaluation.

    This backend will eventually analyse the semantic *intent* of an
    agent action and decide whether it aligns with the declared policy.
    """

    def execute(self, ctx: RequestContext, **kwargs: Any) -> ActionResult:
        """Not yet implemented — always returns failure."""
        return ActionResult(
            success=False,
            error="Intent security not yet implemented",
        )
