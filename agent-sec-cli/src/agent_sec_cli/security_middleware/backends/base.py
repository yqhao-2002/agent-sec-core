"""Abstract base class for all security middleware backends."""

from abc import ABC, abstractmethod
from typing import Any

from agent_sec_cli.security_middleware.context import RequestContext
from agent_sec_cli.security_middleware.result import ActionResult


class BaseBackend(ABC):
    """All backend implementations must inherit from this class."""

    @abstractmethod
    def execute(self, ctx: RequestContext, **kwargs: Any) -> ActionResult:
        """Execute the backend action and return a unified ActionResult."""
        pass
