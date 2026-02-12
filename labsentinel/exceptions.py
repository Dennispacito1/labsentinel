"""Custom exceptions used across LabSentinel."""

from __future__ import annotations

from typing import Optional


class LabSentinelError(Exception):
    """Base exception for LabSentinel runtime errors."""


class ProxmoxApiError(LabSentinelError):
    """Raised when a Proxmox API request fails."""

    def __init__(
        self,
        status_code: Optional[int],
        method: str,
        path: str,
        details: str,
        message: Optional[str] = None,
    ) -> None:
        self.status_code = status_code
        self.method = method
        self.path = path
        self.details = details
        self.message = message or "Proxmox API request failed."
        super().__init__(self.__str__())

    def __str__(self) -> str:
        code = self.status_code if self.status_code is not None else "n/a"
        return f"{self.message} [{self.method} {self.path}] (HTTP {code})"


class ProxmoxAuthError(ProxmoxApiError):
    """Raised when Proxmox authentication fails."""

    def __init__(self, status_code: Optional[int], method: str, path: str, details: str) -> None:
        super().__init__(
            status_code=status_code,
            method=method,
            path=path,
            details=details,
            message="Proxmox authentication failed.",
        )


class ProxmoxConnectionError(LabSentinelError):
    """Raised when Proxmox is unreachable or TLS/network fails."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)

    def __str__(self) -> str:
        return self.message
