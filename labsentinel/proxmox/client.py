"""Proxmox API client using ticket/cookie authentication."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import requests
import urllib3
from requests import Response, Session
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import ReadTimeout, RequestException, SSLError
from urllib3.exceptions import InsecureRequestWarning

from labsentinel.exceptions import ProxmoxApiError, ProxmoxAuthError, ProxmoxConnectionError


class ProxmoxClient:
    """Minimal Proxmox API client using the ticket/cookie flow."""

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        realm: Optional[str] = None,
        otp: Optional[str] = None,
        verify_tls: bool = True,
        timeout: int = 5,
    ) -> None:
        self.host = host.strip()
        self.user = user.strip()
        self.password = password
        self.realm = realm.strip() if realm else None
        self.otp = otp
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session: Session = requests.Session()
        self.csrf_token: Optional[str] = None
        if not self.verify_tls:
            urllib3.disable_warnings(InsecureRequestWarning)

    @property
    def _api_base(self) -> str:
        return f"https://{self.host}:8006/api2/json"

    @property
    def _auth_username(self) -> str:
        if "@" in self.user:
            return self.user
        if self.realm:
            return f"{self.user}@{self.realm}"
        return self.user

    def login(self) -> Dict[str, Any]:
        """Authenticate and store ticket cookie + CSRF token."""
        auth_path = "/access/ticket"
        payload: Dict[str, str] = {
            "username": self._auth_username,
            "password": self.password,
        }
        if self.otp:
            payload["otp"] = self.otp

        try:
            body, response = self.request("POST", auth_path, data=payload)
        except SSLError as exc:
            raise ProxmoxConnectionError(
                "TLS verification failed when connecting to Proxmox. Use --insecure to skip cert verification."
            ) from exc
        except ProxmoxApiError as exc:
            if exc.status_code in (401, 403):
                raise ProxmoxAuthError(
                    status_code=exc.status_code,
                    method=exc.method,
                    path=exc.path,
                    details=exc.details,
                ) from exc
            raise

        data = body if isinstance(body, dict) else {}
        ticket = data.get("ticket")
        self.csrf_token = data.get("CSRFPreventionToken")

        if not ticket:
            raise ProxmoxAuthError(
                status_code=response.status_code,
                method="POST",
                path=auth_path,
                details=self._truncate_response_text(response.text),
            )

        if "PVEAuthCookie" not in self.session.cookies:
            self.session.cookies.set("PVEAuthCookie", ticket)

        return data

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Any, Response]:
        """Perform an authenticated API request and return `(data, response)`."""
        normalized_method = method.upper()
        normalized_path = path if path.startswith("/") else f"/{path}"
        url = f"{self._api_base}{normalized_path}"

        headers: Dict[str, str] = {}
        if normalized_method in {"POST", "PUT", "DELETE"} and self.csrf_token:
            headers["CSRFPreventionToken"] = self.csrf_token

        try:
            response = self.session.request(
                method=normalized_method,
                url=url,
                params=params,
                data=data,
                headers=headers or None,
                verify=self.verify_tls,
                timeout=(self.timeout, self.timeout),
            )
        except SSLError as exc:
            raise ProxmoxConnectionError(
                "TLS verification failed when connecting to Proxmox. Use --insecure to skip cert verification."
            ) from exc
        except ReadTimeout as exc:
            raise ProxmoxConnectionError(
                f"Timed out while calling Proxmox API {normalized_method} {normalized_path}."
            ) from exc
        except RequestsConnectionError as exc:
            raise ProxmoxConnectionError(
                f"Connection failed while calling Proxmox API {normalized_method} {normalized_path}."
            ) from exc
        except RequestException as exc:
            raise ProxmoxConnectionError(
                f"Request failed while calling Proxmox API {normalized_method} {normalized_path}: {exc}"
            ) from exc

        if not response.ok:
            raise ProxmoxApiError(
                status_code=response.status_code,
                method=normalized_method,
                path=normalized_path,
                details=self._truncate_response_text(response.text),
                message="Proxmox API request returned an error response.",
            )

        payload = self._parse_json(response, method=normalized_method, path=normalized_path)
        return payload.get("data"), response

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Perform authenticated GET and return parsed `data`."""
        data, _ = self.request("GET", path, params=params)
        return data

    def post(self, path: str, data: Optional[Dict[str, Any]] = None) -> Any:
        """Perform authenticated POST and return parsed `data`."""
        response_data, _ = self.request("POST", path, data=data)
        return response_data

    @staticmethod
    def _parse_json(response: Response, *, method: str, path: str) -> Dict[str, Any]:
        try:
            parsed = response.json()
        except ValueError as exc:
            raise ProxmoxApiError(
                status_code=response.status_code,
                method=method,
                path=path,
                details=f"Invalid JSON: {ProxmoxClient._truncate_response_text(response.text)}",
                message="Proxmox API response parsing failed.",
            ) from exc
        if not isinstance(parsed, dict):
            raise ProxmoxApiError(
                status_code=response.status_code,
                method=method,
                path=path,
                details=f"Invalid JSON shape: {ProxmoxClient._truncate_response_text(response.text)}",
                message="Proxmox API response parsing failed.",
            )
        return parsed

    @staticmethod
    def _truncate_response_text(response_text: Optional[str]) -> str:
        text = (response_text or "").strip()
        if len(text) <= 500:
            return text
        return f"{text[:500]}..."
