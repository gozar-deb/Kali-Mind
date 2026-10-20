"""Feature #30: Metasploit RPC client for structured exploit integration."""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import httpx


class MetasploitClient:
    """
    Connects to Metasploit's MSGRPC API (msfrpcd).
    Start msfrpcd first: msfrpcd -P password -S -a 127.0.0.1

    IMPORTANT: Only use against authorized targets in lab environments.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        password: Optional[str] = None,
        ssl: bool = False,
    ) -> None:
        scheme = "https" if ssl else "http"
        self.base_url = f"{scheme}://{host}:{port}/api/v1"
        self.password = password if password is not None else os.getenv("MSF_RPC_PASSWORD", "")
        self.verify_tls = bool(ssl)
        self._token: Optional[str] = None

    async def authenticate(self) -> bool:
        if not self.password:
            return False
        try:
            async with httpx.AsyncClient(verify=self.verify_tls, timeout=10) as client:
                resp = await client.post(
                    f"{self.base_url}/auth/login",
                    json={"username": "msf", "password": self.password},
                )
                if resp.status_code == 200:
                    self._token = resp.json().get("token")
                    return self._token is not None
        except Exception:
            pass
        return False

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    async def list_modules(self, module_type: str = "exploit") -> List[str]:
        """List available modules."""
        if not self._token:
            raise RuntimeError("Not authenticated. Call authenticate() first.")
        async with httpx.AsyncClient(verify=self.verify_tls, timeout=30) as client:
            resp = await client.get(
                f"{self.base_url}/modules/{module_type}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json().get("modules", [])

    async def search_modules(self, query: str) -> List[Dict[str, Any]]:
        """Search modules by keyword."""
        if not self._token:
            raise RuntimeError("Not authenticated.")
        async with httpx.AsyncClient(verify=self.verify_tls, timeout=30) as client:
            resp = await client.get(
                f"{self.base_url}/modules/search",
                headers=self._headers(),
                params={"query": query},
            )
            resp.raise_for_status()
            return resp.json().get("modules", [])

    async def run_module(
        self,
        module_type: str,
        module_name: str,
        options: Dict[str, Any],
        authorized_target: str,
        *,
        approved: bool = False,
    ) -> Dict[str, Any]:
        """
        Run a Metasploit module against an authorized target.
        The authorized_target parameter is explicit to enforce scope awareness.
        """
        if not self._token:
            raise RuntimeError("Not authenticated.")
        if not approved:
            raise PermissionError(
                "Metasploit module execution requires explicit approval=True; "
                "this operation can execute exploit code on the target"
            )

        from kali_mind.security.scope import get_scope_manager
        in_scope, reason = get_scope_manager().is_in_scope(authorized_target)
        if not in_scope:
            raise PermissionError(f"Metasploit execution denied by scope policy: {reason}")

        options = dict(options)
        options["RHOSTS"] = authorized_target
        payload = {
            "moduleType": module_type,
            "moduleName": module_name,
            "dataStoreOptions": options,
        }
        async with httpx.AsyncClient(verify=self.verify_tls, timeout=120) as client:
            resp = await client.post(
                f"{self.base_url}/modules/execute",
                headers=self._headers(),
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()

    async def list_sessions(self) -> List[Dict[str, Any]]:
        """List active Metasploit sessions."""
        if not self._token:
            raise RuntimeError("Not authenticated.")
        async with httpx.AsyncClient(verify=self.verify_tls, timeout=10) as client:
            resp = await client.get(
                f"{self.base_url}/sessions",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json().get("sessions", [])

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(verify=self.verify_tls, timeout=5) as client:
                resp = await client.get(f"{self.base_url}/version")
                return resp.status_code == 200
        except Exception:
            return False
