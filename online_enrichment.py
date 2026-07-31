"""Hash-first online enrichment clients for REcluse."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

import requests


def sha256_file(path: str | Path) -> str:
    hasher = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class AbuseChClient:
    """Query-only MalwareBazaar, ThreatFox, and URLhaus enrichment."""

    def __init__(self, auth_key: str, *, timeout: int = 60, session: Any = None):
        if not auth_key.strip():
            raise ValueError("abuse.ch Auth-Key is required")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.headers = {"Auth-Key": auth_key.strip()}

    def _post(self, url: str, *, data: dict | None = None, json: dict | None = None):
        response = self.session.post(
            url, data=data, json=json, headers=self.headers, timeout=self.timeout
        )
        response.raise_for_status()
        return response.json()

    def enrich_hash(self, digest: str) -> dict:
        results = {}
        queries = {
            "malwarebazaar": (
                "https://mb-api.abuse.ch/api/v1/",
                {"query": "get_info", "hash": digest},
                None,
            ),
            "threatfox": (
                "https://threatfox-api.abuse.ch/api/v1/",
                None,
                {"query": "search_hash", "hash": digest},
            ),
            "urlhaus": (
                "https://urlhaus-api.abuse.ch/v1/payload/",
                {"sha256_hash": digest},
                None,
            ),
        }
        for name, (url, data, body) in queries.items():
            try:
                results[name] = {
                    "status": "complete",
                    "result": self._post(url, data=data, json=body),
                }
            except Exception as exc:
                results[name] = {"status": "failed", "error": str(exc)[:500]}
        return {"sha256": digest, "providers": results}


class UnpacMeClient:
    def __init__(
        self,
        api_key: str,
        *,
        timeout: int = 900,
        poll_interval: int = 10,
        private: bool = True,
        session: Any = None,
    ):
        if not api_key.strip():
            raise ValueError("UnpacMe API key is required")
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.private = private
        self.session = session or requests.Session()
        self.headers = {"Authorization": f"Key {api_key.strip()}"}
        self.base_url = "https://api.unpac.me/api/v1/private"

    def _json(self, response):
        response.raise_for_status()
        return response.json()

    def analyze(self, sample_path: str | Path) -> dict:
        path = Path(sample_path)
        with path.open("rb") as handle:
            submitted = self._json(self.session.post(
                f"{self.base_url}/upload/",
                params={"private": str(self.private).lower(), "mode": "analyze"},
                files={"file": (path.name, handle)},
                headers=self.headers,
                timeout=min(self.timeout, 120),
            ))
        unpack_id = str(submitted["id"])
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            status = self._json(self.session.get(
                f"{self.base_url}/status/{unpack_id}",
                headers=self.headers,
                timeout=min(self.timeout, 120),
            ))
            state = str(status.get("status", "")).lower()
            if state in {"complete", "completed", "finished", "success"}:
                result = self._json(self.session.get(
                    f"{self.base_url}/results/{unpack_id}",
                    headers=self.headers,
                    timeout=min(self.timeout, 120),
                ))
                return {"id": unpack_id, "private": self.private, "result": result}
            if state in {"failed", "error", "invalid"}:
                raise RuntimeError(f"UnpacMe analysis {unpack_id} ended with {state}")
            time.sleep(self.poll_interval)
        raise TimeoutError(f"UnpacMe analysis {unpack_id} timed out after {self.timeout}s")
