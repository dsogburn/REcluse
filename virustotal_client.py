"""Bounded VirusTotal API v3 client for optional sample enrichment."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

import requests


DEFAULT_URL = "https://www.virustotal.com/api/v3"
DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024
MAX_UPLOAD_BYTES = 650 * 1024 * 1024


class VirusTotalError(RuntimeError):
    pass


class VirusTotalClient:
    def __init__(
        self,
        api_key: str,
        *,
        timeout: int = 300,
        poll_interval: int = 15,
        base_url: str = DEFAULT_URL,
        session: Any = None,
    ):
        if not api_key.strip():
            raise ValueError("VirusTotal API key is required")
        if timeout < 1 or poll_interval < 1:
            raise ValueError("VirusTotal timeout and poll interval must be positive")
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update({
            "x-apikey": api_key.strip(),
            "Accept": "application/json",
        })

    def _request(self, method: str, url: str, **kwargs):
        kwargs.setdefault("timeout", min(self.timeout, 120))
        response = self.session.request(method, url, **kwargs)
        if response.status_code == 404:
            return None
        try:
            response.raise_for_status()
        except requests.RequestException as exc:
            detail = ""
            try:
                detail = response.json().get("error", {}).get("message", "")
            except (TypeError, ValueError):
                detail = response.text[:500]
            raise VirusTotalError(
                f"VirusTotal API returned HTTP {response.status_code}"
                + (f": {detail}" if detail else "")
            ) from exc
        try:
            return response.json()
        except ValueError as exc:
            raise VirusTotalError("VirusTotal returned a non-JSON response") from exc

    def get_file(self, file_hash: str) -> dict | None:
        return self._request("GET", f"{self.base_url}/files/{file_hash}")

    def _upload(self, sample_path: Path) -> str:
        size = sample_path.stat().st_size
        if size > MAX_UPLOAD_BYTES:
            raise VirusTotalError("VirusTotal public upload limit is 650 MiB")
        upload_url = f"{self.base_url}/files"
        if size > DIRECT_UPLOAD_LIMIT:
            descriptor = self._request("GET", f"{self.base_url}/files/upload_url")
            upload_url = descriptor.get("data", "") if descriptor else ""
            if not upload_url:
                raise VirusTotalError("VirusTotal did not return a large-file upload URL")
        with sample_path.open("rb") as handle:
            response = self._request(
                "POST",
                upload_url,
                files={"file": (sample_path.name, handle)},
            )
        try:
            return str(response["data"]["id"])
        except (KeyError, TypeError) as exc:
            raise VirusTotalError("VirusTotal upload response has no analysis ID") from exc

    def _wait_for_analysis(self, analysis_id: str) -> dict:
        deadline = time.monotonic() + self.timeout
        while True:
            response = self._request(
                "GET",
                f"{self.base_url}/analyses/{analysis_id}",
            )
            if not response:
                raise VirusTotalError("VirusTotal analysis was not found")
            status = response.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return response
            if status in {"failed", "error"}:
                raise VirusTotalError(f"VirusTotal analysis ended with status {status}")
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"VirusTotal analysis did not complete within {self.timeout} seconds"
                )
            time.sleep(self.poll_interval)

    def enrich(
        self,
        sample_path: str | Path,
        *,
        upload_missing: bool = False,
        allow_upload: bool = False,
    ) -> dict:
        path = Path(sample_path)
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
        digest = hasher.hexdigest()
        report = self.get_file(digest)
        if report is not None:
            return {
                "status": "found",
                "sha256": digest,
                "uploaded": False,
                "report": report,
            }
        if not upload_missing:
            return {
                "status": "not_found",
                "sha256": digest,
                "uploaded": False,
                "report": None,
            }
        if not allow_upload:
            raise ValueError(
                "VirusTotal public upload requires explicit sample-disclosure consent"
            )
        analysis_id = self._upload(path)
        analysis = self._wait_for_analysis(analysis_id)
        report = self.get_file(digest)
        if report is None:
            raise VirusTotalError(
                "VirusTotal analysis completed but the file report is unavailable"
            )
        return {
            "status": "uploaded",
            "sha256": digest,
            "uploaded": True,
            "analysis_id": analysis_id,
            "analysis": analysis,
            "report": report,
        }


def summarize_virustotal(result: dict) -> dict:
    """Return a small, model-facing subset while preserving the raw artifact."""
    report = result.get("report") or {}
    data = report.get("data") or {}
    attributes = data.get("attributes") or {}
    names = attributes.get("names") or []
    tags = attributes.get("tags") or []
    return {
        "status": result.get("status"),
        "sha256": result.get("sha256"),
        "uploaded": bool(result.get("uploaded")),
        "analysis_id": result.get("analysis_id"),
        "type_description": attributes.get("type_description"),
        "meaningful_name": attributes.get("meaningful_name"),
        "names": list(names)[:30] if isinstance(names, list) else [],
        "tags": list(tags)[:50] if isinstance(tags, list) else [],
        "reputation": attributes.get("reputation"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "last_analysis_stats": attributes.get("last_analysis_stats") or {},
        "popular_threat_classification": (
            attributes.get("popular_threat_classification") or {}
        ),
        "crowdsourced_yara_results": (
            attributes.get("crowdsourced_yara_results") or []
        )[:20],
    }
