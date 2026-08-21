"""Provider-neutral dynamic-analysis clients for local and hosted sandboxes."""

from __future__ import annotations

import json
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from cape_client import CapeClient, summarize_cape_report


PROVIDERS = {"cape", "anyrun", "joesandbox", "triage"}
JOE_DEFAULT_URL = "https://jbxcloud.joesecurity.org/api"


def validate_provider(value: str) -> str:
    provider = value.strip().lower()
    if provider not in PROVIDERS:
        raise ValueError(
            f"Unknown dynamic-analysis provider {value!r}; choose cape, anyrun, joesandbox, or triage"
        )
    return provider


def validate_providers(values: Any) -> list[str]:
    if isinstance(values, str):
        values = values.split(",")
    providers = []
    for value in values or []:
        if not str(value).strip():
            continue
        provider = validate_provider(str(value))
        if provider not in providers:
            providers.append(provider)
    return providers


def _json_object(value: Any) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    raise RuntimeError("Sandbox provider returned a non-object report")


def _find_first(value: Any, names: set[str]) -> Any:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower().replace("-", "_") in names and item not in (None, ""):
                return item
        for item in value.values():
            found = _find_first(item, names)
            if found not in (None, ""):
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_first(item, names)
            if found not in (None, ""):
                return found
    return None


class AnyRunClient:
    """Thin adapter over ANY.RUN's official anyrun-sdk package."""

    def __init__(self, api_key: str, *, timeout: int = 600, **_: Any):
        if not api_key.strip():
            raise ValueError("ANY.RUN requires an API key")
        self.api_key = api_key.strip()
        self.timeout = timeout

    def analyze(self, sample_path: str, **_: Any) -> tuple[str, dict]:
        try:
            from anyrun.connectors import SandboxConnector
        except ImportError as exc:
            raise RuntimeError(
                "ANY.RUN support requires the anyrun-sdk package; rerun scripts/setup.sh"
            ) from exc

        key = self.api_key
        if not key.lower().startswith(("api-key ", "basic ")):
            key = f"API-Key {key}"
        connector = SandboxConnector.windows(key, timeout=self.timeout)
        with connector:
            task_id = str(connector.run_file_analysis(filepath=str(Path(sample_path))))
            # The official status iterator closes after the task completes.
            for _status in connector.get_task_status(task_id):
                pass
            return task_id, _json_object(connector.get_analysis_report(task_id))


class JoeSandboxClient:
    """Thin adapter over Joe Security's official jbxapi package."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "",
        timeout: int = 600,
        poll_interval: int = 10,
        **_: Any,
    ):
        if not api_key.strip():
            raise ValueError("Joe Sandbox requires an API key")
        self.api_key = api_key.strip()
        self.base_url = (base_url or JOE_DEFAULT_URL).rstrip("/")
        self.timeout = timeout
        self.poll_interval = poll_interval

    def analyze(self, sample_path: str, **_: Any) -> tuple[str, dict]:
        try:
            import jbxapi
        except ImportError as exc:
            raise RuntimeError(
                "Joe Sandbox support requires the jbxapi package; rerun scripts/setup.sh"
            ) from exc

        joe = jbxapi.JoeSandbox(
            apikey=self.api_key,
            apiurl=self.base_url,
            accept_tac=True,
            timeout=min(self.timeout, 120),
            user_agent="REcluse",
        )
        path = Path(sample_path)
        with path.open("rb") as sample:
            submitted = joe.submit_sample((path.name, sample))
        submission_id = _find_first(submitted, {"submission_id", "submissionid", "id"})
        if submission_id is None:
            raise RuntimeError(f"Joe Sandbox did not return a submission ID: {submitted}")

        deadline = time.monotonic() + self.timeout
        webid = None
        last_state = "submitted"
        while time.monotonic() < deadline:
            info = joe.submission_info(submission_id)
            webid = _find_first(info, {"webid", "web_id", "analysis_id"})
            state = _find_first(info, {"status", "state"})
            if state is not None:
                last_state = str(state).lower()
            if webid is not None:
                break
            if any(word in last_state for word in ("failed", "error", "rejected")):
                raise RuntimeError(
                    f"Joe Sandbox submission {submission_id} ended with status {last_state}"
                )
            time.sleep(self.poll_interval)
        if webid is None:
            raise TimeoutError(
                f"Joe Sandbox submission {submission_id} was not assigned an analysis "
                f"within {self.timeout}s (last status: {last_state})"
            )

        while time.monotonic() < deadline:
            info = joe.analysis_info(webid)
            state = _find_first(info, {"status", "state"})
            last_state = str(state or "unknown").lower()
            if any(word in last_state for word in ("finished", "completed", "done")):
                _name, report = joe.analysis_download(webid, "jsonfixed")
                return str(webid), _json_object(report)
            if any(word in last_state for word in ("failed", "error", "rejected")):
                raise RuntimeError(
                    f"Joe Sandbox analysis {webid} ended with status {last_state}"
                )
            time.sleep(self.poll_interval)
        raise TimeoutError(
            f"Joe Sandbox analysis {webid} did not finish within {self.timeout}s "
            f"(last status: {last_state})"
        )


class TriageClient:
    """Hash-first client for Recorded Future Triage public or private cloud."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "https://tria.ge/api/v0",
        timeout: int = 900,
        poll_interval: int = 10,
        allow_upload: bool = False,
        **_: Any,
    ):
        if not api_key.strip():
            raise ValueError("Triage requires an API key")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.allow_upload = allow_upload
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {api_key.strip()}"})

    def _json(self, response):
        response.raise_for_status()
        return response.json()

    def _existing(self, digest: str) -> tuple[str, dict] | None:
        response = self.session.get(
            f"{self.base_url}/search",
            params={"query": f"sha256:{digest}"},
            timeout=min(self.timeout, 120),
        )
        data = self._json(response).get("data") or []
        if not data:
            return None
        sample_id = str(data[0]["id"])
        summary = self._json(self.session.get(
            f"{self.base_url}/samples/{sample_id}/summary",
            timeout=min(self.timeout, 120),
        ))
        return sample_id, {"source": "hash_lookup", "summary": summary}

    def analyze(self, sample_path: str, **_: Any) -> tuple[str, dict]:
        path = Path(sample_path)
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
        existing = self._existing(hasher.hexdigest())
        if existing:
            return existing
        if not self.allow_upload:
            return "not-found", {
                "source": "hash_lookup",
                "status": "not_found",
                "sha256": hasher.hexdigest(),
            }
        with path.open("rb") as handle:
            submitted = self._json(self.session.post(
                f"{self.base_url}/samples",
                files={"file": (path.name, handle)},
                timeout=min(self.timeout, 120),
            ))
        sample_id = str(submitted["id"])
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            sample = self._json(self.session.get(
                f"{self.base_url}/samples/{sample_id}",
                timeout=min(self.timeout, 120),
            ))
            status = sample.get("status")
            if status == "reported":
                summary = self._json(self.session.get(
                    f"{self.base_url}/samples/{sample_id}/summary",
                    timeout=min(self.timeout, 120),
                ))
                return sample_id, {"source": "upload", "summary": summary}
            if status == "failed":
                raise RuntimeError(f"Triage sample {sample_id} failed")
            time.sleep(self.poll_interval)
        raise TimeoutError(f"Triage sample {sample_id} timed out after {self.timeout}s")


class MultiSandboxClient:
    """Run independent sandbox providers concurrently and retain partial results."""

    def __init__(self, clients: dict[str, Any]):
        if not clients:
            raise ValueError("Select at least one dynamic-analysis provider")
        self.clients = clients

    def analyze(self, sample_path: str, **kwargs: Any) -> tuple[dict, dict]:
        task_ids = {}
        results = {}
        with ThreadPoolExecutor(max_workers=len(self.clients)) as executor:
            futures = {
                executor.submit(client.analyze, sample_path, **kwargs): provider
                for provider, client in self.clients.items()
            }
            for future in as_completed(futures):
                provider = futures[future]
                try:
                    task_id, report = future.result()
                    task_ids[provider] = task_id
                    results[provider] = {"status": "complete", "report": report}
                except Exception as exc:
                    results[provider] = {
                        "status": "failed",
                        "error": str(exc)[:1000],
                    }
        if not any(item["status"] == "complete" for item in results.values()):
            errors = "; ".join(
                f"{provider}: {item.get('error', 'failed')}"
                for provider, item in results.items()
            )
            raise RuntimeError(f"All selected sandbox providers failed: {errors}")
        return task_ids, {"providers": results}


def create_sandbox_client(
    provider: str,
    *,
    url: str,
    api_key: str,
    timeout: int,
    poll_interval: int,
    allow_remote: bool,
    upload_allowed: Any = True,
):
    providers = validate_providers(provider)
    if len(providers) > 1:
        urls = url if isinstance(url, dict) else {}
        keys = api_key if isinstance(api_key, dict) else {}
        return MultiSandboxClient({
            selected: create_sandbox_client(
                selected,
                url=urls.get(selected, ""),
                api_key=keys.get(selected, ""),
                timeout=timeout,
                poll_interval=poll_interval,
                allow_remote=allow_remote,
                upload_allowed=(
                    upload_allowed.get(selected, False)
                    if isinstance(upload_allowed, dict) else bool(upload_allowed)
                ),
            )
            for selected in providers
        })
    if not providers:
        raise ValueError("Select at least one dynamic-analysis provider")
    provider = providers[0]
    provider_upload_allowed = (
        bool(upload_allowed.get(provider, False))
        if isinstance(upload_allowed, dict) else bool(upload_allowed)
    )
    if provider in {"anyrun", "joesandbox"} and not allow_remote:
        raise ValueError(
            "Hosted sandbox submission is disabled; enable remote disclosure only "
            "after approving upload of sample bytes to the selected provider"
        )
    if provider == "cape":
        return CapeClient(
            url,
            api_key,
            timeout=timeout,
            poll_interval=poll_interval,
            allow_remote=allow_remote,
        )
    if provider == "anyrun":
        return AnyRunClient(api_key, timeout=timeout)
    if provider == "joesandbox":
        return JoeSandboxClient(
        api_key,
        base_url="" if url == "http://127.0.0.1:8000" else url,
        timeout=timeout,
        poll_interval=poll_interval,
        )
    return TriageClient(
        api_key,
        base_url=url or "https://tria.ge/api/v0",
        timeout=timeout,
        poll_interval=poll_interval,
        allow_upload=provider_upload_allowed,
    )


def summarize_sandbox_report(
    report: dict,
    task_id: Any,
    provider: str,
    *,
    noise_domains: Any = None,
    noise_ips: Any = None,
) -> dict:
    providers = validate_providers(provider)
    if len(providers) > 1:
        raw_results = report.get("providers") or {}
        summaries = {}
        for selected in providers:
            result = raw_results.get(selected) or {}
            if result.get("status") == "complete":
                summaries[selected] = {
                    "status": "complete",
                    "summary": summarize_sandbox_report(
                        result.get("report") or {},
                        (task_id or {}).get(selected),
                        selected,
                        noise_domains=noise_domains,
                        noise_ips=noise_ips,
                    ),
                }
            else:
                summaries[selected] = {
                    "status": "failed",
                    "error": result.get("error", "Provider failed"),
                }
        combined = {"backend": "multiple", "providers": summaries}
        cape_summary = summaries.get("cape", {}).get("summary")
        if isinstance(cape_summary, dict):
            combined = {**cape_summary, **combined}
        return combined
    provider = providers[0]
    if provider == "cape":
        return summarize_cape_report(
            report,
            task_id,
            noise_domains=noise_domains,
            noise_ips=noise_ips,
        )

    summary = {
        "backend": {
            "anyrun": "ANY.RUN", "joesandbox": "Joe Sandbox",
            "triage": "Recorded Future Triage",
        }[provider],
        "task_id": str(task_id),
        "verdict": _find_first(report, {"verdict", "status", "detection"}),
        "score": _find_first(report, {"score", "threat_score", "malicious_score"}),
        "report": report,
    }
    encoded = json.dumps(summary, ensure_ascii=False, default=str)
    if len(encoded) > 120_000:
        summary["report"] = encoded[:110_000] + "\n[provider report truncated]"
        summary["truncated"] = True
    return summary
