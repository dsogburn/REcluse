"""Local web interface for REcluse malware triage."""

import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from urllib.parse import urlencode, urlparse

from cape_client import validate_cape_url
from sandbox_client import validate_provider, validate_providers


PROJECT_DIR = Path(__file__).resolve().parent
STATIC_DIR = PROJECT_DIR / "web"
DEFAULT_REPORTS_DIR = PROJECT_DIR / "reports"
CONDUCTOR = PROJECT_DIR / "conductor.py"
PYTHON = PROJECT_DIR / "venv" / "bin" / "python"
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024
MAX_LOG_LINES = 4000
JOB_MANIFEST = ".recluse-job.json"
JOB_INDEX = DEFAULT_REPORTS_DIR / ".recluse-web-jobs.json"

app = FastAPI(
    title="REcluse API",
    description=(
        "Submit suspicious samples to REcluse, monitor isolated analysis jobs, "
        "and retrieve generated artifacts. This service is intended for local, "
        "trusted integrations."
    ),
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)
executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="recluse-analysis")
jobs = {}
jobs_lock = threading.RLock()


@app.middleware("http")
async def prevent_stale_web_assets(request, call_next):
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.endswith((".html", ".js", ".css")):
        response.headers["Cache-Control"] = "no-store"
    return response


class SettingsUpdate(BaseModel):
    model: str = Field(min_length=1, max_length=300)
    api_base_url: str = Field(default="", max_length=2000)
    api_key: str = Field(default="", max_length=10000)
    clear_api_key: bool = False
    reports_dir: str = Field(min_length=1, max_length=4000)
    archive_password: str = Field(default="infected", max_length=1000)
    max_turns: int = Field(default=20, ge=1, le=200)
    max_tool_errors: int = Field(default=5, ge=1, le=100)
    dynamic_enabled: bool = False
    dynamic_provider: str = Field(default="cape", max_length=30)
    dynamic_providers: list[str] = Field(default_factory=list)
    dynamic_url: str = Field(default="http://127.0.0.1:8000", max_length=2000)
    dynamic_token: str = Field(default="", max_length=10000)
    clear_dynamic_token: bool = False
    cape_url: str = Field(default="http://127.0.0.1:8000", max_length=2000)
    cape_token: str = Field(default="", max_length=10000)
    clear_cape_token: bool = False
    anyrun_api_key: str = Field(default="", max_length=10000)
    clear_anyrun_api_key: bool = False
    joesandbox_url: str = Field(default="", max_length=2000)
    joesandbox_api_key: str = Field(default="", max_length=10000)
    clear_joesandbox_api_key: bool = False
    triage_url: str = Field(default="https://tria.ge/api/v0", max_length=2000)
    triage_api_key: str = Field(default="", max_length=10000)
    clear_triage_api_key: bool = False
    dynamic_timeout: int = Field(default=1800, ge=30, le=86400)
    dynamic_poll_interval: int = Field(default=10, ge=1, le=300)
    dynamic_machine: str = Field(default="", max_length=200)
    dynamic_package: str = Field(default="", max_length=200)
    dynamic_allow_remote: bool = False
    remnux_enabled: bool = True
    remnux_depth: str = Field(default="deep", pattern="^(quick|standard|deep)$")
    remnux_timeout: int = Field(default=900, ge=30, le=3600)
    virustotal_enabled: bool = False
    virustotal_api_key: str = Field(default="", max_length=10000)
    clear_virustotal_api_key: bool = False
    virustotal_upload_missing: bool = False
    virustotal_allow_upload: bool = False
    virustotal_timeout: int = Field(default=300, ge=30, le=86400)
    virustotal_poll_interval: int = Field(default=15, ge=1, le=300)
    abusech_enabled: bool = False
    abusech_auth_key: str = Field(default="", max_length=10000)
    clear_abusech_auth_key: bool = False
    unpacme_enabled: bool = False
    unpacme_api_key: str = Field(default="", max_length=10000)
    clear_unpacme_api_key: bool = False
    unpacme_private: bool = True
    unpacme_timeout: int = Field(default=900, ge=30, le=86400)
    unpacme_poll_interval: int = Field(default=10, ge=1, le=300)
    verbose: bool = False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def public_job(job: dict) -> dict:
    with jobs_lock:
        public_parameters = {
            key: value
            for key, value in job["parameters"].items()
            if key not in {
                "api_key", "dynamic_token", "dynamic_tokens", "virustotal_api_key",
                "abusech_auth_key", "unpacme_api_key",
            }
        }
        public_parameters["api_key_override"] = bool(job["parameters"].get("api_key"))
        public_parameters["dynamic_token_configured"] = bool(
            job["parameters"].get("dynamic_token")
            or job["parameters"].get("dynamic_tokens")
        )
        public_parameters["virustotal_api_key_configured"] = bool(
            job["parameters"].get("virustotal_api_key")
        )
        return {
            "id": job["id"],
            "filename": job["filename"],
            "status": job["status"],
            "created_at": job["created_at"],
            "started_at": job.get("started_at"),
            "finished_at": job.get("finished_at"),
            "return_code": job.get("return_code"),
            "parameters": public_parameters,
            "report_dir": str(job["report_dir"]),
            "log": list(job["log"]),
            "artifacts": list(job.get("artifacts", [])),
            "error": job.get("error"),
        }


def append_log(job: dict, line: str) -> None:
    with jobs_lock:
        job["log"].append(line.rstrip())


def job_status_from_return_code(return_code: int) -> str:
    if return_code == 0:
        return "completed"
    if return_code == 2:
        return "completed_with_warnings"
    return "failed"


def has_successful_report(job: dict) -> bool:
    report_dir = Path(job["report_dir"]).resolve()
    for artifact in job.get("artifacts", []):
        if artifact.get("kind") != "report":
            continue
        try:
            path = (report_dir / artifact["path"]).resolve()
            path.relative_to(report_dir)
            report = json.loads(path.read_text())
        except (OSError, ValueError, TypeError, KeyError):
            continue
        if (report.get("analysis") or {}).get("status") == "complete":
            return True
    return False


def _write_json_atomic(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")
    os.replace(temporary, path)


def _persisted_job(job: dict) -> dict:
    parameters = {
        key: value
        for key, value in job["parameters"].items()
        if key not in {
            "api_key", "dynamic_token", "dynamic_tokens", "virustotal_api_key",
            "abusech_auth_key", "unpacme_api_key",
        }
    }
    return {
        "schema_version": 1,
        "id": job["id"],
        "filename": job["filename"],
        "status": job["status"],
        "created_at": job["created_at"],
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "return_code": job.get("return_code"),
        "parameters": parameters,
        "log": list(job.get("log", [])),
        "error": job.get("error"),
    }


def persist_job(job: dict) -> None:
    with jobs_lock:
        report_dir = Path(job["report_dir"]).resolve()
        manifest = _persisted_job(job)
        known_paths = set()
        try:
            known_paths.update(json.loads(JOB_INDEX.read_text()))
        except (OSError, ValueError, TypeError):
            pass
        known_paths.add(str(report_dir))
        _write_json_atomic(report_dir / JOB_MANIFEST, manifest)
        _write_json_atomic(JOB_INDEX, sorted(known_paths))


def remove_job_from_index(report_dir: Path) -> None:
    with jobs_lock:
        try:
            known_paths = set(json.loads(JOB_INDEX.read_text()))
        except (OSError, ValueError, TypeError):
            known_paths = set()
        known_paths.discard(str(report_dir.resolve()))
        _write_json_atomic(JOB_INDEX, sorted(known_paths))


def _legacy_job(report_dir: Path, job_id: str) -> dict | None:
    reports = sorted(report_dir.glob("*.report.json"))
    if not reports:
        return None
    report_path = reports[0]
    try:
        report = json.loads(report_path.read_text())
    except (OSError, ValueError, TypeError):
        report = {}
    sample = report.get("sample") or {}
    analysis = report.get("analysis") or {}
    analysis_status = analysis.get("status")
    status = "completed" if analysis_status == "complete" else "failed"
    timestamp = datetime.fromtimestamp(
        report_path.stat().st_mtime, timezone.utc
    ).isoformat()
    return {
        "id": job_id,
        "filename": sample.get("member_name") or report_path.name.removesuffix(".report.json"),
        "status": status,
        "created_at": timestamp,
        "started_at": None,
        "finished_at": timestamp,
        "return_code": 0 if status == "completed" else 1,
        "parameters": {"model": analysis.get("model") or "unknown"},
        "log": deque(["Recovered from persisted report artifacts."], maxlen=MAX_LOG_LINES),
        "artifacts": [],
        "report_dir": report_dir,
        "error": None,
    }


def load_persisted_jobs() -> None:
    candidates = set()
    roots = {DEFAULT_REPORTS_DIR.resolve()}
    configured_root = Path(configured_defaults()["reports_dir"]).expanduser()
    if not configured_root.is_absolute():
        configured_root = PROJECT_DIR / configured_root
    roots.add(configured_root.resolve())
    for root in roots:
        if root.is_dir():
            candidates.update(path.resolve() for path in root.glob("web-*") if path.is_dir())
    try:
        candidates.update(Path(path).resolve() for path in json.loads(JOB_INDEX.read_text()))
    except (OSError, ValueError, TypeError):
        pass

    for report_dir in candidates:
        if not report_dir.is_dir() or not report_dir.name.startswith("web-"):
            continue
        job_id = report_dir.name.removeprefix("web-")
        manifest_path = report_dir / JOB_MANIFEST
        persisted = None
        try:
            persisted = json.loads(manifest_path.read_text())
        except (OSError, ValueError, TypeError):
            pass
        if isinstance(persisted, dict) and persisted.get("id") == job_id:
            status = persisted.get("status", "failed")
            if status in {"queued", "running"}:
                status = "failed"
                persisted["error"] = "Analysis was interrupted by a WebGUI restart"
                persisted["finished_at"] = utc_now()
            job = {
                **persisted,
                "status": status,
                "parameters": persisted.get("parameters") or {"model": "unknown"},
                "log": deque(persisted.get("log") or [], maxlen=MAX_LOG_LINES),
                "artifacts": [],
                "report_dir": report_dir,
            }
        else:
            job = _legacy_job(report_dir, job_id)
        if job is None:
            continue
        collect_artifacts(job)
        if job["status"] == "failed" and has_successful_report(job):
            job["status"] = "completed_with_warnings"
            job["return_code"] = 2
        with jobs_lock:
            jobs[job_id] = job
        persist_job(job)


def collect_artifacts(job: dict) -> None:
    artifacts = []
    report_dir = job["report_dir"]
    if report_dir.exists():
        member_verdicts = {}
        for report_path in report_dir.rglob("*.report.json"):
            try:
                report_data = json.loads(report_path.read_text())
                member = str(
                    (report_data.get("sample") or {}).get("member_name")
                    or report_path.name.removesuffix(".report.json")
                )
                member_verdicts[member] = str(
                    (report_data.get("triage") or {}).get("verdict") or "unknown"
                ).lower()
            except (OSError, ValueError, TypeError):
                continue
        for path in sorted(report_dir.rglob("*")):
            if not path.is_file():
                continue
            if path.name == JOB_MANIFEST:
                continue
            relative = path.relative_to(report_dir)
            kind = "file"
            if path.name.endswith(".report.json"):
                kind = "report"
            elif path.name.endswith(".transcript.json"):
                kind = "transcript"
            elif path.name.endswith(".deobfuscated.txt"):
                kind = "deobfuscated"
            elif ".decoded." in path.name:
                kind = "decoded"
            elif ".dynamic." in path.name and path.name.endswith(".json"):
                kind = "dynamic"
            elif path.name.endswith(".remnux.json"):
                kind = "remnux"
            elif path.name.endswith(".virustotal.json"):
                kind = "virustotal"
            elif path.name.endswith(".abusech.json"):
                kind = "reputation"
            elif path.name.endswith(".unpacme.json"):
                kind = "unpacking"
            elif path.name.endswith(".package.json"):
                kind = "package"
            member_name = path.name
            for suffix in (
                ".report.json", ".transcript.json", ".remnux.json",
                ".virustotal.json", ".abusech.json", ".unpacme.json",
                ".deobfuscated.txt",
            ):
                if member_name.endswith(suffix):
                    member_name = member_name[:-len(suffix)]
                    break
            member_name = re.sub(
                r"\.dynamic(?:\.[^.]+)?\.json$|\.decoded\.[^.]+$", "",
                member_name,
                flags=re.IGNORECASE,
            )
            artifacts.append({
                "name": path.name,
                "path": relative.as_posix(),
                "kind": kind,
                "size": path.stat().st_size,
                "member_name": member_name,
                "verdict": member_verdicts.get(member_name),
            })
    with jobs_lock:
        job["artifacts"] = artifacts


def run_analysis(job: dict) -> None:
    with jobs_lock:
        job["status"] = "running"
        job["started_at"] = utc_now()
    persist_job(job)

    parameters = job["parameters"]
    command = [
        str(PYTHON),
        "-u",
        str(CONDUCTOR),
        str(job["upload_path"]),
        "--password",
        parameters["password"],
        "--model",
        parameters["model"],
        "--reports-dir",
        str(job["report_dir"]),
        "--max-turns",
        str(parameters["max_turns"]),
        "--max-tool-errors",
        str(parameters["max_tool_errors"]),
    ]
    if parameters.get("api_key"):
        command.extend(["--api-key", parameters["api_key"]])
    command.extend([
        "--remnux" if parameters.get("remnux_enabled") else "--no-remnux",
        "--remnux-depth", parameters["remnux_depth"],
        "--remnux-timeout", str(parameters["remnux_timeout"]),
    ])
    command.extend([
        "--abusech" if parameters.get("abusech_enabled") else "--no-abusech",
        "--unpacme" if parameters.get("unpacme_enabled") else "--no-unpacme",
        "--unpacme-upload" if parameters.get("unpacme_upload") else "--no-unpacme-upload",
        "--unpacme-private" if parameters.get("unpacme_private") else "--no-unpacme-private",
        "--unpacme-timeout", str(parameters["unpacme_timeout"]),
        "--unpacme-poll-interval", str(parameters["unpacme_poll_interval"]),
    ])
    command.extend([
        "--virustotal" if parameters.get("virustotal_enabled") else "--no-virustotal",
        (
            "--virustotal-upload-missing"
            if parameters.get("virustotal_upload_missing")
            else "--no-virustotal-upload-missing"
        ),
        (
            "--virustotal-allow-upload"
            if parameters.get("virustotal_allow_upload")
            else "--no-virustotal-allow-upload"
        ),
        "--virustotal-timeout", str(parameters["virustotal_timeout"]),
        "--virustotal-poll-interval",
        str(parameters["virustotal_poll_interval"]),
    ])
    command.append("--dynamic" if parameters.get("dynamic_enabled") else "--no-dynamic")
    if parameters.get("dynamic_enabled"):
        command.extend([
            "--dynamic-provider", ",".join(parameters["dynamic_providers"]),
            "--dynamic-url", parameters["dynamic_url"],
            "--dynamic-timeout", str(parameters["dynamic_timeout"]),
            "--dynamic-poll-interval", str(parameters["dynamic_poll_interval"]),
        ])
        if parameters.get("dynamic_machine"):
            command.extend(["--dynamic-machine", parameters["dynamic_machine"]])
        if parameters.get("dynamic_package"):
            command.extend(["--dynamic-package", parameters["dynamic_package"]])
        command.append(
            "--dynamic-allow-remote"
            if parameters.get("dynamic_allow_remote")
            else "--no-dynamic-allow-remote"
        )
    command.append("--verbose" if parameters.get("verbose") else "--no-verbose")

    append_log(job, f"$ REcluse analysis started for {job['filename']}")
    try:
        child_env = os.environ.copy()
        if parameters.get("dynamic_token"):
            child_env["RECLUSE_DYNAMIC_TOKEN"] = parameters["dynamic_token"]
        if parameters.get("virustotal_api_key"):
            child_env["RECLUSE_VIRUSTOTAL_API_KEY"] = parameters["virustotal_api_key"]
        if parameters.get("abusech_auth_key"):
            child_env["RECLUSE_ABUSECH_AUTH_KEY"] = parameters["abusech_auth_key"]
        if parameters.get("unpacme_api_key"):
            child_env["RECLUSE_UNPACME_API_KEY"] = parameters["unpacme_api_key"]
        child_env["RECLUSE_DYNAMIC_UPLOAD_PROVIDERS"] = ",".join(
            parameters.get("dynamic_upload_providers") or []
        )
        process = subprocess.Popen(
            command,
            cwd=PROJECT_DIR,
            env=child_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            bufsize=1,
        )
        with jobs_lock:
            job["process_id"] = process.pid
        assert process.stdout is not None
        for line in process.stdout:
            append_log(job, line)
        return_code = process.wait()
        collect_artifacts(job)
        with jobs_lock:
            job["return_code"] = return_code
            job["status"] = job_status_from_return_code(return_code)
            if job["status"] == "failed" and has_successful_report(job):
                job["status"] = "completed_with_warnings"
                job["return_code"] = 2
    except Exception as exc:
        append_log(job, f"Web runner error: {exc}")
        with jobs_lock:
            job["status"] = "failed"
            job["error"] = str(exc)
            job["return_code"] = -1
    finally:
        with jobs_lock:
            job["finished_at"] = utc_now()
        persist_job(job)
        shutil.rmtree(job["upload_dir"], ignore_errors=True)


def read_config() -> dict:
    config = {}
    try:
        config.update(json.loads((PROJECT_DIR / "config.json").read_text()))
    except (OSError, json.JSONDecodeError):
        pass
    return config


def configured_defaults() -> dict:
    config = read_config()
    return {
        "model": config.get("model", ""),
        "api_base_url": config.get("api_base_url", ""),
        "reports_dir": config.get("reports_dir") or str(DEFAULT_REPORTS_DIR),
        "password": config.get("archive_password", "infected"),
        "max_turns": int(config.get("max_turns", 20)),
        "max_tool_errors": int(config.get("max_tool_errors", 5)),
        "dynamic_enabled": bool(config.get("dynamic_enabled", False)),
        "dynamic_provider": config.get("dynamic_provider", "cape"),
        "dynamic_providers": (
            list(config.get("dynamic_providers") or [])
            if "dynamic_providers" in config
            else (
                [config.get("dynamic_provider", "cape")]
                if config.get("dynamic_enabled", False) else []
            )
        ),
        "dynamic_url": config.get("dynamic_url", "http://127.0.0.1:8000"),
        "dynamic_urls": dict(config.get("dynamic_urls") or {}),
        "dynamic_timeout": int(config.get("dynamic_timeout", 1800)),
        "dynamic_poll_interval": int(config.get("dynamic_poll_interval", 10)),
        "dynamic_machine": config.get("dynamic_machine", ""),
        "dynamic_package": config.get("dynamic_package", ""),
        "dynamic_allow_remote": bool(config.get("dynamic_allow_remote", False)),
        "remnux_enabled": bool(config.get("remnux_enabled", True)),
        "remnux_depth": config.get("remnux_depth", "deep"),
        "remnux_timeout": int(config.get("remnux_timeout", 900)),
        "virustotal_enabled": bool(config.get("virustotal_enabled", False)),
        "virustotal_upload_missing": bool(
            config.get("virustotal_upload_missing", False)
        ),
        "virustotal_allow_upload": bool(
            config.get("virustotal_allow_upload", False)
        ),
        "virustotal_timeout": int(config.get("virustotal_timeout", 300)),
        "virustotal_poll_interval": int(
            config.get("virustotal_poll_interval", 15)
        ),
        "abusech_enabled": bool(config.get("abusech_enabled", False)),
        "unpacme_enabled": bool(config.get("unpacme_enabled", False)),
        "unpacme_private": bool(config.get("unpacme_private", True)),
        "unpacme_timeout": int(config.get("unpacme_timeout", 900)),
        "unpacme_poll_interval": int(config.get("unpacme_poll_interval", 10)),
        "verbose": bool(config.get("verbose", False)),
    }


def write_config(settings: SettingsUpdate) -> dict:
    endpoint = settings.api_base_url.strip()
    if endpoint:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise HTTPException(
                status_code=400,
                detail="Endpoint URL must be an absolute HTTP or HTTPS URL",
            )
    try:
        dynamic_providers = validate_providers(settings.dynamic_providers)
        dynamic_provider = dynamic_providers[0] if dynamic_providers else "cape"
        dynamic_url = validate_cape_url(
            (settings.cape_url or settings.dynamic_url).strip().rstrip("/"),
            allow_remote=settings.dynamic_allow_remote,
        )
        joe_url = settings.joesandbox_url.strip().rstrip("/")
        if joe_url:
            parsed_joe = urlparse(joe_url)
            if parsed_joe.scheme not in {"http", "https"} or not parsed_joe.netloc:
                raise ValueError("Joe Sandbox endpoint must be an absolute HTTP or HTTPS URL")
        triage_url = settings.triage_url.strip().rstrip("/")
        parsed_triage = urlparse(triage_url)
        if parsed_triage.scheme not in {"http", "https"} or not parsed_triage.netloc:
            raise ValueError("Triage endpoint must be an absolute HTTP or HTTPS URL")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    current = read_config()
    dynamic_tokens = dict(current.get("dynamic_tokens") or {})
    if current.get("dynamic_token") and not dynamic_tokens.get("cape"):
        dynamic_tokens["cape"] = current["dynamic_token"]
    token_updates = {
        "cape": (settings.cape_token, settings.clear_cape_token),
        "anyrun": (settings.anyrun_api_key, settings.clear_anyrun_api_key),
        "joesandbox": (
            settings.joesandbox_api_key, settings.clear_joesandbox_api_key
        ),
        "triage": (settings.triage_api_key, settings.clear_triage_api_key),
    }
    for provider, (token, clear) in token_updates.items():
        if clear:
            dynamic_tokens.pop(provider, None)
        elif token:
            dynamic_tokens[provider] = token
    updated = {
        **current,
        "model": settings.model.strip(),
        "api_base_url": endpoint.rstrip("/"),
        "reports_dir": str(Path(settings.reports_dir).expanduser()),
        "archive_password": settings.archive_password,
        "max_turns": settings.max_turns,
        "max_tool_errors": settings.max_tool_errors,
        "dynamic_enabled": settings.dynamic_enabled,
        "dynamic_provider": dynamic_provider,
        "dynamic_providers": dynamic_providers,
        "dynamic_url": dynamic_url,
        "dynamic_urls": {"cape": dynamic_url, "joesandbox": joe_url},
        "dynamic_timeout": settings.dynamic_timeout,
        "dynamic_poll_interval": settings.dynamic_poll_interval,
        "dynamic_machine": settings.dynamic_machine.strip(),
        "dynamic_package": settings.dynamic_package.strip(),
        "dynamic_allow_remote": settings.dynamic_allow_remote,
        "remnux_enabled": settings.remnux_enabled,
        "remnux_depth": settings.remnux_depth,
        "remnux_timeout": settings.remnux_timeout,
        "virustotal_enabled": settings.virustotal_enabled,
        "virustotal_upload_missing": settings.virustotal_upload_missing,
        "virustotal_allow_upload": settings.virustotal_allow_upload,
        "virustotal_timeout": settings.virustotal_timeout,
        "virustotal_poll_interval": settings.virustotal_poll_interval,
        "abusech_enabled": settings.abusech_enabled,
        "unpacme_enabled": settings.unpacme_enabled,
        "unpacme_private": settings.unpacme_private,
        "unpacme_timeout": settings.unpacme_timeout,
        "unpacme_poll_interval": settings.unpacme_poll_interval,
        "verbose": settings.verbose,
    }
    if settings.clear_api_key:
        updated["api_key"] = ""
    elif settings.api_key:
        updated["api_key"] = settings.api_key
    if settings.clear_dynamic_token:
        if dynamic_provider == "cape":
            updated["dynamic_token"] = ""
        dynamic_tokens.pop(dynamic_provider, None)
    elif settings.dynamic_token:
        dynamic_tokens[dynamic_provider] = settings.dynamic_token
        if dynamic_provider == "cape":
            updated["dynamic_token"] = settings.dynamic_token
    updated["dynamic_tokens"] = dynamic_tokens
    updated["dynamic_urls"]["triage"] = triage_url
    missing_keys = [
        provider for provider in dynamic_providers
        if provider in {"anyrun", "joesandbox", "triage"} and not dynamic_tokens.get(provider)
    ]
    if missing_keys:
        raise HTTPException(
            status_code=400,
            detail="Store an API key before enabling: " + ", ".join(missing_keys),
        )
    if settings.clear_virustotal_api_key:
        updated["virustotal_api_key"] = ""
    elif settings.virustotal_api_key:
        updated["virustotal_api_key"] = settings.virustotal_api_key
    if settings.clear_abusech_auth_key:
        updated["abusech_auth_key"] = ""
    elif settings.abusech_auth_key:
        updated["abusech_auth_key"] = settings.abusech_auth_key
    if settings.clear_unpacme_api_key:
        updated["unpacme_api_key"] = ""
    elif settings.unpacme_api_key:
        updated["unpacme_api_key"] = settings.unpacme_api_key
    if (
        settings.virustotal_enabled
        and not updated.get("virustotal_api_key")
    ):
        raise HTTPException(
            status_code=400,
            detail="A VirusTotal API key is required when enrichment is enabled",
        )
    if settings.virustotal_upload_missing and not settings.virustotal_allow_upload:
        raise HTTPException(
            status_code=400,
            detail=(
                "VirusTotal upload of unknown samples requires explicit "
                "sample-disclosure consent"
            ),
        )
    if settings.abusech_enabled and not updated.get("abusech_auth_key"):
        raise HTTPException(status_code=400, detail="An abuse.ch Auth-Key is required")
    if settings.unpacme_enabled and not updated.get("unpacme_api_key"):
        raise HTTPException(status_code=400, detail="An UnpacMe API key is required")

    config_path = PROJECT_DIR / "config.json"
    temporary = config_path.with_suffix(".json.tmp")
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(updated, handle, indent=2)
        handle.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, config_path)
    return updated


@app.get("/api/health", tags=["system"], summary="Check API readiness")
def health():
    return {
        "status": "ok",
        "service": "recluse",
        "version": app.version,
    }


@app.get("/api/config", tags=["configuration"])
def get_config():
    defaults = configured_defaults()
    stored = read_config()
    tokens = stored.get("dynamic_tokens") or {}
    defaults["dynamic_availability"] = {
        "cape": bool(defaults["dynamic_url"]),
        "anyrun": bool(tokens.get("anyrun")),
        "joesandbox": bool(tokens.get("joesandbox")),
        "triage": bool(tokens.get("triage")),
    }
    defaults["virustotal_available"] = bool(stored.get("virustotal_api_key"))
    defaults["abusech_available"] = bool(stored.get("abusech_auth_key"))
    defaults["unpacme_available"] = bool(stored.get("unpacme_api_key"))
    triage_url = defaults["dynamic_urls"].get("triage", "https://tria.ge/api/v0")
    defaults["triage_public_upload"] = triage_url.rstrip("/") == "https://tria.ge/api/v0"
    return defaults


@app.get("/api/settings", tags=["configuration"])
def get_settings():
    config = read_config()
    defaults = configured_defaults()
    return {
        "model": defaults["model"],
        "api_base_url": defaults["api_base_url"],
        "api_key_configured": bool(config.get("api_key")),
        "reports_dir": defaults["reports_dir"],
        "archive_password": defaults["password"],
        "max_turns": defaults["max_turns"],
        "max_tool_errors": defaults["max_tool_errors"],
        "dynamic_enabled": defaults["dynamic_enabled"],
        "dynamic_provider": defaults["dynamic_provider"],
        "dynamic_providers": defaults["dynamic_providers"],
        "dynamic_url": defaults["dynamic_url"],
        "dynamic_urls": defaults["dynamic_urls"],
        "dynamic_tokens_configured": {
            provider: bool(
                (config.get("dynamic_tokens") or {}).get(provider)
                or (provider == "cape" and config.get("dynamic_token"))
            )
            for provider in ("cape", "anyrun", "joesandbox", "triage")
        },
        "dynamic_timeout": defaults["dynamic_timeout"],
        "dynamic_poll_interval": defaults["dynamic_poll_interval"],
        "dynamic_machine": defaults["dynamic_machine"],
        "dynamic_package": defaults["dynamic_package"],
        "dynamic_allow_remote": defaults["dynamic_allow_remote"],
        "remnux_enabled": defaults["remnux_enabled"],
        "remnux_depth": defaults["remnux_depth"],
        "remnux_timeout": defaults["remnux_timeout"],
        "virustotal_enabled": defaults["virustotal_enabled"],
        "virustotal_api_key_configured": bool(config.get("virustotal_api_key")),
        "virustotal_upload_missing": defaults["virustotal_upload_missing"],
        "virustotal_allow_upload": defaults["virustotal_allow_upload"],
        "virustotal_timeout": defaults["virustotal_timeout"],
        "virustotal_poll_interval": defaults["virustotal_poll_interval"],
        "abusech_enabled": defaults["abusech_enabled"],
        "abusech_auth_key_configured": bool(config.get("abusech_auth_key")),
        "unpacme_enabled": defaults["unpacme_enabled"],
        "unpacme_api_key_configured": bool(config.get("unpacme_api_key")),
        "unpacme_private": defaults["unpacme_private"],
        "unpacme_timeout": defaults["unpacme_timeout"],
        "unpacme_poll_interval": defaults["unpacme_poll_interval"],
        "verbose": defaults["verbose"],
    }


@app.put("/api/settings", tags=["configuration"])
def update_settings(settings: SettingsUpdate):
    updated = write_config(settings)
    return {
        "saved": True,
        "model": updated["model"],
        "api_base_url": updated["api_base_url"],
        "api_key_configured": bool(updated.get("api_key")),
    }


@app.get("/api/jobs", tags=["analysis"], summary="List recent analysis jobs")
def list_jobs():
    with jobs_lock:
        ordered = sorted(jobs.values(), key=lambda item: item["created_at"], reverse=True)
    return [public_job(job) for job in ordered]


def _report_catalog_entries() -> list[dict]:
    """Build searchable metadata from every persisted report artifact."""
    with jobs_lock:
        snapshot = list(jobs.values())
    entries = []
    for job in snapshot:
        report_dir = Path(job["report_dir"])
        for artifact in job.get("artifacts", []):
            if artifact.get("kind") != "report":
                continue
            relative_path = str(artifact.get("path", ""))
            try:
                report_path = (report_dir / relative_path).resolve()
                report_path.relative_to(report_dir.resolve())
                report = json.loads(report_path.read_text())
            except (OSError, ValueError, TypeError):
                continue
            sample = report.get("sample") or {}
            analysis = report.get("analysis") or {}
            triage = report.get("triage") or {}
            entries.append({
                "job_id": job["id"],
                "artifact_path": relative_path,
                "filename": str(sample.get("member_name") or job["filename"]),
                "sha256": str(sample.get("sha256") or ""),
                "created_at": job["created_at"],
                "finished_at": job.get("finished_at"),
                "model": str(analysis.get("model") or
                             job.get("parameters", {}).get("model", "unknown")),
                "verdict": str(triage.get("verdict") or "unknown"),
                "status": analysis.get("status") or job["status"],
            })
    return sorted(entries, key=lambda item: item["created_at"], reverse=True)


@app.get("/api/reports", tags=["analysis"], summary="Search persisted reports")
def search_reports(
    filename: str = "",
    file_hash: str = "",
    date_from: str = "",
    date_to: str = "",
    model: str = "",
    verdict: str = "",
):
    filters = {
        "filename": filename.strip().lower(),
        "file_hash": file_hash.strip().lower(),
        "model": model.strip().lower(),
        "verdict": verdict.strip().lower(),
    }
    for label, value in (("date_from", date_from), ("date_to", date_to)):
        if value:
            try:
                datetime.strptime(value, "%Y-%m-%d")
            except ValueError as exc:
                raise HTTPException(
                    status_code=400, detail=f"{label} must use YYYY-MM-DD"
                ) from exc
    results = []
    for entry in _report_catalog_entries():
        analysis_date = entry["created_at"][:10]
        if filters["filename"] not in entry["filename"].lower():
            continue
        if filters["file_hash"] not in entry["sha256"].lower():
            continue
        if filters["model"] not in entry["model"].lower():
            continue
        if filters["verdict"] and filters["verdict"] != entry["verdict"].lower():
            continue
        if date_from and analysis_date < date_from:
            continue
        if date_to and analysis_date > date_to:
            continue
        results.append(entry)
    return results


@app.get("/api/jobs/{job_id}", tags=["analysis"], summary="Get an analysis job")
def get_job(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    return public_job(job)


@app.delete(
    "/api/jobs/{job_id}",
    status_code=204,
    tags=["analysis"],
    summary="Delete a finished analysis job and its artifacts",
)
def delete_job(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Analysis job not found")
        if job["status"] in {"queued", "running"}:
            raise HTTPException(
                status_code=409,
                detail="A queued or running analysis cannot be deleted",
            )
        report_dir = Path(job["report_dir"]).resolve()
        expected_name = f"web-{job_id}"
        if report_dir.name != expected_name or not report_dir.is_dir():
            raise HTTPException(
                status_code=409,
                detail="Job report directory is not a managed WebGUI directory",
            )
        shutil.rmtree(report_dir)
        jobs.pop(job_id, None)
        remove_job_from_index(report_dir)


@app.post(
    "/api/jobs",
    status_code=202,
    tags=["analysis"],
    summary="Submit a sample for isolated analysis",
)
async def create_job(
    sample: UploadFile = File(..., description="Suspicious sample or archive"),
    password: str = Form("", description="Archive password; uses configured default when omitted"),
    model: str = Form("", description="Model identifier; uses configured default when omitted"),
    api_key: str = Form("", description="Optional per-job model-provider API key"),
    reports_dir: str = Form("", description="Report root; uses configured default when omitted"),
    max_turns: Optional[int] = Form(None),
    max_tool_errors: Optional[int] = Form(None),
    verbose: Optional[bool] = Form(None),
    dynamic_providers: Optional[str] = Form(None),
    dynamic_upload_providers: str = Form(""),
    virustotal_enabled: Optional[bool] = Form(None),
    virustotal_upload_missing: bool = Form(False),
    abusech_enabled: Optional[bool] = Form(None),
    unpacme_enabled: Optional[bool] = Form(None),
    unpacme_upload: bool = Form(False),
    upload_acknowledgement: str = Form(""),
):
    dynamic_defaults = configured_defaults()
    stored_config = read_config()
    password = password or dynamic_defaults["password"]
    model = model.strip() or dynamic_defaults["model"]
    reports_dir = reports_dir or dynamic_defaults["reports_dir"]
    max_turns = max_turns if max_turns is not None else dynamic_defaults["max_turns"]
    max_tool_errors = (
        max_tool_errors
        if max_tool_errors is not None
        else dynamic_defaults["max_tool_errors"]
    )
    verbose = verbose if verbose is not None else dynamic_defaults["verbose"]
    selected_dynamic_providers = (
        validate_providers(dynamic_providers)
        if dynamic_providers is not None
        else dynamic_defaults["dynamic_providers"]
    )
    selected_virustotal = (
        virustotal_enabled
        if virustotal_enabled is not None
        else dynamic_defaults["virustotal_enabled"]
    )
    selected_upload_providers = validate_providers(dynamic_upload_providers)
    selected_unpacme = (
        unpacme_enabled if unpacme_enabled is not None
        else dynamic_defaults["unpacme_enabled"]
    )
    selected_abusech = (
        abusech_enabled if abusech_enabled is not None
        else dynamic_defaults["abusech_enabled"]
    )
    # Hosted sandboxes without a hash-search workflow only run when upload was
    # explicitly selected for this job. Triage remains selected for hash lookup.
    selected_dynamic_providers = [
        provider for provider in selected_dynamic_providers
        if provider in {"cape", "triage"} or provider in selected_upload_providers
    ]
    available_tokens = stored_config.get("dynamic_tokens") or {}
    unavailable = [
        provider for provider in selected_dynamic_providers
        if provider in {"anyrun", "joesandbox", "triage"}
        and not available_tokens.get(provider)
    ]
    if unavailable:
        raise HTTPException(
            status_code=400,
            detail="Sandbox API key is not configured for: " + ", ".join(unavailable),
        )
    if selected_virustotal and not stored_config.get("virustotal_api_key"):
        raise HTTPException(
            status_code=400,
            detail="VirusTotal API key is not configured",
        )
    if selected_unpacme and not stored_config.get("unpacme_api_key"):
        raise HTTPException(status_code=400, detail="UnpacMe API key is not configured")
    if selected_abusech and not stored_config.get("abusech_auth_key"):
        raise HTTPException(status_code=400, detail="abuse.ch Auth-Key is not configured")
    triage_url = (dynamic_defaults["dynamic_urls"].get("triage")
                  or "https://tria.ge/api/v0")
    public_uploads = []
    if virustotal_upload_missing:
        public_uploads.append("VirusTotal")
    if "triage" in selected_upload_providers and triage_url.rstrip("/") == "https://tria.ge/api/v0":
        public_uploads.append("Triage public cloud")
    if any(provider in selected_upload_providers for provider in ("anyrun", "joesandbox")):
        public_uploads.append("hosted sandbox")
    if unpacme_upload and not dynamic_defaults["unpacme_private"]:
        public_uploads.append("non-private UnpacMe")
    if public_uploads and upload_acknowledgement.strip() != "acknowledge":
        raise HTTPException(
            status_code=400,
            detail="Type acknowledge to authorize public sample upload",
        )
    selected_provider = dynamic_defaults["dynamic_provider"]
    stored_dynamic_token = (
        (stored_config.get("dynamic_tokens") or {}).get(selected_provider)
        or (
            stored_config.get("dynamic_token", "")
            if selected_provider == "cape"
            else ""
        )
    )
    if not sample.filename:
        raise HTTPException(status_code=400, detail="Choose a sample to analyze")
    if not model:
        raise HTTPException(
            status_code=400,
            detail="Model is required; pass model or configure a default",
        )
    if not 1 <= max_turns <= 200:
        raise HTTPException(status_code=400, detail="Maximum turns must be between 1 and 200")
    if not 1 <= max_tool_errors <= 100:
        raise HTTPException(status_code=400, detail="Tool-error limit must be between 1 and 100")

    safe_filename = Path(sample.filename).name
    job_id = uuid.uuid4().hex[:12]
    upload_dir = Path(tempfile.mkdtemp(prefix=f"recluse_web_{job_id}_"))
    upload_path = upload_dir / safe_filename
    size = 0
    try:
        with open(upload_path, "wb") as destination:
            while chunk := await sample.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Sample exceeds the 2 GiB upload limit")
                destination.write(chunk)
    except Exception:
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise
    finally:
        await sample.close()

    requested_root = Path(reports_dir).expanduser()
    if not requested_root.is_absolute():
        requested_root = PROJECT_DIR / requested_root
    job_report_dir = requested_root.resolve() / f"web-{job_id}"
    job_report_dir.mkdir(parents=True, exist_ok=False)
    job = {
        "id": job_id,
        "filename": safe_filename,
        "upload_dir": upload_dir,
        "upload_path": upload_path,
        "report_dir": job_report_dir,
        "status": "queued",
        "created_at": utc_now(),
        "return_code": None,
        "log": deque(maxlen=MAX_LOG_LINES),
        "artifacts": [],
        "parameters": {
            "password": password,
            "model": model,
            "api_key": api_key,
            "reports_dir": str(requested_root.resolve()),
            "max_turns": max_turns,
            "max_tool_errors": max_tool_errors,
            "dynamic_enabled": bool(selected_dynamic_providers),
            "dynamic_providers": selected_dynamic_providers,
            "dynamic_upload_providers": selected_upload_providers,
            "dynamic_provider": dynamic_defaults["dynamic_provider"],
            "dynamic_url": dynamic_defaults["dynamic_url"],
            "dynamic_token": stored_dynamic_token,
            "dynamic_timeout": dynamic_defaults["dynamic_timeout"],
            "dynamic_poll_interval": dynamic_defaults["dynamic_poll_interval"],
            "dynamic_machine": dynamic_defaults["dynamic_machine"],
            "dynamic_package": dynamic_defaults["dynamic_package"],
            "dynamic_allow_remote": any(
                provider in selected_upload_providers
                for provider in ("anyrun", "joesandbox")
            ),
            "remnux_enabled": dynamic_defaults["remnux_enabled"],
            "remnux_depth": dynamic_defaults["remnux_depth"],
            "remnux_timeout": dynamic_defaults["remnux_timeout"],
            "virustotal_enabled": selected_virustotal,
            "virustotal_api_key": stored_config.get("virustotal_api_key", ""),
            "virustotal_upload_missing": virustotal_upload_missing,
            "virustotal_allow_upload": virustotal_upload_missing,
            "virustotal_timeout": dynamic_defaults["virustotal_timeout"],
            "virustotal_poll_interval": dynamic_defaults[
                "virustotal_poll_interval"
            ],
            "abusech_enabled": selected_abusech,
            "abusech_auth_key": stored_config.get("abusech_auth_key", ""),
            "unpacme_enabled": selected_unpacme,
            "unpacme_api_key": stored_config.get("unpacme_api_key", ""),
            "unpacme_upload": unpacme_upload,
            "unpacme_private": dynamic_defaults["unpacme_private"],
            "unpacme_timeout": dynamic_defaults["unpacme_timeout"],
            "unpacme_poll_interval": dynamic_defaults["unpacme_poll_interval"],
            "verbose": verbose,
        },
    }
    with jobs_lock:
        jobs[job_id] = job
    persist_job(job)
    loop = asyncio.get_running_loop()
    loop.run_in_executor(executor, run_analysis, job)
    return public_job(job)


def resolve_job_artifact(job_id: str, artifact_path: str) -> Path:
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    root = job["report_dir"].resolve()
    target = (root / artifact_path).resolve()
    if root not in target.parents or not target.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")
    return target


@app.get(
    "/api/jobs/{job_id}/artifact-content/{artifact_path:path}",
    tags=["artifacts"],
    summary="Read an artifact without browser redirection",
)
def view_artifact(job_id: str, artifact_path: str):
    target = resolve_job_artifact(job_id, artifact_path)
    media_type = (
        "application/json"
        if target.suffix.lower() == ".json"
        else "text/plain; charset=utf-8"
    )
    return FileResponse(target, media_type=media_type)


@app.get(
    "/api/jobs/{job_id}/artifacts/{artifact_path:path}",
    tags=["artifacts"],
    summary="Download or view an artifact",
)
def download_artifact(job_id: str, artifact_path: str, download: bool = False):
    target = resolve_job_artifact(job_id, artifact_path)
    if not download and target.suffix.lower() in {".json", ".txt"}:
        query = urlencode({"job": job_id, "artifact": artifact_path})
        return RedirectResponse(f"/report.html?{query}", status_code=303)
    return FileResponse(target, filename=target.name)


load_persisted_jobs()
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="web")
