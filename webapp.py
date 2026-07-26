"""Local web interface for REcluse malware triage."""

import asyncio
import json
import os
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
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from urllib.parse import urlparse


PROJECT_DIR = Path(__file__).resolve().parent
STATIC_DIR = PROJECT_DIR / "web"
DEFAULT_REPORTS_DIR = PROJECT_DIR / "reports"
CONDUCTOR = PROJECT_DIR / "conductor.py"
PYTHON = PROJECT_DIR / "venv" / "bin" / "python"
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024
MAX_LOG_LINES = 4000

app = FastAPI(title="REcluse Analyst Console", docs_url=None, redoc_url=None)
executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="recluse-analysis")
jobs = {}
jobs_lock = threading.RLock()


class SettingsUpdate(BaseModel):
    model: str = Field(min_length=1, max_length=300)
    api_base_url: str = Field(default="", max_length=2000)
    api_key: str = Field(default="", max_length=10000)
    clear_api_key: bool = False
    reports_dir: str = Field(min_length=1, max_length=4000)
    archive_password: str = Field(default="infected", max_length=1000)
    max_turns: int = Field(default=20, ge=1, le=200)
    max_tool_errors: int = Field(default=5, ge=1, le=100)
    verbose: bool = False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def public_job(job: dict) -> dict:
    with jobs_lock:
        public_parameters = {
            key: value
            for key, value in job["parameters"].items()
            if key != "api_key"
        }
        public_parameters["api_key_override"] = bool(job["parameters"].get("api_key"))
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


def collect_artifacts(job: dict) -> None:
    artifacts = []
    report_dir = job["report_dir"]
    if report_dir.exists():
        for path in sorted(report_dir.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(report_dir)
            kind = "file"
            if path.name.endswith(".report.json"):
                kind = "report"
            elif path.name.endswith(".transcript.json"):
                kind = "transcript"
            elif path.name.endswith(".deobfuscated.txt"):
                kind = "deobfuscated"
            artifacts.append({
                "name": path.name,
                "path": relative.as_posix(),
                "kind": kind,
                "size": path.stat().st_size,
            })
    with jobs_lock:
        job["artifacts"] = artifacts


def run_analysis(job: dict) -> None:
    with jobs_lock:
        job["status"] = "running"
        job["started_at"] = utc_now()

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
    command.append("--verbose" if parameters.get("verbose") else "--no-verbose")

    append_log(job, f"$ REcluse analysis started for {job['filename']}")
    try:
        process = subprocess.Popen(
            command,
            cwd=PROJECT_DIR,
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
            job["status"] = "completed" if return_code == 0 else "failed"
    except Exception as exc:
        append_log(job, f"Web runner error: {exc}")
        with jobs_lock:
            job["status"] = "failed"
            job["error"] = str(exc)
            job["return_code"] = -1
    finally:
        with jobs_lock:
            job["finished_at"] = utc_now()
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

    current = read_config()
    updated = {
        **current,
        "model": settings.model.strip(),
        "api_base_url": endpoint.rstrip("/"),
        "reports_dir": str(Path(settings.reports_dir).expanduser()),
        "archive_password": settings.archive_password,
        "max_turns": settings.max_turns,
        "max_tool_errors": settings.max_tool_errors,
        "verbose": settings.verbose,
    }
    if settings.clear_api_key:
        updated["api_key"] = ""
    elif settings.api_key:
        updated["api_key"] = settings.api_key

    config_path = PROJECT_DIR / "config.json"
    temporary = config_path.with_suffix(".json.tmp")
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(updated, handle, indent=2)
        handle.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, config_path)
    return updated


@app.get("/api/config")
def get_config():
    return configured_defaults()


@app.get("/api/settings")
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
        "verbose": defaults["verbose"],
    }


@app.put("/api/settings")
def update_settings(settings: SettingsUpdate):
    updated = write_config(settings)
    return {
        "saved": True,
        "model": updated["model"],
        "api_base_url": updated["api_base_url"],
        "api_key_configured": bool(updated.get("api_key")),
    }


@app.get("/api/jobs")
def list_jobs():
    with jobs_lock:
        ordered = sorted(jobs.values(), key=lambda item: item["created_at"], reverse=True)
    return [public_job(job) for job in ordered[:30]]


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    return public_job(job)


@app.post("/api/jobs", status_code=202)
async def create_job(
    sample: UploadFile = File(...),
    password: str = Form("infected"),
    model: str = Form(...),
    api_key: str = Form(""),
    reports_dir: str = Form(str(DEFAULT_REPORTS_DIR)),
    max_turns: int = Form(20),
    max_tool_errors: int = Form(5),
    verbose: bool = Form(False),
):
    if not sample.filename:
        raise HTTPException(status_code=400, detail="Choose a sample to analyze")
    if not model.strip():
        raise HTTPException(status_code=400, detail="Model is required")
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
            "model": model.strip(),
            "api_key": api_key,
            "reports_dir": str(requested_root.resolve()),
            "max_turns": max_turns,
            "max_tool_errors": max_tool_errors,
            "verbose": verbose,
        },
    }
    with jobs_lock:
        jobs[job_id] = job
    loop = asyncio.get_running_loop()
    loop.run_in_executor(executor, run_analysis, job)
    return public_job(job)


@app.get("/api/jobs/{job_id}/artifacts/{artifact_path:path}")
def download_artifact(job_id: str, artifact_path: str):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    root = job["report_dir"].resolve()
    target = (root / artifact_path).resolve()
    if root not in target.parents or not target.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")
    return FileResponse(target, filename=target.name)


app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="web")
