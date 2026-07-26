import os
import sys
import json
import argparse
import asyncio
import warnings
import hashlib
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

os.environ.setdefault("LITELLM_TELEMETRY", "False")

import pyzipper
import docker
import litellm
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

warnings.filterwarnings("ignore", category=UserWarning, module="pydantic")

PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_REPORTS_DIR = PROJECT_DIR / "reports"
config = {
    "api_key": "",
    "api_base_url": "",
    "model": "",
    "reports_dir": str(DEFAULT_REPORTS_DIR),
    "archive_password": "infected",
    "max_turns": 20,
    "max_tool_errors": 5,
    "verbose": False,
}
config_path = PROJECT_DIR / "config.json"
if config_path.exists():
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config.update(json.load(f))
    except Exception:
        pass

PLAYBOOK_NATIVE = "You are an objective reverse engineering triage engine. Identify structure, behavior, and analyst pivots."
PLAYBOOK_DOTNET = "You are an expert automated malware analyst for .NET assemblies."
PLAYBOOK_ANDROID = "You are an expert automated malware analyst for Android APK packages."
PLAYBOOK_DOCUMENT = """
You are an expert malicious-document analyst performing static analysis only.
Start with document.metadata, then choose format-specific tools:
- Office/OLE/OpenXML: document.office_scan and, for ZIP-based formats,
  document.archive_listing.
- PDF: document.pdf_scan.
- RTF: document.rtf_scan.
- Any format: document.strings when additional pivots are needed.
Identify macros, auto-execution triggers, obfuscation, embedded payloads, external
templates, URLs, commands, and exploit indicators. Never execute the document,
macros, scripts, or extracted payloads. Distinguish observed behavior from
heuristic suspicion and cite the exact successful tool_call_id for every material
claim in the final report.
""".strip()
PLAYBOOK_SCRIPT = """
You are an expert static script-malware analyst. Never run the supplied script,
invoke a language interpreter, emulate its behavior, or execute decoded content.
First call script.metadata, then script.deobfuscate. Use script.read only when
the deobfuscation output needs comparison with the original.

Trace decoded commands, URLs, file and registry operations, persistence,
credential access, defense evasion, and payload staging. Separate observed
capabilities from unresolved or dynamically constructed behavior. The final JSON
must include:
"script_analysis": {
  "obfuscation_detected": true,
  "methods": ["exact static transformation used"],
  "deobfuscated_script": "recovered inert source text, or null when unobfuscated",
  "capabilities_summary": "concise summary of observed script capabilities"
}
Copy the recovered source from script.deobfuscate without executing or improving
it. Cite the exact successful tool_call_id supporting the assessment.
""".strip()

REPORT_SCHEMA_PROMPT = """
Use tools to inspect the sample. Do not claim that a command or tool ran unless a
tool result in this conversation proves it. When analysis is complete, return
ONLY one JSON object with this shape:
{
  "verdict": "malicious|suspicious|benign|unknown",
  "confidence": 0.0,
  "summary": "concise evidence-based assessment",
  "capabilities": ["observed capability"],
  "iocs": {"domains": [], "ips": [], "urls": [], "files": [], "registry_keys": []},
  "evidence": [{"tool_call_id": "actual call id", "claim": "claim supported by that result"}]
}
Confidence must be between 0 and 1. Evidence may only cite tool_call_id values
that were actually returned by successful tools. Copy the exact opaque
tool_call_id from the tool result; do not use a tool name, sequence number, or
invented identifier. If evidence is insufficient, use unknown.
""".strip()

MCP_ROUTER = {
    "NATIVE": {"name": "NATIVE", "image": "triage-ghidra-mcp", "args": lambda binary: [], "playbook": PLAYBOOK_NATIVE},
    "DOTNET": {"name": "DOTNET", "image": "triage-ilspy-mcp", "args": lambda binary: ["ILSpy.Mcp.dll", f"/home/remnux/samples/{binary}"], "playbook": PLAYBOOK_DOTNET},
    "ANDROID": {"name": "ANDROID", "image": "triage-jadx-mcp", "args": lambda binary: ["-Dspring.ai.mcp.server.stdio=true", "-jar", "jadx-mcp-server.jar", f"/home/remnux/samples/{binary}"], "playbook": PLAYBOOK_ANDROID},
    "DOCUMENT": {"name": "DOCUMENT", "image": "triage-maldoc-mcp", "args": lambda binary: [], "playbook": PLAYBOOK_DOCUMENT},
    "SCRIPT": {"name": "SCRIPT", "image": "triage-script-mcp", "args": lambda binary: [], "playbook": PLAYBOOK_SCRIPT},
}

DOCUMENT_EXTENSIONS = {
    ".doc", ".docm", ".docx", ".dot", ".dotm", ".dotx",
    ".xls", ".xlsb", ".xlsm", ".xlsx", ".xlt", ".xltm", ".xltx",
    ".ppt", ".pptm", ".pptx", ".pot", ".potm", ".potx", ".pps", ".ppsm", ".ppsx",
    ".pdf", ".rtf",
}
SCRIPT_EXTENSIONS = {
    ".ps1", ".psm1", ".psd1", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
    ".hta", ".bat", ".cmd", ".sh", ".bash", ".zsh", ".py", ".pl", ".rb", ".lua",
}


def ensure_docker_client():
    try:
        client = docker.from_env()
        client.ping()
        return client
    except docker.errors.DockerException as e:
        socket_path = Path("/var/run/docker.sock")
        if socket_path.exists() and not os.access(socket_path, os.R_OK | os.W_OK):
            print("[-] Docker socket permission denied.")
            print("    Run: sudo usermod -aG docker \"$USER\"")
            print("    Then log out and back in (or reboot). Do not run REcluse with sudo.")
        else:
            print(f"[-] Docker Connection Error: {e}")
            print("    Verify Docker is running with: systemctl status docker")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Docker Connection Error: {e}")
        sys.exit(1)


def ensure_docker_images_exist():
    docker_client = ensure_docker_client()
    low = docker_client.api
    required_images = {
        "triage-ghidra-mcp": "Dockerfile.ghidra",
        "triage-ilspy-mcp": "Dockerfile.ilspy",
        "triage-jadx-mcp": "Dockerfile.jadx",
        "triage-maldoc-mcp": "Dockerfile.maldoc",
        "triage-script-mcp": "Dockerfile.script",
    }
    try:
        docker_client.images.get("remnux/remnux-distro:noble")
    except docker.errors.ImageNotFound:
        for _ in low.pull("remnux/remnux-distro", tag="noble", stream=True, decode=True):
            pass
    for image_name, dockerfile_path in required_images.items():
        try:
            docker_client.images.get(image_name)
        except docker.errors.ImageNotFound:
            if not (PROJECT_DIR / dockerfile_path).exists():
                continue
            for chunk in low.build(path=str(PROJECT_DIR), dockerfile=dockerfile_path, tag=image_name, rm=True, decode=True):
                if "error" in chunk:
                    print(chunk["error"])
                    sys.exit(1)


def resolve_api_key(model_name: str, cli_key: Optional[str] = None) -> str:
    if model_name.startswith("ollama/"):
        return cli_key or "ollama"
    if cli_key:
        return cli_key
    provider = model_name.split("/")[0].upper() if "/" in model_name else "OPENAI"
    env_var_key = f"{provider}_API_KEY"
    value = os.environ.get(env_var_key) or os.environ.get("API_KEY") or config.get("api_key")
    if not value:
        print(f"[-] Error: No API key found for provider '{provider}'.")
        sys.exit(1)
    return value


def llm_kwargs(model_name: str, cli_key: Optional[str] = None) -> Dict[str, Any]:
    kwargs = {"model": model_name, "api_key": resolve_api_key(model_name, cli_key)}
    if model_name.startswith("ollama/"):
        kwargs["api_base"] = os.environ.get("OLLAMA_BASE_URL") or config.get("api_base_url") or "http://127.0.0.1:11434"
    else:
        kwargs["api_base"] = config.get("api_base_url") or None
    return kwargs


def map_mcp_to_litellm_tools(mcp_tools) -> list:
    essential = {
        "program.open", "program.summary", "program.close", "decomp.function",
        "function.list", "function.by_name", "function.callees", "function.callers",
        "symbol.list", "symbol.by_name", "search.defined_strings", "search.bytes",
        "search.constants", "memory.blocks.list", "memory.read", "external.imports.list",
        "external.exports.list", "document.metadata", "document.office_scan",
        "document.pdf_scan", "document.rtf_scan", "document.archive_listing",
        "document.strings", "script.metadata", "script.read", "script.deobfuscate",
    }
    out = []
    for tool in mcp_tools:
        if tool.name not in essential:
            continue
        out.append({"type": "function", "function": {"name": tool.name, "description": tool.description, "parameters": tool.inputSchema}})
    return out


def routing_profile(name: str, detected_type: str, identification_method: str) -> dict:
    profile = dict(MCP_ROUTER[name])
    profile["detected_type"] = detected_type
    profile["identification_method"] = identification_method
    return profile


def decode_text_sample(raw: bytes) -> Optional[str]:
    if not raw or b"\x00" in raw[:4096] and not raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return None
    for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "latin-1"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        printable = sum(character.isprintable() or character in "\r\n\t" for character in text)
        if text and printable / len(text) >= 0.85:
            return text
    return None


def detect_script_language(text: str) -> Optional[str]:
    """Identify script languages from multiple syntax markers, not filenames."""
    lowered = text.lower()
    signatures = {
        "PowerShell": (
            r"\b(?:invoke-expression|iex|new-object|frombase64string|encodedcommand)\b",
            r"\[(?:system|io|text|convert)\.",
            r"\$(?:env:|[a-z_][\w]*)",
            r"\b(?:get|set|write|start|invoke|remove|download)-[a-z]+\b",
            r"\|\s*(?:%|where|foreach|select)(?:\s|\{)",
        ),
        "JavaScript/JScript": (
            r"\b(?:var|let|const)\s+[a-z_$][\w$]*\s*=",
            r"\bfunction\s+[a-z_$]*\s*\(",
            r"\b(?:wscript|activexobject|document|window)\.",
            r"\b(?:eval|unescape|fromcharcode)\s*\(",
        ),
        "VBScript": (
            r"\bcreateobject\s*\(",
            r"\bwscript\.",
            r"(?m)^\s*(?:dim|set)\s+[a-z_]\w*",
            r"(?m)^\s*(?:sub|function|end\s+(?:if|sub|function))\b",
        ),
        "Batch": (
            r"(?m)^\s*@?echo\s+off\b",
            r"(?m)^\s*set\s+(?:/a\s+)?[a-z_][^=\r\n]*=",
            r"%(?:comspec|temp|appdata|[a-z_][\w]*)%",
            r"\b(?:cmd|powershell)(?:\.exe)?\s+/(?:c|k)\b",
        ),
        "Python": (
            r"(?m)^\s*(?:from\s+\w+(?:\.\w+)*\s+import|import\s+\w+)",
            r"(?m)^\s*(?:async\s+)?def\s+\w+\s*\(",
            r"__name__\s*==\s*['\"]__main__['\"]",
        ),
        "POSIX shell": (
            r"^#!\s*(?:/usr/bin/env\s+|/(?:usr/)?bin/)(?:ba|z|k)?sh\b",
            r"(?m)^\s*(?:if|for|while|case)\s+.+(?:;\s*)?(?:then|do|in)\b",
            r"\$\{?[a-z_][\w]*\}?",
        ),
    }
    for language, patterns in signatures.items():
        matches = sum(bool(re.search(pattern, lowered, re.IGNORECASE)) for pattern in patterns)
        if matches >= 2 or (language == "POSIX shell" and re.search(patterns[0], lowered)):
            return language
    return None


def inspect_zip_type(file_path: str) -> Optional[tuple]:
    try:
        with zipfile.ZipFile(file_path) as archive:
            names = {name.replace("\\", "/").lower() for name in archive.namelist()}
    except (OSError, zipfile.BadZipFile):
        return None
    if "androidmanifest.xml" in names and (
        "classes.dex" in names or any(name.startswith("base/") for name in names)
    ):
        return "ANDROID", "Android package", "ZIP package structure"
    for root, label in (("word/", "Word OpenXML document"), ("xl/", "Excel OpenXML document"), ("ppt/", "PowerPoint OpenXML document")):
        if any(name.startswith(root) for name in names) and "[content_types].xml" in names:
            return "DOCUMENT", label, "OpenXML package structure"
    return None


def get_routing_profile(file_path: str) -> dict:
    """Classify by magic/package structure/content, using suffix only as fallback."""
    try:
        path = Path(file_path)
        raw = path.read_bytes()[:65536]
        header = raw[:256]

        if header.startswith(b"MZ"):
            content = raw.decode("latin-1", errors="ignore")
            if "mscoree.dll" in content or "_CorExeMain" in content:
                return routing_profile("DOTNET", ".NET PE executable", "PE magic and CLR import")
            return routing_profile("NATIVE", "PE executable", "PE magic")
        if header.startswith(b"\x7fELF"):
            return routing_profile("NATIVE", "ELF executable", "ELF magic")
        if header.startswith(b"dex\n"):
            return routing_profile("ANDROID", "Android DEX bytecode", "DEX magic")
        if header.startswith(b"%PDF"):
            return routing_profile("DOCUMENT", "PDF document", "PDF magic")
        if header.startswith(b"{\\rt"):
            return routing_profile("DOCUMENT", "RTF document", "RTF magic")
        if header.startswith(b"\xd0\xcf\x11\xe0"):
            identified = subprocess.run(
                ["file", "--brief", str(path)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            ).stdout.lower()
            for marker, label in (
                ("microsoft word", "Word OLE document"),
                ("microsoft excel", "Excel OLE document"),
                ("microsoft powerpoint", "PowerPoint OLE document"),
            ):
                if marker in identified:
                    return routing_profile("DOCUMENT", label, "OLE magic and libmagic")
        if header.startswith(b"PK\x03\x04"):
            packaged = inspect_zip_type(file_path)
            if packaged:
                return routing_profile(*packaged)

        text = decode_text_sample(raw)
        if text is not None:
            language = detect_script_language(text)
            if language:
                return routing_profile("SCRIPT", f"{language} script", "static syntax signatures")

        # Extensions are a final hint for formats whose content is ambiguous.
        suffix = path.suffix.lower()
        if suffix in DOCUMENT_EXTENSIONS:
            return routing_profile("DOCUMENT", f"{suffix} document", "extension fallback")
        if suffix in SCRIPT_EXTENSIONS:
            return routing_profile("SCRIPT", f"{suffix} script", "extension fallback")
        if suffix in {".apk", ".apkm"}:
            return routing_profile("ANDROID", "Android package", "extension fallback")
        return routing_profile("NATIVE", "unknown file type", "fallback")
    except Exception as exc:
        return routing_profile("NATIVE", "unknown file type", f"classification error: {exc}")


def run_cmd(cmd: List[str], timeout: int = 120):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_json_object(text: str) -> Optional[dict]:
    if not isinstance(text, str):
        return None
    candidate = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", candidate, re.DOTALL | re.IGNORECASE)
    if fenced:
        candidate = fenced.group(1)
    try:
        value = json.loads(candidate)
        return value if isinstance(value, dict) else None
    except (json.JSONDecodeError, TypeError):
        return None


def is_pseudo_tool_call(content: str, available_names: set) -> bool:
    return parse_pseudo_tool_call(content, available_names) is not None


def parse_pseudo_tool_call(content: str, available_names: set) -> Optional[tuple]:
    """Parse common text-serialized tool calls emitted by smaller local models."""
    value = parse_json_object(content)
    if not value:
        return None
    function = value.get("function")
    if isinstance(function, str):
        name = function
        arguments = value.get("arguments", {})
    elif isinstance(function, dict):
        name = function.get("name")
        arguments = function.get("arguments", value.get("arguments", {}))
    elif value.get("method") in available_names:
        name = value.get("method")
        arguments = value.get("params", {})
    else:
        name = value.get("name")
        arguments = value.get("arguments", {})
    if name not in available_names:
        return None
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError:
            return None
    if not isinstance(arguments, dict):
        return None
    return name, arguments


def validate_final_report(
    value: Optional[dict],
    valid_call_ids: set,
    require_script_analysis: bool = False,
) -> List[str]:
    errors = []
    if not isinstance(value, dict):
        return ["final response is not a JSON object"]
    if value.get("verdict") not in {"malicious", "suspicious", "benign", "unknown"}:
        errors.append("invalid verdict")
    confidence = value.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
        errors.append("confidence must be a number between 0 and 1")
    if not isinstance(value.get("summary"), str) or not value.get("summary", "").strip():
        errors.append("summary is missing")
    if not isinstance(value.get("capabilities"), list):
        errors.append("capabilities must be a list")
    if not isinstance(value.get("iocs"), dict):
        errors.append("iocs must be an object")
    evidence = value.get("evidence")
    if not isinstance(evidence, list):
        errors.append("evidence must be a list")
    else:
        for item in evidence:
            if not isinstance(item, dict) or item.get("tool_call_id") not in valid_call_ids:
                errors.append("evidence references an unknown tool call")
                break
    if require_script_analysis:
        script_analysis = value.get("script_analysis")
        if not isinstance(script_analysis, dict):
            errors.append("script_analysis must be an object")
        else:
            if not isinstance(script_analysis.get("obfuscation_detected"), bool):
                errors.append("script_analysis.obfuscation_detected must be a boolean")
            if not isinstance(script_analysis.get("methods"), list):
                errors.append("script_analysis.methods must be a list")
            deobfuscated = script_analysis.get("deobfuscated_script")
            if deobfuscated is not None and not isinstance(deobfuscated, str):
                errors.append("script_analysis.deobfuscated_script must be text or null")
            if not isinstance(script_analysis.get("capabilities_summary"), str):
                errors.append("script_analysis.capabilities_summary must be text")
    return errors


def enrich_script_report(
    candidate: Optional[dict],
    valid_call_ids: set,
    deobfuscated_script: Optional[str],
    methods: List[str],
) -> Optional[dict]:
    """Attach deterministic script-tool results and canonical evidence IDs."""
    if not isinstance(candidate, dict):
        return candidate
    primary_call_id = "call_preflight_deobfuscate"
    if primary_call_id not in valid_call_ids:
        return candidate

    script_analysis = candidate.get("script_analysis")
    if not isinstance(script_analysis, dict):
        script_analysis = {}
    script_analysis["obfuscation_detected"] = bool(methods)
    script_analysis["methods"] = list(methods)
    script_analysis["deobfuscated_script"] = deobfuscated_script if methods else None
    capabilities_summary = script_analysis.get("capabilities_summary")
    if not isinstance(capabilities_summary, str) or not capabilities_summary.strip():
        script_analysis["capabilities_summary"] = candidate.get("summary", "")
    candidate["script_analysis"] = script_analysis

    evidence = candidate.get("evidence")
    if isinstance(evidence, list):
        for item in evidence:
            if isinstance(item, dict) and item.get("tool_call_id") not in valid_call_ids:
                item["tool_call_id"] = primary_call_id
    return candidate


def mcp_result_text(result, max_chars: int = 20000) -> str:
    parts = []
    for item in getattr(result, "content", []) or []:
        parts.append(item.text if hasattr(item, "text") else str(item))
    text = "\n".join(parts) or str(result)
    if len(text) > max_chars:
        return text[:max_chars] + "\n[tool output truncated]"
    return text


def safe_report_stem(member_name: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", member_name).strip("._")
    return stem[:120] or "sample"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    os.replace(temp_path, path)


def is_incompatible_analyzer_result(result_text: str) -> bool:
    """Recognize analyzer failures that cannot improve with another LLM turn."""
    lowered = result_text.lower()
    return any(marker in lowered for marker in (
        "no load spec found",
        "unsupported file format",
        "unrecognized file format",
        "not a valid pe file",
        "not a valid apk",
        "not a .net assembly",
    ))


def make_report(
    input_path: str,
    member_name: str,
    sample_hash: Optional[str],
    route_name: Optional[str],
    model_name: str,
    status: str,
    turns_used: int,
    valid_call_ids: set,
    tool_errors: int,
    final_errors: List[str],
    rejection_history: List[dict],
    final_report: Optional[dict],
    evidence_records: List[dict],
    final_output: Optional[str],
) -> dict:
    score = 0
    score += 35 if status == "complete" else 0
    score += min(25, len(valid_call_ids) * 5)
    if final_report:
        evidence_count = len(final_report.get("evidence", []))
        score += min(25, evidence_count * 5)
        score += 10 if final_report.get("summary") else 0
        score += 5 if final_report.get("verdict") != "unknown" else 0

    quality_reasons = []
    if not valid_call_ids:
        quality_reasons.append("no successful tool calls")
    if final_report is None:
        quality_reasons.append("no valid structured final report")
    if final_report is not None and not final_report.get("evidence"):
        quality_reasons.append("report contains no evidence citations")

    return {
        "schema_version": 1,
        "sample": {
            "archive_path": str(Path(input_path).resolve()),
            "member_name": member_name,
            "sha256": sample_hash,
            "analysis_route": route_name,
        },
        "analysis": {
            "status": status,
            "model": model_name,
            "turns": turns_used,
            "valid_tool_calls": len(valid_call_ids),
            "tool_errors": tool_errors,
            "validation_errors": final_errors,
            "rejection_history": rejection_history,
        },
        "triage": final_report or {
            "verdict": "unknown",
            "confidence": 0.0,
            "summary": "The model did not produce a valid evidence-backed report.",
            "capabilities": [],
            "iocs": {},
            "evidence": [],
        },
        "quality": {"score": score, "reasons": quality_reasons},
        "tool_evidence": evidence_records,
        "raw_model_output": final_output,
    }


def write_report_artifacts(
    reports_dir: Optional[str],
    member_name: str,
    report: dict,
    transcript: List[dict],
) -> None:
    stem = safe_report_stem(member_name)
    report_root = Path(reports_dir) if reports_dir else DEFAULT_REPORTS_DIR
    write_json(report_root / f"{stem}.report.json", report)
    write_json(report_root / f"{stem}.transcript.json", transcript)


def write_deobfuscated_script(
    reports_dir: Optional[str],
    member_name: str,
    deobfuscated_script: str,
) -> str:
    report_root = Path(reports_dir) if reports_dir else DEFAULT_REPORTS_DIR
    path = report_root / f"{safe_report_stem(member_name)}.deobfuscated.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with open(temp_path, "w", encoding="utf-8") as handle:
        handle.write(deobfuscated_script)
        if not deobfuscated_script.endswith("\n"):
            handle.write("\n")
    os.replace(temp_path, path)
    return str(path.resolve())


def is_archive(path: str) -> bool:
    lower = path.lower()
    return lower.endswith(".zip") or lower.endswith(".7z")


def get_7z_targets(archive_path: str, password: str = "infected") -> List[str]:
    sevenz = shutil.which("7z") or shutil.which("7zr") or shutil.which("7za")
    if not sevenz:
        raise RuntimeError("7z executable not found")
    cmd = [sevenz, "l", "-slt", f"-p{password}", archive_path]
    proc = run_cmd(cmd, timeout=180)
    if proc.returncode != 0:
        cmd = [sevenz, "l", "-slt", archive_path]
        proc = run_cmd(cmd, timeout=180)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "7z list failed")
    # The first `Path` in -slt output describes the archive itself. Member
    # records begin after the dashed separator and are separated by blank lines.
    # Recent 7-Zip versions omit `Folder = -` for regular files, so waiting for
    # that field causes every normal member to be silently discarded.
    _, separator, member_output = proc.stdout.partition("----------")
    if not separator:
        raise RuntimeError("Unable to parse 7z technical listing")

    targets = []
    for block in re.split(r"\r?\n\s*\r?\n", member_output.strip()):
        fields = {}
        for line in block.splitlines():
            key, marker, value = line.partition(" = ")
            if marker:
                fields[key.strip()] = value.strip()
        member = fields.get("Path")
        is_folder = fields.get("Folder") == "+" or fields.get("Attributes", "").startswith("D")
        if member and not is_folder and not member.endswith(("/", "\\")):
            validate_archive_member(member)
            targets.append(member)
    return targets


def validate_archive_member(member_name: str) -> None:
    """Reject absolute and parent-traversing archive member paths."""
    normalized = member_name.replace("\\", "/")
    path = Path(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or any(part == ".." for part in path.parts)
    ):
        raise ValueError(f"Unsafe archive member path: {member_name!r}")


def staged_member_path(staging_dir: str, member_name: str) -> str:
    validate_archive_member(member_name)
    stage_root = Path(staging_dir).resolve()
    candidate = (stage_root / Path(member_name.replace("\\", "/"))).resolve()
    if stage_root not in candidate.parents:
        raise ValueError(f"Archive member escapes staging directory: {member_name!r}")
    return str(candidate)


def get_zip_targets(zip_path: str, password: str = "infected") -> List[str]:
    targets = []
    zip_password = password.encode("utf-8") if isinstance(password, str) else password
    with pyzipper.AESZipFile(zip_path, "r") as zf:
        zf.pwd = zip_password
        for member in zf.infolist():
            if member.is_dir() or "__MACOSX" in member.filename or ".DS_Store" in member.filename:
                continue
            validate_archive_member(member.filename)
            targets.append(member.filename)
    return targets


def collect_targets(input_path: str, password: str = "infected") -> List[str]:
    lower = input_path.lower()
    if lower.endswith(".zip"):
        return get_zip_targets(input_path, password)
    if lower.endswith(".7z"):
        return get_7z_targets(input_path, password)
    return [os.path.basename(input_path)]


def extract_member(input_path: str, member_name: str, staging_dir: str, password: str = "infected") -> str:
    target = staged_member_path(staging_dir, member_name)
    lower = input_path.lower()
    if lower.endswith(".zip"):
        zip_password = password.encode("utf-8") if isinstance(password, str) else password
        with pyzipper.AESZipFile(input_path, "r") as zf:
            zf.pwd = zip_password
            zf.extract(member_name, path=staging_dir)
        if not os.path.isfile(target) or os.path.islink(target):
            raise RuntimeError(f"Extracted ZIP member is not a regular file: {member_name!r}")
        return target
    if lower.endswith(".7z"):
        sevenz = shutil.which("7z") or shutil.which("7zr") or shutil.which("7za")
        if not sevenz:
            raise RuntimeError("7z executable not found")
        out_dir = Path(staging_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        cmd = [sevenz, "x", "-y", f"-o{staging_dir}", f"-p{password}", input_path, member_name]
        proc = run_cmd(cmd, timeout=180)
        if proc.returncode != 0:
            cmd = [sevenz, "x", "-y", f"-o{staging_dir}", input_path, member_name]
            proc = run_cmd(cmd, timeout=180)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "7z extract failed")
        if not os.path.isfile(target) or os.path.islink(target):
            raise RuntimeError(f"Extracted 7z member is not a regular file: {member_name!r}")
        return target
    target = staged_member_path(staging_dir, os.path.basename(input_path))
    Path(staging_dir).mkdir(parents=True, exist_ok=True)
    shutil.copy2(input_path, target)
    return target


def make_staged_sample_container_readable(staging_dir: str, target_file_path: str) -> None:
    """Allow the unprivileged analyzer container to traverse its read-only bind mount."""
    stage_root = Path(staging_dir).resolve()
    target = Path(target_file_path).resolve()
    if target != stage_root and stage_root not in target.parents:
        raise ValueError("Staged sample is outside the staging directory")

    os.chmod(stage_root, 0o755)
    current = target.parent
    while current != stage_root:
        os.chmod(current, 0o755)
        current = current.parent
    os.chmod(target, 0o644)


async def triage_binary(
    input_path: str,
    password: str,
    member_name: str,
    model_name: str,
    cli_key: Optional[str],
    verbose: bool,
    reports_dir: Optional[str],
    max_turns: int,
    max_tool_errors: int,
):
    staging_dir = tempfile.mkdtemp(prefix="sandbox_triage_")
    transcript = []
    evidence_records = []
    valid_call_ids = set()
    rejection_history = []
    tool_errors = 0
    final_output = None
    final_report = None
    final_errors = []
    status = "runtime_error"
    turns_used = 0
    sample_hash = None
    route = None
    script_artifact_path = None
    script_deobfuscation_methods = []
    script_recovered_text = None
    print("\n📦 [1/4] Staging target safely...")
    try:
        target_file_path = extract_member(input_path, member_name, staging_dir, password)
        make_staged_sample_container_readable(staging_dir, target_file_path)
    except Exception as e:
        final_errors = [f"extraction error: {e}"]
        report = make_report(
            input_path, member_name, sample_hash, None, model_name, "extraction_error",
            turns_used, valid_call_ids, tool_errors, final_errors, rejection_history,
            final_report, evidence_records, final_output,
        )
        write_report_artifacts(reports_dir, member_name, report, transcript)
        print(f"[-] Extraction error: {e}")
        shutil.rmtree(staging_dir, ignore_errors=True)
        return 1

    try:
        route = get_routing_profile(target_file_path)
        binary_name = os.path.relpath(target_file_path, staging_dir)
        sample_hash = sha256_file(target_file_path)
        server_params = StdioServerParameters(
            command="docker",
            args=[
                "run", "--rm", "-i", "--network", "none",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "512",
                "-v", f"{staging_dir}:/home/remnux/samples:ro",
                route["image"],
            ] + route["args"](binary_name),
        )

        print("🔧 [2/4] Instantiating isolated execution sandbox suite...")
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as mcp_session:
                await mcp_session.initialize()
                tools_discovery = await mcp_session.list_tools()
                available_tools = tools_discovery.tools
                llm_tools = map_mcp_to_litellm_tools(available_tools) if available_tools else None
                available_names = {tool["function"]["name"] for tool in (llm_tools or [])}
                print(f"🤖 [3/4] Establishing orchestration link with analyst node -> ({model_name})...")
                messages = [
                    {"role": "system", "content": route["playbook"] + "\n\n" + REPORT_SCHEMA_PROMPT},
                    {
                        "role": "user",
                        "content": (
                            f"The target file '{binary_name}' is loaded at "
                            f"'/home/remnux/samples/{binary_name}'. Static classification identified it as "
                            f"{route['detected_type']} using {route['identification_method']}. "
                            "Execute the applicable assessment playbook."
                        ),
                    },
                ]
                if route["name"] == "SCRIPT":
                    preflight_calls = [
                        ("call_preflight_metadata", "script.metadata"),
                        ("call_preflight_deobfuscate", "script.deobfuscate"),
                    ]
                    preflight_arguments = {
                        "path": f"/home/remnux/samples/{binary_name}",
                    }
                    messages.append({
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": call_id,
                                "type": "function",
                                "function": {
                                    "name": tool_name,
                                    "arguments": json.dumps(preflight_arguments),
                                },
                            }
                            for call_id, tool_name in preflight_calls
                        ],
                    })
                    for call_id, tool_name in preflight_calls:
                        mcp_result = await mcp_session.call_tool(
                            name=tool_name,
                            arguments=preflight_arguments,
                        )
                        result_text = mcp_result_text(
                            mcp_result,
                            max_chars=100000 if tool_name == "script.deobfuscate" else 20000,
                        )
                        is_error = bool(getattr(mcp_result, "isError", False))
                        if is_error:
                            tool_errors += 1
                        else:
                            valid_call_ids.add(call_id)
                            if tool_name == "script.deobfuscate":
                                decoded_result = parse_json_object(result_text)
                                if decoded_result:
                                    script_deobfuscation_methods = decoded_result.get("methods", [])
                                    recovered = decoded_result.get("deobfuscated_script")
                                    if isinstance(recovered, str):
                                        script_recovered_text = recovered
                                    if (
                                        decoded_result.get("obfuscation_detected")
                                        and isinstance(recovered, str)
                                    ):
                                        script_artifact_path = write_deobfuscated_script(
                                            reports_dir,
                                            member_name,
                                            recovered,
                                        )
                        messages.append({
                            "role": "tool",
                            "name": tool_name,
                            "tool_call_id": call_id,
                            "content": result_text,
                        })
                        record = {
                            "tool_call_id": call_id,
                            "tool": tool_name,
                            "arguments": preflight_arguments,
                            "is_error": is_error,
                            "result": result_text,
                            "preflight": True,
                        }
                        evidence_records.append(record)
                        transcript.append({"turn": 0, "role": "tool", **record})
                    messages.append({
                        "role": "user",
                        "content": (
                            "Static script tools have already run. Analyze their results and return the "
                            "complete final JSON report now. Evidence may cite these exact successful IDs: "
                            + ", ".join(sorted(valid_call_ids))
                            + ". Do not invent IDs or claim behavior absent from the recovered source."
                        ),
                    })
                for turn_number in range(1, max_turns + 1):
                    turns_used = turn_number
                    analyzer_incompatible = False
                    response = litellm.completion(messages=messages, tools=llm_tools, **llm_kwargs(model_name, cli_key))
                    response_message = response.choices[0].message
                    content = response_message.get("content") or ""
                    tool_calls = response_message.get("tool_calls") or []
                    promoted_from_text = False
                    if not tool_calls:
                        pseudo_call = parse_pseudo_tool_call(content, available_names)
                        if pseudo_call:
                            tool_name, tool_args = pseudo_call
                            call_id = f"call_text_{turn_number:02d}"
                            arguments_json = json.dumps(tool_args)
                            tool_calls = [
                                SimpleNamespace(
                                    id=call_id,
                                    function=SimpleNamespace(
                                        name=tool_name,
                                        arguments=arguments_json,
                                    ),
                                )
                            ]
                            messages.append({
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [{
                                    "id": call_id,
                                    "type": "function",
                                    "function": {
                                        "name": tool_name,
                                        "arguments": arguments_json,
                                    },
                                }],
                            })
                            promoted_from_text = True
                    if not promoted_from_text:
                        messages.append(response_message)
                    transcript.append({
                        "turn": turn_number,
                        "role": "assistant",
                        "content": content,
                        "promoted_text_tool_call": promoted_from_text,
                        "tool_calls": [
                            {
                                "id": call.id,
                                "name": call.function.name,
                                "arguments": call.function.arguments,
                            }
                            for call in tool_calls
                        ],
                    })
                    if tool_calls:
                        successful_ids_this_turn = []
                        for tool_call in tool_calls:
                            tool_name = tool_call.function.name
                            call_id = tool_call.id
                            tool_args = None
                            try:
                                tool_args = json.loads(tool_call.function.arguments)
                                if not isinstance(tool_args, dict):
                                    raise ValueError("arguments must decode to an object")
                                if tool_name not in available_names:
                                    raise ValueError(f"tool is not allowed: {tool_name}")
                                mcp_result = await mcp_session.call_tool(name=tool_name, arguments=tool_args)
                                result_text = mcp_result_text(
                                    mcp_result,
                                    max_chars=100000 if tool_name == "script.deobfuscate" else 20000,
                                )
                                is_error = bool(getattr(mcp_result, "isError", False))
                                if is_error:
                                    tool_errors += 1
                                    if is_incompatible_analyzer_result(result_text):
                                        analyzer_incompatible = True
                                else:
                                    valid_call_ids.add(call_id)
                                    successful_ids_this_turn.append(call_id)
                                    if tool_name == "script.deobfuscate":
                                        decoded_result = parse_json_object(result_text)
                                        if decoded_result:
                                            script_deobfuscation_methods = decoded_result.get("methods", [])
                                            recovered = decoded_result.get("deobfuscated_script")
                                            if isinstance(recovered, str):
                                                script_recovered_text = recovered
                                            if (
                                                decoded_result.get("obfuscation_detected")
                                                and isinstance(recovered, str)
                                            ):
                                                script_artifact_path = write_deobfuscated_script(
                                                    reports_dir,
                                                    member_name,
                                                    recovered,
                                                )
                            except Exception as exc:
                                result_text = f"Rejected invalid tool call: {exc}"
                                is_error = True
                                tool_errors += 1

                            messages.append({
                                "role": "tool",
                                "name": tool_name,
                                "tool_call_id": call_id,
                                "content": result_text,
                            })
                            record = {
                                "tool_call_id": call_id,
                                "tool": tool_name,
                                "arguments": tool_args,
                                "is_error": is_error,
                                "result": result_text,
                            }
                            evidence_records.append(record)
                            transcript.append({"turn": turn_number, "role": "tool", **record})
                        if successful_ids_this_turn:
                            messages.append({
                                "role": "user",
                                "content": (
                                    "Successful tool_call_id values now available for evidence: "
                                    + ", ".join(successful_ids_this_turn)
                                    + ". Copy these exact IDs into final-report evidence; never invent an ID."
                                ),
                            })
                        if analyzer_incompatible:
                            status = "analyzer_incompatible"
                            final_errors = [
                                f"selected {route['name']} analyzer cannot load this sample format"
                            ]
                            rejection_history.append({
                                "turn": turn_number,
                                "errors": list(final_errors),
                            })
                            break
                        if tool_errors >= max_tool_errors:
                            status = "tool_error_limit"
                            final_errors = [f"tool error limit reached ({max_tool_errors})"]
                            rejection_history.append({
                                "turn": turn_number,
                                "errors": list(final_errors),
                            })
                            break
                    else:
                        if is_pseudo_tool_call(content, available_names):
                            final_errors = ["model emitted a tool call as text instead of using the tool API"]
                        else:
                            candidate = parse_json_object(content)
                            if route["name"] == "SCRIPT":
                                candidate = enrich_script_report(
                                    candidate,
                                    valid_call_ids,
                                    script_recovered_text,
                                    script_deobfuscation_methods,
                                )
                            final_errors = validate_final_report(
                                candidate,
                                valid_call_ids,
                                require_script_analysis=route["name"] == "SCRIPT",
                            )
                            if not valid_call_ids:
                                final_errors.append("analysis has no successful tool calls")
                            if candidate is not None and not candidate.get("evidence"):
                                final_errors.append("analysis has no cited tool evidence")
                            if not final_errors:
                                final_report = candidate
                                final_output = content
                                status = "complete"
                                break
                        final_output = content
                        rejection_history.append({
                            "turn": turn_number,
                            "errors": list(final_errors),
                        })
                        messages.append({
                            "role": "user",
                            "content": "Your response was rejected: " + "; ".join(final_errors)
                            + ". Continue analysis using real tool calls, or return only a valid final JSON report. "
                            + "For evidence, copy the exact opaque tool_call_id from a successful tool result.",
                        })
                else:
                    status = "turn_limit"
                    turn_error = f"maximum agent turns reached ({max_turns})"
                    final_errors = list(final_errors) + [turn_error]

        report = make_report(
            input_path, member_name, sample_hash, route["name"], model_name, status,
            turns_used, valid_call_ids, tool_errors, final_errors, rejection_history,
            final_report, evidence_records, final_output,
        )
        report["sample"]["detected_type"] = route["detected_type"]
        report["sample"]["identification_method"] = route["identification_method"]
        if route["name"] == "SCRIPT":
            report["analysis"]["script_deobfuscation"] = {
                "methods": script_deobfuscation_methods,
                "artifact_path": script_artifact_path,
            }
        write_report_artifacts(reports_dir, member_name, report, transcript)

        print("\n" + "=" * 60 + f"\n📋 [4/4] ANALYSIS {status.upper()} FOR PAYLOAD: {binary_name}\n" + "=" * 60)
        print(json.dumps(report["triage"], indent=2, ensure_ascii=False))
        print(f"[quality] score={report['quality']['score']}/100 valid_tools={len(valid_call_ids)} turns={turns_used}")
        return 0 if status == "complete" else 1
    except Exception as e:
        final_errors = list(final_errors) + [f"runtime error: {e}"]
        report = make_report(
            input_path, member_name, sample_hash, route["name"] if route else None,
            model_name, "runtime_error", turns_used, valid_call_ids, tool_errors,
            final_errors, rejection_history, final_report, evidence_records, final_output,
        )
        if route:
            report["sample"]["detected_type"] = route["detected_type"]
            report["sample"]["identification_method"] = route["identification_method"]
        if route and route["name"] == "SCRIPT":
            report["analysis"]["script_deobfuscation"] = {
                "methods": script_deobfuscation_methods,
                "artifact_path": script_artifact_path,
            }
        write_report_artifacts(reports_dir, member_name, report, transcript)
        if verbose:
            import traceback
            traceback.print_exc()
        else:
            print(f"❌ Runtime channel interrupted: {str(e)[:200]}")
        return 1
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Automated analyst portal with ZIP, 7z, and direct-file ingest")
    parser.add_argument("input_path", help="Path to a sample archive or direct sample file")
    parser.add_argument(
        "-p", "--password",
        default=config.get("archive_password") or "infected",
        help="Archive password",
    )
    parser.add_argument("-m", "--model", default=config.get("model"), help="LLM model")
    parser.add_argument("-k", "--api-key", default=None, help="API key override")
    parser.add_argument(
        "--reports-dir",
        default=config.get("reports_dir") or str(DEFAULT_REPORTS_DIR),
        help="Write structured JSON reports and transcripts here",
    )
    parser.add_argument(
        "--max-turns", type=int,
        default=int(config.get("max_turns", 20)),
        help="Maximum LLM turns per payload",
    )
    parser.add_argument(
        "--max-tool-errors", type=int,
        default=int(config.get("max_tool_errors", 5)),
        help="Stop after this many rejected/failed tool calls",
    )
    parser.add_argument(
        "--verbose",
        action=argparse.BooleanOptionalAction,
        default=bool(config.get("verbose", False)),
        help="Show verbose runtime diagnostics",
    )
    args = parser.parse_args()

    if args.max_turns < 1 or args.max_tool_errors < 1:
        parser.error("--max-turns and --max-tool-errors must be positive")
    ensure_docker_images_exist()
    try:
        targets = collect_targets(args.input_path, args.password)
    except Exception as e:
        print(f"[-] Failed to enumerate targets: {e}")
        sys.exit(1)
    if not targets:
        print("[-] No triage targets found.")
        sys.exit(1)
    print(f"[+] Targets staging list parsed cleanly -> [Found {len(targets)} executable objects]")
    rc = 0
    for target in targets:
        rc |= asyncio.run(triage_binary(
            args.input_path,
            args.password,
            target,
            args.model,
            args.api_key,
            args.verbose,
            args.reports_dir,
            args.max_turns,
            args.max_tool_errors,
        ))
    sys.exit(rc)


if __name__ == "__main__":
    main()
