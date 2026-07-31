import os
import sys
import json
import argparse
import asyncio
import base64
import warnings
import hashlib
import re
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

os.environ.setdefault("LITELLM_TELEMETRY", "False")

import pyzipper
import docker
import litellm
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from sandbox_client import (
    create_sandbox_client,
    summarize_sandbox_report,
    validate_providers,
)
from virustotal_client import VirusTotalClient, summarize_virustotal
from online_enrichment import AbuseChClient, UnpacMeClient

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
    "dynamic_enabled": False,
    "dynamic_provider": "cape",
    "dynamic_providers": [],
    "dynamic_url": "http://127.0.0.1:8000",
    "dynamic_urls": {},
    "dynamic_token": "",
    "dynamic_timeout": 1800,
    "dynamic_poll_interval": 10,
    "dynamic_machine": "",
    "dynamic_package": "",
    "dynamic_allow_remote": False,
    "cape_noise_domains": None,
    "cape_noise_ips": None,
    "remnux_enabled": True,
    "remnux_depth": "deep",
    "remnux_timeout": 900,
    "virustotal_enabled": False,
    "virustotal_api_key": "",
    "virustotal_upload_missing": False,
    "virustotal_allow_upload": False,
    "virustotal_timeout": 300,
    "virustotal_poll_interval": 15,
    "abusech_enabled": False,
    "abusech_auth_key": "",
    "unpacme_enabled": False,
    "unpacme_api_key": "",
    "unpacme_private": True,
    "unpacme_timeout": 900,
    "unpacme_poll_interval": 10,
    "verbose": False,
}
config_path = PROJECT_DIR / "config.json"
if config_path.exists():
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config.update(json.load(f))
    except Exception:
        pass

PLAYBOOK_NATIVE = """
You are an objective reverse-engineering triage engine. Identify structure,
behavior, and analyst pivots. Do not classify a sample as malicious merely
because it implements networking, SSH, cryptography, credential prompts,
process creation, registry access, packing, or other dual-use functionality.
A malicious verdict requires specific evidence of harmful intent or observed
harmful behavior; otherwise use suspicious or unknown. Evidence claims must
state the exact fact returned by the cited tool and must not turn a generic
import or string into an unsupported behavioral conclusion.
""".strip()
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
  "recommended_next_steps": ["specific analyst pivot, extraction step, breakpoint, or artifact to inspect"],
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
        client = docker.from_env(timeout=30)
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
    print("🐳 [startup] Checking Docker and analyzer images...", flush=True)
    docker_client = ensure_docker_client()
    low = docker_client.api
    required_images = {
        "triage-ghidra-mcp": ("Dockerfile.ghidra", False),
        "triage-ilspy-mcp": ("Dockerfile.ilspy", False),
        "triage-jadx-mcp": ("Dockerfile.jadx", False),
        "triage-maldoc-mcp": ("Dockerfile.maldoc", True),
        "triage-script-mcp": ("Dockerfile.script", True),
    }
    try:
        docker_client.images.get("remnux/remnux-distro:noble")
    except docker.errors.ImageNotFound:
        print("🐳 [startup] Pulling REMnux base image; this can take several minutes...", flush=True)
        for chunk in low.pull("remnux/remnux-distro", tag="noble", stream=True, decode=True):
            if chunk.get("status"):
                print(f"[docker] {chunk['status']}", flush=True)
    for image_name, (dockerfile_path, requires_mcp_v1) in required_images.items():
        rebuild = False
        try:
            image = docker_client.images.get(image_name)
            labels = image.attrs.get("Config", {}).get("Labels") or {}
            rebuild = requires_mcp_v1 and labels.get("org.recluse.mcp-api") != "1"
        except docker.errors.ImageNotFound:
            rebuild = True
        if not rebuild:
            continue
        if not (PROJECT_DIR / dockerfile_path).exists():
            continue
        print(f"🐳 [startup] Building {image_name}; first-time setup may take several minutes...", flush=True)
        labels = {"org.recluse.mcp-api": "1"} if requires_mcp_v1 else None
        for chunk in low.build(
            path=str(PROJECT_DIR), dockerfile=dockerfile_path,
            tag=image_name, labels=labels, rm=True, decode=True,
        ):
            if "error" in chunk:
                print(chunk["error"], flush=True)
                sys.exit(1)
            output = str(chunk.get("stream") or "").strip()
            if output:
                print(f"[docker] {output}", flush=True)
    print("🐳 [startup] Analyzer images ready.", flush=True)


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
    if re.search(r"<Project\b", text, re.IGNORECASE) and re.search(
        r"(?:CodeTaskFactory|TaskFactory|UsingTask|Target\b)", text, re.IGNORECASE
    ):
        return "MSBuild XML"
    return None


def decode_pem_armored_payload(file_path: str) -> Optional[dict]:
    """Decode inert PEM-armored Base64 data without interpreting or executing it."""
    raw = Path(file_path).read_bytes()
    match = re.fullmatch(
        rb"\s*-----BEGIN ([^-\r\n]+)-----\s*(.*?)\s*-----END \1-----\s*",
        raw,
        re.DOTALL,
    )
    if not match:
        return None
    encoded = re.sub(rb"\s+", b"", match.group(2))
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    if not decoded:
        return None
    text = decode_text_sample(decoded[:65536])
    language = detect_script_language(text) if text is not None else None
    suffix = {
        "VBScript": ".vbs", "PowerShell": ".ps1", "JavaScript/JScript": ".js",
        "Batch": ".cmd", "Python": ".py", "POSIX shell": ".sh",
        "MSBuild XML": ".xml",
    }.get(language, ".bin")
    return {
        "encoding": "PEM-armored Base64",
        "label": match.group(1).decode("ascii", errors="replace"),
        "decoded": decoded,
        "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
        "decoded_size": len(decoded),
        "detected_content": language or "unknown data",
        "suggested_suffix": suffix,
    }


def stage_decoded_payload(file_path: str, decoded: dict) -> str:
    output = Path(file_path).with_name(
        Path(file_path).name + ".decoded" + decoded["suggested_suffix"]
    )
    output.write_bytes(decoded["decoded"])
    os.chmod(output, 0o644)
    return str(output)


def add_actionable_next_steps(report: Optional[dict], member_name: str,
                              decoded: Optional[dict] = None,
                              source_text: Optional[str] = None) -> Optional[dict]:
    if not isinstance(report, dict):
        return report
    steps = report.get("recommended_next_steps")
    if not isinstance(steps, list):
        steps = []
    if decoded:
        safe_name = Path(member_name).name
        output_name = safe_name + ".decoded" + decoded["suggested_suffix"]
        generated = [
            f"Decode {safe_name} locally with `certutil -decode \"{safe_name}\" \"{output_name}\"` on Windows; the wrapper is PEM-armored Base64.",
            f"On Linux, remove the PEM BEGIN/END lines and pipe the remaining Base64 through `base64 -d` into `{output_name}`.",
            f"Verify the decoded output SHA-256 is `{decoded['decoded_sha256']}` before reviewing it as {decoded['detected_content']}; do not execute it.",
        ]
        for step in generated:
            if step not in steps:
                steps.append(step)
    if source_text:
        decode_commands = re.findall(
            r"certutil(?:\.exe)?\s+-decode\s+(?:\"([^\"]+)\"|(\S+))\s+"
            r"(?:\"([^\"]+)\"|(\S+))",
            source_text,
            re.IGNORECASE,
        )
        for source_quoted, source_plain, output_quoted, output_plain in decode_commands:
            source = source_quoted or source_plain
            output = output_quoted or output_plain
            step = (
                f"Reproduce the script's inert decode manually with `certutil -decode "
                f"\"{source}\" \"{output}\"`, hash the output, then inspect it without execution."
            )
            if step not in steps:
                steps.append(step)
        for command in re.findall(
            r"(?:Exec|Run)\s*\(\s*\"([^\"]+)\"", source_text, re.IGNORECASE
        ):
            step = (
                f"Trace the launched command `{command}` in a debugger or controlled "
                "sandbox and collect any child process, written file, registry, and network artifacts."
            )
            if step not in steps:
                steps.append(step)
    report["recommended_next_steps"] = steps
    return report


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
    verdict = value.get("verdict")
    if not isinstance(verdict, str) or verdict not in {
        "malicious", "suspicious", "benign", "unknown"
    }:
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
            if not isinstance(item.get("claim"), str) or not item["claim"].strip():
                errors.append("each evidence item must include a non-empty claim")
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


def normalize_final_report(
    value: Optional[dict],
    valid_call_ids: Optional[set] = None,
    dynamic_evidence: Optional[dict] = None,
) -> Optional[dict]:
    """Flatten common, unambiguous report shapes emitted by smaller models."""
    if not isinstance(value, dict):
        return value

    report_operation = (
        value.get("op") == "report" and isinstance(value.get("arguments"), dict)
    )
    normalized = dict(value["arguments"] if report_operation else value)
    if report_operation:
        nested_evidence = normalized.get("evidence")
        first_evidence = (
            nested_evidence[0]
            if isinstance(nested_evidence, list)
            and nested_evidence
            and isinstance(nested_evidence[0], dict)
            else {}
        )
        normalized.setdefault("verdict", "unknown")
        normalized.setdefault("confidence", first_evidence.get("confidence", 0.0))
        normalized.setdefault("capabilities", first_evidence.get("capabilities", []))
        normalized.setdefault("iocs", first_evidence.get("iocs", {}))

        if isinstance(nested_evidence, list):
            for item in nested_evidence:
                if not isinstance(item, dict):
                    continue
                call_id = item.get("tool_call_id")
                looks_like_strings = (
                    isinstance(call_id, str) and "string" in call_id.lower()
                ) or "strings" in (item.get("iocs") or {})
                if (
                    valid_call_ids is not None
                    and looks_like_strings
                    and "call_preflight_strings" in valid_call_ids
                ):
                    item["tool_call_id"] = "call_preflight_strings"
                    item["claim"] = (
                        "The cited static string output contains the string "
                        "indicators summarized in this evidence item."
                    )

    verdict = normalized.get("verdict")
    if isinstance(verdict, dict):
        normalized["verdict"] = (
            verdict.get("type") or verdict.get("value") or verdict.get("status")
        )
        if "confidence" not in normalized and "confidence" in verdict:
            normalized["confidence"] = verdict["confidence"]
    if normalized.get("verdict") in {"threat", "malware", "potential_threat"}:
        normalized["verdict"] = "suspicious"

    summary = normalized.get("summary")
    if isinstance(summary, dict):
        normalized["summary"] = summary.get("description") or summary.get("text")
        if "capabilities" not in normalized and isinstance(summary.get("capabilities"), list):
            normalized["capabilities"] = summary["capabilities"]

    evidence = normalized.get("evidence")
    if isinstance(evidence, list):
        normalized_evidence = [
            {
                **item,
                "tool_call_id": (
                    item.get("tool_call_id")
                    or item.get("opaque_tool_call_id")
                    or item.get("id")
                ),
                "claim": item.get("claim") or item.get("description"),
            }
            if isinstance(item, dict) else item
            for item in evidence
        ]
        canonical_claims = {
            "call_preflight_program_open": (
                "Ghidra successfully opened the sample and returned the program "
                "metadata contained in the cited result."
            ),
            "call_preflight_program_summary": (
                "Ghidra produced the program summary contained in the cited result."
            ),
            "call_preflight_imports": (
                "Ghidra produced the imported-function data contained in the "
                "cited result."
            ),
            "call_preflight_strings": (
                "Ghidra produced the defined-string data contained in the cited result."
            ),
            "call_dynamic_sandbox": (
                "The selected dynamic-analysis provider(s) produced the static and "
                "runtime observations contained in the cited sandbox report."
            ),
        }
        for item in normalized_evidence:
            if not isinstance(item, dict):
                continue
            evidence_aliases = {
                "call_remnux_get_file_info": "call_remnux_file_info",
                "call_remnux_analyze_file": "call_remnux_analysis",
            }
            item["tool_call_id"] = evidence_aliases.get(
                item.get("tool_call_id"), item.get("tool_call_id")
            )
            canonical_claim = canonical_claims.get(item.get("tool_call_id"))
            if canonical_claim:
                item["claim"] = canonical_claim
        if valid_call_ids is not None:
            # Unsupported citations cannot substantiate a claim. Drop them while
            # retaining any evidence that references a real successful call.
            normalized_evidence = [
                item for item in normalized_evidence
                if isinstance(item, dict)
                and item.get("tool_call_id") in valid_call_ids
            ]
        normalized["evidence"] = normalized_evidence

    if (
        normalized.get("verdict") in {"malicious", "suspicious"}
        and isinstance(dynamic_evidence, dict)
    ):
        runtime_fields = (
            "processes", "process_tree", "domains", "dns", "http", "hosts",
            "dropped", "registry", "files_written", "mutexes",
        )
        observed_runtime = any(dynamic_evidence.get(field) for field in runtime_fields)
        signatures = dynamic_evidence.get("signatures")
        if not observed_runtime and isinstance(signatures, list) and signatures:
            normalized["verdict"] = "suspicious"
            confidence = normalized.get("confidence")
            if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
                normalized["confidence"] = min(confidence, 0.7)
            normalized["summary"] = (
                "CAPE reported static PE anomalies, including packing or entropy "
                "indicators and a writable-executable section, but recorded no "
                "process, network, file, registry, or mutex behavior. The sample "
                "is suspicious pending corroborating runtime evidence."
            )
    if isinstance(dynamic_evidence, dict):
        analyst_details = dynamic_evidence.get("analyst_details")
        if isinstance(analyst_details, dict):
            normalized["analyst_details"] = analyst_details
            normalized["recommended_next_steps"] = analyst_details.get(
                "recommended_next_steps", []
            )
    return normalized


def deterministic_dynamic_report(dynamic_evidence: dict) -> dict:
    """Build a bounded report when a model repeatedly fails report formatting."""
    signatures = [
        item for item in dynamic_evidence.get("signatures", [])
        if isinstance(item, dict)
    ]
    # Process creation alone only proves the submitted sample ran. It is context,
    # not suspicious behavior. Network fields have already had VM baseline noise
    # removed by the CAPE summarizer.
    runtime_fields = (
        "domains", "dns", "http", "hosts", "dropped", "registry",
        "files_written", "mutexes",
    )
    observed = [field for field in runtime_fields if dynamic_evidence.get(field)]
    low_signal_static = {
        "contains_pe_overlay",
        "pe_section_vsize_rsize_anomaly",
        "pe_writable_executable_section",
        "packer_entropy",
    }
    actionable_signatures = [
        item for item in signatures
        if (
            item.get("name") not in low_signal_static
            and (
                (item.get("severity") or 0) >= 3
                or "static" not in (item.get("categories") or [])
            )
        )
    ]
    target = dynamic_evidence.get("target")
    hashes = {}
    if isinstance(target, dict):
        hashes = {
            key: target[key]
            for key in ("md5", "sha1", "sha256", "sha512")
            if target.get(key)
        }
    if observed:
        summary = (
            "CAPE produced runtime observations in: "
            + ", ".join(observed)
            + ". Automated model responses did not satisfy the report schema; "
            "review the cited sandbox evidence for details."
        )
    elif actionable_signatures:
        summary = (
            "CAPE reported static PE anomalies but no process, network, file, "
            "registry, or mutex behavior. Automated model responses did not "
            "satisfy the report schema; the sample remains suspicious pending review."
        )
    else:
        summary = (
            "CAPE produced no supported suspicious runtime observations. Automated "
            "model responses did not satisfy the report schema."
        )
    analyst_details = dynamic_evidence.get("analyst_details")
    return {
        "verdict": "suspicious" if actionable_signatures or observed else "unknown",
        "confidence": 0.6 if actionable_signatures or observed else 0.0,
        "summary": summary,
        "capabilities": [
            item.get("name") or item.get("description")
            for item in signatures
            if item.get("name") or item.get("description")
        ],
        "iocs": {"file_hashes": hashes} if hashes else {},
        "evidence": [{
            "tool_call_id": "call_dynamic_sandbox",
            "claim": (
                "The selected dynamic-analysis provider(s) produced the static and "
                "runtime observations contained in the cited sandbox report."
            ),
        }],
        "analyst_details": analyst_details if isinstance(analyst_details, dict) else {},
        "recommended_next_steps": (
            analyst_details.get("recommended_next_steps", [])
            if isinstance(analyst_details, dict) else []
        ),
        "report_basis": "deterministic_dynamic_fallback",
    }


def _interesting_string_score(value: str, string_type: str) -> int:
    lowered = value.lower()
    score = 3 if string_type not in {"static", "static_strings"} else 0
    indicators = (
        "http://", "https://", "ftp://", "\\\\", "hkey_", "software\\",
        "powershell", "cmd.exe", "rundll32", "regsvr32", "schtasks",
        "virtualalloc", "writeprocessmemory", "createremotethread",
        "download", "user-agent", "mutex", "password", "token", "base64",
    )
    score += sum(2 for marker in indicators if marker in lowered)
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value):
        score += 3
    if re.search(r"\b[a-z0-9.-]+\.(?:com|net|org|ru|cn|io|onion)\b", lowered):
        score += 3
    if 8 <= len(value) <= 240:
        score += 1
    return score


def summarize_floss_output(value: dict, limit: int = 100) -> dict:
    strings_root = value.get("strings") if isinstance(value, dict) else {}
    candidates = []
    if isinstance(strings_root, dict):
        for string_type, items in strings_root.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, str):
                    text, address = item, None
                elif isinstance(item, dict):
                    text = item.get("string") or item.get("value")
                    address = (
                        item.get("address")
                        or item.get("offset")
                        or item.get("function")
                    )
                else:
                    continue
                if not isinstance(text, str) or not text.strip():
                    continue
                score = _interesting_string_score(text, string_type)
                if score:
                    if isinstance(address, int):
                        address = f"0x{address:08x}"
                    candidates.append({
                        "type": string_type.removesuffix("_strings"),
                        "value": text[:2000],
                        "location": address,
                        "score": score,
                    })
    deduped = {}
    for item in sorted(candidates, key=lambda entry: (-entry["score"], entry["value"])):
        deduped.setdefault(item["value"], item)
    counts = {
        key.removesuffix("_strings"): len(items)
        for key, items in (strings_root or {}).items()
        if isinstance(items, list)
    } if isinstance(strings_root, dict) else {}
    return {
        "status": "complete",
        "counts": counts,
        "interesting_strings": list(deduped.values())[:limit],
    }


def summarize_capa_output(value: dict, limit: int = 100) -> dict:
    rules = value.get("rules") if isinstance(value, dict) else {}
    capabilities = []
    if isinstance(rules, dict):
        for rule_name, rule in rules.items():
            if not isinstance(rule, dict):
                continue
            meta = rule.get("meta") or {}
            matches = rule.get("matches") or []
            locations = []
            for match in matches[:20] if isinstance(matches, list) else []:
                if isinstance(match, (list, tuple)) and match:
                    location = match[0]
                    if isinstance(location, dict):
                        location_value = location.get("value")
                        locations.append(
                            f"0x{location_value:08x}"
                            if location.get("type") == "absolute"
                            and isinstance(location_value, int)
                            else str(location_value or location.get("type") or "")
                        )
                    else:
                        locations.append(str(location))
                elif isinstance(match, dict):
                    locations.append(str(match.get("address") or match.get("location") or ""))
            def mapping_label(mapping):
                if not isinstance(mapping, dict):
                    return str(mapping)
                parts = mapping.get("parts") or []
                label = "::".join(str(part) for part in parts if part)
                identifier = mapping.get("id")
                return f"{label} [{identifier}]" if identifier else label
            capabilities.append({
                "name": meta.get("name") or rule_name,
                "namespace": meta.get("namespace"),
                "description": meta.get("description"),
                "attack": [mapping_label(item) for item in (meta.get("attack") or [])],
                "mbc": [mapping_label(item) for item in (meta.get("mbc") or [])],
                "references": meta.get("references") or [],
                "locations": [item for item in locations if item],
                "match_count": len(matches) if isinstance(matches, list) else 0,
            })
    return {
        "status": "complete",
        "capabilities": capabilities[:limit],
        "capability_count": len(capabilities),
    }


def run_native_companion_tools(
    staging_dir: str,
    binary_name: str,
    reports_dir: Optional[str] = None,
    member_name: Optional[str] = None,
) -> dict:
    """Run bundled REMnux FLOSS/capa in isolated, read-only companion containers."""
    sample_path = f"/home/remnux/samples/{binary_name}"
    common = [
        "docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "512",
        "-v", f"{staging_dir}:/home/remnux/samples:ro",
    ]
    results = {}
    commands = {
        "floss": common + ["--entrypoint", "floss", "triage-ghidra-mcp", "-j", "--", sample_path],
        "capa": common + ["--entrypoint", "capa", "triage-ghidra-mcp", "-j", sample_path],
    }
    for name, command in commands.items():
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            try:
                parsed = json.loads(completed.stdout)
            except json.JSONDecodeError:
                results[name] = {
                    "status": "unavailable",
                    "error": (completed.stderr or completed.stdout)[-1000:],
                }
                continue
            if member_name:
                report_root = Path(reports_dir) if reports_dir else DEFAULT_REPORTS_DIR
                artifact_path = report_root / (
                    f"{safe_report_stem(member_name)}.{name}.json"
                )
                write_json(artifact_path, parsed)
            results[name] = (
                summarize_floss_output(parsed)
                if name == "floss"
                else summarize_capa_output(parsed)
            )
            if member_name:
                results[name]["artifact_path"] = str(artifact_path.resolve())
            if completed.returncode != 0:
                results[name]["warning"] = completed.stderr[-1000:]
        except Exception as exc:
            results[name] = {"status": "unavailable", "error": str(exc)[:1000]}
    return results


async def run_remnux_mcp_analysis(
    target_file_path: str,
    staging_dir: str,
    reports_dir: Optional[str],
    member_name: str,
    depth: str,
    timeout: int,
) -> dict:
    """Run REMnux MCP Scenario 1 against an ephemeral, offline container."""
    server_binary = PROJECT_DIR / "node_modules" / ".bin" / "remnux-mcp-server"
    if not server_binary.is_file():
        return {
            "status": "unavailable",
            "error": "REMnux MCP server is not installed; run ./setup.sh",
        }

    container_name = f"recluse-remnux-{uuid.uuid4().hex[:12]}"
    sample_name = f"{sha256_file(target_file_path)[:16]}-{Path(target_file_path).name}"
    container_path = f"/home/remnux/files/samples/{sample_name}"
    start_command = [
        "docker", "run", "-d", "--rm", "--name", container_name,
        "--network", "none", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "1024",
        "--entrypoint", "sleep", "remnux/remnux-distro:noble", "infinity",
    ]
    try:
        started = subprocess.run(
            start_command, capture_output=True, text=True, timeout=60, check=False,
        )
        if started.returncode != 0:
            raise RuntimeError(started.stderr.strip() or "could not start REMnux container")
        prepared = subprocess.run(
            [
                "docker", "exec", "-u", "remnux", container_name, "mkdir", "-p",
                "/home/remnux/files/samples", "/home/remnux/files/output",
            ],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if prepared.returncode != 0:
            raise RuntimeError(prepared.stderr.strip() or "could not prepare REMnux directories")
        copied = subprocess.run(
            ["docker", "cp", target_file_path, f"{container_name}:{container_path}"],
            capture_output=True, text=True, timeout=120, check=False,
        )
        if copied.returncode != 0:
            raise RuntimeError(copied.stderr.strip() or "could not copy sample into REMnux")

        params = StdioServerParameters(
            command=str(server_binary),
            args=[
                "--mode=docker", f"--container={container_name}", "--sandbox",
                f"--ingest-root={Path(staging_dir).resolve()}",
                f"--timeout={timeout}",
            ],
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                discovered = await session.list_tools()
                names = {tool.name for tool in discovered.tools}
                calls = []
                for call_id, tool_name, arguments in (
                    ("call_remnux_file_info", "get_file_info", {"file": sample_name}),
                    ("call_remnux_suggestions", "suggest_tools", {"file": sample_name}),
                    (
                        "call_remnux_analysis",
                        "analyze_file",
                        {"file": sample_name, "depth": depth},
                    ),
                ):
                    if tool_name not in names:
                        continue
                    result = await session.call_tool(
                        name=tool_name,
                        arguments=arguments,
                        read_timeout_seconds=timedelta(
                            seconds=max(timeout * 8, 3600)
                        ),
                    )
                    calls.append({
                        "tool_call_id": call_id,
                        "tool": f"remnux.{tool_name}",
                        "arguments": arguments,
                        "is_error": bool(getattr(result, "isError", False)),
                        "result": mcp_result_text(result, max_chars=120000),
                        "preflight": True,
                    })

        artifact = {
            "status": "complete" if any(not item["is_error"] for item in calls) else "failed",
            "depth": depth,
            "sample": sample_name,
            "calls": calls,
        }
        report_root = Path(reports_dir) if reports_dir else DEFAULT_REPORTS_DIR
        artifact_path = report_root / f"{safe_report_stem(member_name)}.remnux.json"
        write_json(artifact_path, artifact)
        artifact["artifact_path"] = str(artifact_path.resolve())
        return artifact
    except Exception as exc:
        return {"status": "unavailable", "depth": depth, "error": str(exc)[:2000]}
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True, text=True, timeout=30, check=False,
        )


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
    structured = mcp_structured_content(result)
    if structured:
        parts.append(json.dumps(structured, indent=2, ensure_ascii=False, default=str))
    text = "\n".join(parts) or str(result)
    if len(text) > max_chars:
        return text[:max_chars] + "\n[tool output truncated]"
    return text


def mcp_structured_content(result) -> dict:
    value = getattr(result, "structuredContent", None)
    return value if isinstance(value, dict) else {}


def exception_details(exc: BaseException) -> str:
    """Preserve nested ExceptionGroup causes in persisted runtime reports."""
    details = [f"{type(exc).__name__}: {exc}"]
    nested = getattr(exc, "exceptions", None)
    if nested:
        for child in nested:
            for line in exception_details(child).splitlines():
                details.append(f"  {line}")
    cause = getattr(exc, "__cause__", None)
    if cause is not None and not nested:
        for line in exception_details(cause).splitlines():
            details.append(f"  caused by: {line}")
    return "\n".join(details)


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


def write_dynamic_report(
    reports_dir: Optional[str],
    member_name: str,
    dynamic_report: dict,
    provider: Optional[str] = None,
) -> str:
    report_root = Path(reports_dir) if reports_dir else DEFAULT_REPORTS_DIR
    suffix = f".dynamic.{provider}.json" if provider else ".dynamic.json"
    path = report_root / f"{safe_report_stem(member_name)}{suffix}"
    write_json(path, dynamic_report)
    return str(path.resolve())


def write_virustotal_report(
    reports_dir: Optional[str],
    member_name: str,
    virustotal_report: dict,
) -> str:
    report_root = Path(reports_dir) if reports_dir else DEFAULT_REPORTS_DIR
    path = report_root / f"{safe_report_stem(member_name)}.virustotal.json"
    write_json(path, virustotal_report)
    return str(path.resolve())


def write_online_report(
    reports_dir: Optional[str], member_name: str, provider: str, report: dict,
) -> str:
    report_root = Path(reports_dir) if reports_dir else DEFAULT_REPORTS_DIR
    path = report_root / f"{safe_report_stem(member_name)}.{provider}.json"
    write_json(path, report)
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


def prioritize_archive_targets(targets: List[str]) -> List[str]:
    """Analyze likely orchestrators before opaque payload/support files."""
    executable_suffixes = {".exe", ".dll", ".sys", ".scr", ".com", ".apk", ".dex"}

    def priority(item: tuple[int, str]) -> tuple[int, int]:
        index, name = item
        suffix = Path(name).suffix.lower()
        if suffix in SCRIPT_EXTENSIONS:
            return 0, index
        if suffix in executable_suffixes or suffix in DOCUMENT_EXTENSIONS:
            return 1, index
        return 2, index

    return [name for _, name in sorted(enumerate(targets), key=priority)]


def compact_archive_context(member_name: str, report: dict) -> dict:
    """Retain bounded, analyst-relevant findings for related archive members."""
    sample = report.get("sample") or {}
    analysis = report.get("analysis") or {}
    triage = report.get("triage") or {}
    return {
        "member_name": member_name,
        "sha256": sample.get("sha256"),
        "analysis_route": sample.get("analysis_route"),
        "status": analysis.get("status"),
        "verdict": triage.get("verdict"),
        "confidence": triage.get("confidence"),
        "summary": str(triage.get("summary") or "")[:4000],
        "capabilities": list(triage.get("capabilities") or [])[:50],
        "iocs": triage.get("iocs") or {},
        "recommended_next_steps": list(
            triage.get("recommended_next_steps") or []
        )[:20],
    }


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
    dynamic_enabled: bool,
    dynamic_provider: str,
    dynamic_url: str,
    dynamic_token: str,
    dynamic_timeout: int,
    dynamic_poll_interval: int,
    dynamic_machine: str,
    dynamic_package: str,
    dynamic_allow_remote: bool,
    remnux_enabled: bool,
    remnux_depth: str,
    remnux_timeout: int,
    virustotal_enabled: bool,
    virustotal_api_key: str,
    virustotal_upload_missing: bool,
    virustotal_allow_upload: bool,
    virustotal_timeout: int,
    virustotal_poll_interval: int,
    abusech_enabled: bool,
    abusech_auth_key: str,
    unpacme_enabled: bool,
    unpacme_api_key: str,
    unpacme_upload: bool,
    unpacme_private: bool,
    unpacme_timeout: int,
    unpacme_poll_interval: int,
    archive_members: Optional[List[str]] = None,
    archive_context: Optional[List[dict]] = None,
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
    decoded_payload = None
    decoded_artifact_path = None
    script_artifact_path = None
    script_deobfuscation_methods = []
    script_recovered_text = None
    dynamic_status = "disabled"
    dynamic_task_id = None
    dynamic_artifact_path = None
    dynamic_error = None
    native_enrichment = None
    native_enrichment_future = None
    remnux_enrichment = None
    virustotal_status = "disabled"
    virustotal_artifact_path = None
    virustotal_error = None
    online_results = {
        "abusech": {"status": "disabled", "artifact_path": None, "error": None},
        "unpacme": {"status": "disabled", "artifact_path": None, "error": None},
    }
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
        decoded_payload = decode_pem_armored_payload(target_file_path)
        analysis_file_path = target_file_path
        if decoded_payload:
            analysis_file_path = stage_decoded_payload(target_file_path, decoded_payload)
            if reports_dir:
                artifact_root = Path(reports_dir)
                artifact_root.mkdir(parents=True, exist_ok=True)
                artifact = artifact_root / (
                    safe_report_stem(member_name) + ".decoded" +
                    decoded_payload["suggested_suffix"]
                )
                artifact.write_bytes(decoded_payload["decoded"])
                decoded_artifact_path = str(artifact.resolve())
            print(
                "[static] Decoded PEM-armored Base64 payload for inert content "
                f"analysis ({decoded_payload['detected_content']})."
            )
        route = get_routing_profile(analysis_file_path)
        binary_name = os.path.relpath(analysis_file_path, staging_dir)
        sample_hash = sha256_file(target_file_path)
        dynamic_evidence = None
        dynamic_future = None
        virustotal_future = None
        abusech_future = None
        unpacme_future = None
        provider_label = None
        dynamic_candidate = (
            route["name"] == "DOTNET"
            or route["detected_type"].startswith("PE ")
        )
        if dynamic_enabled and dynamic_candidate:
            dynamic_status = "running"
            selected_providers = validate_providers(dynamic_provider)
            provider_label = ", ".join({
                "cape": "CAPE",
                "anyrun": "ANY.RUN",
                "joesandbox": "Joe Sandbox",
                "triage": "Recorded Future Triage",
            }.get(provider, provider) for provider in selected_providers)
            print(f"🧪 [dynamic] Submitting Windows payload to {provider_label}...")
            try:
                provider_urls = dict(config.get("dynamic_urls") or {})
                provider_urls.setdefault("cape", dynamic_url)
                provider_urls.setdefault("triage", "https://tria.ge/api/v0")
                provider_tokens = dict(config.get("dynamic_tokens") or {})
                upload_providers = validate_providers(
                    os.environ.get("RECLUSE_DYNAMIC_UPLOAD_PROVIDERS", "")
                )
                if len(selected_providers) == 1 and dynamic_token:
                    provider_tokens[selected_providers[0]] = dynamic_token
                sandbox = create_sandbox_client(
                    dynamic_provider,
                    url=(provider_urls if len(selected_providers) > 1 else
                         provider_urls.get(selected_providers[0], dynamic_url)),
                    api_key=(
                        provider_tokens
                        if len(selected_providers) > 1
                        else provider_tokens.get(selected_providers[0], dynamic_token)
                    ),
                    timeout=dynamic_timeout,
                    poll_interval=dynamic_poll_interval,
                    allow_remote=dynamic_allow_remote,
                    upload_allowed={
                        provider: provider in upload_providers
                        for provider in selected_providers
                    },
                )
                dynamic_future = asyncio.create_task(asyncio.to_thread(
                    sandbox.analyze,
                    target_file_path,
                    package=dynamic_package,
                    machine=dynamic_machine,
                ))
            except Exception as exc:
                dynamic_status = "failed"
                dynamic_error = str(exc)[:1000]
                print(
                    f"[dynamic] {provider_label} could not be started: "
                    f"{dynamic_error[:300]}"
                )
        elif dynamic_enabled:
            dynamic_status = "not_applicable"
        if virustotal_enabled:
            virustotal_status = "running"
            print("🛡️ [reputation] Querying VirusTotal by SHA-256...")
            try:
                vt_client = VirusTotalClient(
                    virustotal_api_key,
                    timeout=virustotal_timeout,
                    poll_interval=virustotal_poll_interval,
                )
                virustotal_future = asyncio.create_task(asyncio.to_thread(
                    vt_client.enrich,
                    target_file_path,
                    upload_missing=virustotal_upload_missing,
                    allow_upload=virustotal_allow_upload,
                ))
            except Exception as exc:
                virustotal_status = "failed"
                virustotal_error = str(exc)[:1000]
                print(
                    "[reputation] VirusTotal could not be started: "
                    f"{virustotal_error[:300]}"
                )
        if abusech_enabled:
            online_results["abusech"]["status"] = "running"
            try:
                abuse_client = AbuseChClient(abusech_auth_key)
                abusech_future = asyncio.create_task(asyncio.to_thread(
                    abuse_client.enrich_hash, sample_hash,
                ))
            except Exception as exc:
                online_results["abusech"].update(
                    status="failed", error=str(exc)[:1000]
                )
        if unpacme_enabled:
            if unpacme_upload:
                online_results["unpacme"]["status"] = "running"
                try:
                    unpac_client = UnpacMeClient(
                        unpacme_api_key, timeout=unpacme_timeout,
                        poll_interval=unpacme_poll_interval,
                        private=unpacme_private,
                    )
                    unpacme_future = asyncio.create_task(asyncio.to_thread(
                        unpac_client.analyze, target_file_path,
                    ))
                except Exception as exc:
                    online_results["unpacme"].update(
                        status="failed", error=str(exc)[:1000]
                    )
            else:
                online_results["unpacme"]["status"] = "upload_not_authorized"
        if remnux_enabled:
            print(
                f"🔬 [static] Running REMnux MCP {remnux_depth} analysis "
                "(this may take several minutes)..."
            )
            remnux_enrichment = await run_remnux_mcp_analysis(
                target_file_path,
                staging_dir,
                reports_dir,
                member_name,
                remnux_depth,
                remnux_timeout,
            )
        elif route["name"] == "NATIVE":
            native_enrichment_future = asyncio.create_task(asyncio.to_thread(
                run_native_companion_tools,
                staging_dir,
                binary_name,
                reports_dir,
                member_name,
            ))

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
                if archive_members and len(archive_members) > 1:
                    related_context = json.dumps(
                        archive_context or [], ensure_ascii=False, default=str
                    )[:30000]
                    messages.append({
                        "role": "user",
                        "content": (
                            "This file is one member of a multi-file package. "
                            f"Package members: {json.dumps(archive_members)}. "
                            "Findings already established for earlier members are "
                            f"provided below:\n{related_context}\n"
                            "Use those findings to test this member's likely role, "
                            "including whether it is configuration, encoded data, a "
                            "certificate, or a second-stage payload. Preserve relevant "
                            "capabilities and relationships across members, but cite "
                            "this member's own tool evidence before claiming that it "
                            "implements or exhibits behavior."
                        ),
                    })
                    context_record = {
                        "tool_call_id": "call_package_context",
                        "tool": "package.prior_member_context",
                        "arguments": {"member": member_name},
                        "is_error": False,
                        "result": related_context,
                        "preflight": True,
                    }
                    transcript.append({"turn": 0, "role": "tool", **context_record})
                if decoded_payload:
                    decode_result = json.dumps({
                        key: value for key, value in decoded_payload.items()
                        if key != "decoded"
                    }, ensure_ascii=False, indent=2)
                    call_id = "call_preflight_pem_decode"
                    valid_call_ids.add(call_id)
                    decode_record = {
                        "tool_call_id": call_id,
                        "tool": "static.pem_base64_decode",
                        "arguments": {"path": member_name},
                        "is_error": False,
                        "result": decode_result,
                        "preflight": True,
                    }
                    evidence_records.append(decode_record)
                    transcript.append({"turn": 0, "role": "tool", **decode_record})
                    messages.extend([{
                        "role": "assistant", "content": None,
                        "tool_calls": [{"id": call_id, "type": "function", "function": {
                            "name": "static.pem_base64_decode",
                            "arguments": json.dumps({"path": member_name}),
                        }}],
                    }, {
                        "role": "tool", "name": "static.pem_base64_decode",
                        "tool_call_id": call_id, "content": decode_result,
                    }, {
                        "role": "user",
                        "content": (
                            "The original member was safely decoded as PEM-armored Base64. "
                            f"Analyze the inert decoded file at /home/remnux/samples/{binary_name}. "
                            "Explain the encoding and give exact manual decoding and follow-up steps. "
                            "You may cite call_preflight_pem_decode."
                        ),
                    }])
                if route["name"] == "NATIVE":
                    open_call_id = "call_preflight_program_open"
                    open_arguments = {
                        "path": f"/home/remnux/samples/{binary_name}",
                        "update_analysis": True,
                        "read_only": True,
                    }
                    messages.append({
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": open_call_id,
                            "type": "function",
                            "function": {
                                "name": "program.open",
                                "arguments": json.dumps(open_arguments),
                            },
                        }],
                    })
                    open_result = await mcp_session.call_tool(
                        name="program.open",
                        arguments=open_arguments,
                    )
                    open_text = mcp_result_text(open_result)
                    open_error = bool(getattr(open_result, "isError", False))
                    open_structured = mcp_structured_content(open_result)
                    session_id = open_structured.get("session_id")
                    if not session_id:
                        match = re.search(r"\bsession_id=([A-Za-z0-9_-]+)", open_text)
                        session_id = match.group(1) if match else None
                    if open_error:
                        tool_errors += 1
                    else:
                        valid_call_ids.add(open_call_id)
                    messages.append({
                        "role": "tool",
                        "name": "program.open",
                        "tool_call_id": open_call_id,
                        "content": open_text,
                    })
                    open_record = {
                        "tool_call_id": open_call_id,
                        "tool": "program.open",
                        "arguments": open_arguments,
                        "is_error": open_error,
                        "result": open_text,
                        "preflight": True,
                    }
                    evidence_records.append(open_record)
                    transcript.append({"turn": 0, "role": "tool", **open_record})

                    if not open_error and session_id:
                        summary_call_id = "call_preflight_program_summary"
                        summary_arguments = {"session_id": session_id}
                        messages.append({
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [{
                                "id": summary_call_id,
                                "type": "function",
                                "function": {
                                    "name": "program.summary",
                                    "arguments": json.dumps(summary_arguments),
                                },
                            }],
                        })
                        summary_result = await mcp_session.call_tool(
                            name="program.summary",
                            arguments=summary_arguments,
                        )
                        summary_text = mcp_result_text(summary_result)
                        summary_error = bool(getattr(summary_result, "isError", False))
                        if summary_error:
                            tool_errors += 1
                        else:
                            valid_call_ids.add(summary_call_id)
                        messages.append({
                            "role": "tool",
                            "name": "program.summary",
                            "tool_call_id": summary_call_id,
                            "content": summary_text,
                        })
                        summary_record = {
                            "tool_call_id": summary_call_id,
                            "tool": "program.summary",
                            "arguments": summary_arguments,
                            "is_error": summary_error,
                            "result": summary_text,
                            "preflight": True,
                        }
                        evidence_records.append(summary_record)
                        transcript.append({"turn": 0, "role": "tool", **summary_record})
                        for call_id, tool_name, arguments in (
                            (
                                "call_preflight_imports",
                                "external.imports.list",
                                {"session_id": session_id, "offset": 0, "limit": 100},
                            ),
                            (
                                "call_preflight_strings",
                                "search.defined_strings",
                                {"session_id": session_id, "offset": 0, "limit": 100},
                            ),
                        ):
                            if tool_name not in available_names:
                                continue
                            messages.append({
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [{
                                    "id": call_id,
                                    "type": "function",
                                    "function": {
                                        "name": tool_name,
                                        "arguments": json.dumps(arguments),
                                    },
                                }],
                            })
                            result = await mcp_session.call_tool(
                                name=tool_name,
                                arguments=arguments,
                            )
                            result_text = mcp_result_text(result)
                            is_error = bool(getattr(result, "isError", False))
                            if is_error:
                                tool_errors += 1
                            else:
                                valid_call_ids.add(call_id)
                            messages.append({
                                "role": "tool",
                                "name": tool_name,
                                "tool_call_id": call_id,
                                "content": result_text,
                            })
                            record = {
                                "tool_call_id": call_id,
                                "tool": tool_name,
                                "arguments": arguments,
                                "is_error": is_error,
                                "result": result_text,
                                "preflight": True,
                            }
                            evidence_records.append(record)
                            transcript.append({"turn": 0, "role": "tool", **record})
                    messages.append({
                        "role": "user",
                        "content": (
                            "Ghidra has already opened and analyzed the sample. Continue with targeted "
                            "Ghidra tool calls using the returned session_id. Final evidence may cite "
                            "these exact successful preflight IDs: "
                            + ", ".join(sorted(valid_call_ids))
                            + "."
                        ),
                    })
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
                if native_enrichment_future is not None:
                    print("🔎 [static] Collecting FLOSS strings and capa capabilities...")
                    native_enrichment = await native_enrichment_future
                    for key, tool_name in (
                        ("floss", "static.floss"),
                        ("capa", "static.capa"),
                    ):
                        result = native_enrichment.get(key) or {}
                        if result.get("status") != "complete":
                            continue
                        call_id = f"call_{key}"
                        result_text = json.dumps(result, indent=2, ensure_ascii=False)
                        valid_call_ids.add(call_id)
                        messages.extend([
                            {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [{
                                    "id": call_id,
                                    "type": "function",
                                    "function": {
                                        "name": tool_name,
                                        "arguments": "{}",
                                    },
                                }],
                            },
                            {
                                "role": "tool",
                                "name": tool_name,
                                "tool_call_id": call_id,
                                "content": result_text,
                            },
                        ])
                        record = {
                            "tool_call_id": call_id,
                            "tool": tool_name,
                            "arguments": {},
                            "is_error": False,
                            "result": result_text,
                            "preflight": True,
                        }
                        evidence_records.append(record)
                        transcript.append({"turn": 0, "role": "tool", **record})

                if isinstance(remnux_enrichment, dict):
                    for record in remnux_enrichment.get("calls", []):
                        evidence_records.append(record)
                        transcript.append({"turn": 0, "role": "tool", **record})
                        if record["is_error"]:
                            continue
                        call_id = record["tool_call_id"]
                        valid_call_ids.add(call_id)
                        messages.extend([
                            {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [{
                                    "id": call_id,
                                    "type": "function",
                                    "function": {
                                        "name": record["tool"],
                                        "arguments": json.dumps(record["arguments"]),
                                    },
                                }],
                            },
                            {
                                "role": "tool",
                                "name": record["tool"],
                                "tool_call_id": call_id,
                                "content": record["result"],
                            },
                        ])
                    if remnux_enrichment.get("status") == "complete":
                        messages.append({
                            "role": "user",
                            "content": (
                                "REMnux MCP completed its tool-selection and "
                                f"{remnux_depth} analysis workflow. Use its concrete findings, "
                                "offsets, tool advisories, capability evidence, and IOC results "
                                "to guide targeted reverse engineering. Distinguish artifacts "
                                "from behavior and cite the exact call_remnux_* evidence IDs."
                            ),
                        })
                    else:
                        print(
                            "[static] REMnux MCP unavailable: "
                            f"{remnux_enrichment.get('error', 'analysis failed')[:300]}"
                        )

                if dynamic_future is not None:
                    print(
                        f"🧪 [dynamic] Static preflight complete; waiting up to "
                        f"{dynamic_timeout}s for {provider_label}..."
                    )
                    try:
                        dynamic_task_id, full_dynamic_report = await dynamic_future
                        dynamic_evidence = summarize_sandbox_report(
                            full_dynamic_report,
                            dynamic_task_id,
                            dynamic_provider,
                            noise_domains=config.get("cape_noise_domains"),
                            noise_ips=config.get("cape_noise_ips"),
                        )
                        if len(selected_providers) > 1:
                            dynamic_artifact_path = {}
                            provider_reports = full_dynamic_report.get("providers") or {}
                            for provider in selected_providers:
                                provider_result = provider_reports.get(provider) or {}
                                if provider_result.get("status") == "complete":
                                    dynamic_artifact_path[provider] = write_dynamic_report(
                                        reports_dir, member_name,
                                        provider_result.get("report") or {}, provider,
                                    )
                        else:
                            dynamic_artifact_path = write_dynamic_report(
                                reports_dir, member_name, full_dynamic_report,
                            )
                        dynamic_status = "complete"
                        print(f"[dynamic] {provider_label} task {dynamic_task_id} completed.")
                        call_id = "call_dynamic_sandbox"
                        result_text = json.dumps(dynamic_evidence, indent=2, ensure_ascii=False)
                        valid_call_ids.add(call_id)
                        messages.extend([
                            {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [{
                                    "id": call_id,
                                    "type": "function",
                                    "function": {
                                        "name": "dynamic.sandbox_report",
                                        "arguments": json.dumps({"task_id": dynamic_task_id}),
                                    },
                                }],
                            },
                            {
                                "role": "tool",
                                "name": "dynamic.sandbox_report",
                                "tool_call_id": call_id,
                                "content": result_text,
                            },
                            {
                                "role": "user",
                                "content": (
                                    f"{provider_label} dynamic analysis has completed. Correlate observed "
                                    "runtime behavior with static findings. You may cite "
                                    "call_dynamic_sandbox for claims directly supported by that report."
                                ),
                            },
                        ])
                        record = {
                            "tool_call_id": call_id,
                            "tool": "dynamic.sandbox_report",
                            "arguments": {"task_id": dynamic_task_id},
                            "is_error": False,
                            "result": result_text,
                            "preflight": True,
                        }
                        evidence_records.append(record)
                        transcript.append({"turn": 0, "role": "tool", **record})
                    except Exception as exc:
                        dynamic_status = "failed"
                        dynamic_error = str(exc)[:1000]
                        print(
                            f"[dynamic] {provider_label} analysis unavailable: "
                            f"{dynamic_error[:300]}"
                        )

                if virustotal_future is not None:
                    try:
                        virustotal_result = await virustotal_future
                        virustotal_status = virustotal_result["status"]
                        if virustotal_result.get("report") is not None:
                            virustotal_artifact_path = write_virustotal_report(
                                reports_dir,
                                member_name,
                                virustotal_result,
                            )
                            vt_summary = summarize_virustotal(virustotal_result)
                            call_id = "call_virustotal_reputation"
                            result_text = json.dumps(
                                vt_summary, indent=2, ensure_ascii=False
                            )
                            valid_call_ids.add(call_id)
                            record = {
                                "tool_call_id": call_id,
                                "tool": "reputation.virustotal",
                                "arguments": {"sha256": sample_hash},
                                "is_error": False,
                                "result": result_text,
                                "preflight": True,
                            }
                            messages.extend([
                                {
                                    "role": "assistant",
                                    "content": None,
                                    "tool_calls": [{
                                        "id": call_id,
                                        "type": "function",
                                        "function": {
                                            "name": "reputation.virustotal",
                                            "arguments": json.dumps(
                                                {"sha256": sample_hash}
                                            ),
                                        },
                                    }],
                                },
                                {
                                    "role": "tool",
                                    "name": "reputation.virustotal",
                                    "tool_call_id": call_id,
                                    "content": result_text,
                                },
                                {
                                    "role": "user",
                                    "content": (
                                        "VirusTotal reputation enrichment is available. "
                                        "Treat vendor detections as reputation evidence, "
                                        "not proof of observed runtime behavior. Claims may "
                                        "cite call_virustotal_reputation."
                                    ),
                                },
                            ])
                            evidence_records.append(record)
                            transcript.append({"turn": 0, "role": "tool", **record})
                        print(
                            "[reputation] VirusTotal lookup "
                            f"{virustotal_status.replace('_', ' ')}."
                        )
                    except Exception as exc:
                        virustotal_status = "failed"
                        virustotal_error = str(exc)[:1000]
                        print(
                            "[reputation] VirusTotal enrichment unavailable: "
                            f"{virustotal_error[:300]}"
                        )

                for provider, future in (
                    ("abusech", abusech_future), ("unpacme", unpacme_future)
                ):
                    if future is None:
                        continue
                    try:
                        provider_result = await future
                        artifact_path = write_online_report(
                            reports_dir, member_name, provider, provider_result
                        )
                        online_results[provider].update(
                            status="complete", artifact_path=artifact_path
                        )
                        call_id = f"call_online_{provider}"
                        result_text = json.dumps(
                            provider_result, ensure_ascii=False, default=str
                        )[:100000]
                        valid_call_ids.add(call_id)
                        record = {
                            "tool_call_id": call_id,
                            "tool": f"online.{provider}",
                            "arguments": {"sha256": sample_hash},
                            "is_error": False,
                            "result": result_text,
                            "preflight": True,
                        }
                        messages.extend([{
                            "role": "assistant", "content": None,
                            "tool_calls": [{"id": call_id, "type": "function",
                                "function": {"name": f"online.{provider}",
                                "arguments": json.dumps({"sha256": sample_hash})}}],
                        }, {
                            "role": "tool", "name": f"online.{provider}",
                            "tool_call_id": call_id, "content": result_text,
                        }])
                        evidence_records.append(record)
                        transcript.append({"turn": 0, "role": "tool", **record})
                    except Exception as exc:
                        online_results[provider].update(
                            status="failed", error=str(exc)[:1000]
                        )

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
                            candidate = normalize_final_report(
                                parse_json_object(content),
                                valid_call_ids,
                                dynamic_evidence,
                            )
                            if route["name"] == "SCRIPT":
                                candidate = enrich_script_report(
                                    candidate,
                                    valid_call_ids,
                                    script_recovered_text,
                                    script_deobfuscation_methods,
                                )
                            source_text = decode_text_sample(
                                Path(analysis_file_path).read_bytes()[:1000000]
                            )
                            candidate = add_actionable_next_steps(
                                candidate, member_name, decoded_payload, source_text
                            )
                            if isinstance(candidate, dict) and isinstance(native_enrichment, dict):
                                candidate["static_enrichment"] = native_enrichment
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
                        if (
                            len(rejection_history) >= 5
                            and isinstance(dynamic_evidence, dict)
                            and "call_dynamic_sandbox" in valid_call_ids
                            and route["name"] != "SCRIPT"
                        ):
                            final_report = deterministic_dynamic_report(dynamic_evidence)
                            final_errors = []
                            status = "complete"
                            print(
                                "[report] Model formatting failed repeatedly; "
                                "using bounded CAPE evidence fallback."
                            )
                            break
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

        if isinstance(final_report, dict) and isinstance(native_enrichment, dict):
            final_report["static_enrichment"] = native_enrichment
        report = make_report(
            input_path, member_name, sample_hash, route["name"], model_name, status,
            turns_used, valid_call_ids, tool_errors, final_errors, rejection_history,
            final_report, evidence_records, final_output,
        )
        report["sample"]["detected_type"] = route["detected_type"]
        report["sample"]["identification_method"] = route["identification_method"]
        if decoded_payload:
            report["analysis"]["decoded_payload"] = {
                **{key: value for key, value in decoded_payload.items() if key != "decoded"},
                "artifact_path": decoded_artifact_path,
                "analyzed_member_path": binary_name,
            }
        if route["name"] == "SCRIPT":
            report["analysis"]["script_deobfuscation"] = {
                "methods": script_deobfuscation_methods,
                "artifact_path": script_artifact_path,
            }
        report["analysis"]["dynamic_analysis"] = {
            "enabled": dynamic_enabled,
            "status": dynamic_status,
            "backend": dynamic_provider if dynamic_enabled else None,
            "task_id": dynamic_task_id,
            "artifact_path": dynamic_artifact_path,
            "error": dynamic_error,
        }
        report["analysis"]["native_enrichment"] = {
            key: (value or {}).get("status", "unavailable")
            for key, value in (native_enrichment or {}).items()
        }
        report["analysis"]["remnux_mcp"] = {
            "enabled": remnux_enabled,
            "status": (remnux_enrichment or {}).get(
                "status", "disabled" if not remnux_enabled else "unavailable"
            ),
            "depth": remnux_depth if remnux_enabled else None,
            "artifact_path": (remnux_enrichment or {}).get("artifact_path"),
            "error": (remnux_enrichment or {}).get("error"),
        }
        report["analysis"]["virustotal"] = {
            "enabled": virustotal_enabled,
            "status": virustotal_status,
            "upload_missing": (
                virustotal_upload_missing if virustotal_enabled else False
            ),
            "artifact_path": virustotal_artifact_path,
            "error": virustotal_error,
        }
        report["analysis"]["online_enrichment"] = online_results
        if isinstance(final_report, dict) and isinstance(remnux_enrichment, dict):
            final_report.setdefault("static_enrichment", {})["remnux"] = {
                "status": remnux_enrichment.get("status"),
                "depth": remnux_enrichment.get("depth"),
                "artifact_path": remnux_enrichment.get("artifact_path"),
            }
        write_report_artifacts(reports_dir, member_name, report, transcript)

        print("\n" + "=" * 60 + f"\n📋 [4/4] ANALYSIS {status.upper()} FOR PAYLOAD: {binary_name}\n" + "=" * 60)
        print(json.dumps(report["triage"], indent=2, ensure_ascii=False))
        print(f"[quality] score={report['quality']['score']}/100 valid_tools={len(valid_call_ids)} turns={turns_used}")
        return 0 if status == "complete" else 1
    except Exception as e:
        final_errors = list(final_errors) + [f"runtime error: {exception_details(e)}"]
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
        report["analysis"]["dynamic_analysis"] = {
            "enabled": dynamic_enabled,
            "status": dynamic_status,
            "backend": dynamic_provider if dynamic_enabled else None,
            "task_id": dynamic_task_id,
            "artifact_path": dynamic_artifact_path,
            "error": dynamic_error,
        }
        report["analysis"]["virustotal"] = {
            "enabled": virustotal_enabled,
            "status": virustotal_status,
            "upload_missing": (
                virustotal_upload_missing if virustotal_enabled else False
            ),
            "artifact_path": virustotal_artifact_path,
            "error": virustotal_error,
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
    parser.add_argument(
        "--dynamic",
        action=argparse.BooleanOptionalAction,
        default=bool(config.get("dynamic_enabled", False)),
        help="Submit Windows PE/.NET samples to a configured dynamic-analysis sandbox",
    )
    parser.add_argument(
        "--dynamic-provider",
        default=(
            ",".join(config.get("dynamic_providers") or [])
            or config.get("dynamic_provider", "cape")
        ),
        help="Comma-separated sandbox providers: cape, anyrun, joesandbox, triage",
    )
    parser.add_argument("--dynamic-url", default=config.get("dynamic_url", "http://127.0.0.1:8000"))
    parser.add_argument(
        "--dynamic-token",
        default=os.environ.get("RECLUSE_DYNAMIC_TOKEN", ""),
    )
    parser.add_argument("--dynamic-timeout", type=int, default=int(config.get("dynamic_timeout", 1800)))
    parser.add_argument("--dynamic-poll-interval", type=int, default=int(config.get("dynamic_poll_interval", 10)))
    parser.add_argument("--dynamic-machine", default=config.get("dynamic_machine", ""))
    parser.add_argument("--dynamic-package", default=config.get("dynamic_package", ""))
    parser.add_argument(
        "--dynamic-allow-remote",
        action=argparse.BooleanOptionalAction,
        default=bool(config.get("dynamic_allow_remote", False)),
        help="Allow sample bytes to be disclosed to a remote sandbox provider",
    )
    parser.add_argument(
        "--remnux",
        action=argparse.BooleanOptionalAction,
        default=bool(config.get("remnux_enabled", True)),
        help="Run broad static analysis through the local REMnux MCP container",
    )
    parser.add_argument(
        "--remnux-depth",
        choices=("quick", "standard", "deep"),
        default=config.get("remnux_depth", "deep"),
    )
    parser.add_argument(
        "--remnux-timeout",
        type=int,
        default=int(config.get("remnux_timeout", 900)),
        help="Per-command REMnux MCP timeout in seconds",
    )
    parser.add_argument(
        "--virustotal",
        action=argparse.BooleanOptionalAction,
        default=bool(config.get("virustotal_enabled", False)),
        help="Query VirusTotal file reputation by SHA-256",
    )
    parser.add_argument(
        "--virustotal-api-key",
        default=os.environ.get("RECLUSE_VIRUSTOTAL_API_KEY", ""),
    )
    parser.add_argument(
        "--virustotal-upload-missing",
        action=argparse.BooleanOptionalAction,
        default=bool(config.get("virustotal_upload_missing", False)),
        help="Upload samples whose hashes are unknown to VirusTotal",
    )
    parser.add_argument(
        "--virustotal-allow-upload",
        action=argparse.BooleanOptionalAction,
        default=bool(config.get("virustotal_allow_upload", False)),
        help="Consent to disclose unknown sample bytes to VirusTotal",
    )
    parser.add_argument(
        "--virustotal-timeout",
        type=int,
        default=int(config.get("virustotal_timeout", 300)),
    )
    parser.add_argument(
        "--virustotal-poll-interval",
        type=int,
        default=int(config.get("virustotal_poll_interval", 15)),
    )
    parser.add_argument("--abusech", action=argparse.BooleanOptionalAction,
                        default=bool(config.get("abusech_enabled", False)))
    parser.add_argument("--abusech-auth-key",
                        default=os.environ.get("RECLUSE_ABUSECH_AUTH_KEY", ""))
    parser.add_argument("--unpacme", action=argparse.BooleanOptionalAction,
                        default=bool(config.get("unpacme_enabled", False)))
    parser.add_argument("--unpacme-api-key",
                        default=os.environ.get("RECLUSE_UNPACME_API_KEY", ""))
    parser.add_argument("--unpacme-upload", action=argparse.BooleanOptionalAction,
                        default=False)
    parser.add_argument("--unpacme-private", action=argparse.BooleanOptionalAction,
                        default=bool(config.get("unpacme_private", True)))
    parser.add_argument("--unpacme-timeout", type=int,
                        default=int(config.get("unpacme_timeout", 900)))
    parser.add_argument("--unpacme-poll-interval", type=int,
                        default=int(config.get("unpacme_poll_interval", 10)))
    args = parser.parse_args()
    selected_dynamic_providers = validate_providers(args.dynamic_provider)
    if not args.dynamic_token and len(selected_dynamic_providers) == 1:
        selected_provider = selected_dynamic_providers[0]
        args.dynamic_token = (
            (config.get("dynamic_tokens") or {}).get(selected_provider)
            or (config.get("dynamic_token", "") if selected_provider == "cape" else "")
        )
    if not args.virustotal_api_key:
        args.virustotal_api_key = config.get("virustotal_api_key", "")
    if not args.abusech_auth_key:
        args.abusech_auth_key = config.get("abusech_auth_key", "")
    if not args.unpacme_api_key:
        args.unpacme_api_key = config.get("unpacme_api_key", "")

    if (
        args.max_turns < 1
        or args.max_tool_errors < 1
        or args.dynamic_timeout < 1
        or args.dynamic_poll_interval < 1
        or args.remnux_timeout < 1
        or args.virustotal_timeout < 1
        or args.virustotal_poll_interval < 1
        or args.unpacme_timeout < 1
        or args.unpacme_poll_interval < 1
    ):
        parser.error("turn, error, timeout, and polling limits must be positive")
    ensure_docker_images_exist()
    try:
        targets = collect_targets(args.input_path, args.password)
    except Exception as e:
        print(f"[-] Failed to enumerate targets: {e}")
        sys.exit(1)
    if not targets:
        print("[-] No triage targets found.")
        sys.exit(1)
    targets = prioritize_archive_targets(targets)
    print(f"[+] Targets staging list parsed cleanly -> [Found {len(targets)} executable objects]")
    archive_context = []
    member_results = []
    for target in targets:
        target_rc = asyncio.run(triage_binary(
            args.input_path,
            args.password,
            target,
            args.model,
            args.api_key,
            args.verbose,
            args.reports_dir,
            args.max_turns,
            args.max_tool_errors,
            args.dynamic,
            args.dynamic_provider,
            args.dynamic_url,
            args.dynamic_token,
            args.dynamic_timeout,
            args.dynamic_poll_interval,
            args.dynamic_machine,
            args.dynamic_package,
            args.dynamic_allow_remote,
            args.remnux,
            args.remnux_depth,
            args.remnux_timeout,
            args.virustotal,
            args.virustotal_api_key,
            args.virustotal_upload_missing,
            args.virustotal_allow_upload,
            args.virustotal_timeout,
            args.virustotal_poll_interval,
            args.abusech,
            args.abusech_auth_key,
            args.unpacme,
            args.unpacme_api_key,
            args.unpacme_upload,
            args.unpacme_private,
            args.unpacme_timeout,
            args.unpacme_poll_interval,
            targets,
            archive_context,
        ))
        report_root = Path(args.reports_dir) if args.reports_dir else DEFAULT_REPORTS_DIR
        report_path = report_root / f"{safe_report_stem(target)}.report.json"
        report = {}
        try:
            report = json.loads(report_path.read_text())
            archive_context.append(compact_archive_context(target, report))
        except (OSError, ValueError, TypeError):
            pass
        member_results.append({
            "member_name": target,
            "return_code": target_rc,
            "report_path": str(report_path.resolve()) if report_path.exists() else None,
            "status": (report.get("analysis") or {}).get("status", "failed"),
            "verdict": (report.get("triage") or {}).get("verdict", "unknown"),
        })

    succeeded = sum(item["return_code"] == 0 for item in member_results)
    package_status = (
        "complete" if succeeded == len(member_results)
        else "completed_with_warnings" if succeeded
        else "failed"
    )
    if len(member_results) > 1:
        package_path = (
            Path(args.reports_dir) if args.reports_dir else DEFAULT_REPORTS_DIR
        ) / f"{safe_report_stem(Path(args.input_path).name)}.package.json"
        write_json(package_path, {
            "schema_version": 1,
            "archive_path": str(Path(args.input_path).resolve()),
            "status": package_status,
            "successful_members": succeeded,
            "total_members": len(member_results),
            "members": member_results,
            "shared_context": archive_context,
        })
        print(
            f"[package] {package_status.replace('_', ' ')}: "
            f"{succeeded}/{len(member_results)} members completed successfully."
        )
    sys.exit(0 if package_status == "complete" else 2 if succeeded else 1)


if __name__ == "__main__":
    main()
