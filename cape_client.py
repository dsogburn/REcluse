"""Small, bounded client for a self-hosted CAPE dynamic-analysis service."""

from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests


TERMINAL_FAILURES = {"failed_analysis", "failed_processing", "failed_reporting"}
TERMINAL_SUCCESS = {"completed", "reported"}
DEFAULT_CAPE_NOISE_DOMAINS = {
    "cdn.onenote.net",
    "cdn.onenote.net.edgekey.net",
    "e1553.dspg.akamaiedge.net",
}
DEFAULT_CAPE_NOISE_IPS = {
    "2.18.67.213",
    "4.154.177.13",
    "23.11.32.159",
    "23.44.203.27",
    "23.57.90.148",
    "23.57.90.167",
    "23.217.42.55",
    "40.90.64.229",
    "150.171.85.254",
}


def _noise_indicator(value: Any, domains: set[str], ips: set[str]) -> bool:
    """Match only explicit baseline indicators, including subdomains."""
    if not isinstance(value, str):
        return False
    normalized = value.strip().lower().rstrip(".")
    if normalized in ips:
        return True
    return any(
        normalized == domain or normalized.endswith(f".{domain}")
        for domain in domains
    )


def _item_is_noise(value: Any, domains: set[str], ips: set[str]) -> bool:
    if isinstance(value, dict):
        return any(_item_is_noise(item, domains, ips) for item in value.values())
    if isinstance(value, list):
        return any(_item_is_noise(item, domains, ips) for item in value)
    return _noise_indicator(value, domains, ips)


def filter_cape_baseline_noise(
    summary: dict,
    noise_domains: Any = None,
    noise_ips: Any = None,
) -> dict:
    """Remove known VM baseline traffic from scoring while recording exclusions."""
    domains = {
        str(item).strip().lower().rstrip(".")
        for item in (
            DEFAULT_CAPE_NOISE_DOMAINS if noise_domains is None else noise_domains
        )
        if str(item).strip()
    }
    ips = {
        str(item).strip()
        for item in (DEFAULT_CAPE_NOISE_IPS if noise_ips is None else noise_ips)
        if str(item).strip()
    }
    excluded = {"domains": [], "dns": [], "hosts": [], "signature_data": []}
    for field in ("domains", "dns", "hosts"):
        retained = []
        for item in summary.get(field, []):
            if _item_is_noise(item, domains, ips):
                excluded[field].append(item)
            else:
                retained.append(item)
        summary[field] = retained

    signatures = []
    for signature in summary.get("signatures", []):
        if not isinstance(signature, dict) or signature.get("name") != "stealth_network":
            signatures.append(signature)
            continue
        retained_data = []
        for item in signature.get("data", []):
            if _item_is_noise(item, domains, ips):
                excluded["signature_data"].append(item)
            else:
                retained_data.append(item)
        if retained_data:
            signature = dict(signature)
            signature["data"] = retained_data
            signatures.append(signature)
    summary["signatures"] = signatures

    details = summary.get("analyst_details")
    if isinstance(details, dict):
        details["anomalies"] = [
            item for item in details.get("anomalies", [])
            if not (
                isinstance(item, dict)
                and item.get("signature") == "stealth_network"
                and _item_is_noise(item.get("detail"), domains, ips)
            )
        ]
    counts = {key: len(value) for key, value in excluded.items()}
    summary["baseline_noise"] = {
        "filtered": sum(counts.values()),
        "counts": counts,
        "domains": sorted(domains),
        "ips": sorted(ips),
        "excluded": excluded,
        "note": (
            "Excluded from IOC scoring and model-facing network evidence; "
            "the complete unmodified CAPE report remains in the dynamic artifact."
        ),
    }
    return summary


def validate_cape_url(value: str, allow_remote: bool = False) -> str:
    """Require an explicit HTTP(S) endpoint and default to private infrastructure."""
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("CAPE URL must be an absolute HTTP or HTTPS URL")
    if parsed.username or parsed.password:
        raise ValueError("CAPE URL must not contain embedded credentials")
    if not allow_remote:
        host = parsed.hostname.lower()
        private = host in {"localhost", "127.0.0.1", "::1"}
        try:
            address = ipaddress.ip_address(host)
            private = address.is_private or address.is_loopback
        except ValueError:
            # A hostname cannot be proven private without a DNS lookup.
            private = host.endswith((".local", ".lan", ".internal"))
        if not private:
            raise ValueError(
                "CAPE endpoint is not visibly private; set dynamic_allow_remote=true "
                "only after approving sample disclosure to that service"
            )
    return value.rstrip("/")


class CapeClient:
    def __init__(
        self,
        base_url: str,
        token: str = "",
        *,
        timeout: int = 600,
        poll_interval: int = 10,
        allow_remote: bool = False,
    ):
        self.base_url = validate_cape_url(base_url, allow_remote)
        self.api_url = (
            self.base_url
            if self.base_url.endswith("/apiv2")
            else f"{self.base_url}/apiv2"
        )
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.session = requests.Session()
        if token:
            self.session.headers["Authorization"] = f"Token {token}"

    def _json(self, response: requests.Response) -> dict:
        response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict):
            raise RuntimeError("CAPE returned a non-object JSON response")
        if value.get("error") is True:
            detail = value.get("error_value") or value.get("detail") or "unknown API error"
            raise RuntimeError(f"CAPE API error: {detail}")
        return value

    def submit(self, sample_path: str, *, package: str = "", machine: str = "") -> int:
        path = Path(sample_path)
        data = {}
        if package:
            data["package"] = package
        if machine:
            data["machine"] = machine
        with path.open("rb") as sample:
            response = self.session.post(
                f"{self.api_url}/tasks/create/file/",
                files={"file": (path.name, sample, "application/octet-stream")},
                data=data,
                timeout=60,
            )
        payload = self._json(response)
        task_id = payload.get("task_id")
        if not isinstance(task_id, int):
            task_ids = payload.get("data", {}).get("task_ids", [])
            task_id = task_ids[0] if task_ids else None
        if not isinstance(task_id, int):
            raise RuntimeError(f"CAPE did not return a task ID: {payload}")
        return task_id

    def task_status(self, task_id: int) -> str:
        """Read task state without depending on CAPE's less-stable task view."""
        status_response = self.session.get(
            f"{self.api_url}/tasks/status/{task_id}/",
            timeout=30,
        )
        try:
            status_payload = self._json(status_response)
        except (requests.HTTPError, RuntimeError):
            # Older deployments may not expose the dedicated status API.
            status_payload = None
        if status_payload is not None:
            status = status_payload.get("data")
            if isinstance(status, str):
                return status.lower()
            if isinstance(status, dict):
                return str(status.get("status", "unknown")).lower()

        try:
            view = self._json(self.session.get(
                f"{self.api_url}/tasks/view/{task_id}/",
                timeout=30,
            ))
        except RuntimeError as exc:
            # Some CAPE versions return an API-level error while a task exists
            # but has not reached reporting yet. This is a pending state, not a
            # terminal analysis failure.
            if "still being analyzed" in str(exc).lower():
                return "processing"
            raise
        task = view.get("task") or view.get("data") or view
        if not isinstance(task, dict):
            raise RuntimeError(f"CAPE returned an invalid task status: {view}")
        return str(task.get("status", "unknown")).lower()

    def wait_for_report(self, task_id: int) -> dict:
        deadline = time.monotonic() + self.timeout
        last_status = "unknown"
        while time.monotonic() < deadline:
            last_status = self.task_status(task_id)
            if last_status in TERMINAL_FAILURES:
                raise RuntimeError(f"CAPE task {task_id} ended with status {last_status}")
            if last_status in TERMINAL_SUCCESS:
                response = self.session.get(
                    f"{self.api_url}/tasks/get/report/{task_id}/json/",
                    timeout=60,
                )
                try:
                    return self._json(response)
                except RuntimeError as exc:
                    # CAPE can mark a task reported slightly before the JSON
                    # report has been committed and exposed by the API.
                    if "still being analyzed" not in str(exc).lower():
                        raise
            time.sleep(self.poll_interval)
        raise TimeoutError(
            f"CAPE task {task_id} did not finish within {self.timeout}s "
            f"(last status: {last_status})"
        )

    def analyze(self, sample_path: str, *, package: str = "", machine: str = "") -> tuple[int, dict]:
        task_id = self.submit(sample_path, package=package, machine=machine)
        return task_id, self.wait_for_report(task_id)


def _take(values: Any, limit: int = 50) -> list:
    return list(values[:limit]) if isinstance(values, list) else []


def cape_analyst_details(report: dict) -> dict:
    """Extract deterministic PE pivots and concrete analyst next steps."""
    target = report.get("target") or {}
    target_file = target.get("file", target) if isinstance(target, dict) else {}
    pe = target_file.get("pe") or {} if isinstance(target_file, dict) else {}
    behavior = report.get("behavior") or {}
    behavior_summary = behavior.get("summary") or {}
    network = report.get("network") or {}
    try:
        image_base = int(str(pe.get("imagebase", "0")), 16)
    except ValueError:
        image_base = 0

    sections = []
    for section in _take(pe.get("sections"), 100):
        if not isinstance(section, dict):
            continue
        try:
            rva = int(str(section.get("virtual_address", "0")), 16)
        except ValueError:
            rva = 0
        characteristics = str(section.get("characteristics", ""))
        try:
            entropy = float(section.get("entropy"))
        except (TypeError, ValueError):
            entropy = None
        sections.append({
            "name": section.get("name"),
            "raw_offset": section.get("raw_address"),
            "rva": section.get("virtual_address"),
            "virtual_address": f"0x{image_base + rva:08x}" if image_base else None,
            "virtual_size": section.get("virtual_size"),
            "raw_size": section.get("size_of_data"),
            "entropy": entropy,
            "characteristics": characteristics,
            "writable": "MEM_WRITE" in characteristics,
            "executable": "MEM_EXECUTE" in characteristics,
            "high_entropy": entropy is not None and entropy >= 7.0,
        })

    yara_matches = []
    for rule in _take(target_file.get("yara"), 100) if isinstance(target_file, dict) else []:
        if not isinstance(rule, dict):
            continue
        addresses = []
        for identifier, offset in (rule.get("addresses") or {}).items():
            addresses.append({
                "identifier": identifier,
                "offset": offset,
                "offset_hex": f"0x{offset:08x}" if isinstance(offset, int) else str(offset),
            })
        yara_matches.append({
            "rule": rule.get("name"),
            "description": (rule.get("meta") or {}).get("description"),
            "author": (rule.get("meta") or {}).get("author"),
            "strings": _take(rule.get("strings"), 25),
            "matches": addresses,
        })

    signatures = [
        item for item in _take(report.get("signatures"), 100)
        if isinstance(item, dict)
    ]
    anomalies = []
    for signature in signatures:
        for datum in _take(signature.get("data"), 50):
            anomalies.append({
                "signature": signature.get("name"),
                "severity": signature.get("severity"),
                "confidence": signature.get("confidence"),
                "detail": datum,
            })

    api_categories = {
        "process_injection": {
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtWriteVirtualMemory", "QueueUserAPC",
        },
        "process_execution": {
            "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA",
            "ShellExecuteW",
        },
        "persistence_registry": {
            "RegSetValueA", "RegSetValueW", "RegSetValueExA", "RegSetValueExW",
        },
        "network": {
            "InternetOpenA", "InternetOpenW", "InternetConnectA",
            "InternetConnectW", "HttpSendRequestA", "HttpSendRequestW",
            "WSAConnect", "connect", "send", "recv",
        },
        "anti_analysis": {
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "GetTickCount",
        },
        "dynamic_loading": {
            "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
            "LoadLibraryExW", "GetProcAddress",
        },
        "unpacking_memory": {
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
            "VirtualProtectEx", "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory", "RtlDecompressBuffer",
        },
        "cryptography": {
            "CryptEncrypt", "CryptDecrypt", "CryptProtectData",
            "BCryptEncrypt", "BCryptDecrypt",
        },
    }
    interesting_imports = []
    imports = pe.get("imports") or {}
    if isinstance(imports, dict):
        for dll_name, dll in imports.items():
            for imported in _take((dll or {}).get("imports"), 1000):
                if not isinstance(imported, dict):
                    continue
                api_name = imported.get("name")
                categories = [
                    category for category, names in api_categories.items()
                    if api_name in names
                ]
                if categories:
                    interesting_imports.append({
                        "dll": (dll or {}).get("dll") or dll_name,
                        "api": api_name,
                        "address": imported.get("address"),
                        "categories": categories,
                    })

    resources = []
    for resource in _take(pe.get("resources"), 100):
        if not isinstance(resource, dict):
            continue
        try:
            resource_entropy = float(resource.get("entropy"))
        except (TypeError, ValueError):
            resource_entropy = None
        if resource_entropy is not None and resource_entropy >= 7.0:
            resources.append({
                "name": resource.get("name"),
                "offset": resource.get("offset"),
                "size": resource.get("size"),
                "filetype": resource.get("filetype"),
                "entropy": resource_entropy,
                "language": resource.get("language"),
            })

    entry_rva = pe.get("entrypoint")
    try:
        entry_va = f"0x{image_base + int(str(entry_rva), 16):08x}" if image_base else None
    except (TypeError, ValueError):
        entry_va = None
    pivots = []
    for section in sections:
        reasons = []
        if section["writable"] and section["executable"]:
            reasons.append("writable and executable")
        if section["high_entropy"]:
            reasons.append(f"high entropy ({section['entropy']:.2f})")
        if entry_rva and section["rva"] == entry_rva:
            reasons.append("contains entry point")
        if reasons:
            pivots.append({
                "location": section["virtual_address"] or section["rva"],
                "section": section["name"],
                "reasons": reasons,
            })
    for match in yara_matches:
        for location in match["matches"]:
            pivots.append({
                "location": location["offset_hex"],
                "section": None,
                "reasons": [f"YARA {match['rule']} match ({location['identifier']})"],
            })

    registry_keys = [
        str(value) for value in _take(behavior_summary.get("write_keys"), 75)
        if value
    ]
    written_files = [
        str(value) for value in _take(behavior_summary.get("write_files"), 75)
        if value
    ]
    mutexes = [
        str(value) for value in _take(behavior_summary.get("mutexes"), 75)
        if value
    ]
    dropped_files = []
    for dropped in _take(report.get("dropped"), 50):
        if not isinstance(dropped, dict):
            continue
        dropped_files.append({
            "name": dropped.get("name"),
            "path": dropped.get("path") or dropped.get("guest_paths"),
            "sha256": dropped.get("sha256"),
            "type": dropped.get("type"),
        })

    endpoints = []
    for request in _take(network.get("http"), 75):
        if not isinstance(request, dict):
            continue
        url = request.get("url") or request.get("uri")
        if not url:
            host = request.get("host") or request.get("hostname")
            path = request.get("path")
            if host:
                url = f"{host}{path or ''}"
        if url:
            endpoints.append({
                "url": str(url),
                "method": request.get("method"),
                "status": request.get("status") or request.get("status_code"),
            })
    processes = []
    for process in _take(behavior.get("processes"), 75):
        if not isinstance(process, dict):
            continue
        processes.append({
            "pid": process.get("process_id"),
            "parent_id": process.get("parent_id"),
            "name": process.get("process_name"),
            "command_line": process.get("command_line"),
        })

    next_steps = []
    wx_sections = [item for item in sections if item["writable"] and item["executable"]]
    if wx_sections:
        section_targets = ", ".join(
            f"{item['name'] or 'unnamed'} at {item['virtual_address'] or item['rva']}"
            for item in wx_sections[:4]
        )
        entry_target = entry_va or entry_rva or "the PE entry point"
        next_steps.append(
            f"Set an execute breakpoint at {entry_target}; trace writes into the "
            f"writable/executable section(s) {section_targets}, then break on the "
            "first control transfer into newly written code to identify the OEP."
        )
    high_entropy_sections = [item for item in sections if item["high_entropy"]]
    packing_signatures = {
        "packer_entropy", "packer_unknown_pe_section_name",
        "pe_writable_executable_section",
    }
    looks_packed = bool(
        wx_sections
        or high_entropy_sections
        or any(item.get("name") in packing_signatures for item in signatures)
    )
    if looks_packed and not wx_sections and (entry_va or entry_rva):
        next_steps.append(
            f"Set the initial debugger breakpoint at {entry_va or entry_rva}; trace "
            "the unpacking stub until it changes page protections or transfers control "
            "outside the entry-point section, then dump and rebuild imports at that OEP."
        )
    if high_entropy_sections:
        targets = ", ".join(
            f"{item['name'] or 'unnamed'} at VA {item['virtual_address'] or item['rva']} "
            f"/ raw offset {item['raw_offset']} (entropy {item['entropy']:.2f})"
            for item in high_entropy_sections[:4]
        )
        next_steps.append(
            f"Carve the packed-section candidates {targets}; compare their in-memory "
            "bytes after the suspected OEP transfer with the on-disk bytes to isolate "
            "the unpacked payload."
        )
    unpacking_imports = [
        item for item in interesting_imports
        if "unpacking_memory" in item["categories"]
    ]
    if unpacking_imports:
        targets = ", ".join(
            f"{item['api']} at {item['address'] or 'its import thunk'}"
            for item in unpacking_imports[:6]
        )
        next_steps.append(
            f"Set API breakpoints on {targets}; record destination ranges and "
            "protection changes, then dump a range after it becomes executable."
        )
    for resource in resources[:3]:
        next_steps.append(
            f"Extract the high-entropy resource {resource['name'] or 'unnamed'} at "
            f"file offset {resource['offset'] or 'unknown'} (size "
            f"{resource['size'] or 'unknown'}, entropy {resource['entropy']:.2f}) and "
            "identify/decompress it as a separate candidate payload."
        )
    yara_pivots = [
        (match["rule"], location["offset_hex"])
        for match in yara_matches
        for location in match["matches"]
    ]
    if yara_pivots:
        targets = ", ".join(
            f"{rule or 'unnamed rule'} at file offset {offset}"
            for rule, offset in yara_pivots[:6]
        )
        next_steps.append(
            f"Open the matched bytes for {targets} in the disassembler and follow "
            "cross-references to the containing function before relying on the rule."
        )
    if registry_keys:
        keys = "; ".join(registry_keys[:6])
        next_steps.append(
            f"Review and export the observed registry writes ({keys}); identify the "
            "writing PID and check the referenced value data for persistence paths, "
            "commands, or staged payload locations."
        )
    if written_files:
        paths = "; ".join(written_files[:6])
        next_steps.append(
            f"Acquire the observed written file(s) from the sandbox ({paths}), hash "
            "them, preserve their parent-process lineage, and submit each executable "
            "or script as a new REcluse analysis target."
        )
    if dropped_files:
        targets = "; ".join(
            f"{item['path'] or item['name'] or 'unnamed drop'}"
            + (f" [SHA-256 {item['sha256']}]" if item["sha256"] else "")
            for item in dropped_files[:6]
        )
        next_steps.append(
            f"Pull the dropped artifact(s) from the sandbox ({targets}) and analyze "
            "them independently; correlate each hash with the process that created it."
        )
    if endpoints:
        targets = "; ".join(
            f"{item['method'] or 'request'} {item['url']}"
            for item in endpoints[:6]
        )
        next_steps.append(
            f"Reproduce the observed endpoint request(s) only from an isolated analysis "
            f"network ({targets}); preserve response bytes and headers, then hash and "
            "triage any returned second-stage binary separately."
        )
    child_processes = [
        item for item in processes
        if item.get("parent_id") and (item.get("command_line") or item.get("name"))
    ]
    if child_processes:
        targets = "; ".join(
            f"PID {item['pid']}: {item['command_line'] or item['name']}"
            for item in child_processes[:6]
        )
        next_steps.append(
            f"Recreate breakpoints on process creation for {targets}; inspect the "
            "parent's call site and capture any decoded command line or injected buffer."
        )
    if mutexes:
        next_steps.append(
            "Pivot on the observed mutex name(s) " + "; ".join(mutexes[:6])
            + " across memory, endpoint telemetry, and related samples to identify "
            "execution guards or campaign clustering."
        )
    if any(item.get("signature") == "static_pe_anomaly" for item in anomalies):
        next_steps.append(
            "Compare duplicated section ranges and recalculate the PE checksum; verify "
            "whether the layout is a legitimate build artifact or post-link modification."
        )
    if not next_steps:
        next_steps.append(
            "Validate provenance using the exact hashes and compare against a trusted "
            "vendor release; no address, API, filesystem, registry, or network pivot "
            "was present in the available evidence."
        )

    return {
        "pe": {
            "image_base": pe.get("imagebase"),
            "entry_point_rva": entry_rva,
            "entry_point_va": entry_va,
            "sections": sections,
        },
        "yara_matches": yara_matches,
        "anomalies": anomalies,
        "binary_metadata": {
            "compile_timestamp": pe.get("timestamp"),
            "imphash": pe.get("imphash"),
            "ssdeep": target_file.get("ssdeep") if isinstance(target_file, dict) else None,
            "tlsh": target_file.get("tlsh") if isinstance(target_file, dict) else None,
            "pdb_path": pe.get("pdbpath"),
            "reported_checksum": pe.get("reported_checksum"),
            "actual_checksum": pe.get("actual_checksum"),
            "digitally_signed": bool(pe.get("digital_signers")),
            "digital_signers": _take(pe.get("digital_signers"), 20),
            "exports": _take(pe.get("exports"), 100),
        },
        "interesting_imports": interesting_imports[:100],
        "high_entropy_resources": resources,
        "prioritized_pivots": pivots,
        "runtime_pivots": {
            "registry_keys": registry_keys,
            "written_files": written_files,
            "dropped_files": dropped_files,
            "endpoints": endpoints,
            "processes": processes,
            "mutexes": mutexes,
        },
        "recommended_next_steps": next_steps,
    }


def summarize_cape_report(
    report: dict,
    task_id: int,
    noise_domains: Any = None,
    noise_ips: Any = None,
) -> dict:
    """Reduce a large CAPE report to high-value behavioral evidence for the LLM."""
    behavior = report.get("behavior") or {}
    network = report.get("network") or {}
    target = report.get("target") or {}
    target_file = target.get("file", target) if isinstance(target, dict) else {}
    if isinstance(target_file, dict):
        target_file = {
            key: target_file.get(key)
            for key in ("name", "size", "type", "md5", "sha1", "sha256", "sha512")
            if target_file.get(key) is not None
        }
    signatures = _take(report.get("signatures"), 75)
    summary = {
        "backend": "CAPE",
        "task_id": task_id,
        "target": target_file,
        "score": (report.get("info") or {}).get("score"),
        "signatures": [
            {
                "name": item.get("name"),
                "description": item.get("description"),
                "severity": item.get("severity"),
                "confidence": item.get("confidence"),
                "categories": _take(item.get("categories"), 20),
                "data": _take(item.get("data"), 50),
                "references": _take(item.get("references"), 20),
                "ttps": _take(item.get("ttps"), 20),
            }
            for item in signatures if isinstance(item, dict)
        ],
        "processes": [
            {
                "pid": item.get("process_id"),
                "parent_id": item.get("parent_id"),
                "name": item.get("process_name"),
                "command_line": item.get("command_line"),
            }
            for item in _take(behavior.get("processes"), 75) if isinstance(item, dict)
        ],
        "process_tree": _take(behavior.get("processtree"), 30),
        "domains": _take(network.get("domains"), 75),
        "dns": _take(network.get("dns"), 75),
        "http": _take(network.get("http"), 75),
        "hosts": _take(network.get("hosts"), 75),
        "dropped": _take(report.get("dropped"), 50),
        "registry": _take((behavior.get("summary") or {}).get("write_keys"), 75),
        "files_written": _take((behavior.get("summary") or {}).get("write_files"), 75),
        "mutexes": _take((behavior.get("summary") or {}).get("mutexes"), 75),
        "analyst_details": cape_analyst_details(report),
    }
    summary = filter_cape_baseline_noise(summary, noise_domains, noise_ips)
    # Enforce a hard prompt-size ceiling while retaining valid JSON.
    encoded = json.dumps(summary, ensure_ascii=False)
    if len(encoded) > 120_000:
        for key, limit in (
            ("signatures", 25),
            ("processes", 30),
            ("process_tree", 0),
            ("domains", 30),
            ("dns", 30),
            ("http", 20),
            ("hosts", 30),
            ("dropped", 20),
            ("registry", 30),
            ("files_written", 30),
            ("mutexes", 30),
        ):
            summary[key] = summary[key][:limit]
        summary["truncated"] = True
        encoded = json.dumps(summary, ensure_ascii=False)
    if len(encoded) > 120_000:
        # A provider field can itself contain unusually large strings. Retain a
        # valid, bounded evidence object instead of flooding the model context.
        summary = {
            "backend": "CAPE",
            "task_id": task_id,
            "target": target_file,
            "score": (report.get("info") or {}).get("score"),
            "signatures": summary["signatures"][:10],
            "truncated": True,
            "truncation_reason": "CAPE evidence exceeded the prompt-size ceiling",
        }
    return summary
