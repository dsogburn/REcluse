"""Read-only MCP tools for static malicious-document triage."""

import os
import subprocess
from pathlib import Path
from typing import List

from mcp.server.fastmcp import FastMCP


SAMPLES_ROOT = Path("/home/remnux/samples").resolve()
MAX_OUTPUT_CHARS = 30000
COMMAND_TIMEOUT_SECONDS = 90

mcp = FastMCP("REcluse Malicious Document Analyzer")


def safe_sample_path(path: str) -> Path:
    candidate = Path(path).resolve()
    if candidate == SAMPLES_ROOT or SAMPLES_ROOT not in candidate.parents:
        raise ValueError("path must identify a file below /home/remnux/samples")
    if not candidate.is_file() or candidate.is_symlink():
        raise ValueError("path must identify a regular, non-symlink file")
    return candidate


def run_tool(arguments: List[str]) -> str:
    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except subprocess.TimeoutExpired:
        return f"$ {' '.join(arguments)}\nerror: command timed out"
    except OSError as exc:
        return f"$ {' '.join(arguments)}\nerror: {exc}"

    output = completed.stdout
    if completed.stderr:
        output += ("\n" if output else "") + completed.stderr
    rendered = f"$ {' '.join(arguments)}\nexit_code={completed.returncode}\n{output}"
    if len(rendered) > MAX_OUTPUT_CHARS:
        rendered = rendered[:MAX_OUTPUT_CHARS] + "\n[output truncated]"
    return rendered


@mcp.tool(name="document.metadata")
def document_metadata(path: str) -> str:
    """Identify a document and extract filesystem and embedded metadata."""
    sample = safe_sample_path(path)
    return "\n\n".join((
        run_tool(["file", "-b", str(sample)]),
        run_tool(["exiftool", str(sample)]),
    ))


@mcp.tool(name="document.office_scan")
def office_scan(path: str) -> str:
    """Inspect OLE/OpenXML documents for macros, suspicious VBA, and embedded objects."""
    sample = safe_sample_path(path)
    return "\n\n".join((
        run_tool(["oleid", str(sample)]),
        run_tool(["olevba", "--decode", "--reveal", str(sample)]),
        run_tool(["oleobj", str(sample)]),
    ))


@mcp.tool(name="document.pdf_scan")
def pdf_scan(path: str) -> str:
    """Inspect a PDF for JavaScript, actions, embedded files, and suspicious objects."""
    sample = safe_sample_path(path)
    return "\n\n".join((
        run_tool(["pdfid.py", str(sample)]),
        run_tool(["pdf-parser.py", "--stats", str(sample)]),
    ))


@mcp.tool(name="document.rtf_scan")
def rtf_scan(path: str) -> str:
    """Inspect an RTF document for embedded and potentially exploitable objects."""
    sample = safe_sample_path(path)
    return run_tool(["rtfobj", str(sample)])


@mcp.tool(name="document.archive_listing")
def archive_listing(path: str) -> str:
    """List the internal ZIP/OpenXML package structure without extracting or executing it."""
    sample = safe_sample_path(path)
    return run_tool(["zipinfo", "-l", str(sample)])


@mcp.tool(name="document.strings")
def document_strings(path: str, minimum_length: int = 6) -> str:
    """Extract printable strings for URLs, commands, script fragments, and analyst pivots."""
    sample = safe_sample_path(path)
    if not 4 <= minimum_length <= 40:
        raise ValueError("minimum_length must be between 4 and 40")
    return run_tool(["strings", "-a", f"-n{minimum_length}", str(sample)])


if __name__ == "__main__":
    mcp.run(transport="stdio")
