"""Read-only, non-executing MCP tools for static script deobfuscation."""

import base64
import hashlib
import html
import json
import re
import zlib
from pathlib import Path
from typing import Callable, List, Tuple
from urllib.parse import unquote

from mcp.server.fastmcp import FastMCP


SAMPLES_ROOT = Path("/home/remnux/samples").resolve()
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_CHARS = 60000
MAX_PASSES = 6

mcp = FastMCP("REcluse Static Script Analyzer")


def safe_sample_path(path: str) -> Path:
    candidate = Path(path).resolve()
    if candidate == SAMPLES_ROOT or SAMPLES_ROOT not in candidate.parents:
        raise ValueError("path must identify a file below /home/remnux/samples")
    if not candidate.is_file() or candidate.is_symlink():
        raise ValueError("path must identify a regular, non-symlink file")
    if candidate.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"script exceeds the {MAX_INPUT_BYTES}-byte static-analysis limit")
    return candidate


def read_script(path: str) -> Tuple[Path, bytes, str, str]:
    sample = safe_sample_path(path)
    raw = sample.read_bytes()
    encoding = "utf-8"
    for candidate in ("utf-8-sig", "utf-16", "utf-16-le", "latin-1"):
        try:
            text = raw.decode(candidate)
            encoding = candidate
            break
        except UnicodeDecodeError:
            continue
    return sample, raw, text, encoding


def printable(value: str) -> bool:
    if not value:
        return False
    good = sum(character.isprintable() or character in "\r\n\t" for character in value)
    return good / len(value) >= 0.85


def decode_base64(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 8 or len(compact) > MAX_OUTPUT_CHARS * 2:
        return None
    try:
        raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except Exception:
        return None
    encodings = ("utf-16-le", "utf-8", "latin-1") if b"\x00" in raw else ("utf-8", "utf-16-le", "latin-1")
    for encoding in encodings:
        try:
            decoded = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if printable(decoded):
            return decoded
    return None


def decode_compressed_base64(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    try:
        raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except Exception:
        return None
    for window_bits in (-zlib.MAX_WBITS, zlib.MAX_WBITS, zlib.MAX_WBITS | 16):
        try:
            decompressor = zlib.decompressobj(window_bits)
            decoded = decompressor.decompress(raw, MAX_OUTPUT_CHARS + 1)
        except zlib.error:
            continue
        if len(decoded) > MAX_OUTPUT_CHARS:
            return None
        for encoding in ("utf-8", "utf-16-le", "latin-1"):
            try:
                text = decoded.decode(encoding)
            except UnicodeDecodeError:
                continue
            if printable(text):
                return text
    return None


def substitute(
    text: str,
    pattern: str,
    decoder: Callable[[re.Match], str | None],
) -> Tuple[str, int]:
    count = 0

    def replacement(match: re.Match) -> str:
        nonlocal count
        decoded = decoder(match)
        if decoded is None:
            return match.group(0)
        count += 1
        return decoded

    return re.sub(pattern, replacement, text, flags=re.IGNORECASE), count


def deobfuscate_text(text: str) -> Tuple[str, List[str]]:
    methods: List[str] = []
    current = text
    if re.search(r"(?:deflate|gzip|compression)", text, re.IGNORECASE):
        for candidate in re.findall(r"['\"]([A-Za-z0-9+/=]{40,})['\"]", text):
            decoded_payload = decode_compressed_base64(candidate)
            if decoded_payload is not None:
                current = decoded_payload
                methods.append("DEFLATE/GZip-compressed Base64 decoding")
                break

    transformations = [
        (
            "DEFLATE/GZip-compressed Base64 decoding",
            r"['\"]([A-Za-z0-9+/=]{40,})['\"]",
            lambda match: json.dumps(decode_compressed_base64(match.group(1)))
            if decode_compressed_base64(match.group(1)) is not None else None,
        ),
        (
            "PowerShell encoded-command Base64 decoding",
            r"-(?:e|en|enc|enco|encod|encode|encodedcommand)\s+['\"]?([A-Za-z0-9+/=]{8,})['\"]?",
            lambda match: decode_base64(match.group(1)),
        ),
        (
            "FromBase64String literal decoding",
            r"(?:\[Convert\]::)?FromBase64String\(\s*['\"]([A-Za-z0-9+/=\s]{8,})['\"]\s*\)",
            lambda match: json.dumps(decode_base64(match.group(1)))
            if decode_base64(match.group(1)) is not None else None,
        ),
        (
            "JavaScript fromCharCode decoding",
            r"(?:String\.)?fromCharCode\(\s*((?:0x[0-9a-f]+|\d+)(?:\s*,\s*(?:0x[0-9a-f]+|\d+))*)\s*\)",
            lambda match: json.dumps("".join(
                chr(int(value.strip(), 0))
                for value in match.group(1).split(",")
                if int(value.strip(), 0) <= 0x10FFFF
            )),
        ),
        (
            "PowerShell character-code decoding",
            r"\[char\]\s*(0x[0-9a-f]+|\d+)",
            lambda match: json.dumps(chr(int(match.group(1), 0)))
            if int(match.group(1), 0) <= 0x10FFFF else None,
        ),
        (
            "hexadecimal escape decoding",
            r"\\x([0-9a-f]{2})",
            lambda match: chr(int(match.group(1), 16)),
        ),
        (
            "Unicode escape decoding",
            r"\\u([0-9a-f]{4})",
            lambda match: chr(int(match.group(1), 16)),
        ),
        (
            "percent-encoding decoding",
            r"(?:%[0-9a-f]{2}){2,}",
            lambda match: unquote(match.group(0)),
        ),
        (
            "HTML entity decoding",
            r"(?:&#(?:x[0-9a-f]+|\d+);|&(?:amp|lt|gt|quot|apos);)",
            lambda match: html.unescape(match.group(0)),
        ),
    ]

    for _ in range(MAX_PASSES):
        changed = False
        for method, pattern, decoder in transformations:
            updated, count = substitute(current, pattern, decoder)
            if count and updated != current:
                current = updated
                changed = True
                if method not in methods:
                    methods.append(method)

        # Fold adjacent same-quote string literals joined with +, &, or PowerShell -join.
        concat_pattern = r"(['\"])([^'\"\r\n]{0,200})\1\s*(?:\+|&)\s*\1([^'\"\r\n]{0,200})\1"
        updated, count = substitute(
            current,
            concat_pattern,
            lambda match: match.group(1) + match.group(2) + match.group(3) + match.group(1),
        )
        if count and updated != current:
            current = updated
            changed = True
            if "literal string-concatenation folding" not in methods:
                methods.append("literal string-concatenation folding")
        if not changed:
            break

    return current[:MAX_OUTPUT_CHARS], methods


@mcp.tool(name="script.metadata")
def script_metadata(path: str) -> str:
    """Return script size, hash, encoding, and language hint without executing it."""
    sample, raw, _, encoding = read_script(path)
    return json.dumps({
        "path": str(sample),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "encoding": encoding,
        "extension": sample.suffix.lower(),
    }, indent=2)


@mcp.tool(name="script.read")
def script_read(path: str) -> str:
    """Read the original script as inert text. This never invokes an interpreter."""
    _, _, text, _ = read_script(path)
    return text[:MAX_OUTPUT_CHARS]


@mcp.tool(name="script.deobfuscate")
def script_deobfuscate(path: str) -> str:
    """Apply bounded static decoders and return recovered text plus every method used."""
    _, raw, text, encoding = read_script(path)
    deobfuscated, methods = deobfuscate_text(text)
    return json.dumps({
        "sha256": hashlib.sha256(raw).hexdigest(),
        "source_encoding": encoding,
        "obfuscation_detected": bool(methods),
        "methods": methods,
        "deobfuscated_script": deobfuscated,
        "truncated": len(deobfuscated) >= MAX_OUTPUT_CHARS,
        "safety": "Static text transformations only; no script interpreter or eval was used.",
    }, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run(transport="stdio")
