"""OWASP ASVS v5.0 security guards for files, inputs, URLs, and commands."""

import hashlib
import hmac
import html
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Dict, Sequence
from urllib.parse import ParseResult, urlparse

import yaml

from content_hub.constants import (
    FILE_HASH_CHUNK_BYTES,
    HTTP_BAD_REQUEST,
    HTTP_FORBIDDEN,
    HTTP_OK,
    MAX_FILE_HASH_CHUNKS,
    MAX_INPUT_FIELD_CHARS,
    MAX_PATH_LENGTH,
    MAX_SUBPROCESS_ARGS,
    MAX_URL_CHARS,
    SAFE_ENV_KEYS,
    SHA256_HEX_LEN,
    SQLI_DENY_PATTERN,
    SUBPROCESS_TIMEOUT_SECONDS,
    UTF8_ENCODING,
    XSS_DENY_PATTERN,
    XXE_DENY_TOKENS,
    ZERO_INT,
)
from content_hub.contracts import (
    OperationResult,
    bounded_range,
    verify_condition,
)


def resolve_safe_path(
    base_dir: Path,
    target_path: Path,
) -> OperationResult[Path]:
    """Canonicalizes target_path and verifies containment within base_dir.

    Args:
        base_dir: Trusted workspace root directory.
        target_path: Candidate relative or absolute path to validate.

    Returns:
        OperationResult wrapping the canonical Path when safe.
    """
    raw_str: str = str(target_path)
    if "\x00" in raw_str or len(raw_str) > MAX_PATH_LENGTH:
        return OperationResult(
            ok=False,
            value=None,
            error_code="INVALID_PATH_ENCODING_OR_LENGTH",
            http_status=HTTP_BAD_REQUEST,
        )
    if ".." in target_path.parts:
        return OperationResult(
            ok=False,
            value=None,
            error_code="PATH_TRAVERSAL_SEQUENCE_BLOCKED",
            http_status=HTTP_FORBIDDEN,
        )
    resolved_base: Path = base_dir.resolve()
    candidate_raw: Path = (
        target_path
        if target_path.is_absolute()
        else (resolved_base / target_path)
    )
    if candidate_raw.exists() and candidate_raw.is_symlink():
        return OperationResult(
            ok=False,
            value=None,
            error_code="SYMLINK_PATH_REJECTED",
            http_status=HTTP_FORBIDDEN,
        )
    canonical: Path = candidate_raw.resolve()
    if not canonical.is_relative_to(resolved_base):
        return OperationResult(
            ok=False,
            value=None,
            error_code="PATH_ESCAPED_WORKSPACE_ROOT",
            http_status=HTTP_FORBIDDEN,
        )
    verify_condition(
        canonical.is_relative_to(resolved_base),
        "Resolved path escaped workspace root",
    )
    return OperationResult(ok=True, value=canonical, http_status=HTTP_OK)


def load_safe_yaml_config(
    config_path: Path,
    base_dir: Path,
    max_bytes: int,
) -> OperationResult[Dict[str, Any]]:
    """Loads a YAML configuration file safely using yaml.safe_load.

    Args:
        config_path: Path to the target YAML file.
        base_dir: Trusted root directory containing configuration files.
        max_bytes: Maximum permitted file size in bytes.

    Returns:
        OperationResult containing the validated configuration dictionary.
    """
    verify_condition(max_bytes > ZERO_INT, "max_bytes must be positive")
    path_res: OperationResult[Path] = resolve_safe_path(base_dir, config_path)
    if not path_res.ok or path_res.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code=path_res.error_code,
            http_status=path_res.http_status,
        )
    resolved_file: Path = path_res.value
    if not resolved_file.exists() or not resolved_file.is_file():
        return OperationResult(
            ok=False,
            value=None,
            error_code="CONFIG_FILE_NOT_FOUND",
            http_status=HTTP_BAD_REQUEST,
        )
    file_size: int = resolved_file.stat().st_size
    if file_size <= ZERO_INT or file_size > max_bytes:
        return OperationResult(
            ok=False,
            value=None,
            error_code="CONFIG_BYTE_LIMIT_EXCEEDED",
            http_status=HTTP_BAD_REQUEST,
        )
    raw_text: str = resolved_file.read_text(encoding=UTF8_ENCODING)
    parsed: Any = yaml.safe_load(raw_text)
    if not isinstance(parsed, dict):
        return OperationResult(
            ok=False,
            value=None,
            error_code="CONFIG_ROOT_NOT_DICT",
            http_status=HTTP_BAD_REQUEST,
        )
    verify_condition(isinstance(parsed, dict), "Parsed YAML must be a dict")
    return OperationResult(ok=True, value=parsed, http_status=HTTP_OK)


def validate_and_sanitize_text(
    raw_text: str,
    max_chars: int = MAX_INPUT_FIELD_CHARS,
    allow_empty: bool = False,
) -> OperationResult[str]:
    """Rejects SQLi and XSS payloads and HTML-escapes user input text.

    Args:
        raw_text: Untrusted string from an API payload, form, or query field.
        max_chars: Maximum permitted character length.
        allow_empty: Whether empty strings after trimming are allowed.

    Returns:
        OperationResult wrapping the sanitized and HTML-escaped string.
    """
    verify_condition(max_chars > ZERO_INT, "max_chars must be positive")
    if not isinstance(raw_text, str) or "\x00" in raw_text:
        return OperationResult(
            ok=False,
            value=None,
            error_code="INVALID_INPUT_TYPE_OR_NULL_BYTE",
            http_status=HTTP_BAD_REQUEST,
        )
    trimmed: str = raw_text.strip()
    if not allow_empty and len(trimmed) == ZERO_INT:
        return OperationResult(
            ok=False,
            value=None,
            error_code="EMPTY_REQUIRED_INPUT",
            http_status=HTTP_BAD_REQUEST,
        )
    if len(trimmed) > max_chars:
        return OperationResult(
            ok=False,
            value=None,
            error_code="INPUT_EXCEEDS_MAX_CHARS",
            http_status=HTTP_BAD_REQUEST,
        )
    if re.search(SQLI_DENY_PATTERN, trimmed) is not None:
        return OperationResult(
            ok=False,
            value=None,
            error_code="SQL_INJECTION_TOKEN_REJECTED",
            http_status=HTTP_BAD_REQUEST,
        )
    if re.search(XSS_DENY_PATTERN, trimmed) is not None:
        return OperationResult(
            ok=False,
            value=None,
            error_code="XSS_TOKEN_REJECTED",
            http_status=HTTP_BAD_REQUEST,
        )
    escaped: str = html.escape(trimmed, quote=True)
    return OperationResult(ok=True, value=escaped, http_status=HTTP_OK)


def validate_safe_xml_text(
    xml_text: str,
    max_bytes: int,
) -> OperationResult[str]:
    """Blocks XXE DOCTYPE and ENTITY declarations and enforces XML byte bounds.

    Args:
        xml_text: Raw XML document string.
        max_bytes: Maximum allowed UTF-8 byte length.

    Returns:
        OperationResult containing the verified XML string when safe.
    """
    verify_condition(max_bytes > ZERO_INT, "max_bytes must be positive")
    encoded_len: int = len(xml_text.encode(UTF8_ENCODING))
    if encoded_len <= ZERO_INT or encoded_len > max_bytes:
        return OperationResult(
            ok=False,
            value=None,
            error_code="XML_BYTE_CEILING_EXCEEDED",
            http_status=HTTP_BAD_REQUEST,
        )
    upper_xml: str = xml_text.upper()
    for idx in bounded_range(len(XXE_DENY_TOKENS)):
        forbidden: str = XXE_DENY_TOKENS[idx]
        if forbidden in upper_xml:
            return OperationResult(
                ok=False,
                value=None,
                error_code="XXE_DECLARATION_BLOCKED",
                http_status=HTTP_BAD_REQUEST,
            )
    return OperationResult(ok=True, value=xml_text, http_status=HTTP_OK)


def validate_outbound_url(
    url: str,
    allowed_schemes: Sequence[str],
    allowed_hosts: Sequence[str],
) -> OperationResult[str]:
    """Validates an outbound URL against scheme and hostname allowlists.

    Args:
        url: Candidate outbound HTTP or HTTPS endpoint URL.
        allowed_schemes: Permitted URL schemes such as http and https.
        allowed_hosts: Permitted target hostnames or loopback addresses.

    Returns:
        OperationResult wrapping the validated URL string when permitted.
    """
    trimmed: str = url.strip()
    if len(trimmed) == ZERO_INT or len(trimmed) > MAX_URL_CHARS:
        return OperationResult(
            ok=False,
            value=None,
            error_code="INVALID_OUTBOUND_URL_LENGTH",
            http_status=HTTP_BAD_REQUEST,
        )
    parsed: ParseResult = urlparse(trimmed)
    scheme: str = parsed.scheme.lower()
    hostname: str = (parsed.hostname or "").lower()
    if scheme not in allowed_schemes or hostname not in allowed_hosts:
        return OperationResult(
            ok=False,
            value=None,
            error_code="SSRF_HOST_OR_SCHEME_BLOCKED",
            http_status=HTTP_FORBIDDEN,
        )
    return OperationResult(ok=True, value=trimmed, http_status=HTTP_OK)


def verify_sha256_file_digest(
    file_path: Path,
    base_dir: Path,
    expected_hex_digest: str,
    max_bytes: int,
) -> OperationResult[str]:
    """Computes a bounded SHA-256 file digest and compares in constant time.

    Args:
        file_path: Candidate artifact or checkpoint path.
        base_dir: Trusted workspace root boundary.
        expected_hex_digest: Expected 64-character lowercase SHA-256 hex string.
        max_bytes: Maximum allowed file byte size.

    Returns:
        OperationResult containing the verified SHA-256 digest on match.
    """
    verify_condition(max_bytes > ZERO_INT, "max_bytes must be positive")
    safe_res: OperationResult[Path] = resolve_safe_path(base_dir, file_path)
    if not safe_res.ok or safe_res.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code=safe_res.error_code,
            http_status=safe_res.http_status,
        )
    target: Path = safe_res.value
    if not target.exists() or not target.is_file():
        return OperationResult(
            ok=False,
            value=None,
            error_code="ARTIFACT_NOT_FOUND",
            http_status=HTTP_BAD_REQUEST,
        )
    size_bytes: int = target.stat().st_size
    if size_bytes <= ZERO_INT or size_bytes > max_bytes:
        return OperationResult(
            ok=False,
            value=None,
            error_code="ARTIFACT_SIZE_OUT_OF_BOUNDS",
            http_status=HTTP_BAD_REQUEST,
        )
    hasher = hashlib.sha256()
    with target.open("rb") as handle:
        for _ in bounded_range(MAX_FILE_HASH_CHUNKS, MAX_FILE_HASH_CHUNKS):
            chunk: bytes = handle.read(FILE_HASH_CHUNK_BYTES)
            if len(chunk) == ZERO_INT:
                break
            hasher.update(chunk)
    computed_hex: str = hasher.hexdigest()
    verify_condition(
        len(computed_hex) == SHA256_HEX_LEN,
        "Computed SHA-256 digest length mismatch",
    )
    if not hmac.compare_digest(computed_hex, expected_hex_digest.lower()):
        return OperationResult(
            ok=False,
            value=None,
            error_code="ARTIFACT_CHECKSUM_MISMATCH",
            http_status=HTTP_FORBIDDEN,
        )
    return OperationResult(ok=True, value=computed_hex, http_status=HTTP_OK)


def execute_allowlisted_command(
    command_args: Sequence[str],
    allowed_binaries: Sequence[str],
    working_dir: Path,
) -> OperationResult[str]:
    """Executes an allowlisted binary with shell=False and a clean environment.

    Args:
        command_args: Sequence of command arguments starting with binary name.
        allowed_binaries: Sequence of permitted executable names.
        working_dir: Validated working directory for execution.

    Returns:
        OperationResult wrapping standard output text when returncode is zero.
    """
    arg_count: int = len(command_args)
    if arg_count <= ZERO_INT or arg_count > MAX_SUBPROCESS_ARGS:
        return OperationResult(
            ok=False,
            value=None,
            error_code="INVALID_SUBPROCESS_ARG_COUNT",
            http_status=HTTP_BAD_REQUEST,
        )
    binary_name: str = Path(command_args[ZERO_INT]).name
    if binary_name not in allowed_binaries:
        return OperationResult(
            ok=False,
            value=None,
            error_code="SUBPROCESS_BINARY_NOT_ALLOWLISTED",
            http_status=HTTP_FORBIDDEN,
        )
    clean_env: Dict[str, str] = {}
    for idx in bounded_range(len(SAFE_ENV_KEYS)):
        env_key: str = SAFE_ENV_KEYS[idx]
        env_val: str = os.environ.get(env_key, "")
        if len(env_val) > ZERO_INT:
            clean_env[env_key] = env_val
    completed: subprocess.CompletedProcess[str] = subprocess.run(
        list(command_args),
        shell=False,
        cwd=str(working_dir.resolve()),
        env=clean_env,
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != ZERO_INT:
        return OperationResult(
            ok=False,
            value=None,
            error_code="SUBPROCESS_EXECUTION_FAILED",
            http_status=HTTP_BAD_REQUEST,
        )
    return OperationResult(
        ok=True,
        value=completed.stdout,
        http_status=HTTP_OK,
    )
