"""UK and EU GDPR privacy-by-design controls for ContentCreatorHub."""

import hashlib
import hmac
import json
import os
import re
import string
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

import numpy as np
from PIL import Image

from content_hub.constants import (
    DOMAIN_CREATOR,
    EIGHT_INT,
    GENESIS_AUDIT_HASH,
    HKDF_HASH_LEN,
    HTTP_BAD_REQUEST,
    HTTP_FORBIDDEN,
    HTTP_INTERNAL_ERROR,
    HTTP_OK,
    MAX_AUDIT_READ_LINES,
    MAX_BATCH_POSTS,
    MAX_DIRECTORY_SCAN_ITEMS,
    ONE_INT,
    PII_EMAIL_PATTERN,
    PII_IPV4_PATTERN,
    PII_PHONE_PATTERN,
    RGB_MODE,
    SHA256_HEX_LEN,
    SHORT_HASH_PREFIX_LEN,
    TWO_INT,
    UTF8_ENCODING,
    ZERO_INT,
)
from content_hub.contracts import (
    OperationResult,
    bounded_range,
    verify_condition,
)
from content_hub.security import resolve_safe_path

DbEraseCallback = Callable[[str], OperationResult[int]]


def resolve_master_secret(
    gdpr_cfg: Mapping[str, Any],
) -> OperationResult[bytes]:
    """Resolves the master GDPR secret from environment or sandbox fallback.

    Args:
        gdpr_cfg: GDPR configuration mapping loaded from config.yaml.

    Returns:
        OperationResult wrapping non-empty UTF-8 secret key bytes.
    """
    env_name: str = str(
        gdpr_cfg.get("master_key_env_var", "CONTENT_HUB_GDPR_SECRET")
    ).strip()
    fallback_secret: str = str(
        gdpr_cfg.get("fallback_sandbox_secret", "")
    ).strip()
    env_secret: str = os.environ.get(env_name, "").strip()
    chosen_secret: str = env_secret if env_secret else fallback_secret
    if len(chosen_secret) == ZERO_INT:
        return OperationResult(
            ok=False,
            value=None,
            error_code="GDPR_MASTER_SECRET_MISSING",
            http_status=HTTP_INTERNAL_ERROR,
        )
    encoded_key: bytes = chosen_secret.encode(UTF8_ENCODING)
    verify_condition(
        len(encoded_key) > ZERO_INT,
        "Master secret bytes must be non-empty",
    )
    return OperationResult(ok=True, value=encoded_key, http_status=HTTP_OK)


def derive_hkdf_subkey(
    master_secret: bytes,
    domain: str,
    rotation_epoch: str,
) -> OperationResult[bytes]:
    """Derives an isolated domain subkey using RFC 5869 HKDF-SHA256.

    Args:
        master_secret: High-entropy master key material bytes.
        domain: Domain separation label preventing cross-table correlation.
        rotation_epoch: Key rotation epoch identifier acting as HKDF salt.

    Returns:
        OperationResult containing a derived 32-byte subkey.
    """
    if (
        len(master_secret) == ZERO_INT
        or len(domain.strip()) == ZERO_INT
        or len(rotation_epoch.strip()) == ZERO_INT
    ):
        return OperationResult(
            ok=False,
            value=None,
            error_code="INVALID_HKDF_PARAMETERS",
            http_status=HTTP_BAD_REQUEST,
        )
    salt_bytes: bytes = rotation_epoch.strip().encode(UTF8_ENCODING)
    info_bytes: bytes = domain.strip().encode(UTF8_ENCODING)
    prk: bytes = hmac.new(
        salt_bytes,
        master_secret,
        hashlib.sha256,
    ).digest()
    okm: bytes = hmac.new(
        prk,
        info_bytes + bytes([ONE_INT]),
        hashlib.sha256,
    ).digest()[:HKDF_HASH_LEN]
    verify_condition(
        len(okm) == HKDF_HASH_LEN,
        "Derived HKDF subkey length mismatch",
    )
    return OperationResult(ok=True, value=okm, http_status=HTTP_OK)


def pseudonymize_subject(
    raw_identifier: str,
    master_secret: bytes,
    domain: str,
    rotation_epoch: str,
) -> OperationResult[str]:
    """Computes a domain-separated HMAC-SHA256 pseudonym for a subject ID.

    Args:
        raw_identifier: Raw creator, user, or campaign subject identifier.
        master_secret: Master GDPR secret bytes.
        domain: Cryptographic domain separation label.
        rotation_epoch: Active key rotation epoch label.

    Returns:
        OperationResult wrapping a lowercase hexadecimal SHA-256 pseudonym.
    """
    cleaned_id: str = raw_identifier.strip()
    if len(cleaned_id) == ZERO_INT:
        return OperationResult(
            ok=False,
            value=None,
            error_code="EMPTY_SUBJECT_IDENTIFIER",
            http_status=HTTP_BAD_REQUEST,
        )
    subkey_res: OperationResult[bytes] = derive_hkdf_subkey(
        master_secret=master_secret,
        domain=domain,
        rotation_epoch=rotation_epoch,
    )
    if not subkey_res.ok or subkey_res.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code=subkey_res.error_code,
            http_status=subkey_res.http_status,
        )
    digest_hex: str = hmac.new(
        subkey_res.value,
        cleaned_id.encode(UTF8_ENCODING),
        hashlib.sha256,
    ).hexdigest()
    verify_condition(
        len(digest_hex) == SHA256_HEX_LEN,
        "Pseudonym hex length must equal SHA-256 digest length",
    )
    return OperationResult(ok=True, value=digest_hex, http_status=HTTP_OK)


def redact_pii_text(
    raw_text: str,
    redaction_token: str,
) -> OperationResult[str]:
    """Scrubs email addresses, phone numbers, and IPv4 literals from text.

    Args:
        raw_text: Input string potentially containing personal data.
        redaction_token: Replacement token inserted over matched PII spans.

    Returns:
        OperationResult containing the PII-scrubbed text string.
    """
    if not isinstance(raw_text, str):
        return OperationResult(
            ok=False,
            value=None,
            error_code="PII_REDACT_INPUT_NOT_STRING",
            http_status=HTTP_BAD_REQUEST,
        )
    token: str = redaction_token.strip() or "[REDACTED_PII]"
    no_emails: str = re.sub(PII_EMAIL_PATTERN, token, raw_text)
    no_phones: str = re.sub(PII_PHONE_PATTERN, token, no_emails)
    scrubbed: str = re.sub(PII_IPV4_PATTERN, token, no_phones)
    return OperationResult(ok=True, value=scrubbed, http_status=HTTP_OK)


def strip_exif_and_redact_regions(
    source_image: Image.Image,
    boxes: Sequence[Tuple[int, int, int, int]] = (),
    block_size: int = EIGHT_INT,
) -> OperationResult[Image.Image]:
    """Clones pixels to strip EXIF metadata and block-redacts sensitive boxes.

    Args:
        source_image: Decoded PIL Image that may carry EXIF or GPS tags.
        boxes: Sequence of (x, y, width, height) regions to irreversibly blur.
        block_size: Quantization cell dimension in pixels.

    Returns:
        OperationResult wrapping a clean RGB Image with zero metadata.
    """
    rgb_img: Image.Image = source_image.convert(RGB_MODE)
    width, height = rgb_img.size
    if width <= ZERO_INT or height <= ZERO_INT:
        return OperationResult(
            ok=False,
            value=None,
            error_code="INVALID_IMAGE_DIMENSIONS",
            http_status=HTTP_BAD_REQUEST,
        )
    clean_img: Image.Image = Image.frombytes(
        RGB_MODE,
        (width, height),
        rgb_img.tobytes(),
    )
    verify_condition(
        len(clean_img.info) == ZERO_INT,
        "Clean image buffer retained metadata dictionary entries",
    )
    if len(boxes) == ZERO_INT:
        return OperationResult(ok=True, value=clean_img, http_status=HTTP_OK)
    pixel_array: np.ndarray = np.asarray(clean_img, dtype=np.uint8).copy()
    step: int = block_size if block_size >= TWO_INT else TWO_INT
    for box_idx in bounded_range(len(boxes), MAX_BATCH_POSTS):
        bx, by, bw, bh = boxes[box_idx]
        x_start: int = max(ZERO_INT, min(width, bx))
        y_start: int = max(ZERO_INT, min(height, by))
        x_end: int = max(x_start, min(width, bx + bw))
        y_end: int = max(y_start, min(height, by + bh))
        y_steps: int = divmod(
            (y_end - y_start) + step - ONE_INT,
            step,
        )[ZERO_INT]
        x_steps: int = divmod(
            (x_end - x_start) + step - ONE_INT,
            step,
        )[ZERO_INT]
        for row_idx in bounded_range(y_steps):
            ry0: int = y_start + row_idx * step
            ry1: int = min(y_end, ry0 + step)
            for col_idx in bounded_range(x_steps):
                rx0: int = x_start + col_idx * step
                rx1: int = min(x_end, rx0 + step)
                patch: np.ndarray = pixel_array[ry0:ry1, rx0:rx1]
                if patch.size > ZERO_INT:
                    mean_rgb: np.ndarray = patch.mean(
                        axis=(ZERO_INT, ONE_INT),
                    ).astype(np.uint8)
                    pixel_array[ry0:ry1, rx0:rx1] = mean_rgb
    redacted_img: Image.Image = Image.fromarray(pixel_array, mode=RGB_MODE)
    verify_condition(
        len(redacted_img.info) == ZERO_INT,
        "Redacted image retained metadata tags",
    )
    return OperationResult(ok=True, value=redacted_img, http_status=HTTP_OK)


def validate_cloud_residency(
    active_region: str,
    allowed_regions: Sequence[str],
) -> OperationResult[str]:
    """Verifies that active_region belongs to the UK/EU residency allowlist.

    Args:
        active_region: Configured cloud region identifier.
        allowed_regions: Sequence of approved UK and EU region identifiers.

    Returns:
        OperationResult wrapping the normalized region string on match.
    """
    normalized: str = active_region.strip().lower()
    for idx in bounded_range(len(allowed_regions)):
        candidate: str = str(allowed_regions[idx]).strip().lower()
        if len(normalized) > ZERO_INT and normalized == candidate:
            return OperationResult(
                ok=True,
                value=normalized,
                http_status=HTTP_OK,
            )
    return OperationResult(
        ok=False,
        value=None,
        error_code="GDPR_DATA_RESIDENCY_VIOLATION",
        http_status=HTTP_FORBIDDEN,
    )


class ImmutableAuditLogger:
    """Thread-safe, SHA-256 hash-chained JSONL accountability audit ledger."""

    def __init__(
        self,
        log_path: Path,
        base_dir: Path,
        redaction_token: str,
    ) -> None:
        """Initializes the audit logger inside the validated workspace root.

        Args:
            log_path: Target JSONL ledger path.
            base_dir: Trusted workspace root boundary.
            redaction_token: Token used to scrub accidental PII in log text.
        """
        safe_res: OperationResult[Path] = resolve_safe_path(base_dir, log_path)
        verify_condition(
            safe_res.ok and safe_res.value is not None,
            "Audit log path failed workspace sandbox check",
        )
        resolved_log: Path = (
            safe_res.value
            if safe_res.value is not None
            else base_dir / "audit_log.jsonl"
        )
        self._lock: threading.RLock = threading.RLock()
        self._log_path: Path = resolved_log
        self._redaction_token: str = redaction_token
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def append_event(
        self,
        event_type: str,
        actor_pseudonym: str,
        details: str,
    ) -> OperationResult[Dict[str, Any]]:
        """Appends a zero-PII, SHA-256 hash-chained record to the JSONL log.

        Args:
            event_type: Canonical uppercase audit event identifier.
            actor_pseudonym: Pseudonymized subject or system actor label.
            details: Human-readable description automatically scrubbed of PII.

        Returns:
            OperationResult wrapping the persisted audit dictionary.
        """
        scrub_res: OperationResult[str] = redact_pii_text(
            details,
            self._redaction_token,
        )
        if not scrub_res.ok or scrub_res.value is None:
            return OperationResult(
                ok=False,
                value=None,
                error_code=scrub_res.error_code,
                http_status=HTTP_INTERNAL_ERROR,
            )
        clean_details: str = scrub_res.value
        with self._lock:
            prev_hash: str = self._read_tail_hash_unlocked()
            timestamp_utc: str = datetime.now(timezone.utc).isoformat()
            canonical_input: str = (
                f"{timestamp_utc}|{event_type}|{actor_pseudonym}|"
                f"{clean_details}|{prev_hash}"
            )
            record_hash: str = hashlib.sha256(
                canonical_input.encode(UTF8_ENCODING)
            ).hexdigest()
            record: Dict[str, Any] = {
                "timestamp_utc": timestamp_utc,
                "event_type": event_type,
                "actor_pseudonym": actor_pseudonym,
                "details": clean_details,
                "previous_hash": prev_hash,
                "record_hash": record_hash,
            }
            encoded_line: str = json.dumps(record, sort_keys=True) + "\n"
            with self._log_path.open("a", encoding=UTF8_ENCODING) as handle:
                written: int = handle.write(encoded_line)
                verify_condition(
                    written == len(encoded_line),
                    "Audit ledger write was truncated",
                )
        return OperationResult(ok=True, value=record, http_status=HTTP_OK)

    def verify_and_read_events(
        self,
        limit: int = MAX_AUDIT_READ_LINES,
    ) -> OperationResult[Tuple[Dict[str, Any], ...]]:
        """Verifies the entire SHA-256 hash chain and returns recent records.

        Args:
            limit: Maximum number of trailing verified records to return.

        Returns:
            OperationResult wrapping verified audit dictionaries.
        """
        verify_condition(limit > ZERO_INT, "Audit read limit must be positive")
        with self._lock:
            if not self._log_path.exists():
                return OperationResult(ok=True, value=(), http_status=HTTP_OK)
            lines: List[str] = self._log_path.read_text(
                encoding=UTF8_ENCODING
            ).splitlines()
        verified: List[Dict[str, Any]] = []
        expected_prev: str = GENESIS_AUDIT_HASH
        for idx in bounded_range(len(lines), MAX_DIRECTORY_SCAN_ITEMS):
            raw_line: str = lines[idx].strip()
            if len(raw_line) == ZERO_INT:
                continue
            entry: Dict[str, Any] = json.loads(raw_line)
            if str(entry.get("previous_hash", "")) != expected_prev:
                return OperationResult(
                    ok=False,
                    value=None,
                    error_code="AUDIT_LEDGER_HASH_CHAIN_BROKEN",
                    http_status=HTTP_INTERNAL_ERROR,
                )
            recomputed_payload: str = (
                f"{entry.get('timestamp_utc')}|{entry.get('event_type')}|"
                f"{entry.get('actor_pseudonym')}|{entry.get('details')}|"
                f"{expected_prev}"
            )
            recomputed_hash: str = hashlib.sha256(
                recomputed_payload.encode(UTF8_ENCODING)
            ).hexdigest()
            if not hmac.compare_digest(
                recomputed_hash,
                str(entry.get("record_hash", "")),
            ):
                return OperationResult(
                    ok=False,
                    value=None,
                    error_code="AUDIT_RECORD_DIGEST_TAMPERED",
                    http_status=HTTP_INTERNAL_ERROR,
                )
            expected_prev = recomputed_hash
            verified.append(entry)
        capped_slice: Tuple[Dict[str, Any], ...] = tuple(verified[-limit:])
        return OperationResult(
            ok=True,
            value=capped_slice,
            http_status=HTTP_OK,
        )

    def _read_tail_hash_unlocked(self) -> str:
        """Reads the latest record_hash or returns the genesis hash."""
        if not self._log_path.exists():
            return GENESIS_AUDIT_HASH
        lines: List[str] = self._log_path.read_text(
            encoding=UTF8_ENCODING
        ).splitlines()
        if len(lines) == ZERO_INT:
            return GENESIS_AUDIT_HASH
        last_entry: Dict[str, Any] = json.loads(lines[-ONE_INT])
        return str(last_entry.get("record_hash", GENESIS_AUDIT_HASH))


def purge_expired_workspace_files(
    directories: Sequence[Path],
    base_dir: Path,
    ttl_seconds: int,
    audit_logger: ImmutableAuditLogger,
) -> OperationResult[int]:
    """Deletes regular workspace files older than ttl_seconds and logs count.

    Args:
        directories: Workspace folders subject to GDPR storage limitation.
        base_dir: Trusted workspace root boundary.
        ttl_seconds: Maximum permitted file age in seconds.
        audit_logger: Audit ledger recording the retention sweep.

    Returns:
        OperationResult containing the number of deleted files.
    """
    verify_condition(ttl_seconds >= ZERO_INT, "ttl_seconds cannot be negative")
    now_epoch: float = time.time()
    purged_total: int = ZERO_INT
    for dir_idx in bounded_range(len(directories)):
        safe_dir: OperationResult[Path] = resolve_safe_path(
            base_dir,
            directories[dir_idx],
        )
        if not safe_dir.ok or safe_dir.value is None:
            continue
        folder: Path = safe_dir.value
        if not folder.exists() or not folder.is_dir():
            continue
        entries: List[Path] = list(folder.iterdir())
        for item_idx in bounded_range(len(entries), MAX_DIRECTORY_SCAN_ITEMS):
            candidate: Path = entries[item_idx]
            if candidate.is_file() and not candidate.is_symlink():
                age_sec: float = now_epoch - candidate.stat().st_mtime
                if age_sec >= float(ttl_seconds):
                    candidate.unlink()
                    purged_total += ONE_INT
    log_res: OperationResult[Dict[str, Any]] = audit_logger.append_event(
        event_type="GDPR_RETENTION_TTL_SWEEP",
        actor_pseudonym="SYSTEM_RETENTION_CONTROLLER",
        details=(
            f"Purged {purged_total} expired files exceeding "
            f"TTL {ttl_seconds}s"
        ),
    )
    if not log_res.ok:
        return OperationResult(
            ok=False,
            value=None,
            error_code=log_res.error_code,
            http_status=HTTP_INTERNAL_ERROR,
        )
    return OperationResult(ok=True, value=purged_total, http_status=HTTP_OK)


def execute_article_17_erasure(
    subject_identifier: str,
    gdpr_cfg: Mapping[str, Any],
    workspace_dirs: Sequence[Path],
    base_dir: Path,
    audit_logger: ImmutableAuditLogger,
    db_erase_callback: Optional[DbEraseCallback] = None,
) -> OperationResult[Dict[str, Any]]:
    """Executes GDPR Article 17 Right to Erasure across disk and database.

    Args:
        subject_identifier: Raw creator ID or hexadecimal SHA-256 pseudonym.
        gdpr_cfg: GDPR configuration block from config.yaml.
        workspace_dirs: Directories containing raw or derived JSON/media files.
        base_dir: Trusted workspace root boundary.
        audit_logger: Hash-chained accountability audit logger.
        db_erase_callback: Optional callback deleting matching SQLite rows.

    Returns:
        OperationResult summarizing removed files, JSON rows, and DB rows.
    """
    cleaned_id: str = subject_identifier.strip()
    pseudo_res: OperationResult[str] = _resolve_erasure_pseudonym(
        cleaned_id,
        gdpr_cfg,
    )
    if not pseudo_res.ok or pseudo_res.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code=pseudo_res.error_code,
            http_status=pseudo_res.http_status,
        )
    target_pseudonym: str = pseudo_res.value
    prefix: str = target_pseudonym[:SHORT_HASH_PREFIX_LEN]
    removed_files: int = ZERO_INT
    scrubbed_json_rows: int = ZERO_INT
    for dir_idx in bounded_range(len(workspace_dirs)):
        safe_dir: OperationResult[Path] = resolve_safe_path(
            base_dir,
            workspace_dirs[dir_idx],
        )
        if not safe_dir.ok or safe_dir.value is None:
            continue
        folder: Path = safe_dir.value
        if not folder.exists() or not folder.is_dir():
            continue
        children: List[Path] = list(folder.iterdir())
        for f_idx in bounded_range(len(children), MAX_DIRECTORY_SCAN_ITEMS):
            item: Path = children[f_idx]
            if not item.is_file() or item.is_symlink():
                continue
            if prefix in item.name or cleaned_id in item.name:
                item.unlink()
                removed_files += ONE_INT
            elif item.suffix == ".json":
                scrub_res: OperationResult[int] = _scrub_json_manifest_file(
                    item,
                    target_pseudonym,
                    cleaned_id,
                )
                if scrub_res.ok and scrub_res.value is not None:
                    scrubbed_json_rows += scrub_res.value
    erased_db_rows: int = ZERO_INT
    if db_erase_callback is not None:
        db_res: OperationResult[int] = db_erase_callback(target_pseudonym)
        if not db_res.ok or db_res.value is None:
            return OperationResult(
                ok=False,
                value=None,
                error_code=db_res.error_code,
                http_status=HTTP_INTERNAL_ERROR,
            )
        erased_db_rows = db_res.value
    audit_res: OperationResult[Dict[str, Any]] = audit_logger.append_event(
        event_type="GDPR_ARTICLE_17_ERASURE",
        actor_pseudonym=target_pseudonym,
        details=(
            f"Erasure completed: files={removed_files}, "
            f"json_records={scrubbed_json_rows}, db_rows={erased_db_rows}"
        ),
    )
    if not audit_res.ok:
        return OperationResult(
            ok=False,
            value=None,
            error_code=audit_res.error_code,
            http_status=HTTP_INTERNAL_ERROR,
        )
    summary: Dict[str, Any] = {
        "subject_pseudonym": target_pseudonym,
        "removed_files": removed_files,
        "scrubbed_json_records": scrubbed_json_rows,
        "erased_db_rows": erased_db_rows,
    }
    return OperationResult(ok=True, value=summary, http_status=HTTP_OK)


def _is_valid_sha256_hex(candidate: str) -> bool:
    """Checks via bounded loop whether candidate is a 64-char hex digest."""
    if len(candidate) != SHA256_HEX_LEN:
        return False
    for idx in bounded_range(SHA256_HEX_LEN, SHA256_HEX_LEN):
        if candidate[idx] not in string.hexdigits:
            return False
    return True


def _resolve_erasure_pseudonym(
    cleaned_id: str,
    gdpr_cfg: Mapping[str, Any],
) -> OperationResult[str]:
    """Determines or computes the DOMAIN_CREATOR pseudonym for erasure."""
    if len(cleaned_id) == ZERO_INT:
        return OperationResult(
            ok=False,
            value=None,
            error_code="ERASURE_SUBJECT_EMPTY",
            http_status=HTTP_BAD_REQUEST,
        )
    if _is_valid_sha256_hex(cleaned_id):
        return OperationResult(
            ok=True,
            value=cleaned_id.lower(),
            http_status=HTTP_OK,
        )
    key_res: OperationResult[bytes] = resolve_master_secret(gdpr_cfg)
    if not key_res.ok or key_res.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code=key_res.error_code,
            http_status=key_res.http_status,
        )
    epoch: str = str(gdpr_cfg.get("key_rotation_epoch", "2026-Q4"))
    return pseudonymize_subject(
        raw_identifier=cleaned_id,
        master_secret=key_res.value,
        domain=DOMAIN_CREATOR,
        rotation_epoch=epoch,
    )


def _scrub_json_manifest_file(
    json_path: Path,
    target_pseudonym: str,
    raw_subject_id: str,
) -> OperationResult[int]:
    """Atomically removes subject entries from a workspace JSON manifest."""
    raw_text: str = json_path.read_text(encoding=UTF8_ENCODING)
    parsed: Any = json.loads(raw_text)
    if not isinstance(parsed, dict):
        return OperationResult(ok=True, value=ZERO_INT, http_status=HTTP_OK)
    sections: Tuple[str, ...] = (
        "posts",
        "campaigns",
        "records",
        "images",
        "annotations",
    )
    removed: int = ZERO_INT
    for sec_idx in bounded_range(len(sections)):
        sec_key: str = sections[sec_idx]
        items: Any = parsed.get(sec_key)
        if isinstance(items, list):
            kept: List[Any] = []
            for row_idx in bounded_range(len(items)):
                entry: Any = items[row_idx]
                serialized: str = json.dumps(entry)
                if (
                    target_pseudonym in serialized
                    or raw_subject_id in serialized
                ):
                    removed += ONE_INT
                else:
                    kept.append(entry)
            parsed[sec_key] = kept
    if removed > ZERO_INT:
        updated_json: str = json.dumps(parsed, indent=TWO_INT)
        temp_path: Path = json_path.with_suffix(".json.tmp")
        written: int = temp_path.write_text(
            updated_json,
            encoding=UTF8_ENCODING,
        )
        verify_condition(
            written == len(updated_json),
            "Atomic JSON scrub temporary write incomplete",
        )
        os.replace(temp_path, json_path)
    return OperationResult(ok=True, value=removed, http_status=HTTP_OK)
