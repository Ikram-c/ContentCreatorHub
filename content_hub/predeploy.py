"""Ten-point pre-deployment controls and indexed SQLite store."""

from collections import deque
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from typing import Any, Deque, Dict, List, Mapping, Sequence, Tuple

from content_hub.constants import (
    DEFAULT_BEARER_TOKEN,
    DEFAULT_CREATOR_ID,
    DOMAIN_AUTH_RESET,
    HDR_AUTH,
    HDR_ORIGIN,
    HDR_USER_ID,
    HTTP_BAD_REQUEST,
    HTTP_FORBIDDEN,
    HTTP_GONE,
    HTTP_OK,
    HTTP_TOO_MANY_REQUESTS,
    HTTP_UNAUTHORIZED,
    LOG_LEVEL_CRITICAL,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFO,
    MAX_ACTIVE_RESET_TOKENS,
    MAX_RATE_LIMIT_CLIENTS,
    MAX_SQL_ROWS,
    ONE_INT,
    SHA256_HEX_LEN,
    SLOT_BLUE,
    SLOT_GREEN,
    SLOT_STATE_ACTIVE,
    SLOT_STATE_HEALTH_VERIFIED,
    SLOT_STATE_ROLLED_BACK,
    SLOT_STATE_STAGING,
    SLOT_STATE_STANDBY,
    TOKEN_RANDOM_BYTES,
    TOKEN_STATE_CONSUMED,
    TOKEN_STATE_EXPIRED,
    TOKEN_STATE_ISSUED,
    UTF8_ENCODING,
    ZERO_INT,
)
from content_hub.contracts import (
    OperationResult,
    bounded_range,
    verify_condition,
    verify_state_transition,
)
from content_hub.gdpr import derive_hkdf_subkey, resolve_master_secret
from content_hub.security import resolve_safe_path

ALLOWED_SLOT_TRANSITIONS: Tuple[Tuple[str, str], ...] = (
    (SLOT_STATE_STANDBY, SLOT_STATE_STAGING),
    (SLOT_STATE_STAGING, SLOT_STATE_HEALTH_VERIFIED),
    (SLOT_STATE_HEALTH_VERIFIED, SLOT_STATE_ACTIVE),
    (SLOT_STATE_STAGING, SLOT_STATE_ROLLED_BACK),
    (SLOT_STATE_ACTIVE, SLOT_STATE_ROLLED_BACK),
    (SLOT_STATE_ROLLED_BACK, SLOT_STATE_ACTIVE),
)


def verify_bola_ownership(
    headers: Mapping[str, str],
    resource_owner_id: str,
) -> OperationResult[str]:
    """Verifies bearer auth and constant-time resource ownership (BOLA).

    Args:
        headers: HTTP request headers mapping.
        resource_owner_id: Owner identifier associated with the target object.

    Returns:
        OperationResult containing the authenticated caller ID on match.
    """
    auth_val: str = headers.get(HDR_AUTH, "")
    caller_id: str = headers.get(HDR_USER_ID, "").strip()
    if len(auth_val) == ZERO_INT or not hmac.compare_digest(
        auth_val,
        DEFAULT_BEARER_TOKEN,
    ):
        return OperationResult(
            ok=False,
            value=None,
            error_code="INVALID_BEARER_CREDENTIALS",
            http_status=HTTP_UNAUTHORIZED,
        )
    if len(caller_id) == ZERO_INT or len(resource_owner_id.strip()) == ZERO_INT:
        return OperationResult(
            ok=False,
            value=None,
            error_code="MISSING_RESOURCE_OWNER_CONTEXT",
            http_status=HTTP_FORBIDDEN,
        )
    if not hmac.compare_digest(caller_id, resource_owner_id.strip()):
        return OperationResult(
            ok=False,
            value=None,
            error_code="BOLA_RESOURCE_ACCESS_DENIED",
            http_status=HTTP_FORBIDDEN,
        )
    return OperationResult(ok=True, value=caller_id, http_status=HTTP_OK)


def validate_cors_origin(
    headers: Mapping[str, str],
    allowed_origins: Sequence[str],
) -> OperationResult[str]:
    """Validates request Origin against configured allowed_cors_origins.

    Args:
        headers: HTTP request headers mapping.
        allowed_origins: Explicit domain allowlist from config.yaml.

    Returns:
        OperationResult wrapping the approved origin string.
    """
    default_origin: str = (
        str(allowed_origins[ZERO_INT]).strip()
        if len(allowed_origins) > ZERO_INT
        else ""
    )
    origin: str = headers.get(HDR_ORIGIN, default_origin).strip()
    for idx in bounded_range(len(allowed_origins)):
        permitted: str = str(allowed_origins[idx]).strip()
        if len(origin) > ZERO_INT and origin == permitted:
            return OperationResult(
                ok=True,
                value=origin,
                http_status=HTTP_OK,
            )
    return OperationResult(
        ok=False,
        value=None,
        error_code="CORS_ORIGIN_NOT_ALLOWED",
        http_status=HTTP_FORBIDDEN,
    )


class SlidingWindowRateLimiter:
    """Thread-safe per-client sliding-window API rate limiter."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        """Initializes the rate limiter with request and window bounds.

        Args:
            max_requests: Maximum permitted requests per window.
            window_seconds: Sliding window duration in seconds.
        """
        verify_condition(max_requests > ZERO_INT, "max_requests must be > 0")
        verify_condition(
            window_seconds > ZERO_INT,
            "window_seconds must be > 0",
        )
        self._lock: threading.RLock = threading.RLock()
        self._max_requests: int = max_requests
        self._window_seconds: int = window_seconds
        self._clients: Dict[str, List[float]] = {}

    def check_request(self, client_ip: str) -> OperationResult[int]:
        """Evaluates and records a client request against rate limits.

        Args:
            client_ip: Client network address string.

        Returns:
            OperationResult with remaining quota or HTTP 429 on limit hit.
        """
        now_sec: float = time.time()
        cutoff: float = now_sec - float(self._window_seconds)
        with self._lock:
            if (
                len(self._clients) >= MAX_RATE_LIMIT_CLIENTS
                and client_ip not in self._clients
            ):
                return OperationResult(
                    ok=False,
                    value=ZERO_INT,
                    error_code="RATE_LIMIT_CAPACITY_FULL",
                    http_status=HTTP_TOO_MANY_REQUESTS,
                )
            timestamps: List[float] = self._clients.get(client_ip, [])
            active: List[float] = []
            for idx in bounded_range(
                len(timestamps),
                self._max_requests + ONE_INT,
            ):
                ts_val: float = timestamps[idx]
                if ts_val >= cutoff:
                    active.append(ts_val)
            if len(active) >= self._max_requests:
                self._clients[client_ip] = active
                return OperationResult(
                    ok=False,
                    value=ZERO_INT,
                    error_code="API_RATE_LIMIT_EXCEEDED",
                    http_status=HTTP_TOO_MANY_REQUESTS,
                )
            active.append(now_sec)
            self._clients[client_ip] = active
            remaining: int = self._max_requests - len(active)
            return OperationResult(
                ok=True,
                value=remaining,
                http_status=HTTP_OK,
            )


class PasswordResetManager:
    """Manages single-use 30-minute expiring HMAC password reset tokens."""

    def __init__(
        self,
        ttl_seconds: int,
        gdpr_cfg: Mapping[str, Any],
    ) -> None:
        """Initializes the reset token manager with TTL and HKDF key.

        Args:
            ttl_seconds: Token validity duration in seconds (1800 = 30 min).
            gdpr_cfg: GDPR configuration block providing master secret info.
        """
        verify_condition(ttl_seconds > ZERO_INT, "ttl_seconds must be > 0")
        secret_res: OperationResult[bytes] = resolve_master_secret(gdpr_cfg)
        verify_condition(
            secret_res.ok and secret_res.value is not None,
            "Master secret required for reset token signing",
        )
        raw_master: bytes = (
            secret_res.value if secret_res.value is not None else b""
        )
        epoch: str = str(gdpr_cfg.get("key_rotation_epoch", "2026-Q4"))
        subkey_res: OperationResult[bytes] = derive_hkdf_subkey(
            master_secret=raw_master,
            domain=DOMAIN_AUTH_RESET,
            rotation_epoch=epoch,
        )
        verify_condition(
            subkey_res.ok and subkey_res.value is not None,
            "Subkey derivation failed for reset manager",
        )
        self._signing_key: bytes = (
            subkey_res.value if subkey_res.value is not None else b""
        )
        self._ttl_seconds: int = ttl_seconds
        self._lock: threading.RLock = threading.RLock()
        self._records: Dict[str, Dict[str, Any]] = {}

    def issue_reset_token(
        self,
        owner_id: str,
    ) -> OperationResult[Dict[str, Any]]:
        """Issues a signed, single-use reset token valid for ttl_seconds.

        Args:
            owner_id: Target user identifier requesting a password reset.

        Returns:
            OperationResult wrapping token metadata and expiration details.
        """
        cleaned_owner: str = owner_id.strip()
        if len(cleaned_owner) == ZERO_INT:
            return OperationResult(
                ok=False,
                value=None,
                error_code="EMPTY_RESET_OWNER_ID",
                http_status=HTTP_BAD_REQUEST,
            )
        nonce_hex: str = secrets.token_hex(TOKEN_RANDOM_BYTES)
        issued_epoch: float = time.time()
        expires_epoch: float = issued_epoch + float(self._ttl_seconds)
        payload: str = f"{cleaned_owner}|{nonce_hex}|{int(expires_epoch)}"
        sig_hex: str = hmac.new(
            self._signing_key,
            payload.encode(UTF8_ENCODING),
            hashlib.sha256,
        ).hexdigest()
        token_digest: str = hashlib.sha256(
            sig_hex.encode(UTF8_ENCODING)
        ).hexdigest()
        with self._lock:
            if len(self._records) >= MAX_ACTIVE_RESET_TOKENS:
                self._evict_oldest_unlocked()
            self._records[token_digest] = {
                "owner_id": cleaned_owner,
                "expires_at": expires_epoch,
                "state": TOKEN_STATE_ISSUED,
            }
        response_data: Dict[str, Any] = {
            "owner_id": cleaned_owner,
            "reset_token": sig_hex,
            "ttl_seconds": self._ttl_seconds,
            "expires_at_epoch": expires_epoch,
            "state": TOKEN_STATE_ISSUED,
        }
        return OperationResult(
            ok=True,
            value=response_data,
            http_status=HTTP_OK,
        )

    def consume_reset_token(
        self,
        reset_token: str,
        owner_id: str,
        current_epoch: float | None = None,
    ) -> OperationResult[str]:
        """Validates and consumes a single-use password reset token.

        Args:
            reset_token: Candidate hexadecimal reset signature string.
            owner_id: Caller user ID claiming the reset token.
            current_epoch: Optional override timestamp for deterministic tests.

        Returns:
            OperationResult returning HTTP 410 if expired or reused.
        """
        cleaned_token: str = reset_token.strip()
        if len(cleaned_token) != SHA256_HEX_LEN:
            return OperationResult(
                ok=False,
                value=None,
                error_code="MALFORMED_RESET_TOKEN",
                http_status=HTTP_BAD_REQUEST,
            )
        token_digest: str = hashlib.sha256(
            cleaned_token.encode(UTF8_ENCODING)
        ).hexdigest()
        now_val: float = (
            current_epoch if current_epoch is not None else time.time()
        )
        with self._lock:
            record: Dict[str, Any] | None = self._records.get(token_digest)
            if record is None:
                return OperationResult(
                    ok=False,
                    value=None,
                    error_code="RESET_TOKEN_UNKNOWN",
                    http_status=HTTP_GONE,
                )
            if not hmac.compare_digest(
                str(record["owner_id"]),
                owner_id.strip(),
            ):
                return OperationResult(
                    ok=False,
                    value=None,
                    error_code="RESET_TOKEN_OWNER_MISMATCH",
                    http_status=HTTP_FORBIDDEN,
                )
            if str(record["state"]) != TOKEN_STATE_ISSUED:
                return OperationResult(
                    ok=False,
                    value=None,
                    error_code="RESET_TOKEN_ALREADY_CONSUMED",
                    http_status=HTTP_GONE,
                )
            if now_val > float(record["expires_at"]):
                record["state"] = TOKEN_STATE_EXPIRED
                return OperationResult(
                    ok=False,
                    value=None,
                    error_code="RESET_TOKEN_EXPIRED",
                    http_status=HTTP_GONE,
                )
            record["state"] = TOKEN_STATE_CONSUMED
        return OperationResult(
            ok=True,
            value=TOKEN_STATE_CONSUMED,
            http_status=HTTP_OK,
        )

    def _evict_oldest_unlocked(self) -> int:
        """Removes the earliest token record when registry capacity is full."""
        keys: List[str] = list(self._records.keys())
        if len(keys) == ZERO_INT:
            return ZERO_INT
        del self._records[keys[ZERO_INT]]
        return ONE_INT


class CostCappedLoggerAndAlerts:
    """Bounded ring-buffer logger with immediate ERROR and CRITICAL alerts."""

    def __init__(
        self,
        capacity: int,
        max_message_chars: int,
        alert_sink_path: Path,
        base_dir: Path,
    ) -> None:
        """Initializes bounded log storage and immediate alert sink file.

        Args:
            capacity: Maximum retained entries in the in-memory ring buffer.
            max_message_chars: Truncation ceiling per log message.
            alert_sink_path: JSONL file path for immediate breakage alerts.
            base_dir: Trusted workspace root boundary.
        """
        verify_condition(capacity > ZERO_INT, "Log capacity must be > 0")
        verify_condition(
            max_message_chars > ZERO_INT,
            "max_message_chars must be > 0",
        )
        safe_alert: OperationResult[Path] = resolve_safe_path(
            base_dir,
            alert_sink_path,
        )
        verify_condition(
            safe_alert.ok and safe_alert.value is not None,
            "Alert sink path outside workspace sandbox",
        )
        self._lock: threading.RLock = threading.RLock()
        self._ring: Deque[Dict[str, str]] = deque(maxlen=capacity)
        self._alerts: Deque[Dict[str, str]] = deque(maxlen=capacity)
        self._max_chars: int = max_message_chars
        self._alert_path: Path = (
            safe_alert.value
            if safe_alert.value is not None
            else base_dir / "alerts.jsonl"
        )
        self._alert_path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(
        self,
        level: str,
        component: str,
        message: str,
    ) -> OperationResult[Dict[str, str]]:
        """Records a truncated log entry and fires alerts on ERROR/CRITICAL.

        Args:
            level: Severity level (INFO, WARNING, ERROR, CRITICAL).
            component: Subsystem identifier string.
            message: Diagnostic text truncated to max_message_chars.

        Returns:
            OperationResult wrapping the stored log record.
        """
        clean_msg: str = " ".join(message.splitlines())[: self._max_chars]
        timestamp_utc: str = datetime.now(timezone.utc).isoformat()
        entry: Dict[str, str] = {
            "timestamp_utc": timestamp_utc,
            "level": level,
            "component": component,
            "message": clean_msg,
        }
        with self._lock:
            self._ring.append(entry)
            if level in (LOG_LEVEL_ERROR, LOG_LEVEL_CRITICAL):
                self._alerts.append(entry)
                line: str = json.dumps(entry, sort_keys=True) + "\n"
                with self._alert_path.open("a", encoding=UTF8_ENCODING) as fh:
                    written: int = fh.write(line)
                    verify_condition(
                        written == len(line),
                        "Immediate alert write truncated",
                    )
        return OperationResult(ok=True, value=entry, http_status=HTTP_OK)

    def get_recent_alerts(self) -> Tuple[Dict[str, str], ...]:
        """Returns a snapshot of dispatched breakage alerts."""
        with self._lock:
            return tuple(self._alerts)

    def get_recent_logs(self) -> Tuple[Dict[str, str], ...]:
        """Returns a snapshot of bounded production log entries."""
        with self._lock:
            return tuple(self._ring)


class BlueGreenDeploymentController:
    """Health-gated Blue-Green deployment controller with instant rollback."""

    def __init__(self, active_slot: str, standby_slot: str) -> None:
        """Initializes blue and green slots with deterministic states.

        Args:
            active_slot: Initially active traffic slot (blue or green).
            standby_slot: Initially standby slot (green or blue).
        """
        verify_condition(
            active_slot in (SLOT_BLUE, SLOT_GREEN)
            and standby_slot in (SLOT_BLUE, SLOT_GREEN)
            and active_slot != standby_slot,
            "Blue-Green controller requires distinct blue and green slots",
        )
        self._lock: threading.RLock = threading.RLock()
        self._active_slot: str = active_slot
        self._standby_slot: str = standby_slot
        self._slot_states: Dict[str, str] = {
            active_slot: SLOT_STATE_ACTIVE,
            standby_slot: SLOT_STATE_STANDBY,
        }

    def stage_and_promote(
        self,
        health_check_passed: bool,
    ) -> OperationResult[Dict[str, Any]]:
        """Stages into standby, checks health, and promotes or rolls back.

        Args:
            health_check_passed: Result of pre-promotion health verification.

        Returns:
            OperationResult detailing active slot, standby slot, and states.
        """
        with self._lock:
            target: str = self._standby_slot
            current: str = self._active_slot
            stage_res = verify_state_transition(
                self._slot_states[target],
                SLOT_STATE_STAGING,
                ALLOWED_SLOT_TRANSITIONS,
            )
            if not stage_res.ok:
                self._slot_states[target] = SLOT_STATE_STANDBY
                stage_res = verify_state_transition(
                    self._slot_states[target],
                    SLOT_STATE_STAGING,
                    ALLOWED_SLOT_TRANSITIONS,
                )
            verify_condition(stage_res.ok, "Failed transition to STAGING")
            self._slot_states[target] = SLOT_STATE_STAGING
            if not health_check_passed:
                self._slot_states[target] = SLOT_STATE_ROLLED_BACK
                return OperationResult(
                    ok=False,
                    value=self.snapshot_unlocked(),
                    error_code="STANDBY_HEALTH_CHECK_FAILED_ROLLED_BACK",
                    http_status=HTTP_BAD_REQUEST,
                )
            self._slot_states[target] = SLOT_STATE_HEALTH_VERIFIED
            self._slot_states[target] = SLOT_STATE_ACTIVE
            self._slot_states[current] = SLOT_STATE_STANDBY
            self._active_slot = target
            self._standby_slot = current
            return OperationResult(
                ok=True,
                value=self.snapshot_unlocked(),
                http_status=HTTP_OK,
            )

    def rollback_to_standby(self) -> OperationResult[Dict[str, Any]]:
        """Immediately rolls back active traffic to the prior standby slot.

        Returns:
            OperationResult containing updated slot state snapshot.
        """
        with self._lock:
            failed_active: str = self._active_slot
            restored_slot: str = self._standby_slot
            self._slot_states[failed_active] = SLOT_STATE_ROLLED_BACK
            self._slot_states[restored_slot] = SLOT_STATE_ACTIVE
            self._active_slot = restored_slot
            self._standby_slot = failed_active
            return OperationResult(
                ok=True,
                value=self.snapshot_unlocked(),
                http_status=HTTP_OK,
            )

    def snapshot_unlocked(self) -> Dict[str, Any]:
        """Builds a dictionary snapshot of current Blue-Green slot states."""
        return {
            "active_slot": self._active_slot,
            "standby_slot": self._standby_slot,
            "slot_states": dict(self._slot_states),
        }

    def snapshot(self) -> Dict[str, Any]:
        """Returns a thread-safe snapshot of Blue-Green deployment states."""
        with self._lock:
            return self.snapshot_unlocked()


class CreatorHubDatabase:
    """Parameterized SQLite WAL store with targeted query indexes only."""

    def __init__(self, db_path: Path, base_dir: Path) -> None:
        """Initializes SQLite tables and targeted owner_id/batch_id indexes.

        Args:
            db_path: Path to the SQLite database file inside workspace.
            base_dir: Trusted workspace root boundary.
        """
        safe_db: OperationResult[Path] = resolve_safe_path(base_dir, db_path)
        verify_condition(
            safe_db.ok and safe_db.value is not None,
            "SQLite database path outside workspace sandbox",
        )
        self._lock: threading.RLock = threading.RLock()
        self._db_path: Path = (
            safe_db.value
            if safe_db.value is not None
            else base_dir / "hub.db"
        )
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    def _connect(self) -> sqlite3.Connection:
        """Opens a configured SQLite connection with WAL mode enabled."""
        conn: sqlite3.Connection = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _initialize_schema(self) -> None:
        """Creates tables and targeted indexes only on queried columns."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS post_analyses ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "batch_id TEXT NOT NULL, "
                    "owner_id TEXT NOT NULL, "
                    "creator_pseudonym TEXT NOT NULL, "
                    "target_platform TEXT NOT NULL, "
                    "overall_score REAL NOT NULL, "
                    "engagement_tier TEXT NOT NULL, "
                    "sentiment_label TEXT NOT NULL, "
                    "sanitized_preview TEXT NOT NULL, "
                    "created_utc TEXT NOT NULL"
                    ");"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_post_analyses_owner "
                    "ON post_analyses (owner_id);"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_post_analyses_batch "
                    "ON post_analyses (batch_id);"
                )
                conn.commit()

    def insert_analysis_record(
        self,
        batch_id: str,
        owner_id: str,
        creator_pseudonym: str,
        report_dict: Mapping[str, Any],
    ) -> OperationResult[int]:
        """Inserts a post analysis record using parameterized SQL placeholders.

        Args:
            batch_id: Pipeline execution batch identifier.
            owner_id: Authenticated creator owner identifier.
            creator_pseudonym: HKDF-SHA256 pseudonymized creator digest.
            report_dict: Serialized PostAnalysisReport dictionary.

        Returns:
            OperationResult wrapping the inserted row ID.
        """
        created_utc: str = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                cursor: sqlite3.Cursor = conn.execute(
                    "INSERT INTO post_analyses ("
                    "batch_id, owner_id, creator_pseudonym, target_platform, "
                    "overall_score, engagement_tier, sentiment_label, "
                    "sanitized_preview, created_utc"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
                    (
                        batch_id,
                        owner_id,
                        creator_pseudonym,
                        str(report_dict.get("target_platform", "")),
                        float(report_dict.get("overall_score", 0.0)),
                        str(report_dict.get("engagement_tier", "")),
                        str(report_dict.get("sentiment_label", "")),
                        str(report_dict.get("sanitized_preview", "")),
                        created_utc,
                    ),
                )
                conn.commit()
                row_id: int = int(cursor.lastrowid or ZERO_INT)
        return OperationResult(ok=True, value=row_id, http_status=HTTP_OK)

    def fetch_owner_history(
        self,
        owner_id: str,
        limit: int = MAX_SQL_ROWS,
    ) -> OperationResult[Tuple[Dict[str, Any], ...]]:
        """Queries post analysis history scoped strictly to owner_id.

        Args:
            owner_id: Authenticated resource owner identifier.
            limit: Maximum number of rows returned.

        Returns:
            OperationResult wrapping tuple of historical analysis dicts.
        """
        capped_limit: int = max(ONE_INT, min(MAX_SQL_ROWS, limit))
        with self._lock:
            with self._connect() as conn:
                cursor: sqlite3.Cursor = conn.execute(
                    "SELECT batch_id, target_platform, overall_score, "
                    "engagement_tier, sentiment_label, sanitized_preview, "
                    "created_utc FROM post_analyses WHERE owner_id = ? "
                    "ORDER BY id DESC LIMIT ?;",
                    (owner_id, capped_limit),
                )
                raw_rows: List[Tuple[Any, ...]] = cursor.fetchall()
        records: List[Dict[str, Any]] = []
        for idx in bounded_range(len(raw_rows), MAX_SQL_ROWS):
            row = raw_rows[idx]
            records.append(
                {
                    "batch_id": str(row[ZERO_INT]),
                    "target_platform": str(row[ONE_INT]),
                    "overall_score": float(row[2]),
                    "engagement_tier": str(row[3]),
                    "sentiment_label": str(row[4]),
                    "sanitized_preview": str(row[5]),
                    "created_utc": str(row[6]),
                }
            )
        return OperationResult(
            ok=True,
            value=tuple(records),
            http_status=HTTP_OK,
        )

    def delete_subject_rows(
        self,
        target_pseudonym: str,
        raw_owner_id: str = DEFAULT_CREATOR_ID,
    ) -> OperationResult[int]:
        """Deletes all SQLite rows matching a subject pseudonym or owner_id.

        Args:
            target_pseudonym: 64-char HKDF pseudonym targeted for erasure.
            raw_owner_id: Optional raw owner identifier match.

        Returns:
            OperationResult containing count of deleted database rows.
        """
        with self._lock:
            with self._connect() as conn:
                cursor: sqlite3.Cursor = conn.execute(
                    "DELETE FROM post_analyses "
                    "WHERE creator_pseudonym = ? OR owner_id = ?;",
                    (target_pseudonym, raw_owner_id),
                )
                conn.commit()
                deleted: int = int(cursor.rowcount)
        return OperationResult(ok=True, value=deleted, http_status=HTTP_OK)
