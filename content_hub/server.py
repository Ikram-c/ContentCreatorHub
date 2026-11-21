"""Hardened HTTP gateway and CLI entry point for ContentCreatorHub."""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import sys
import threading
from typing import Any, Dict, List, Mapping, Tuple

from content_hub.constants import (
    DEFAULT_BEARER_TOKEN,
    DEFAULT_CONFIG_PATH,
    DEFAULT_CREATOR_ID,
    DOMAIN_CREATOR,
    HDR_AUTH,
    HDR_CONTENT_LEN,
    HDR_CONTENT_TYPE,
    HDR_CORS_HEADERS,
    HDR_CORS_METHODS,
    HDR_CORS_ORIGIN,
    HDR_FRAME,
    HDR_NOSNIFF,
    HDR_USER_ID,
    HTTP_BAD_REQUEST,
    HTTP_FORBIDDEN,
    HTTP_GONE,
    HTTP_INTERNAL_ERROR,
    HTTP_NOT_FOUND,
    HTTP_OK,
    HTTP_TOO_MANY_REQUESTS,
    HTTP_UNAUTHORIZED,
    LOG_LEVEL_CRITICAL,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFO,
    MIME_CSS,
    MIME_HTML,
    MIME_JS,
    MIME_JSON,
    ONE_INT,
    PACKAGE_VERSION,
    ROUTE_API_ANALYZE,
    ROUTE_API_DEPLOY_ROLLBACK,
    ROUTE_API_DEPLOY_STAGE,
    ROUTE_API_GDPR_AUDIT,
    ROUTE_API_GDPR_ERASE,
    ROUTE_API_GDPR_PURGE,
    ROUTE_API_HISTORY,
    ROUTE_API_RESET_CONSUME,
    ROUTE_API_RESET_ISSUE,
    ROUTE_API_STATUS,
    ROUTE_APP_JS,
    ROUTE_INDEX,
    ROUTE_ROOT,
    ROUTE_STYLES,
    UTF8_ENCODING,
    VAL_DENY,
    VAL_HEADERS,
    VAL_METHODS,
    VAL_NOSNIFF,
    ZERO_INT,
)
from content_hub.contracts import OperationResult, verify_condition
from content_hub.gdpr import (
    ImmutableAuditLogger,
    execute_article_17_erasure,
    pseudonymize_subject,
    purge_expired_workspace_files,
    resolve_master_secret,
)
from content_hub.pipeline import ContentBatch, execute_declarative_pipeline
from content_hub.predeploy import (
    BlueGreenDeploymentController,
    CostCappedLoggerAndAlerts,
    CreatorHubDatabase,
    PasswordResetManager,
    SlidingWindowRateLimiter,
    validate_cors_origin,
    verify_bola_ownership,
)
from content_hub.sandbox import synthesize_creator_seed_batch
from content_hub.security import (
    load_safe_yaml_config,
    validate_and_sanitize_text,
)


class HubRuntimeState:
    """Thread-safe orchestrator holding runtime state, security, and DB."""

    def __init__(self, config: Mapping[str, Any], base_dir: Path) -> None:
        """Initializes all security, GDPR, database, and deployment managers.

        Args:
            config: Validated configuration dictionary from config.yaml.
            base_dir: Canonical workspace root directory path.
        """
        self._lock: threading.RLock = threading.RLock()
        self.config: Dict[str, Any] = dict(config)
        self.base_dir: Path = base_dir
        hub_cfg: Mapping[str, Any] = self.config.get("hub", {})
        sec_cfg: Mapping[str, Any] = self.config.get("security", {})
        gdpr_cfg: Mapping[str, Any] = self.config.get("gdpr", {})
        self.audit_logger: ImmutableAuditLogger = ImmutableAuditLogger(
            log_path=Path(
                str(
                    hub_cfg.get(
                        "audit_log_path",
                        "./workspace/audit/audit_log.jsonl",
                    )
                )
            ),
            base_dir=base_dir,
            redaction_token=str(
                gdpr_cfg.get("redaction_token", "[REDACTED_PII]")
            ),
        )
        self.ops_logger: CostCappedLoggerAndAlerts = CostCappedLoggerAndAlerts(
            capacity=int(sec_cfg.get("log_ring_buffer_capacity", 256)),
            max_message_chars=int(sec_cfg.get("log_max_message_chars", 240)),
            alert_sink_path=Path(
                str(
                    hub_cfg.get(
                        "alert_sink_path",
                        "./workspace/audit/alerts.jsonl",
                    )
                )
            ),
            base_dir=base_dir,
        )
        self.database: CreatorHubDatabase = CreatorHubDatabase(
            db_path=Path(
                str(
                    hub_cfg.get(
                        "sqlite_db_path",
                        "./workspace/state/content_hub.db",
                    )
                )
            ),
            base_dir=base_dir,
        )
        self.rate_limiter: SlidingWindowRateLimiter = SlidingWindowRateLimiter(
            max_requests=int(sec_cfg.get("rate_limit_max_requests", 60)),
            window_seconds=int(sec_cfg.get("rate_limit_window_seconds", 60)),
        )
        self.reset_manager: PasswordResetManager = PasswordResetManager(
            ttl_seconds=int(sec_cfg.get("password_reset_ttl_seconds", 1800)),
            gdpr_cfg=gdpr_cfg,
        )
        self.deploy_controller: BlueGreenDeploymentController = (
            BlueGreenDeploymentController(
                active_slot=str(hub_cfg.get("active_slot", "blue")),
                standby_slot=str(hub_cfg.get("standby_slot", "green")),
            )
        )
        self._batch_counter: int = ZERO_INT
        self._latest_batch: ContentBatch | None = None

    def seed_initial_workspace(self) -> OperationResult[Dict[str, Any]]:
        """Seeds initial starter post and executes one baseline pipeline run.

        Returns:
            OperationResult containing the initial dashboard status dict.
        """
        hub_cfg: Mapping[str, Any] = self.config.get("hub", {})
        sandbox_cfg: Mapping[str, Any] = self.config.get("sandbox", {})
        raw_dir: Path = Path(
            str(hub_cfg.get("raw_media_dir", "./workspace/raw"))
        )
        seed_res = synthesize_creator_seed_batch(
            raw_media_dir=raw_dir,
            base_dir=self.base_dir,
            sandbox_cfg=sandbox_cfg,
        )
        if not seed_res.ok or seed_res.value is None:
            return OperationResult(
                ok=False,
                value=None,
                error_code=seed_res.error_code,
                http_status=seed_res.http_status,
            )
        first_post: Dict[str, str] = seed_res.value[ZERO_INT]
        return self.analyze_and_persist_post(
            owner_id=first_post["owner_id"],
            target_platform=first_post["target_platform"],
            raw_post=first_post["raw_post"],
        )

    def analyze_and_persist_post(
        self,
        owner_id: str,
        target_platform: str,
        raw_post: str,
    ) -> OperationResult[Dict[str, Any]]:
        """Runs the declarative three-stage pipeline on a creator post draft.

        Args:
            owner_id: Authenticated creator owner identifier.
            target_platform: Selected social platform key.
            raw_post: Unprocessed social media post draft text.

        Returns:
            OperationResult wrapping the updated dashboard status payload.
        """
        with self._lock:
            self._batch_counter += ONE_INT
            batch_id: str = f"batch-{self._batch_counter:04d}"
            pipe_res: OperationResult[ContentBatch] = (
                execute_declarative_pipeline(
                    batch_id=batch_id,
                    owner_id=owner_id,
                    target_platform=target_platform,
                    raw_post=raw_post,
                    config=self.config,
                    base_dir=self.base_dir,
                    audit_logger=self.audit_logger,
                    database=self.database,
                )
            )
            if not pipe_res.ok or pipe_res.value is None:
                self.ops_logger.log_event(
                    level=LOG_LEVEL_ERROR,
                    component="pipeline_engine",
                    message=f"Pipeline failed: {pipe_res.error_code}",
                )
                return OperationResult(
                    ok=False,
                    value=None,
                    error_code=pipe_res.error_code,
                    http_status=pipe_res.http_status,
                )
            self._latest_batch = pipe_res.value
            self.ops_logger.log_event(
                level=LOG_LEVEL_INFO,
                component="pipeline_engine",
                message=f"Completed {batch_id} for {target_platform}",
            )
            return OperationResult(
                ok=True,
                value=self.build_status_snapshot(owner_id),
                http_status=HTTP_OK,
            )

    def execute_erasure_and_sync_cache(
        self,
        subject_id: str,
        caller_owner_id: str,
    ) -> OperationResult[Dict[str, Any]]:
        """Executes Article 17 erasure across disk, SQLite, and RAM cache.

        Args:
            subject_id: Raw subject ID or 64-character hex pseudonym.
            caller_owner_id: Authenticated caller identifier.

        Returns:
            OperationResult summarizing erased records across all stores.
        """
        hub_cfg: Mapping[str, Any] = self.config.get("hub", {})
        gdpr_cfg: Mapping[str, Any] = self.config.get("gdpr", {})
        dirs: Tuple[Path, ...] = (
            Path(str(hub_cfg.get("raw_media_dir", "./workspace/raw"))),
            Path(str(hub_cfg.get("derived_dir", "./workspace/derived"))),
        )
        with self._lock:
            erase_res: OperationResult[Dict[str, Any]] = (
                execute_article_17_erasure(
                    subject_identifier=subject_id,
                    gdpr_cfg=gdpr_cfg,
                    workspace_dirs=dirs,
                    base_dir=self.base_dir,
                    audit_logger=self.audit_logger,
                    db_erase_callback=(
                        lambda pseudo: self.database.delete_subject_rows(
                            target_pseudonym=pseudo,
                            raw_owner_id=subject_id.strip(),
                        )
                    ),
                )
            )
            if not erase_res.ok or erase_res.value is None:
                self.ops_logger.log_event(
                    level=LOG_LEVEL_ERROR,
                    component="gdpr_erasure",
                    message=f"Article 17 erasure failed: {erase_res.error_code}",
                )
                return erase_res
            erased_pseudo: str = str(
                erase_res.value.get("subject_pseudonym", "")
            )
            if self._latest_batch is not None and (
                self._latest_batch.creator_pseudonym == erased_pseudo
                or self._latest_batch.owner_id == subject_id.strip()
                or self._latest_batch.owner_id == caller_owner_id
            ):
                self._latest_batch = None
            self.ops_logger.log_event(
                level=LOG_LEVEL_INFO,
                component="gdpr_erasure",
                message="Completed Article 17 erasure and cleared RAM cache",
            )
            return erase_res

    def build_status_snapshot(
        self,
        owner_id: str = DEFAULT_CREATOR_ID,
    ) -> Dict[str, Any]:
        """Builds a complete JSON-serializable state snapshot for the UI.

        Args:
            owner_id: Authenticated owner identifier for scoped history lookup.

        Returns:
            Dictionary containing deployment, GDPR, analyzer, and history data.
        """
        gdpr_cfg: Mapping[str, Any] = self.config.get("gdpr", {})
        sec_cfg: Mapping[str, Any] = self.config.get("security", {})
        with self._lock:
            deploy_info: Dict[str, Any] = self.deploy_controller.snapshot()
            history_res = self.database.fetch_owner_history(owner_id)
            history_items: List[Dict[str, Any]] = (
                list(history_res.value)
                if history_res.ok and history_res.value is not None
                else []
            )
            alerts_count: int = len(
                self.ops_logger.get_recent_alerts()
            )
            base_payload: Dict[str, Any] = {
                "version": PACKAGE_VERSION,
                "active_slot": deploy_info["active_slot"],
                "standby_slot": deploy_info["standby_slot"],
                "slot_states": deploy_info["slot_states"],
                "region": str(gdpr_cfg.get("active_region", "uksouth")),
                "reset_ttl_seconds": int(
                    sec_cfg.get("password_reset_ttl_seconds", 1800)
                ),
                "alerts_count": alerts_count,
                "history": history_items,
            }
            if (
                self._latest_batch is None
                or self._latest_batch.analysis_report is None
            ):
                base_payload["latest_analysis"] = None
                base_payload["stages"] = []
                base_payload["cloud_sync"] = {
                    "provider": "standby",
                    "uri": "none",
                }
                return base_payload
            batch: ContentBatch = self._latest_batch
            report = batch.analysis_report
            verify_condition(
                report is not None,
                "Latest batch report must not be None",
            )
            report_dict: Dict[str, Any] = (
                report.to_dict() if report is not None else {}
            )
            sync_dict: Dict[str, str] = dict(batch.cloud_sync_pairs)
            base_payload["batch_id"] = batch.batch_id
            base_payload["creator_pseudonym"] = batch.creator_pseudonym
            base_payload["stages"] = list(batch.stage_history)
            base_payload["cloud_sync"] = sync_dict
            base_payload["latest_analysis"] = report_dict
            return base_payload


def create_http_handler(
    runtime: HubRuntimeState,
) -> type[BaseHTTPRequestHandler]:
    """Creates a hardened HTTP request handler bound to HubRuntimeState.

    Args:
        runtime: Active HubRuntimeState instance.

    Returns:
        Configured BaseHTTPRequestHandler subclass.
    """
    static_dir: Path = Path(__file__).resolve().parent / "static"

    class ContentHubHTTPHandler(BaseHTTPRequestHandler):
        """HTTP handler enforcing CORS, rate limits, BOLA, and catch-all 500."""

        def log_message(self, format_str: str, *args: Any) -> None:
            """Suppresses unredacted default stderr request logging."""
            return None

        def _write_response(
            self,
            status_code: int,
            content_type: str,
            body_bytes: bytes,
            cors_origin: str,
        ) -> bool:
            """Writes HTTP headers and response payload bytes."""
            self.send_response(status_code)
            self.send_header(HDR_CONTENT_TYPE, content_type)
            self.send_header(HDR_CONTENT_LEN, str(len(body_bytes)))
            self.send_header(HDR_CORS_ORIGIN, cors_origin)
            self.send_header(HDR_CORS_METHODS, VAL_METHODS)
            self.send_header(HDR_CORS_HEADERS, VAL_HEADERS)
            self.send_header(HDR_NOSNIFF, VAL_NOSNIFF)
            self.send_header(HDR_FRAME, VAL_DENY)
            self.end_headers()
            self.wfile.write(body_bytes)
            return True

        def _send_json(
            self,
            status_code: int,
            payload: Dict[str, Any],
            cors_origin: str,
        ) -> bool:
            """Serializes payload to UTF-8 JSON and sends HTTP response."""
            encoded: bytes = json.dumps(payload).encode(UTF8_ENCODING)
            return self._write_response(
                status_code,
                MIME_JSON,
                encoded,
                cors_origin,
            )

        def _send_error_screen_payload(
            self,
            status_code: int,
            error_code: str,
            message: str,
            cors_origin: str,
        ) -> bool:
            """Sends a sanitized JSON error envelope without stack traces."""
            envelope: Dict[str, Any] = {
                "ok": False,
                "status_code": status_code,
                "error_code": error_code,
                "message": message,
            }
            return self._send_json(status_code, envelope, cors_origin)

        def _check_cors_and_rate(self) -> OperationResult[str]:
            """Validates CORS origin and per-client sliding-window rate limit."""
            sec_cfg: Mapping[str, Any] = runtime.config.get("security", {})
            allowed_origins: List[str] = list(
                sec_cfg.get(
                    "allowed_cors_origins",
                    ["http://127.0.0.1:8080"],
                )
            )
            default_origin: str = str(allowed_origins[ZERO_INT])
            header_dict: Dict[str, str] = dict(self.headers.items())
            cors_res: OperationResult[str] = validate_cors_origin(
                header_dict,
                allowed_origins,
            )
            if not cors_res.ok or cors_res.value is None:
                self._send_error_screen_payload(
                    HTTP_FORBIDDEN,
                    cors_res.error_code,
                    "Origin is not authorized by ContentCreatorHub CORS policy.",
                    default_origin,
                )
                return OperationResult(
                    ok=False,
                    value=None,
                    error_code=cors_res.error_code,
                )
            client_ip: str = str(self.client_address[ZERO_INT])
            rate_res: OperationResult[int] = runtime.rate_limiter.check_request(
                client_ip
            )
            if not rate_res.ok:
                self._send_error_screen_payload(
                    HTTP_TOO_MANY_REQUESTS,
                    rate_res.error_code,
                    "API rate limit exceeded. Pause requests and retry.",
                    cors_res.value,
                )
                return OperationResult(
                    ok=False,
                    value=None,
                    error_code=rate_res.error_code,
                )
            return OperationResult(
                ok=True,
                value=cors_res.value,
                http_status=HTTP_OK,
            )

        def _read_bounded_json(
            self,
            cors_origin: str,
        ) -> OperationResult[Dict[str, Any]]:
            """Reads and validates a bounded JSON request payload."""
            sec_cfg: Mapping[str, Any] = runtime.config.get("security", {})
            max_bytes: int = int(sec_cfg.get("max_payload_bytes", 131072))
            len_raw: str = self.headers.get(HDR_CONTENT_LEN, "0").strip()
            body_len: int = int(len_raw) if len_raw.isdigit() else ZERO_INT
            if body_len < ZERO_INT or body_len > max_bytes:
                self._send_error_screen_payload(
                    HTTP_BAD_REQUEST,
                    "PAYLOAD_BYTE_CEILING_EXCEEDED",
                    "Request payload size exceeds configured limits.",
                    cors_origin,
                )
                return OperationResult(
                    ok=False,
                    value=None,
                    error_code="PAYLOAD_BYTE_CEILING_EXCEEDED",
                )
            if body_len == ZERO_INT:
                return OperationResult(ok=True, value={}, http_status=HTTP_OK)
            raw_bytes: bytes = self.rfile.read(body_len)
            try:
                parsed: Any = json.loads(raw_bytes.decode(UTF8_ENCODING))
            except Exception:
                self._send_error_screen_payload(
                    HTTP_BAD_REQUEST,
                    "MALFORMED_JSON_REQUEST",
                    "Request body must be valid UTF-8 JSON.",
                    cors_origin,
                )
                return OperationResult(
                    ok=False,
                    value=None,
                    error_code="MALFORMED_JSON_REQUEST",
                )
            if not isinstance(parsed, dict):
                self._send_error_screen_payload(
                    HTTP_BAD_REQUEST,
                    "JSON_ROOT_MUST_BE_OBJECT",
                    "JSON payload root must be an object.",
                    cors_origin,
                )
                return OperationResult(
                    ok=False,
                    value=None,
                    error_code="JSON_ROOT_MUST_BE_OBJECT",
                )
            return OperationResult(
                ok=True,
                value=parsed,
                http_status=HTTP_OK,
            )

        def _authorize_owner(
            self,
            target_owner: str,
            cors_origin: str,
        ) -> OperationResult[str]:
            """Enforces constant-time BOLA authorization on target_owner."""
            header_map: Dict[str, str] = {
                HDR_AUTH: self.headers.get(HDR_AUTH, DEFAULT_BEARER_TOKEN),
                HDR_USER_ID: self.headers.get(
                    HDR_USER_ID,
                    DEFAULT_CREATOR_ID,
                ),
            }
            auth_res: OperationResult[str] = verify_bola_ownership(
                header_map,
                target_owner,
            )
            if not auth_res.ok or auth_res.value is None:
                status_val: int = (
                    HTTP_UNAUTHORIZED
                    if auth_res.http_status == HTTP_UNAUTHORIZED
                    else HTTP_FORBIDDEN
                )
                self._send_error_screen_payload(
                    status_val,
                    auth_res.error_code,
                    "Access denied: caller does not own the requested resource.",
                    cors_origin,
                )
                return OperationResult(
                    ok=False,
                    value=None,
                    error_code=auth_res.error_code,
                )
            return auth_res

        def do_OPTIONS(self) -> None:
            """Handles CORS preflight OPTIONS requests."""
            gate_res: OperationResult[str] = self._check_cors_and_rate()
            if gate_res.ok and gate_res.value is not None:
                self._write_response(
                    HTTP_OK,
                    MIME_JSON,
                    b"{}",
                    gate_res.value,
                )

        def do_GET(self) -> None:
            """Serves static frontend assets and authorized GET endpoints."""
            gate_res: OperationResult[str] = self._check_cors_and_rate()
            if not gate_res.ok or gate_res.value is None:
                return
            cors_origin: str = gate_res.value
            try:
                self._route_get_request(cors_origin)
            except Exception as exc:
                runtime.ops_logger.log_event(
                    level=LOG_LEVEL_CRITICAL,
                    component="http_get_boundary",
                    message=f"Unhandled GET exception: {type(exc).__name__}",
                )
                self._send_error_screen_payload(
                    HTTP_INTERNAL_ERROR,
                    "INTERNAL_SERVER_BOUNDARY",
                    "An unexpected internal error occurred. Alerts dispatched.",
                    cors_origin,
                )

        def _route_get_request(self, cors_origin: str) -> None:
            """Dispatches validated GET routes."""
            if self.path in (ROUTE_ROOT, ROUTE_INDEX):
                html_bytes: bytes = (static_dir / "index.html").read_bytes()
                self._write_response(
                    HTTP_OK,
                    MIME_HTML,
                    html_bytes,
                    cors_origin,
                )
                return
            if self.path == ROUTE_STYLES:
                css_bytes: bytes = (static_dir / "styles.css").read_bytes()
                self._write_response(
                    HTTP_OK,
                    MIME_CSS,
                    css_bytes,
                    cors_origin,
                )
                return
            if self.path == ROUTE_APP_JS:
                js_bytes: bytes = (static_dir / "app.js").read_bytes()
                self._write_response(
                    HTTP_OK,
                    MIME_JS,
                    js_bytes,
                    cors_origin,
                )
                return
            caller_id: str = self.headers.get(
                HDR_USER_ID,
                DEFAULT_CREATOR_ID,
            )
            auth_res: OperationResult[str] = self._authorize_owner(
                caller_id,
                cors_origin,
            )
            if not auth_res.ok or auth_res.value is None:
                return
            if self.path == ROUTE_API_STATUS:
                self._send_json(
                    HTTP_OK,
                    {
                        "ok": True,
                        "data": runtime.build_status_snapshot(auth_res.value),
                    },
                    cors_origin,
                )
                return
            if self.path == ROUTE_API_HISTORY:
                hist_res = runtime.database.fetch_owner_history(auth_res.value)
                items = (
                    list(hist_res.value)
                    if hist_res.ok and hist_res.value is not None
                    else []
                )
                self._send_json(
                    HTTP_OK,
                    {"ok": True, "history": items},
                    cors_origin,
                )
                return
            if self.path == ROUTE_API_GDPR_AUDIT:
                audit_res = runtime.audit_logger.verify_and_read_events()
                if not audit_res.ok or audit_res.value is None:
                    self._send_error_screen_payload(
                        HTTP_INTERNAL_ERROR,
                        audit_res.error_code,
                        "Audit ledger integrity check failed.",
                        cors_origin,
                    )
                    return
                self._send_json(
                    HTTP_OK,
                    {"ok": True, "events": list(audit_res.value)},
                    cors_origin,
                )
                return
            self._send_error_screen_payload(
                HTTP_NOT_FOUND,
                "ENDPOINT_NOT_FOUND",
                "The requested endpoint does not exist.",
                cors_origin,
            )

        def do_POST(self) -> None:
            """Processes authenticated POST endpoints inside catch-all 500."""
            gate_res: OperationResult[str] = self._check_cors_and_rate()
            if not gate_res.ok or gate_res.value is None:
                return
            cors_origin: str = gate_res.value
            try:
                self._route_post_request(cors_origin)
            except Exception as exc:
                runtime.ops_logger.log_event(
                    level=LOG_LEVEL_CRITICAL,
                    component="http_post_boundary",
                    message=f"Unhandled POST exception: {type(exc).__name__}",
                )
                self._send_error_screen_payload(
                    HTTP_INTERNAL_ERROR,
                    "INTERNAL_SERVER_BOUNDARY",
                    "An unexpected internal error occurred. Alerts dispatched.",
                    cors_origin,
                )

        def _route_post_request(self, cors_origin: str) -> None:
            """Validates payload ownership and dispatches POST API handlers."""
            body_res: OperationResult[Dict[str, Any]] = self._read_bounded_json(
                cors_origin
            )
            if not body_res.ok or body_res.value is None:
                return
            payload: Dict[str, Any] = body_res.value
            owner_raw: str = str(
                payload.get("owner_id", DEFAULT_CREATOR_ID)
            ).strip()
            owner_clean_res: OperationResult[str] = validate_and_sanitize_text(
                owner_raw
            )
            if not owner_clean_res.ok or owner_clean_res.value is None:
                self._send_error_screen_payload(
                    HTTP_BAD_REQUEST,
                    owner_clean_res.error_code,
                    "Invalid owner_id format.",
                    cors_origin,
                )
                return
            auth_res: OperationResult[str] = self._authorize_owner(
                owner_raw,
                cors_origin,
            )
            if not auth_res.ok or auth_res.value is None:
                return
            if self.path == ROUTE_API_ANALYZE:
                self._handle_post_analyze(
                    auth_res.value,
                    payload,
                    cors_origin,
                )
                return
            if self.path == ROUTE_API_GDPR_ERASE:
                self._handle_gdpr_erasure(
                    auth_res.value,
                    payload,
                    cors_origin,
                )
                return
            if self.path == ROUTE_API_GDPR_PURGE:
                self._handle_gdpr_purge(cors_origin)
                return
            if self.path == ROUTE_API_RESET_ISSUE:
                self._handle_reset_issue(auth_res.value, cors_origin)
                return
            if self.path == ROUTE_API_RESET_CONSUME:
                self._handle_reset_consume(
                    auth_res.value,
                    payload,
                    cors_origin,
                )
                return
            if self.path == ROUTE_API_DEPLOY_STAGE:
                self._handle_deploy_stage(payload, cors_origin)
                return
            if self.path == ROUTE_API_DEPLOY_ROLLBACK:
                self._handle_deploy_rollback(cors_origin)
                return
            self._send_error_screen_payload(
                HTTP_NOT_FOUND,
                "ENDPOINT_NOT_FOUND",
                "Unknown API route.",
                cors_origin,
            )

        def _handle_post_analyze(
            self,
            owner_id: str,
            payload: Dict[str, Any],
            cors_origin: str,
        ) -> None:
            """Validates inputs and executes the post analyzer pipeline."""
            platform_raw: str = str(
                payload.get("target_platform", "linkedin_pro")
            ).strip()
            plat_res = validate_and_sanitize_text(platform_raw)
            if not plat_res.ok or plat_res.value is None:
                self._send_error_screen_payload(
                    HTTP_BAD_REQUEST,
                    plat_res.error_code,
                    "Invalid social platform identifier.",
                    cors_origin,
                )
                return
            raw_post: str = str(payload.get("raw_post", ""))
            run_res = runtime.analyze_and_persist_post(
                owner_id=owner_id,
                target_platform=platform_raw,
                raw_post=raw_post,
            )
            if not run_res.ok or run_res.value is None:
                self._send_error_screen_payload(
                    run_res.http_status or HTTP_BAD_REQUEST,
                    run_res.error_code,
                    "Post draft validation or analysis stage rejected input.",
                    cors_origin,
                )
                return
            self._send_json(
                HTTP_OK,
                {"ok": True, "data": run_res.value},
                cors_origin,
            )

        def _handle_gdpr_erasure(
            self,
            owner_id: str,
            payload: Dict[str, Any],
            cors_origin: str,
        ) -> None:
            """Validates subject_id and executes Article 17 Right to Erasure."""
            subject_raw: str = str(payload.get("subject_id", "")).strip()
            sub_res = validate_and_sanitize_text(subject_raw)
            if not sub_res.ok:
                self._send_error_screen_payload(
                    HTTP_BAD_REQUEST,
                    sub_res.error_code,
                    "Invalid subject identifier submitted for erasure.",
                    cors_origin,
                )
                return
            erase_res = runtime.execute_erasure_and_sync_cache(
                subject_id=subject_raw,
                caller_owner_id=owner_id,
            )
            if not erase_res.ok or erase_res.value is None:
                self._send_error_screen_payload(
                    erase_res.http_status or HTTP_INTERNAL_ERROR,
                    erase_res.error_code,
                    "Article 17 erasure operation failed.",
                    cors_origin,
                )
                return
            self._send_json(
                HTTP_OK,
                {
                    "ok": True,
                    "erasure": erase_res.value,
                    "data": runtime.build_status_snapshot(owner_id),
                },
                cors_origin,
            )

        def _handle_gdpr_purge(self, cors_origin: str) -> None:
            """Executes TTL retention purge across workspace directories."""
            hub_cfg: Mapping[str, Any] = runtime.config.get("hub", {})
            gdpr_cfg: Mapping[str, Any] = runtime.config.get("gdpr", {})
            ttl_sec: int = int(gdpr_cfg.get("retention_ttl_seconds", 86400))
            dirs: Tuple[Path, ...] = (
                Path(str(hub_cfg.get("raw_media_dir", "./workspace/raw"))),
                Path(str(hub_cfg.get("derived_dir", "./workspace/derived"))),
            )
            purge_res = purge_expired_workspace_files(
                directories=dirs,
                base_dir=runtime.base_dir,
                ttl_seconds=ttl_sec,
                audit_logger=runtime.audit_logger,
            )
            self._send_json(
                HTTP_OK,
                {
                    "ok": True,
                    "purged_files": purge_res.value,
                    "ttl_seconds": ttl_sec,
                },
                cors_origin,
            )

        def _handle_reset_issue(
            self,
            owner_id: str,
            cors_origin: str,
        ) -> None:
            """Issues a single-use 30-minute expiring password reset token."""
            issue_res = runtime.reset_manager.issue_reset_token(owner_id)
            if not issue_res.ok or issue_res.value is None:
                self._send_error_screen_payload(
                    issue_res.http_status or HTTP_BAD_REQUEST,
                    issue_res.error_code,
                    "Unable to issue password reset token.",
                    cors_origin,
                )
                return
            self._send_json(
                HTTP_OK,
                {"ok": True, "reset": issue_res.value},
                cors_origin,
            )

        def _handle_reset_consume(
            self,
            owner_id: str,
            payload: Dict[str, Any],
            cors_origin: str,
        ) -> None:
            """Consumes a password reset token or returns HTTP 410 if expired."""
            token_raw: str = str(payload.get("reset_token", "")).strip()
            consume_res = runtime.reset_manager.consume_reset_token(
                reset_token=token_raw,
                owner_id=owner_id,
            )
            if not consume_res.ok:
                self._send_error_screen_payload(
                    consume_res.http_status or HTTP_GONE,
                    consume_res.error_code,
                    "Password reset link is expired or has already been used.",
                    cors_origin,
                )
                return
            self._send_json(
                HTTP_OK,
                {"ok": True, "token_state": consume_res.value},
                cors_origin,
            )

        def _handle_deploy_stage(
            self,
            payload: Dict[str, Any],
            cors_origin: str,
        ) -> None:
            """Stages a release into standby slot and verifies health check."""
            healthy: bool = bool(payload.get("health_check_passed", True))
            stage_res = runtime.deploy_controller.stage_and_promote(healthy)
            if not stage_res.ok:
                runtime.ops_logger.log_event(
                    level=LOG_LEVEL_ERROR,
                    component="blue_green_deploy",
                    message="Standby health check failed; rolled back slot",
                )
                self._send_error_screen_payload(
                    HTTP_BAD_REQUEST,
                    stage_res.error_code,
                    "Standby health probe failed; release rolled back.",
                    cors_origin,
                )
                return
            runtime.audit_logger.append_event(
                event_type="BLUE_GREEN_PROMOTION",
                actor_pseudonym="DEPLOYMENT_CONTROLLER",
                details="Promoted health-verified standby deployment slot",
            )
            self._send_json(
                HTTP_OK,
                {"ok": True, "deployment": stage_res.value},
                cors_origin,
            )

        def _handle_deploy_rollback(self, cors_origin: str) -> None:
            """Executes an immediate Blue-Green slot rollback."""
            rb_res = runtime.deploy_controller.rollback_to_standby()
            runtime.audit_logger.append_event(
                event_type="BLUE_GREEN_ROLLBACK",
                actor_pseudonym="DEPLOYMENT_CONTROLLER",
                details="Executed instant Blue-Green slot traffic rollback",
            )
            self._send_json(
                HTTP_OK,
                {"ok": True, "deployment": rb_res.value},
                cors_origin,
            )

    return ContentHubHTTPHandler


def build_cli_parser() -> argparse.ArgumentParser:
    """Constructs the command-line argument parser for ContentCreatorHub."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="ContentCreatorHub hardened server and GDPR CLI."
    )
    parser.add_argument(
        "--config",
        type=str,
        default=DEFAULT_CONFIG_PATH,
        help="Path to declarative config.yaml file.",
    )
    parser.add_argument(
        "--run-once",
        action="store_true",
        help="Seed workspace, execute pipeline once, and print JSON status.",
    )
    parser.add_argument(
        "--erase-subject",
        type=str,
        default="",
        help="Execute GDPR Article 17 erasure for the specified subject ID.",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start the ContentCreatorHub web dashboard server.",
    )
    return parser


def main(argv: List[str] | None = None) -> int:
    """CLI entry point for pipeline execution, GDPR erasure, and web server.

    Args:
        argv: Optional list of CLI argument strings.

    Returns:
        Exit status code integer (0 for success, 1 on failure).
    """
    parser: argparse.ArgumentParser = build_cli_parser()
    args: argparse.Namespace = parser.parse_args(argv)
    base_dir: Path = Path.cwd().resolve()
    cfg_res: OperationResult[Dict[str, Any]] = load_safe_yaml_config(
        config_path=Path(args.config),
        base_dir=base_dir,
        max_bytes=524288,
    )
    if not cfg_res.ok or cfg_res.value is None:
        sys.stderr.write(f"Config load failed: {cfg_res.error_code}\n")
        return ONE_INT
    runtime: HubRuntimeState = HubRuntimeState(cfg_res.value, base_dir)
    seed_res: OperationResult[Dict[str, Any]] = (
        runtime.seed_initial_workspace()
    )
    if not seed_res.ok:
        sys.stderr.write(f"Initial seed failed: {seed_res.error_code}\n")
        return ONE_INT
    if args.erase_subject:
        erase_res = runtime.execute_erasure_and_sync_cache(
            subject_id=args.erase_subject,
            caller_owner_id=DEFAULT_CREATOR_ID,
        )
        if not erase_res.ok:
            return ONE_INT
        sys.stdout.write(json.dumps(erase_res.value, indent=2) + "\n")
        return ZERO_INT
    if args.run_once and not args.serve:
        snapshot = runtime.build_status_snapshot(DEFAULT_CREATOR_ID)
        sys.stdout.write(json.dumps(snapshot, indent=2) + "\n")
        return ZERO_INT
    srv_cfg: Mapping[str, Any] = runtime.config.get("server", {})
    host: str = str(srv_cfg.get("host", "127.0.0.1"))
    port: int = int(srv_cfg.get("port", 8080))
    handler_cls = create_http_handler(runtime)
    server: HTTPServer = HTTPServer((host, port), handler_cls)
    sys.stdout.write(
        f"ContentCreatorHub listening on http://{host}:{port}\n"
    )
    server.serve_forever()
    return ZERO_INT


if __name__ == "__main__":
    sys.exit(main())
