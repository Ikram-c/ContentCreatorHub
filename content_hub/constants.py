"""Centralized symbolic constants for ContentCreatorHub."""

from typing import Final, Tuple

PACKAGE_VERSION: Final[str] = "1.0.0"
DEFAULT_CONFIG_PATH: Final[str] = "config.yaml"
UTF8_ENCODING: Final[str] = "utf-8"

ZERO_INT: Final[int] = 0
ONE_INT: Final[int] = 1
TWO_INT: Final[int] = 2
THREE_INT: Final[int] = 3
FOUR_INT: Final[int] = 4
FIVE_INT: Final[int] = 5
EIGHT_INT: Final[int] = 8
TWELVE_INT: Final[int] = 12
SIXTEEN_INT: Final[int] = 16
TWENTY_FOUR_INT: Final[int] = 24
THIRTY_TWO_INT: Final[int] = 32
SIXTY_FOUR_INT: Final[int] = 64
ONE_HUNDRED_INT: Final[int] = 100
TWO_FIFTY_FIVE_INT: Final[int] = 255

ZERO_FLOAT: Final[float] = 0.0
HALF_FLOAT: Final[float] = 0.5
ONE_FLOAT: Final[float] = 1.0
TWO_FLOAT: Final[float] = 2.0
TEN_FLOAT: Final[float] = 10.0
FIFTY_FLOAT: Final[float] = 50.0
ONE_HUNDRED_FLOAT: Final[float] = 100.0
ROUND_DECIMALS_TWO: Final[int] = 2

MAX_LOOP_ITERATIONS: Final[int] = 4096
MAX_PATH_LENGTH: Final[int] = 512
MAX_STAGE_COUNT: Final[int] = 16
MAX_BATCH_POSTS: Final[int] = 64
MAX_DIRECTORY_SCAN_ITEMS: Final[int] = 2048
MAX_AUDIT_READ_LINES: Final[int] = 256
MAX_SQL_ROWS: Final[int] = 256
MAX_SUBPROCESS_ARGS: Final[int] = 16
SUBPROCESS_TIMEOUT_SECONDS: Final[int] = 15
MAX_RATE_LIMIT_CLIENTS: Final[int] = 1024
MAX_ACTIVE_RESET_TOKENS: Final[int] = 512
MAX_INPUT_FIELD_CHARS: Final[int] = 256
MAX_URL_CHARS: Final[int] = 512
MAX_PLATFORM_COUNT: Final[int] = 16
MAX_LEXICON_ITEMS: Final[int] = 256
FILE_HASH_CHUNK_BYTES: Final[int] = 65536
MAX_FILE_HASH_CHUNKS: Final[int] = 1024

HKDF_HASH_LEN: Final[int] = 32
SHA256_HEX_LEN: Final[int] = 64
TOKEN_RANDOM_BYTES: Final[int] = 24
SHORT_HASH_PREFIX_LEN: Final[int] = 12
GENESIS_AUDIT_HASH: Final[str] = "0" * SHA256_HEX_LEN

DOMAIN_CREATOR: Final[str] = "hub-domain-creator"
DOMAIN_CAMPAIGN: Final[str] = "hub-domain-campaign"
DOMAIN_AUTH_RESET: Final[str] = "hub-domain-password-reset"

STAGE_PII_SCRUB: Final[str] = "pii_scrub_stage"
STAGE_POST_ANALYZER: Final[str] = "post_analyzer_stage"
STAGE_TELEMETRY_PERSIST: Final[str] = "telemetry_persist_stage"

SLOT_BLUE: Final[str] = "blue"
SLOT_GREEN: Final[str] = "green"
SLOT_STATE_ACTIVE: Final[str] = "ACTIVE"
SLOT_STATE_STANDBY: Final[str] = "STANDBY"
SLOT_STATE_STAGING: Final[str] = "STAGING"
SLOT_STATE_HEALTH_VERIFIED: Final[str] = "HEALTH_VERIFIED"
SLOT_STATE_ROLLED_BACK: Final[str] = "ROLLED_BACK"

TOKEN_STATE_ISSUED: Final[str] = "ISSUED"
TOKEN_STATE_CONSUMED: Final[str] = "CONSUMED"
TOKEN_STATE_EXPIRED: Final[str] = "EXPIRED"

LOG_LEVEL_INFO: Final[str] = "INFO"
LOG_LEVEL_WARN: Final[str] = "WARNING"
LOG_LEVEL_ERROR: Final[str] = "ERROR"
LOG_LEVEL_CRITICAL: Final[str] = "CRITICAL"

SAFE_ENV_KEYS: Final[Tuple[str, ...]] = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "SystemRoot",
)

PII_EMAIL_PATTERN: Final[str] = (
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
PII_PHONE_PATTERN: Final[str] = (
    r"\b(?:\+?44|0)\s?\d{3,4}[\s-]?\d{3}[\s-]?\d{3,4}\b"
)
PII_IPV4_PATTERN: Final[str] = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

SQLI_DENY_PATTERN: Final[str] = (
    r"(?i)(\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b|"
    r"\bUPDATE\b|\bOR\s+1\s*=\s*1\b|--|/\*|\*/|;)"
)
XSS_DENY_PATTERN: Final[str] = (
    r"(?i)(\x3c\s*script|javascript\s*:|onerror\s*=|onload\s*=|\x3c|\x3e)"
)
XXE_DENY_TOKENS: Final[Tuple[str, ...]] = (
    "<!DOCTYPE",
    "<!ENTITY",
    "SYSTEM",
    "PUBLIC",
)

WORD_TOKEN_PATTERN: Final[str] = r"[A-Za-z0-9']+"
HASHTAG_TOKEN_PATTERN: Final[str] = r"\x23[A-Za-z0-9_]+"
DIGIT_TOKEN_PATTERN: Final[str] = r"\b\d+\b"
SENTENCE_SPLIT_PATTERN: Final[str] = r"[.!?]+"
CTA_ACTION_PATTERN: Final[str] = (
    r"(?i)\b(comment|share|follow|subscribe|save\s+this|read\s+more|"
    r"join|try|reply|bookmark)\b"
)

RGB_MODE: Final[str] = "RGB"
PNG_FORMAT: Final[str] = "PNG"

HTTP_OK: Final[int] = 200
HTTP_BAD_REQUEST: Final[int] = 400
HTTP_UNAUTHORIZED: Final[int] = 401
HTTP_FORBIDDEN: Final[int] = 403
HTTP_NOT_FOUND: Final[int] = 404
HTTP_GONE: Final[int] = 410
HTTP_TOO_MANY_REQUESTS: Final[int] = 429
HTTP_INTERNAL_ERROR: Final[int] = 500

MIME_HTML: Final[str] = "text/html; charset=utf-8"
MIME_CSS: Final[str] = "text/css; charset=utf-8"
MIME_JS: Final[str] = "application/javascript; charset=utf-8"
MIME_JSON: Final[str] = "application/json; charset=utf-8"

HDR_CONTENT_TYPE: Final[str] = "Content-Type"
HDR_CONTENT_LEN: Final[str] = "Content-Length"
HDR_ORIGIN: Final[str] = "Origin"
HDR_CORS_ORIGIN: Final[str] = "Access-Control-Allow-Origin"
HDR_CORS_METHODS: Final[str] = "Access-Control-Allow-Methods"
HDR_CORS_HEADERS: Final[str] = "Access-Control-Allow-Headers"
HDR_NOSNIFF: Final[str] = "X-Content-Type-Options"
HDR_FRAME: Final[str] = "X-Frame-Options"
HDR_AUTH: Final[str] = "Authorization"
HDR_USER_ID: Final[str] = "X-User-Id"

VAL_NOSNIFF: Final[str] = "nosniff"
VAL_DENY: Final[str] = "DENY"
VAL_METHODS: Final[str] = "GET, POST, OPTIONS"
VAL_HEADERS: Final[str] = "Content-Type, Authorization, X-User-Id"
DEFAULT_CREATOR_ID: Final[str] = "creator-alpha"
DEFAULT_BEARER_TOKEN: Final[str] = "Bearer content-hub-session-token"

ALLOWED_PLATFORMS: Final[Tuple[str, ...]] = (
    "x_microblog",
    "linkedin_pro",
    "instagram_caption",
    "youtube_community",
)

ROUTE_ROOT: Final[str] = "/"
ROUTE_INDEX: Final[str] = "/index.html"
ROUTE_STYLES: Final[str] = "/styles.css"
ROUTE_APP_JS: Final[str] = "/app.js"
ROUTE_API_STATUS: Final[str] = "/api/status"
ROUTE_API_ANALYZE: Final[str] = "/api/posts/analyze"
ROUTE_API_HISTORY: Final[str] = "/api/posts/history"
ROUTE_API_GDPR_ERASE: Final[str] = "/api/gdpr/erase"
ROUTE_API_GDPR_PURGE: Final[str] = "/api/gdpr/purge"
ROUTE_API_GDPR_AUDIT: Final[str] = "/api/gdpr/audit"
ROUTE_API_RESET_ISSUE: Final[str] = "/api/auth/reset-issue"
ROUTE_API_RESET_CONSUME: Final[str] = "/api/auth/reset-consume"
ROUTE_API_DEPLOY_STAGE: Final[str] = "/api/deploy/stage"
ROUTE_API_DEPLOY_ROLLBACK: Final[str] = "/api/deploy/rollback"
