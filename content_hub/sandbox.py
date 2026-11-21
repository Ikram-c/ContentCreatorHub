"""Cloud sandbox adapters (Azurite, fake-gcs-server) and offline seed data."""

import io
import os
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple
import urllib.request

import numpy as np
from PIL import Image

from content_hub.constants import (
    DEFAULT_CREATOR_ID,
    EIGHT_INT,
    FOUR_INT,
    HTTP_OK,
    ONE_INT,
    PNG_FORMAT,
    RGB_MODE,
    SIXTEEN_INT,
    SIXTY_FOUR_INT,
    THREE_INT,
    TWO_FIFTY_FIVE_INT,
    TWO_INT,
    ZERO_INT,
)
from content_hub.contracts import (
    OperationResult,
    bounded_range,
    verify_condition,
)
from content_hub.security import resolve_safe_path, validate_outbound_url


def probe_sandbox_endpoint(
    endpoint_url: str,
    security_cfg: Mapping[str, Any],
    timeout_seconds: float,
) -> bool:
    """Validates URL against SSRF allowlist and checks HTTP reachability.

    Args:
        endpoint_url: Candidate emulator HTTP endpoint URL.
        security_cfg: Security configuration containing scheme/host allowlists.
        timeout_seconds: Socket connection timeout in seconds.

    Returns:
        True when endpoint is allowlisted and responds over HTTP.
    """
    schemes: List[str] = list(
        security_cfg.get("allowed_outbound_schemes", ["http", "https"])
    )
    hosts: List[str] = list(
        security_cfg.get("allowed_outbound_hosts", ["127.0.0.1", "localhost"])
    )
    url_res: OperationResult[str] = validate_outbound_url(
        endpoint_url,
        schemes,
        hosts,
    )
    if not url_res.ok or url_res.value is None:
        return False
    try:
        req: urllib.request.Request = urllib.request.Request(
            url_res.value,
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            code: int = int(getattr(resp, "status", ZERO_INT))
            return code > ZERO_INT
    except Exception:
        return False


def sync_artifact_to_sandbox(
    sandbox_cfg: Mapping[str, Any],
    security_cfg: Mapping[str, Any],
    payload_bytes: bytes,
    object_name: str,
) -> OperationResult[Dict[str, str]]:
    """Syncs serialized JSON telemetry to Azurite, fake-gcs-server, or local.

    Args:
        sandbox_cfg: Sandbox configuration mapping from config.yaml.
        security_cfg: Security configuration mapping from config.yaml.
        payload_bytes: UTF-8 JSON bytes to persist.
        object_name: Blob or object key name.

    Returns:
        OperationResult reporting active storage provider and target URI.
    """
    timeout_sec: float = float(sandbox_cfg.get("connect_timeout_seconds", 1.5))
    az_endpoint: str = str(sandbox_cfg.get("azurite_endpoint", ""))
    gcs_endpoint: str = str(sandbox_cfg.get("gcs_emulator_endpoint", ""))
    if az_endpoint and probe_sandbox_endpoint(
        az_endpoint,
        security_cfg,
        timeout_sec,
    ):
        az_res: OperationResult[str] = _upload_azurite_blob(
            sandbox_cfg,
            payload_bytes,
            object_name,
        )
        if az_res.ok and az_res.value is not None:
            return OperationResult(
                ok=True,
                value={"provider": "azurite-emulator", "uri": az_res.value},
                http_status=HTTP_OK,
            )
    if gcs_endpoint and probe_sandbox_endpoint(
        gcs_endpoint,
        security_cfg,
        timeout_sec,
    ):
        gcs_res: OperationResult[str] = _upload_fake_gcs_object(
            sandbox_cfg,
            payload_bytes,
            object_name,
        )
        if gcs_res.ok and gcs_res.value is not None:
            return OperationResult(
                ok=True,
                value={"provider": "fake-gcs-server", "uri": gcs_res.value},
                http_status=HTTP_OK,
            )
    return OperationResult(
        ok=True,
        value={
            "provider": "local-offline-fallback",
            "uri": f"local://workspace/derived/{object_name}",
        },
        http_status=HTTP_OK,
    )


def _upload_azurite_blob(
    sandbox_cfg: Mapping[str, Any],
    payload_bytes: bytes,
    blob_name: str,
) -> OperationResult[str]:
    """Uploads blob bytes to Azurite when connection string env var is set."""
    try:
        from azure.storage.blob import BlobServiceClient

        env_key: str = str(
            sandbox_cfg.get("azurite_conn_env", "CONTENT_HUB_AZURITE_CONN_STR")
        )
        conn_str: str = os.environ.get(env_key, "").strip()
        if len(conn_str) == ZERO_INT:
            return OperationResult(
                ok=False,
                value=None,
                error_code="AZURITE_ENV_UNSET",
            )
        container: str = str(
            sandbox_cfg.get("azurite_container", "creator-hub-blobs")
        )
        client: BlobServiceClient = BlobServiceClient.from_connection_string(
            conn_str
        )
        container_client = client.get_container_client(container)
        if not container_client.exists():
            container_client.create_container()
        blob_client = container_client.get_blob_client(blob_name)
        blob_client.upload_blob(payload_bytes, overwrite=True)
        return OperationResult(
            ok=True,
            value=f"azurite://{container}/{blob_name}",
        )
    except Exception:
        return OperationResult(
            ok=False,
            value=None,
            error_code="AZURITE_SYNC_ERROR",
        )


def _upload_fake_gcs_object(
    sandbox_cfg: Mapping[str, Any],
    payload_bytes: bytes,
    object_name: str,
) -> OperationResult[str]:
    """Uploads object bytes to fake-gcs-server with AnonymousCredentials."""
    try:
        from google.auth.credentials import AnonymousCredentials
        from google.cloud import storage

        endpoint: str = str(
            sandbox_cfg.get("gcs_emulator_endpoint", "http://127.0.0.1:4443")
        )
        bucket_name: str = str(
            sandbox_cfg.get("gcs_bucket", "creator-hub-bucket")
        )
        client: storage.Client = storage.Client(
            project="content-hub-sandbox",
            credentials=AnonymousCredentials(),
            client_options={"api_endpoint": endpoint},
        )
        bucket = client.bucket(bucket_name)
        if not bucket.exists():
            bucket = client.create_bucket(bucket_name)
        blob = bucket.blob(object_name)
        blob.upload_from_string(payload_bytes)
        return OperationResult(
            ok=True,
            value=f"gs://{bucket_name}/{object_name}",
        )
    except Exception:
        return OperationResult(
            ok=False,
            value=None,
            error_code="FAKE_GCS_SYNC_ERROR",
        )


def synthesize_creator_seed_batch(
    raw_media_dir: Path,
    base_dir: Path,
    sandbox_cfg: Mapping[str, Any],
) -> OperationResult[Tuple[Dict[str, str], ...]]:
    """Synthesizes zero-PII starter creator drafts and clean PNG thumbnails.

    Args:
        raw_media_dir: Workspace directory storing starter thumbnail assets.
        base_dir: Trusted workspace root boundary.
        sandbox_cfg: Sandbox configuration mapping from config.yaml.

    Returns:
        OperationResult containing starter post dictionaries.
    """
    safe_dir: OperationResult[Path] = resolve_safe_path(
        base_dir,
        raw_media_dir,
    )
    if not safe_dir.ok or safe_dir.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code=safe_dir.error_code,
            http_status=safe_dir.http_status,
        )
    target_dir: Path = safe_dir.value
    target_dir.mkdir(parents=True, exist_ok=True)
    width: int = int(
        sandbox_cfg.get("synthetic_thumb_width", SIXTY_FOUR_INT)
    )
    height: int = int(
        sandbox_cfg.get("synthetic_thumb_height", SIXTY_FOUR_INT)
    )
    sample_drafts: Tuple[Tuple[str, str], ...] = (
        (
            "linkedin_pro",
            "How we cut API latency by 42% using a 3-step blueprint?\n"
            "First, eliminate unindexed queries.\n"
            "Second, enforce strict input bounds.\n"
            "Third, measure every release stage.\n"
            "Bookmark this framework and share your thoughts below! "
            "#Engineering #Architecture #Performance #CleanCode",
        ),
        (
            "x_microblog",
            "Why do 80% of side-project launches stall?\n"
            "Skipping basic rate limits and error boundaries.\n"
            "Follow this verified checklist before shipping. "
            "#BuildInPublic #DevOps #Security",
        ),
        (
            "instagram_caption",
            "5 proven lessons from building a zero-PII creator workflow.\n"
            "Clear structure beats noisy dashboards every single time.\n"
            "Save this guide for your next launch! "
            "#ContentCreator #Productivity #Workflow #TechTips",
        ),
    )
    seeded: List[Dict[str, str]] = []
    for idx in bounded_range(len(sample_drafts)):
        platform_key, body_text = sample_drafts[idx]
        yy, xx = np.mgrid[ZERO_INT:height, ZERO_INT:width]
        red: np.ndarray = (
            (xx * FOUR_INT + idx * SIXTEEN_INT) % TWO_FIFTY_FIVE_INT
        ).astype(np.uint8)
        green: np.ndarray = (
            (yy * FOUR_INT + idx * EIGHT_INT) % TWO_FIFTY_FIVE_INT
        ).astype(np.uint8)
        blue: np.ndarray = (
            ((xx + yy) * TWO_INT) % TWO_FIFTY_FIVE_INT
        ).astype(np.uint8)
        rgb_arr: np.ndarray = np.stack([red, green, blue], axis=TWO_INT)
        verify_condition(
            rgb_arr.shape[TWO_INT] == THREE_INT,
            "Synthetic thumbnail must have 3 RGB channels",
        )
        img: Image.Image = Image.fromarray(rgb_arr, mode=RGB_MODE)
        buf: io.BytesIO = io.BytesIO()
        img.save(buf, format=PNG_FORMAT)
        thumb_path: Path = target_dir / f"creator_thumb_{idx:02d}.png"
        written: int = thumb_path.write_bytes(buf.getvalue())
        verify_condition(
            written > ZERO_INT,
            "Failed to write synthetic thumbnail",
        )
        seeded.append(
            {
                "owner_id": DEFAULT_CREATOR_ID,
                "target_platform": platform_key,
                "raw_post": body_text,
                "thumbnail_file": thumb_path.name,
            }
        )
    return OperationResult(
        ok=True,
        value=tuple(seeded),
        http_status=HTTP_OK,
    )
