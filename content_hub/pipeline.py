"""Declarative data-driven stage pipeline for ContentCreatorHub."""

from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Tuple

from content_hub.constants import (
    DEFAULT_CREATOR_ID,
    DOMAIN_CREATOR,
    HTTP_BAD_REQUEST,
    HTTP_INTERNAL_ERROR,
    HTTP_OK,
    MAX_BATCH_POSTS,
    MAX_STAGE_COUNT,
    STAGE_PII_SCRUB,
    STAGE_POST_ANALYZER,
    STAGE_TELEMETRY_PERSIST,
    TWO_INT,
    UTF8_ENCODING,
    ZERO_INT,
)
from content_hub.contracts import (
    OperationResult,
    bounded_range,
    verify_condition,
)
from content_hub.gdpr import (
    ImmutableAuditLogger,
    pseudonymize_subject,
    redact_pii_text,
    resolve_master_secret,
    validate_cloud_residency,
)
from content_hub.post_analyzer import PostAnalysisReport, analyze_social_post
from content_hub.predeploy import CreatorHubDatabase
from content_hub.sandbox import sync_artifact_to_sandbox
from content_hub.security import resolve_safe_path


@dataclass(frozen=True)
class ContentBatch:
    """Immutable data carrier flowing sequentially across registered stages.

    Attributes:
        batch_id: Unique batch execution identifier.
        owner_id: Authenticated creator owner identifier.
        target_platform: Selected social media target platform key.
        raw_post: Incoming creator post draft text.
        scrubbed_post: PII-redacted post draft produced by stage 1.
        creator_pseudonym: HKDF-SHA256 pseudonymized creator digest.
        validated_region: Confirmed UK/EU cloud residency region.
        analysis_report: Immutable PostAnalysisReport produced by stage 2.
        persisted_row_id: SQLite row ID generated in stage 3.
        cloud_sync_pairs: Immutable key-value pairs describing sandbox sync.
        stage_history: Immutable sequence of completed stage names.
    """

    batch_id: str
    owner_id: str
    target_platform: str
    raw_post: str
    scrubbed_post: str = ""
    creator_pseudonym: str = ""
    validated_region: str = ""
    analysis_report: PostAnalysisReport | None = None
    persisted_row_id: int = ZERO_INT
    cloud_sync_pairs: Tuple[Tuple[str, str], ...] = ()
    stage_history: Tuple[str, ...] = ()


StageHandler = Callable[
    [
        ContentBatch,
        Mapping[str, Any],
        Path,
        ImmutableAuditLogger,
        CreatorHubDatabase,
    ],
    OperationResult[ContentBatch],
]


def run_pii_scrub_stage(
    batch: ContentBatch,
    config: Mapping[str, Any],
    base_dir: Path,
    audit_logger: ImmutableAuditLogger,
    database: CreatorHubDatabase,
) -> OperationResult[ContentBatch]:
    """Validates UK/EU residency, pseudonymizes creator ID, and redacts PII.

    Args:
        batch: Incoming immutable ContentBatch.
        config: Validated configuration dictionary.
        base_dir: Canonical workspace root path.
        audit_logger: Hash-chained accountability audit logger.
        database: Parameterized SQLite database instance.

    Returns:
        OperationResult wrapping updated ContentBatch with scrubbed text.
    """
    verify_condition(base_dir.exists(), "Workspace base_dir must exist")
    verify_condition(database is not None, "Database handle is required")
    gdpr_cfg: Mapping[str, Any] = config.get("gdpr", {})
    region_res: OperationResult[str] = validate_cloud_residency(
        active_region=str(gdpr_cfg.get("active_region", "uksouth")),
        allowed_regions=list(gdpr_cfg.get("allowed_regions", ["uksouth"])),
    )
    if not region_res.ok or region_res.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code=region_res.error_code,
            http_status=region_res.http_status,
        )
    secret_res: OperationResult[bytes] = resolve_master_secret(gdpr_cfg)
    if not secret_res.ok or secret_res.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code=secret_res.error_code,
            http_status=secret_res.http_status,
        )
    epoch: str = str(gdpr_cfg.get("key_rotation_epoch", "2026-Q4"))
    pseudo_res: OperationResult[str] = pseudonymize_subject(
        raw_identifier=batch.owner_id,
        master_secret=secret_res.value,
        domain=DOMAIN_CREATOR,
        rotation_epoch=epoch,
    )
    if not pseudo_res.ok or pseudo_res.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code=pseudo_res.error_code,
            http_status=pseudo_res.http_status,
        )
    token: str = str(gdpr_cfg.get("redaction_token", "[REDACTED_PII]"))
    scrub_res: OperationResult[str] = redact_pii_text(batch.raw_post, token)
    if not scrub_res.ok or scrub_res.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code=scrub_res.error_code,
            http_status=scrub_res.http_status,
        )
    audit_res = audit_logger.append_event(
        event_type="STAGE_PII_SCRUB_COMPLETE",
        actor_pseudonym=pseudo_res.value,
        details=(
            f"Validated region {region_res.value} and scrubbed PII "
            f"for batch {batch.batch_id}"
        ),
    )
    if not audit_res.ok:
        return OperationResult(
            ok=False,
            value=None,
            error_code=audit_res.error_code,
            http_status=HTTP_INTERNAL_ERROR,
        )
    next_batch: ContentBatch = replace(
        batch,
        scrubbed_post=scrub_res.value,
        creator_pseudonym=pseudo_res.value,
        validated_region=region_res.value,
        stage_history=batch.stage_history + (STAGE_PII_SCRUB,),
    )
    return OperationResult(ok=True, value=next_batch, http_status=HTTP_OK)


def run_post_analyzer_stage(
    batch: ContentBatch,
    config: Mapping[str, Any],
    base_dir: Path,
    audit_logger: ImmutableAuditLogger,
    database: CreatorHubDatabase,
) -> OperationResult[ContentBatch]:
    """Executes multi-metric Social Media Post Analyzer scoring on scrubbed text.

    Args:
        batch: ContentBatch containing scrubbed_post text.
        config: Validated configuration dictionary.
        base_dir: Canonical workspace root path.
        audit_logger: Hash-chained accountability audit logger.
        database: Parameterized SQLite database instance.

    Returns:
        OperationResult wrapping updated ContentBatch with PostAnalysisReport.
    """
    verify_condition(base_dir.exists(), "Workspace base_dir must exist")
    verify_condition(database is not None, "Database handle is required")
    analyzer_cfg: Mapping[str, Any] = config.get("analyzer", {})
    sec_cfg: Mapping[str, Any] = config.get("security", {})
    max_chars: int = int(sec_cfg.get("max_post_chars", 5000))
    report_res: OperationResult[PostAnalysisReport] = analyze_social_post(
        raw_post=batch.scrubbed_post,
        target_platform=batch.target_platform,
        analyzer_cfg=analyzer_cfg,
        max_post_chars=max_chars,
    )
    if not report_res.ok or report_res.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code=report_res.error_code,
            http_status=report_res.http_status,
        )
    report: PostAnalysisReport = report_res.value
    audit_res = audit_logger.append_event(
        event_type="STAGE_POST_ANALYZER_COMPLETE",
        actor_pseudonym=batch.creator_pseudonym,
        details=(
            f"Analyzed {batch.target_platform} post: "
            f"score={report.overall_score}, tier={report.engagement_tier}"
        ),
    )
    if not audit_res.ok:
        return OperationResult(
            ok=False,
            value=None,
            error_code=audit_res.error_code,
            http_status=HTTP_INTERNAL_ERROR,
        )
    next_batch: ContentBatch = replace(
        batch,
        analysis_report=report,
        stage_history=batch.stage_history + (STAGE_POST_ANALYZER,),
    )
    return OperationResult(ok=True, value=next_batch, http_status=HTTP_OK)


def run_telemetry_persist_stage(
    batch: ContentBatch,
    config: Mapping[str, Any],
    base_dir: Path,
    audit_logger: ImmutableAuditLogger,
    database: CreatorHubDatabase,
) -> OperationResult[ContentBatch]:
    """Persists analysis results into SQLite, derived JSON, and cloud sandbox.

    Args:
        batch: ContentBatch containing completed PostAnalysisReport.
        config: Validated configuration dictionary.
        base_dir: Canonical workspace root path.
        audit_logger: Hash-chained accountability audit logger.
        database: Parameterized SQLite database instance.

    Returns:
        OperationResult wrapping the finalized ContentBatch.
    """
    if batch.analysis_report is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code="MISSING_ANALYSIS_REPORT",
            http_status=HTTP_INTERNAL_ERROR,
        )
    report_dict: Dict[str, Any] = batch.analysis_report.to_dict()
    insert_res: OperationResult[int] = database.insert_analysis_record(
        batch_id=batch.batch_id,
        owner_id=batch.owner_id,
        creator_pseudonym=batch.creator_pseudonym,
        report_dict=report_dict,
    )
    if not insert_res.ok or insert_res.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code=insert_res.error_code,
            http_status=HTTP_INTERNAL_ERROR,
        )
    hub_cfg: Mapping[str, Any] = config.get("hub", {})
    derived_rel: Path = Path(
        str(hub_cfg.get("derived_dir", "./workspace/derived"))
    )
    safe_derived: OperationResult[Path] = resolve_safe_path(
        base_dir,
        derived_rel,
    )
    if not safe_derived.ok or safe_derived.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code=safe_derived.error_code,
            http_status=safe_derived.http_status,
        )
    derived_dir: Path = safe_derived.value
    derived_dir.mkdir(parents=True, exist_ok=True)
    manifest_file: Path = derived_dir / "latest_post_analysis.json"
    record_entry: Dict[str, Any] = {
        "batch_id": batch.batch_id,
        "creator_pseudonym": batch.creator_pseudonym,
        "validated_region": batch.validated_region,
        "report": report_dict,
    }
    envelope: Dict[str, Any] = {"posts": [record_entry]}
    serialized_str: str = json.dumps(envelope, indent=TWO_INT)
    temp_file: Path = manifest_file.with_suffix(".json.tmp")
    written: int = temp_file.write_text(serialized_str, encoding=UTF8_ENCODING)
    verify_condition(
        written == len(serialized_str),
        "Atomic derived JSON write was truncated",
    )
    os.replace(temp_file, manifest_file)
    sync_res: OperationResult[Dict[str, str]] = sync_artifact_to_sandbox(
        sandbox_cfg=config.get("sandbox", {}),
        security_cfg=config.get("security", {}),
        payload_bytes=serialized_str.encode(UTF8_ENCODING),
        object_name="latest_post_analysis.json",
    )
    sync_dict: Dict[str, str] = (
        sync_res.value
        if sync_res.ok and sync_res.value is not None
        else {"provider": "local-offline-fallback", "uri": "local://derived"}
    )
    sync_pairs: Tuple[Tuple[str, str], ...] = tuple(sorted(sync_dict.items()))
    audit_res = audit_logger.append_event(
        event_type="STAGE_TELEMETRY_PERSIST_COMPLETE",
        actor_pseudonym=batch.creator_pseudonym,
        details=(
            f"Persisted row {insert_res.value} and synced via "
            f"{sync_dict.get('provider', 'local')}"
        ),
    )
    if not audit_res.ok:
        return OperationResult(
            ok=False,
            value=None,
            error_code=audit_res.error_code,
            http_status=HTTP_INTERNAL_ERROR,
        )
    next_batch: ContentBatch = replace(
        batch,
        persisted_row_id=insert_res.value,
        cloud_sync_pairs=sync_pairs,
        stage_history=batch.stage_history + (STAGE_TELEMETRY_PERSIST,),
    )
    return OperationResult(ok=True, value=next_batch, http_status=HTTP_OK)


STAGE_REGISTRY: Dict[str, StageHandler] = {
    STAGE_PII_SCRUB: run_pii_scrub_stage,
    STAGE_POST_ANALYZER: run_post_analyzer_stage,
    STAGE_TELEMETRY_PERSIST: run_telemetry_persist_stage,
}


def execute_declarative_pipeline(
    batch_id: str,
    owner_id: str,
    target_platform: str,
    raw_post: str,
    config: Mapping[str, Any],
    base_dir: Path,
    audit_logger: ImmutableAuditLogger,
    database: CreatorHubDatabase,
) -> OperationResult[ContentBatch]:
    """Executes all stages declared in config.yaml over an immutable batch.

    Args:
        batch_id: Unique batch execution identifier.
        owner_id: Authenticated creator identifier.
        target_platform: Selected social media platform key.
        raw_post: Creator post draft text.
        config: Validated configuration dictionary.
        base_dir: Canonical workspace root path.
        audit_logger: Immutable GDPR audit logger.
        database: Parameterized SQLite database store.

    Returns:
        OperationResult wrapping the finalized ContentBatch.
    """
    hub_cfg: Mapping[str, Any] = config.get("hub", {})
    stages: List[str] = list(hub_cfg.get("stages", []))
    if len(stages) == ZERO_INT or len(stages) > MAX_STAGE_COUNT:
        return OperationResult(
            ok=False,
            value=None,
            error_code="INVALID_PIPELINE_STAGE_LIST",
            http_status=HTTP_BAD_REQUEST,
        )
    current_batch: ContentBatch = ContentBatch(
        batch_id=batch_id.strip() or "batch-0001",
        owner_id=owner_id.strip() or DEFAULT_CREATOR_ID,
        target_platform=target_platform.strip(),
        raw_post=raw_post,
    )
    for idx in bounded_range(len(stages), MAX_STAGE_COUNT):
        stage_name: str = str(stages[idx]).strip()
        handler: StageHandler | None = STAGE_REGISTRY.get(stage_name)
        if handler is None:
            return OperationResult(
                ok=False,
                value=None,
                error_code=f"UNREGISTERED_STAGE_{stage_name}",
                http_status=HTTP_BAD_REQUEST,
            )
        step_res: OperationResult[ContentBatch] = handler(
            current_batch,
            config,
            base_dir,
            audit_logger,
            database,
        )
        if not step_res.ok or step_res.value is None:
            return OperationResult(
                ok=False,
                value=None,
                error_code=step_res.error_code,
                http_status=step_res.http_status,
            )
        current_batch = step_res.value
    verify_condition(
        len(current_batch.stage_history) == len(stages),
        "Completed stage count must match declarative config stages",
    )
    return OperationResult(
        ok=True,
        value=current_batch,
        http_status=HTTP_OK,
    )
