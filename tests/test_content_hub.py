"""End-to-end security, GDPR, analyzer, and pre-deployment test suite."""

from pathlib import Path
import sqlite3
import tempfile
import tokenize
from typing import Any, Dict, List, Tuple
import unittest

import numpy as np
from PIL import Image

from content_hub.constants import (
    DEFAULT_BEARER_TOKEN,
    DEFAULT_CONFIG_PATH,
    DEFAULT_CREATOR_ID,
    DOMAIN_CAMPAIGN,
    DOMAIN_CREATOR,
    EIGHT_INT,
    FILE_HASH_CHUNK_BYTES,
    HDR_AUTH,
    HDR_ORIGIN,
    HDR_USER_ID,
    HTTP_BAD_REQUEST,
    HTTP_FORBIDDEN,
    HTTP_GONE,
    HTTP_OK,
    HTTP_TOO_MANY_REQUESTS,
    LOG_LEVEL_CRITICAL,
    LOG_LEVEL_INFO,
    MAX_LOOP_ITERATIONS,
    ONE_FLOAT,
    ONE_INT,
    RGB_MODE,
    SIXTEEN_INT,
    SIXTY_FOUR_INT,
    THREE_INT,
    TWO_FIFTY_FIVE_INT,
    TWO_INT,
    UTF8_ENCODING,
    ZERO_FLOAT,
    ZERO_INT,
)
from content_hub.contracts import bounded_range, verify_condition
from content_hub.gdpr import (
    ImmutableAuditLogger,
    pseudonymize_subject,
    redact_pii_text,
    resolve_master_secret,
    strip_exif_and_redact_regions,
    validate_cloud_residency,
)
from content_hub.post_analyzer import analyze_social_post
from content_hub.predeploy import (
    BlueGreenDeploymentController,
    CostCappedLoggerAndAlerts,
    CreatorHubDatabase,
    PasswordResetManager,
    SlidingWindowRateLimiter,
    validate_cors_origin,
    verify_bola_ownership,
)
from content_hub.security import (
    load_safe_yaml_config,
    resolve_safe_path,
    validate_and_sanitize_text,
    validate_outbound_url,
    validate_safe_xml_text,
)
from content_hub.server import HubRuntimeState

JS_INLINE_COMMENT_TOKEN: str = "\x2f\x2f"


class ContentCreatorHubTestSuite(unittest.TestCase):
    """Comprehensive verification suite for ContentCreatorHub MVP release."""

    def setUp(self) -> None:
        """Creates an isolated workspace copy of config.yaml per test."""
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.work_dir: Path = Path(self._tmp_ctx.name).resolve()
        repo_root: Path = Path(__file__).resolve().parent.parent
        src_cfg: Path = repo_root / DEFAULT_CONFIG_PATH
        cfg_text: str = src_cfg.read_text(encoding=UTF8_ENCODING)
        dst_cfg: Path = self.work_dir / DEFAULT_CONFIG_PATH
        written: int = dst_cfg.write_text(cfg_text, encoding=UTF8_ENCODING)
        verify_condition(written > ZERO_INT, "Test config write failed")
        cfg_res = load_safe_yaml_config(
            config_path=Path(DEFAULT_CONFIG_PATH),
            base_dir=self.work_dir,
            max_bytes=FILE_HASH_CHUNK_BYTES * EIGHT_INT,
        )
        self.assertTrue(cfg_res.ok)
        self.assertIsNotNone(cfg_res.value)
        self.config: Dict[str, Any] = (
            cfg_res.value if cfg_res.value is not None else {}
        )

    def tearDown(self) -> None:
        """Cleans up temporary test directory artifacts."""
        self._tmp_ctx.cleanup()

    def test_path_traversal_and_xxe_ssrf_guards(self) -> None:
        """Verifies CWE-22 traversal, CWE-611 XXE, and CWE-918 SSRF blocks."""
        traversal_res = resolve_safe_path(
            self.work_dir,
            Path("../outside_secret.txt"),
        )
        self.assertFalse(traversal_res.ok)
        self.assertEqual(traversal_res.http_status, HTTP_FORBIDDEN)

        xxe_payload: str = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///'>]>"
        xxe_res = validate_safe_xml_text(xxe_payload, FILE_HASH_CHUNK_BYTES)
        self.assertFalse(xxe_res.ok)
        self.assertEqual(xxe_res.http_status, HTTP_BAD_REQUEST)

        ssrf_res = validate_outbound_url(
            url="http://169.254.169.254/latest/meta-data/",
            allowed_schemes=("http", "https"),
            allowed_hosts=("127.0.0.1", "localhost"),
        )
        self.assertFalse(ssrf_res.ok)
        self.assertEqual(ssrf_res.http_status, HTTP_FORBIDDEN)

    def test_gdpr_hkdf_domain_separation_and_pii_exif_scrub(self) -> None:
        """Verifies domain-isolated HKDF pseudonyms, PII scrub, and EXIF."""
        gdpr_cfg: Dict[str, Any] = self.config["gdpr"]
        key_res = resolve_master_secret(gdpr_cfg)
        self.assertTrue(key_res.ok)
        master_key: bytes = key_res.value or b""

        p_creator = pseudonymize_subject(
            raw_identifier=DEFAULT_CREATOR_ID,
            master_secret=master_key,
            domain=DOMAIN_CREATOR,
            rotation_epoch="2026-Q4",
        )
        p_campaign = pseudonymize_subject(
            raw_identifier=DEFAULT_CREATOR_ID,
            master_secret=master_key,
            domain=DOMAIN_CAMPAIGN,
            rotation_epoch="2026-Q4",
        )
        self.assertTrue(p_creator.ok and p_campaign.ok)
        self.assertNotEqual(p_creator.value, p_campaign.value)

        scrub_res = redact_pii_text(
            "Email ops@creator.io or +44 7700 900123 at 192.168.0.9",
            "[REDACTED_PII]",
        )
        self.assertTrue(scrub_res.ok)
        scrubbed_str: str = scrub_res.value or ""
        self.assertNotIn("ops@creator.io", scrubbed_str)
        self.assertNotIn("192.168.0.9", scrubbed_str)

        arr: np.ndarray = np.full(
            (SIXTY_FOUR_INT, SIXTY_FOUR_INT, THREE_INT),
            TWO_FIFTY_FIVE_INT,
            dtype=np.uint8,
        )
        raw_img: Image.Image = Image.fromarray(arr, mode=RGB_MODE)
        raw_img.info["CameraSerial"] = "SN-998877"
        clean_res = strip_exif_and_redact_regions(
            source_image=raw_img,
            boxes=((ZERO_INT, ZERO_INT, SIXTEEN_INT, SIXTEEN_INT),),
            block_size=EIGHT_INT,
        )
        self.assertTrue(clean_res.ok)
        clean_img: Image.Image = clean_res.value or raw_img
        self.assertEqual(len(clean_img.info), ZERO_INT)

        bad_region = validate_cloud_residency("us-east-1", ("uksouth",))
        self.assertFalse(bad_region.ok)
        self.assertEqual(bad_region.http_status, HTTP_FORBIDDEN)

    def test_social_media_post_analyzer_scoring(self) -> None:
        """Verifies hook, readability, sentiment, CTA, and platform matrix."""
        sample_post: str = (
            "How we improved creator retention by 35% with a clear guide?\n"
            "First, structure your opening hook around one proven insight.\n"
            "Second, keep every sentence concise and actionable.\n"
            "Bookmark this lesson and share your thoughts! "
            "\x23CreatorEconomy \x23Growth \x23ContentStrategy"
        )
        sec_cfg: Dict[str, Any] = self.config["security"]
        report_res = analyze_social_post(
            raw_post=sample_post,
            target_platform="linkedin_pro",
            analyzer_cfg=self.config["analyzer"],
            max_post_chars=int(sec_cfg["max_post_chars"]),
        )
        self.assertTrue(report_res.ok)
        self.assertIsNotNone(report_res.value)
        if report_res.value is not None:
            self.assertGreater(report_res.value.overall_score, ZERO_FLOAT)
            self.assertEqual(report_res.value.hashtag_count, THREE_INT)
            self.assertTrue(report_res.value.has_cta)
            self.assertEqual(
                len(report_res.value.platform_matrix),
                len(self.config["analyzer"]["platforms"]),
            )

    def test_ten_point_predeployment_controls(self) -> None:
        """Verifies BOLA, SQLi/XSS, CORS, Rate Limit, 30m Reset, DB, BG."""
        bola_deny = verify_bola_ownership(
            {
                HDR_AUTH: DEFAULT_BEARER_TOKEN,
                HDR_USER_ID: DEFAULT_CREATOR_ID,
            },
            "other-creator-account",
        )
        self.assertFalse(bola_deny.ok)
        self.assertEqual(bola_deny.http_status, HTTP_FORBIDDEN)

        sqli_res = validate_and_sanitize_text("admin' UNION SELECT 1--")
        xss_res = validate_and_sanitize_text("<script>alert(1)</script>")
        self.assertFalse(sqli_res.ok)
        self.assertFalse(xss_res.ok)
        self.assertEqual(sqli_res.http_status, HTTP_BAD_REQUEST)

        cors_deny = validate_cors_origin(
            {HDR_ORIGIN: "https://malicious.example"},
            ("http://127.0.0.1:8080",),
        )
        self.assertFalse(cors_deny.ok)
        self.assertEqual(cors_deny.http_status, HTTP_FORBIDDEN)

        limiter = SlidingWindowRateLimiter(
            max_requests=TWO_INT,
            window_seconds=SIXTY_FOUR_INT,
        )
        self.assertTrue(limiter.check_request("127.0.0.1").ok)
        self.assertTrue(limiter.check_request("127.0.0.1").ok)
        rate_blocked = limiter.check_request("127.0.0.1")
        self.assertFalse(rate_blocked.ok)
        self.assertEqual(rate_blocked.http_status, HTTP_TOO_MANY_REQUESTS)

        reset_mgr = PasswordResetManager(
            ttl_seconds= int(
                self.config["security"]["password_reset_ttl_seconds"]
            ),
            gdpr_cfg=self.config["gdpr"],
        )
        issued_res = reset_mgr.issue_reset_token(DEFAULT_CREATOR_ID)
        self.assertTrue(issued_res.ok)
        issued_val: Dict[str, Any] = issued_res.value or {}
        tok_str: str = str(issued_val["reset_token"])

        first_use = reset_mgr.consume_reset_token(tok_str, DEFAULT_CREATOR_ID)
        self.assertTrue(first_use.ok)
        replay_use = reset_mgr.consume_reset_token(
            tok_str,
            DEFAULT_CREATOR_ID,
        )
        self.assertFalse(replay_use.ok)
        self.assertEqual(replay_use.http_status, HTTP_GONE)

        issued_exp = reset_mgr.issue_reset_token(DEFAULT_CREATOR_ID)
        exp_val: Dict[str, Any] = issued_exp.value or {}
        expired_check = reset_mgr.consume_reset_token(
            str(exp_val["reset_token"]),
            DEFAULT_CREATOR_ID,
            current_epoch=float(exp_val["expires_at_epoch"]) + ONE_FLOAT,
        )
        self.assertFalse(expired_check.ok)
        self.assertEqual(expired_check.http_status, HTTP_GONE)

        db_rel: Path = Path("./workspace/state/test_hub.db")
        hub_db = CreatorHubDatabase(db_rel, self.work_dir)
        with sqlite3.connect(str(self.work_dir / db_rel)) as conn:
            idx_rows: List[Tuple[Any, ...]] = conn.execute(
                "PRAGMA index_list('post_analyses');"
            ).fetchall()
        idx_names: Tuple[str, ...] = tuple(
            sorted(str(r[ONE_INT]) for r in idx_rows)
        )
        self.assertEqual(
            idx_names,
            ("idx_post_analyses_batch", "idx_post_analyses_owner"),
        )
        self.assertIsNotNone(hub_db)

        ops_log = CostCappedLoggerAndAlerts(
            capacity=TWO_INT,
            max_message_chars=SIXTEEN_INT,
            alert_sink_path=Path("./workspace/audit/alerts.jsonl"),
            base_dir=self.work_dir,
        )
        ops_log.log_event(LOG_LEVEL_INFO, "test", "first message")
        ops_log.log_event(LOG_LEVEL_INFO, "test", "second message")
        ops_log.log_event(
            LOG_LEVEL_CRITICAL,
            "test",
            "critical failure exceeding sixteen characters",
        )
        self.assertEqual(len(ops_log.get_recent_logs()), TWO_INT)
        self.assertEqual(len(ops_log.get_recent_alerts()), ONE_INT)

        bg = BlueGreenDeploymentController("blue", "green")
        failed_stage = bg.stage_and_promote(health_check_passed=False)
        self.assertFalse(failed_stage.ok)
        self.assertEqual(bg.snapshot()["active_slot"], "blue")
        ok_stage = bg.stage_and_promote(health_check_passed=True)
        self.assertTrue(ok_stage.ok)
        self.assertEqual(bg.snapshot()["active_slot"], "green")
        rb_res = bg.rollback_to_standby()
        self.assertTrue(rb_res.ok)
        self.assertEqual(bg.snapshot()["active_slot"], "blue")

    def test_runtime_pipeline_audit_chain_and_article_17_erasure(self) -> None:
        """Verifies full pipeline persistence, audit chain, and erasure."""
        runtime = HubRuntimeState(self.config, self.work_dir)
        seed_res = runtime.seed_initial_workspace()
        self.assertTrue(seed_res.ok)
        before_snap = runtime.build_status_snapshot(DEFAULT_CREATOR_ID)
        self.assertIsNotNone(before_snap["latest_analysis"])
        self.assertGreater(len(before_snap["history"]), ZERO_INT)

        erase_res = runtime.execute_erasure_and_sync_cache(
            subject_id=DEFAULT_CREATOR_ID,
            caller_owner_id=DEFAULT_CREATOR_ID,
        )
        self.assertTrue(erase_res.ok)
        after_snap = runtime.build_status_snapshot(DEFAULT_CREATOR_ID)
        self.assertIsNone(after_snap["latest_analysis"])
        self.assertEqual(len(after_snap["history"]), ZERO_INT)

        audit_check: ImmutableAuditLogger = runtime.audit_logger
        chain_res = audit_check.verify_and_read_events()
        self.assertTrue(chain_res.ok)
        events = chain_res.value or ()
        self.assertGreater(len(events), ZERO_INT)

    def test_zero_inline_comments_across_codebase(self) -> None:
        """Verifies zero Python comment tokens and zero JS inline comments."""
        repo_root: Path = Path(__file__).resolve().parent.parent
        py_dirs: Tuple[Path, ...] = (
            repo_root / "content_hub",
            repo_root / "tests",
        )
        for dir_idx in bounded_range(len(py_dirs)):
            folder: Path = py_dirs[dir_idx]
            py_files: List[Path] = sorted(folder.glob("*.py"))
            for file_idx in bounded_range(len(py_files)):
                py_path: Path = py_files[file_idx]
                with tokenize.open(str(py_path)) as stream:
                    tokens = list(tokenize.generate_tokens(stream.readline))
                for tok_idx in bounded_range(
                    len(tokens),
                    MAX_LOOP_ITERATIONS,
                ):
                    self.assertNotEqual(
                        tokens[tok_idx].type,
                        tokenize.COMMENT,
                        f"Inline comment found in {py_path.name}",
                    )

        js_path: Path = repo_root / "content_hub" / "static" / "app.js"
        if js_path.exists():
            js_text: str = js_path.read_text(encoding=UTF8_ENCODING)
            self.assertNotIn(JS_INLINE_COMMENT_TOKEN, js_text)


if __name__ == "__main__":
    unittest.main()
