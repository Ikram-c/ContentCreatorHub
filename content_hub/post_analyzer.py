"""Data-driven Social Media Post Analyzer engine for ContentCreatorHub."""

import html
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from content_hub.constants import (
    ALLOWED_PLATFORMS,
    CTA_ACTION_PATTERN,
    DIGIT_TOKEN_PATTERN,
    EIGHT_INT,
    FIFTY_FLOAT,
    FIVE_INT,
    HASHTAG_TOKEN_PATTERN,
    HTTP_BAD_REQUEST,
    HTTP_OK,
    MAX_LEXICON_ITEMS,
    MAX_PLATFORM_COUNT,
    ONE_FLOAT,
    ONE_HUNDRED_FLOAT,
    ONE_INT,
    ROUND_DECIMALS_TWO,
    SENTENCE_SPLIT_PATTERN,
    SIXTEEN_INT,
    SIXTY_FOUR_INT,
    TEN_FLOAT,
    TWENTY_FOUR_INT,
    TWO_FLOAT,
    TWO_INT,
    WORD_TOKEN_PATTERN,
    XSS_DENY_PATTERN,
    ZERO_FLOAT,
    ZERO_INT,
)
from content_hub.contracts import (
    OperationResult,
    bounded_range,
    verify_condition,
)


@dataclass(frozen=True)
class PlatformFitScore:
    """Immutable character-fit evaluation for a single social platform.

    Attributes:
        platform_key: Internal configuration identifier for the platform.
        platform_label: Display label rendered in the dashboard tab.
        char_count: Measured character count of the analyzed post.
        max_chars: Hard character limit for the platform.
        remaining_chars: Characters remaining before hitting max_chars.
        fit_score: Normalized suitability score from zero to one hundred.
        status: Classification among OPTIMAL, UNDER_TARGET, or OVER_LIMIT.
    """

    platform_key: str
    platform_label: str
    char_count: int
    max_chars: int
    remaining_chars: int
    fit_score: float
    status: str

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the platform fit metrics into a dictionary."""
        return {
            "platform_key": self.platform_key,
            "platform_label": self.platform_label,
            "char_count": self.char_count,
            "max_chars": self.max_chars,
            "remaining_chars": self.remaining_chars,
            "fit_score": self.fit_score,
            "status": self.status,
        }


@dataclass(frozen=True)
class PostAnalysisReport:
    """Immutable composite analysis report for a creator social media post.

    Attributes:
        sanitized_preview: HTML-safe text preview for dashboard display.
        target_platform: Selected primary social platform key.
        char_count: Total character count of the draft.
        word_count: Bounded word token count.
        sentence_count: Bounded sentence count.
        avg_sentence_words: Mean words per sentence.
        hashtag_count: Extracted hashtag count.
        hashtags: Tuple of extracted hashtag strings.
        has_cta: True when an explicit audience call-to-action is detected.
        hook_score: Opening hook strength score.
        readability_score: Sentence cadence and skimmability score.
        sentiment_score: Lexicon polarity score.
        sentiment_label: Classification among POSITIVE, NEUTRAL, CRITICAL_TONE.
        hashtag_cta_score: Combined discovery and CTA score.
        spam_penalty: Deducted points from spam or clickbait phrases.
        overall_score: Weighted composite quality score clamped to bounds.
        engagement_tier: Classification among HIGH_VELOCITY, SOLID_BASELINE,
            or NEEDS_REFINEMENT.
        platform_matrix: Suitability breakdown across all configured channels.
        recommendations: Actionable editorial suggestions for the creator.
    """

    sanitized_preview: str
    target_platform: str
    char_count: int
    word_count: int
    sentence_count: int
    avg_sentence_words: float
    hashtag_count: int
    hashtags: Tuple[str, ...]
    has_cta: bool
    hook_score: float
    readability_score: float
    sentiment_score: float
    sentiment_label: str
    hashtag_cta_score: float
    spam_penalty: float
    overall_score: float
    engagement_tier: str
    platform_matrix: Tuple[PlatformFitScore, ...]
    recommendations: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        """Converts the immutable analysis report into a JSON-ready dict."""
        matrix_list: List[Dict[str, Any]] = []
        for idx in bounded_range(
            len(self.platform_matrix),
            MAX_PLATFORM_COUNT,
        ):
            matrix_list.append(self.platform_matrix[idx].to_dict())
        return {
            "sanitized_preview": self.sanitized_preview,
            "target_platform": self.target_platform,
            "char_count": self.char_count,
            "word_count": self.word_count,
            "sentence_count": self.sentence_count,
            "avg_sentence_words": self.avg_sentence_words,
            "hashtag_count": self.hashtag_count,
            "hashtags": list(self.hashtags),
            "has_cta": self.has_cta,
            "hook_score": self.hook_score,
            "readability_score": self.readability_score,
            "sentiment_score": self.sentiment_score,
            "sentiment_label": self.sentiment_label,
            "hashtag_cta_score": self.hashtag_cta_score,
            "spam_penalty": self.spam_penalty,
            "overall_score": self.overall_score,
            "engagement_tier": self.engagement_tier,
            "platform_matrix": matrix_list,
            "recommendations": list(self.recommendations),
        }


def sanitize_post_draft(
    raw_post: str,
    max_chars: int,
) -> OperationResult[str]:
    """Validates a creator post draft against null bytes, XSS, and length.

    Args:
        raw_post: Untrusted post body submitted by a creator.
        max_chars: Maximum permitted character length from config.yaml.

    Returns:
        OperationResult containing the trimmed, XSS-free post string.
    """
    verify_condition(max_chars > ZERO_INT, "max_chars must be positive")
    if not isinstance(raw_post, str) or "\x00" in raw_post:
        return OperationResult(
            ok=False,
            value=None,
            error_code="INVALID_POST_ENCODING",
            http_status=HTTP_BAD_REQUEST,
        )
    trimmed: str = raw_post.strip()
    if len(trimmed) == ZERO_INT:
        return OperationResult(
            ok=False,
            value=None,
            error_code="POST_DRAFT_EMPTY",
            http_status=HTTP_BAD_REQUEST,
        )
    if len(trimmed) > max_chars:
        return OperationResult(
            ok=False,
            value=None,
            error_code="POST_DRAFT_TOO_LONG",
            http_status=HTTP_BAD_REQUEST,
        )
    if re.search(XSS_DENY_PATTERN, trimmed) is not None:
        return OperationResult(
            ok=False,
            value=None,
            error_code="POST_XSS_PAYLOAD_BLOCKED",
            http_status=HTTP_BAD_REQUEST,
        )
    return OperationResult(ok=True, value=trimmed, http_status=HTTP_OK)


def clamp_metric(
    value: float,
    floor_val: float,
    ceiling_val: float,
) -> float:
    """Clamps a floating-point score into [floor_val, ceiling_val].

    Args:
        value: Raw computed metric value.
        floor_val: Minimum permitted score.
        ceiling_val: Maximum permitted score.

    Returns:
        Rounded, bounded score float.
    """
    verify_condition(
        ceiling_val >= floor_val,
        "Score ceiling must be greater than or equal to floor",
    )
    bounded: float = max(floor_val, min(ceiling_val, value))
    return round(bounded, ROUND_DECIMALS_TWO)


def extract_post_features(
    clean_post: str,
    analyzer_cfg: Mapping[str, Any],
) -> OperationResult[Dict[str, Any]]:
    """Extracts bounded word, sentence, and hashtag tokens from a draft.

    Args:
        clean_post: Validated social media post string.
        analyzer_cfg: Analyzer configuration mapping from config.yaml.

    Returns:
        OperationResult wrapping extracted token tuples.
    """
    max_tokens: int = int(
        analyzer_cfg.get("max_tokens_per_post", MAX_LEXICON_ITEMS)
    )
    max_sentences: int = int(
        analyzer_cfg.get("max_sentences_per_post", SIXTY_FOUR_INT)
    )
    max_tags: int = int(
        analyzer_cfg.get("max_hashtags_analyzed", SIXTY_FOUR_INT)
    )
    raw_words: List[str] = re.findall(WORD_TOKEN_PATTERN, clean_post)
    words: List[str] = []
    for idx in bounded_range(len(raw_words), max_tokens):
        words.append(raw_words[idx].lower())
    raw_tags: List[str] = re.findall(HASHTAG_TOKEN_PATTERN, clean_post)
    tags: List[str] = []
    for idx in bounded_range(len(raw_tags), max_tags):
        tags.append(raw_tags[idx])
    raw_parts: List[str] = re.split(SENTENCE_SPLIT_PATTERN, clean_post)
    sentences: List[str] = []
    for idx in bounded_range(len(raw_parts), max_sentences):
        segment: str = raw_parts[idx].strip()
        if len(segment) > ZERO_INT:
            sentences.append(segment)
    if len(sentences) == ZERO_INT and len(clean_post) > ZERO_INT:
        sentences.append(clean_post)
    features: Dict[str, Any] = {
        "words": tuple(words),
        "hashtags": tuple(tags),
        "sentences": tuple(sentences),
    }
    return OperationResult(ok=True, value=features, http_status=HTTP_OK)


def score_opening_hook(
    clean_post: str,
    analyzer_cfg: Mapping[str, Any],
) -> OperationResult[Tuple[float, Tuple[str, ...]]]:
    """Scores the scroll-stopping hook strength of the opening window.

    Args:
        clean_post: Validated social media post text.
        analyzer_cfg: Analyzer configuration mapping.

    Returns:
        OperationResult containing (hook_score, hook_recommendations).
    """
    floor_val: float = float(analyzer_cfg.get("min_score_floor", ZERO_FLOAT))
    ceil_val: float = float(
        analyzer_cfg.get("max_score_ceiling", ONE_HUNDRED_FLOAT)
    )
    window_len: int = int(
        analyzer_cfg.get("hook_window_chars", SIXTY_FOUR_INT)
    )
    min_hook_len: int = int(
        analyzer_cfg.get("hook_min_chars", TWENTY_FOUR_INT)
    )
    first_line: str = clean_post.splitlines()[ZERO_INT][:window_len]
    lower_hook: str = first_line.lower()
    score: float = float(analyzer_cfg.get("hook_base_score", FIFTY_FLOAT))
    tips: List[str] = []
    if len(first_line) >= min_hook_len:
        score += TEN_FLOAT
    else:
        tips.append(
            "Expand your opening line so the core promise is clear "
            "at a glance."
        )
    if "?" in first_line:
        score += float(analyzer_cfg.get("hook_question_bonus", TEN_FLOAT))
    if re.search(DIGIT_TOKEN_PATTERN, first_line) is not None:
        score += float(analyzer_cfg.get("hook_number_bonus", TEN_FLOAT))
    power_words: List[Any] = list(analyzer_cfg.get("power_hook_words", []))
    matched_power: bool = False
    for idx in bounded_range(len(power_words), MAX_LEXICON_ITEMS):
        candidate: str = str(power_words[idx]).strip().lower()
        if len(candidate) > ZERO_INT and candidate in lower_hook:
            matched_power = True
            break
    if matched_power:
        score += float(analyzer_cfg.get("hook_power_word_bonus", TEN_FLOAT))
    else:
        tips.append(
            "Lead with a concrete framework, metric, or curiosity question "
            "in the first line."
        )
    clamped: float = clamp_metric(score, floor_val, ceil_val)
    return OperationResult(
        ok=True,
        value=(clamped, tuple(tips)),
        http_status=HTTP_OK,
    )


def score_readability_cadence(
    words: Sequence[str],
    sentences: Sequence[str],
    clean_post: str,
    analyzer_cfg: Mapping[str, Any],
) -> OperationResult[Tuple[float, float, Tuple[str, ...]]]:
    """Evaluates sentence length cadence and mobile line-break formatting.

    Args:
        words: Lowercase word token sequence.
        sentences: Extracted sentence sequence.
        clean_post: Original trimmed post draft.
        analyzer_cfg: Analyzer configuration mapping.

    Returns:
        OperationResult wrapping (readability_score, avg_words, tips).
    """
    floor_val: float = float(analyzer_cfg.get("min_score_floor", ZERO_FLOAT))
    ceil_val: float = float(
        analyzer_cfg.get("max_score_ceiling", ONE_HUNDRED_FLOAT)
    )
    min_opt: float = float(
        analyzer_cfg.get("optimal_sentence_words_min", EIGHT_INT)
    )
    max_opt: float = float(
        analyzer_cfg.get("optimal_sentence_words_max", SIXTEEN_INT)
    )
    opt_score: float = float(
        analyzer_cfg.get("readability_optimal_score", ONE_HUNDRED_FLOAT)
    )
    word_penalty: float = float(
        analyzer_cfg.get("readability_word_penalty", TWO_FLOAT)
    )
    lb_bonus: float = float(
        analyzer_cfg.get("readability_linebreak_bonus", float(FIVE_INT))
    )
    sent_count: int = max(ONE_INT, len(sentences))
    avg_words: float = round(
        float(len(words)) / float(sent_count),
        ROUND_DECIMALS_TWO,
    )
    score: float = opt_score
    tips: List[str] = []
    if avg_words > max_opt:
        excess: float = avg_words - max_opt
        score -= excess * word_penalty
        tips.append(
            "Split long sentences into shorter punchy statements for "
            "mobile skimmability."
        )
    elif avg_words < min_opt:
        deficit: float = min_opt - avg_words
        score -= deficit * word_penalty
        tips.append(
            "Add slightly fuller context per sentence so ideas feel "
            "complete."
        )
    if "\n" in clean_post:
        score += lb_bonus
    elif len(words) > TWENTY_FOUR_INT:
        tips.append(
            "Insert whitespace line breaks between key points to prevent "
            "wall-of-text fatigue."
        )
    clamped: float = clamp_metric(score, floor_val, ceil_val)
    return OperationResult(
        ok=True,
        value=(clamped, avg_words, tuple(tips)),
        http_status=HTTP_OK,
    )


def _normalize_lexicon(raw_items: Sequence[Any]) -> Tuple[str, ...]:
    """Normalizes configuration lexicon terms via a bounded loop."""
    normalized: List[str] = []
    for idx in bounded_range(len(raw_items), MAX_LEXICON_ITEMS):
        term: str = str(raw_items[idx]).strip().lower()
        if len(term) > ZERO_INT:
            normalized.append(term)
    return tuple(normalized)


def score_sentiment_and_spam(
    words: Sequence[str],
    clean_post: str,
    analyzer_cfg: Mapping[str, Any],
) -> OperationResult[Tuple[float, str, float, Tuple[str, ...]]]:
    """Computes lexicon sentiment polarity and spam-trigger risk penalties.

    Args:
        words: Lowercase word token sequence.
        clean_post: Validated post string.
        analyzer_cfg: Analyzer configuration mapping.

    Returns:
        OperationResult wrapping (sentiment_score, label, penalty, tips).
    """
    floor_val: float = float(analyzer_cfg.get("min_score_floor", ZERO_FLOAT))
    ceil_val: float = float(
        analyzer_cfg.get("max_score_ceiling", ONE_HUNDRED_FLOAT)
    )
    pos_terms: Tuple[str, ...] = _normalize_lexicon(
        list(analyzer_cfg.get("positive_lexicon", []))
    )
    neg_terms: Tuple[str, ...] = _normalize_lexicon(
        list(analyzer_cfg.get("negative_lexicon", []))
    )
    pos_hits: int = ZERO_INT
    neg_hits: int = ZERO_INT
    for idx in bounded_range(len(words), len(words) + ONE_INT):
        token: str = words[idx]
        if token in pos_terms:
            pos_hits += ONE_INT
        elif token in neg_terms:
            neg_hits += ONE_INT
    base_sent: float = float(
        analyzer_cfg.get("sentiment_base_score", FIFTY_FLOAT)
    )
    pos_step: float = float(
        analyzer_cfg.get("sentiment_positive_step", TEN_FLOAT)
    )
    neg_step: float = float(
        analyzer_cfg.get("sentiment_negative_step", float(EIGHT_INT))
    )
    raw_sent: float = (
        base_sent
        + float(pos_hits) * pos_step
        - float(neg_hits) * neg_step
    )
    sent_score: float = clamp_metric(raw_sent, floor_val, ceil_val)
    sent_label: str = "NEUTRAL"
    if pos_hits > neg_hits:
        sent_label = "POSITIVE"
    elif neg_hits > pos_hits:
        sent_label = "CRITICAL_TONE"
    triggers: Tuple[str, ...] = _normalize_lexicon(
        list(analyzer_cfg.get("spam_triggers", []))
    )
    spam_step: float = float(
        analyzer_cfg.get("penalty_spam_trigger", TEN_FLOAT)
    )
    lower_body: str = clean_post.lower()
    spam_penalty: float = ZERO_FLOAT
    tips: List[str] = []
    for idx in bounded_range(len(triggers), MAX_LEXICON_ITEMS):
        if triggers[idx] in lower_body:
            spam_penalty += spam_step
    if spam_penalty > ZERO_FLOAT:
        tips.append(
            "Remove promotional clickbait phrases that trigger algorithmic "
            "reach suppression."
        )
    return OperationResult(
        ok=True,
        value=(sent_score, sent_label, spam_penalty, tuple(tips)),
        http_status=HTTP_OK,
    )


def score_hashtags_and_cta(
    hashtags: Sequence[str],
    clean_post: str,
    analyzer_cfg: Mapping[str, Any],
) -> OperationResult[Tuple[float, bool, Tuple[str, ...]]]:
    """Scores hashtag density and call-to-action presence.

    Args:
        hashtags: Extracted hashtag strings.
        clean_post: Validated post text.
        analyzer_cfg: Analyzer configuration mapping.

    Returns:
        OperationResult wrapping (hashtag_cta_score, has_cta, tips).
    """
    floor_val: float = float(analyzer_cfg.get("min_score_floor", ZERO_FLOAT))
    ceil_val: float = float(
        analyzer_cfg.get("max_score_ceiling", ONE_HUNDRED_FLOAT)
    )
    ideal_min: int = int(analyzer_cfg.get("ideal_hashtag_min", TWO_INT))
    ideal_max: int = int(analyzer_cfg.get("ideal_hashtag_max", FIVE_INT))
    opt_score: float = float(
        analyzer_cfg.get("hashtag_optimal_score", FIFTY_FLOAT)
    )
    under_score: float = float(
        analyzer_cfg.get("hashtag_under_score", FIFTY_FLOAT)
    )
    excess_pen: float = float(
        analyzer_cfg.get("penalty_per_excess_hashtag", float(EIGHT_INT))
    )
    cta_bonus: float = float(
        analyzer_cfg.get("cta_presence_bonus", TEN_FLOAT)
    )
    tag_count: int = len(hashtags)
    tips: List[str] = []
    if ideal_min <= tag_count <= ideal_max:
        score: float = opt_score
    elif tag_count < ideal_min:
        score = under_score
        tips.append(
            f"Include {ideal_min} to {ideal_max} targeted hashtags to "
            "improve topic indexing."
        )
    else:
        excess_count: int = tag_count - ideal_max
        score = opt_score - float(excess_count) * excess_pen
        tips.append(
            f"Trim hashtags down to {ideal_max} or fewer to avoid looking "
            "over-tagged."
        )
    has_cta: bool = re.search(CTA_ACTION_PATTERN, clean_post) is not None
    if has_cta:
        score += cta_bonus
    else:
        tips.append(
            "Close with a clear call-to-action inviting readers to reply, "
            "bookmark, or share."
        )
    clamped: float = clamp_metric(score, floor_val, ceil_val)
    return OperationResult(
        ok=True,
        value=(clamped, has_cta, tuple(tips)),
        http_status=HTTP_OK,
    )


def evaluate_platform_matrix(
    char_count: int,
    analyzer_cfg: Mapping[str, Any],
) -> OperationResult[Tuple[PlatformFitScore, ...]]:
    """Computes character suitability across all configured social platforms.

    Args:
        char_count: Total character length of the post draft.
        analyzer_cfg: Analyzer configuration mapping containing platforms.

    Returns:
        OperationResult wrapping PlatformFitScore records.
    """
    platforms_cfg: Mapping[str, Any] = analyzer_cfg.get("platforms", {})
    keys: Tuple[str, ...] = tuple(platforms_cfg.keys())
    if len(keys) == ZERO_INT:
        keys = ALLOWED_PLATFORMS
    floor_val: float = float(analyzer_cfg.get("min_score_floor", ZERO_FLOAT))
    ceil_val: float = float(
        analyzer_cfg.get("max_score_ceiling", ONE_HUNDRED_FLOAT)
    )
    results: List[PlatformFitScore] = []
    for idx in bounded_range(len(keys), MAX_PLATFORM_COUNT):
        p_key: str = str(keys[idx])
        spec: Mapping[str, Any] = platforms_cfg.get(p_key, {})
        label: str = str(spec.get("label", p_key))
        max_c: int = max(ONE_INT, int(spec.get("max_chars", SIXTY_FOUR_INT)))
        ideal_min: int = int(spec.get("ideal_min_chars", TWENTY_FOUR_INT))
        ideal_max: int = int(spec.get("ideal_max_chars", max_c))
        remaining: int = max_c - char_count
        if char_count > max_c:
            overflow_ratio: float = float(char_count - max_c) / float(max_c)
            raw_fit: float = FIFTY_FLOAT * (ONE_FLOAT - overflow_ratio)
            status: str = "OVER_LIMIT"
        elif ideal_min <= char_count <= ideal_max:
            raw_fit = ceil_val
            status = "OPTIMAL"
        elif char_count < ideal_min:
            ratio: float = float(char_count) / float(max(ONE_INT, ideal_min))
            raw_fit = FIFTY_FLOAT + FIFTY_FLOAT * ratio
            status = "UNDER_TARGET"
        else:
            raw_fit = ceil_val - TEN_FLOAT
            status = "OPTIMAL"
        fit_score: float = clamp_metric(raw_fit, floor_val, ceil_val)
        results.append(
            PlatformFitScore(
                platform_key=p_key,
                platform_label=label,
                char_count=char_count,
                max_chars=max_c,
                remaining_chars=remaining,
                fit_score=fit_score,
                status=status,
            )
        )
    return OperationResult(
        ok=True,
        value=tuple(results),
        http_status=HTTP_OK,
    )


def analyze_social_post(
    raw_post: str,
    target_platform: str,
    analyzer_cfg: Mapping[str, Any],
    max_post_chars: int,
) -> OperationResult[PostAnalysisReport]:
    """Executes full multi-metric post analysis and builds an immutable report.

    Args:
        raw_post: Scrubbed or raw creator post draft string.
        target_platform: Target platform identifier key.
        analyzer_cfg: Analyzer configuration mapping from config.yaml.
        max_post_chars: Maximum permitted character length from security cfg.

    Returns:
        OperationResult wrapping the completed PostAnalysisReport.
    """
    chosen_platform: str = target_platform.strip()
    if chosen_platform not in ALLOWED_PLATFORMS:
        return OperationResult(
            ok=False,
            value=None,
            error_code="UNSUPPORTED_TARGET_PLATFORM",
            http_status=HTTP_BAD_REQUEST,
        )
    draft_res: OperationResult[str] = sanitize_post_draft(
        raw_post,
        max_post_chars,
    )
    if not draft_res.ok or draft_res.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code=draft_res.error_code,
            http_status=draft_res.http_status,
        )
    clean_post: str = draft_res.value
    feat_res: OperationResult[Dict[str, Any]] = extract_post_features(
        clean_post,
        analyzer_cfg,
    )
    if not feat_res.ok or feat_res.value is None:
        return OperationResult(
            ok=False,
            value=None,
            error_code="FEATURE_EXTRACTION_FAILED",
            http_status=HTTP_BAD_REQUEST,
        )
    features: Dict[str, Any] = feat_res.value
    words: Tuple[str, ...] = features["words"]
    hashtags: Tuple[str, ...] = features["hashtags"]
    sentences: Tuple[str, ...] = features["sentences"]
    hook_res = score_opening_hook(clean_post, analyzer_cfg)
    read_res = score_readability_cadence(
        words,
        sentences,
        clean_post,
        analyzer_cfg,
    )
    sent_res = score_sentiment_and_spam(words, clean_post, analyzer_cfg)
    tag_res = score_hashtags_and_cta(hashtags, clean_post, analyzer_cfg)
    mat_res = evaluate_platform_matrix(len(clean_post), analyzer_cfg)
    if (
        not hook_res.ok
        or hook_res.value is None
        or not read_res.ok
        or read_res.value is None
        or not sent_res.ok
        or sent_res.value is None
        or not tag_res.ok
        or tag_res.value is None
        or not mat_res.ok
        or mat_res.value is None
    ):
        return OperationResult(
            ok=False,
            value=None,
            error_code="ANALYZER_SUBSTAGE_FAILURE",
            http_status=HTTP_BAD_REQUEST,
        )
    hook_score, hook_tips = hook_res.value
    read_score, avg_words, read_tips = read_res.value
    sent_score, sent_label, spam_pen, sent_tips = sent_res.value
    tag_score, has_cta, tag_tips = tag_res.value
    matrix: Tuple[PlatformFitScore, ...] = mat_res.value
    overall, tier = _compute_composite_score(
        hook_score=hook_score,
        read_score=read_score,
        sent_score=sent_score,
        tag_score=tag_score,
        spam_penalty=spam_pen,
        analyzer_cfg=analyzer_cfg,
    )
    all_tips: Tuple[str, ...] = (
        hook_tips + read_tips + sent_tips + tag_tips
    )
    if len(all_tips) == ZERO_INT:
        all_tips = (
            "Strong structure, hook, cadence, and CTA ready to publish.",
        )
    report: PostAnalysisReport = PostAnalysisReport(
        sanitized_preview=html.escape(clean_post, quote=False),
        target_platform=chosen_platform,
        char_count=len(clean_post),
        word_count=len(words),
        sentence_count=len(sentences),
        avg_sentence_words=avg_words,
        hashtag_count=len(hashtags),
        hashtags=hashtags,
        has_cta=has_cta,
        hook_score=hook_score,
        readability_score=read_score,
        sentiment_score=sent_score,
        sentiment_label=sent_label,
        hashtag_cta_score=tag_score,
        spam_penalty=spam_pen,
        overall_score=overall,
        engagement_tier=tier,
        platform_matrix=matrix,
        recommendations=all_tips,
    )
    return OperationResult(ok=True, value=report, http_status=HTTP_OK)


def _compute_composite_score(
    hook_score: float,
    read_score: float,
    sent_score: float,
    tag_score: float,
    spam_penalty: float,
    analyzer_cfg: Mapping[str, Any],
) -> Tuple[float, str]:
    """Combines weighted component scores and assigns an engagement tier."""
    floor_val: float = float(analyzer_cfg.get("min_score_floor", ZERO_FLOAT))
    ceil_val: float = float(
        analyzer_cfg.get("max_score_ceiling", ONE_HUNDRED_FLOAT)
    )
    w_hook: float = float(analyzer_cfg.get("weight_hook", ZERO_FLOAT))
    w_read: float = float(analyzer_cfg.get("weight_readability", ZERO_FLOAT))
    w_sent: float = float(analyzer_cfg.get("weight_sentiment", ZERO_FLOAT))
    w_tag: float = float(analyzer_cfg.get("weight_hashtag_cta", ZERO_FLOAT))
    weighted_sum: float = (
        hook_score * w_hook
        + read_score * w_read
        + sent_score * w_sent
        + tag_score * w_tag
        - spam_penalty
    )
    overall: float = clamp_metric(weighted_sum, floor_val, ceil_val)
    high_cutoff: float = FIFTY_FLOAT + TWO_FLOAT * TEN_FLOAT + float(FIVE_INT)
    if overall >= high_cutoff:
        return (overall, "HIGH_VELOCITY")
    if overall >= FIFTY_FLOAT:
        return (overall, "SOLID_BASELINE")
    return (overall, "NEEDS_REFINEMENT")
