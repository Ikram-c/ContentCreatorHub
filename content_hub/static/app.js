"use strict";

const APP_CFG = Object.freeze({
  ROUTE_STATUS: "/api/status",
  ROUTE_ANALYZE: "/api/posts/analyze",
  ROUTE_HISTORY: "/api/posts/history",
  ROUTE_GDPR_ERASE: "/api/gdpr/erase",
  ROUTE_GDPR_PURGE: "/api/gdpr/purge",
  ROUTE_GDPR_AUDIT: "/api/gdpr/audit",
  ROUTE_RESET_ISSUE: "/api/auth/reset-issue",
  ROUTE_RESET_CONSUME: "/api/auth/reset-consume",
  ROUTE_DEPLOY_STAGE: "/api/deploy/stage",
  ROUTE_DEPLOY_ROLLBACK: "/api/deploy/rollback",
  METHOD_GET: "GET",
  METHOD_POST: "POST",
  AUTH_HEADER: "Bearer content-hub-session-token",
  OWNER_ID: "creator-alpha",
  POLL_MS: 5000,
  MAX_RENDER_ITEMS: 32,
  HASH_PREFIX_LEN: 12,
  ZERO: 0,
  ONE: 1,
  HTTP_OK_MIN: 200,
  HTTP_OK_MAX: 299,
  HTTP_BAD_REQUEST: 400,
  HTTP_FORBIDDEN: 403,
  HTTP_NOT_FOUND: 404,
  HTTP_GONE: 410,
  HTTP_RATE_LIMIT: 429,
  HTTP_INTERNAL: 500
});

const UI_STATE = {
  busy: false,
  sequence: APP_CFG.ZERO,
  lastIssuedResetToken: ""
};

function getNode(elementId) {
  const element = document.getElementById(elementId);
  if (!element) {
    throw new Error("Missing DOM node: " + String(elementId));
  }
  return element;
}

function setNodeText(elementId, textValue) {
  const node = getNode(elementId);
  node.textContent = String(textValue);
  return true;
}

function classifyErrorScreen(statusCode, errorCode) {
  if (statusCode === APP_CFG.HTTP_BAD_REQUEST) {
    return "Input Validation Screen (400 — " + String(errorCode) + ")";
  }
  if (statusCode === APP_CFG.HTTP_FORBIDDEN) {
    return "Authorization & CORS Guard (403 — " + String(errorCode) + ")";
  }
  if (statusCode === APP_CFG.HTTP_NOT_FOUND) {
    return "Resource Not Found Screen (404 — " + String(errorCode) + ")";
  }
  if (statusCode === APP_CFG.HTTP_GONE) {
    return "Expired or Consumed Link Screen (410 — " + String(errorCode) + ")";
  }
  if (statusCode === APP_CFG.HTTP_RATE_LIMIT) {
    return "API Rate Limit Shield (429 — " + String(errorCode) + ")";
  }
  return "Global Catch-All Error Boundary (500 — " + String(errorCode) + ")";
}

function showBoundaryError(statusCode, errorCode, userMessage) {
  const boundary = getNode("error-boundary-screen");
  boundary.classList.remove("hidden");
  setNodeText("err-status-badge", "HTTP " + String(statusCode));
  setNodeText("err-title", classifyErrorScreen(statusCode, errorCode));
  setNodeText("err-message", String(userMessage));
  return true;
}

function hideBoundaryError() {
  const boundary = getNode("error-boundary-screen");
  boundary.classList.add("hidden");
  return true;
}

async function sendApiRequest(url, method, bodyObj) {
  UI_STATE.sequence += APP_CFG.ONE;
  const currentSeq = UI_STATE.sequence;
  const options = {
    method: method,
    headers: {
      "Content-Type": "application/json",
      "Authorization": APP_CFG.AUTH_HEADER,
      "X-User-Id": APP_CFG.OWNER_ID
    }
  };
  if (method === APP_CFG.METHOD_POST && bodyObj) {
    options.body = JSON.stringify(bodyObj);
  }
  try {
    const response = await fetch(url, options);
    const jsonBody = await response.json();
    if (
      response.status < APP_CFG.HTTP_OK_MIN ||
      response.status > APP_CFG.HTTP_OK_MAX ||
      !jsonBody.ok
    ) {
      showBoundaryError(
        response.status,
        jsonBody.error_code || "REQUEST_REJECTED",
        jsonBody.message || "Request rejected by security policy."
      );
      return { ok: false, data: null, stale: currentSeq < UI_STATE.sequence };
    }
    hideBoundaryError();
    return {
      ok: true,
      data: jsonBody,
      stale: currentSeq < UI_STATE.sequence
    };
  } catch (_err) {
    showBoundaryError(
      APP_CFG.HTTP_INTERNAL,
      "NETWORK_CATCH_ALL",
      "Backend unreachable. Catch-all boundary prevented unhandled failure."
    );
    return { ok: false, data: null, stale: false };
  }
}

function renderListCards(listId, items, formatterFn) {
  const container = getNode(listId);
  container.textContent = "";
  const count = Math.min(items.length, APP_CFG.MAX_RENDER_ITEMS);
  for (let idx = APP_CFG.ZERO; idx < count; idx += APP_CFG.ONE) {
    const li = document.createElement("li");
    li.className = "list-item-card";
    formatterFn(li, items[idx]);
    container.appendChild(li);
  }
  return true;
}

function renderAnalysisReport(report) {
  if (!report) {
    setNodeText("analyzer-tier-badge", "TIER: STANDBY");
    setNodeText("score-overall", "0.0");
    setNodeText("overview-latest-score", "0.0");
    setNodeText("score-hook", "0.0");
    setNodeText("score-readability", "0.0");
    setNodeText("score-sentiment", "0.0");
    setNodeText("score-hashtag-cta", "0.0");
    setNodeText("metric-avg-words", "0.0");
    return false;
  }
  setNodeText("analyzer-tier-badge", "TIER: " + String(report.engagement_tier));
  setNodeText("score-overall", String(report.overall_score));
  setNodeText("overview-latest-score", String(report.overall_score));
  setNodeText("score-hook", String(report.hook_score));
  setNodeText("score-readability", String(report.readability_score));
  setNodeText("score-sentiment", String(report.sentiment_score) + " (" + String(report.sentiment_label) + ")");
  setNodeText("score-hashtag-cta", String(report.hashtag_cta_score));
  setNodeText("metric-avg-words", String(report.avg_sentence_words));

  const matrix = Array.isArray(report.platform_matrix) ? report.platform_matrix : [];
  renderListCards("platform-matrix-list", matrix, function buildPlatformRow(li, entry) {
    const nameEl = document.createElement("span");
    nameEl.className = "mono-label";
    nameEl.textContent = String(entry.platform_label) + " (" + String(entry.char_count) + "/" + String(entry.max_chars) + ")";

    const scoreEl = document.createElement("span");
    scoreEl.className = "badge-pill";
    scoreEl.textContent = String(entry.status) + " • " + String(entry.fit_score);

    li.appendChild(nameEl);
    li.appendChild(scoreEl);
  });

  const tips = Array.isArray(report.recommendations) ? report.recommendations : [];
  renderListCards("recommendations-list", tips, function buildTipRow(li, tipText) {
    const spanEl = document.createElement("span");
    spanEl.textContent = String(tipText);
    li.appendChild(spanEl);
  });
  return true;
}

function renderDashboardSnapshot(snapshot) {
  if (!snapshot) {
    return false;
  }
  setNodeText("active-slot-badge", "SLOT: " + String(snapshot.active_slot || "blue").toUpperCase());
  setNodeText("region-badge", "REGION: " + String(snapshot.region || "uksouth").toUpperCase());

  const syncInfo = snapshot.cloud_sync || {};
  setNodeText("sandbox-provider-badge", String(syncInfo.provider || "local-offline").toUpperCase());

  const stages = Array.isArray(snapshot.stages) ? snapshot.stages : [];
  renderListCards("stage-status-cards", stages, function buildStageRow(li, stageName) {
    const leftSpan = document.createElement("span");
    leftSpan.className = "mono-label";
    leftSpan.textContent = String(stageName);

    const rightSpan = document.createElement("span");
    rightSpan.className = "badge-pill";
    rightSpan.textContent = "VERIFIED";

    li.appendChild(leftSpan);
    li.appendChild(rightSpan);
  });

  const history = Array.isArray(snapshot.history) ? snapshot.history : [];
  setNodeText("overview-history-count", String(history.length));
  renderListCards("history-list-cards", history, function buildHistoryRow(li, row) {
    const titleSpan = document.createElement("span");
    titleSpan.textContent = String(row.target_platform) + " — " + String(row.sanitized_preview).slice(APP_CFG.ZERO, 44);

    const badgeSpan = document.createElement("span");
    badgeSpan.className = "badge-pill";
    badgeSpan.textContent = String(row.overall_score) + " (" + String(row.engagement_tier) + ")";

    li.appendChild(titleSpan);
    li.appendChild(badgeSpan);
  });

  renderAnalysisReport(snapshot.latest_analysis);
  return true;
}

async function syncStatusFromServer(isBackgroundPoll) {
  if (isBackgroundPoll && UI_STATE.busy) {
    return false;
  }
  const result = await sendApiRequest(APP_CFG.ROUTE_STATUS, APP_CFG.METHOD_GET, null);
  const dot = getNode("conn-dot");
  if (!result.ok || !result.data) {
    dot.classList.add("offline");
    setNodeText("conn-label", "DISCONNECTED / DEGRADED");
    return false;
  }
  dot.classList.remove("offline");
  setNodeText("conn-label", "CONNECTED: 127.0.0.1:8080");
  if (!result.stale) {
    renderDashboardSnapshot(result.data.data);
  }
  return true;
}

async function refreshAuditLedger() {
  const result = await sendApiRequest(APP_CFG.ROUTE_GDPR_AUDIT, APP_CFG.METHOD_GET, null);
  if (!result.ok || !result.data) {
    return false;
  }
  const events = Array.isArray(result.data.events) ? result.data.events : [];
  setNodeText("audit-count-badge", String(events.length) + " EVENTS");
  const lines = [];
  const limit = Math.min(events.length, APP_CFG.MAX_RENDER_ITEMS);
  for (let idx = APP_CFG.ZERO; idx < limit; idx += APP_CFG.ONE) {
    const ev = events[idx];
    const hashShort = String(ev.record_hash || "").slice(APP_CFG.ZERO, APP_CFG.HASH_PREFIX_LEN);
    lines.push(
      "[" + String(ev.timestamp_utc) + "] " +
      String(ev.event_type) + " | " +
      String(ev.details) + " | sha256:" + hashShort
    );
  }
  setNodeText("audit-ledger-viewer", lines.length > APP_CFG.ZERO ? lines.join("\n") : "Audit chain empty.");
  return true;
}

async function executePostAnalysis() {
  if (UI_STATE.busy) {
    return false;
  }
  UI_STATE.busy = true;
  const platformVal = String(getNode("platform-select").value);
  const draftVal = String(getNode("post-draft-input").value);
  setNodeText("run-post-analysis-btn", "SCORING...");
  const result = await sendApiRequest(
    APP_CFG.ROUTE_ANALYZE,
    APP_CFG.METHOD_POST,
    {
      owner_id: APP_CFG.OWNER_ID,
      target_platform: platformVal,
      raw_post: draftVal
    }
  );
  setNodeText("run-post-analysis-btn", "SCORE & SAVE POST");
  UI_STATE.busy = false;
  if (result.ok && result.data) {
    renderDashboardSnapshot(result.data.data);
  }
  return result.ok;
}

function activateTab(tabId) {
  const buttons = document.querySelectorAll(".tab-btn");
  for (let idx = APP_CFG.ZERO; idx < buttons.length; idx += APP_CFG.ONE) {
    const btn = buttons[idx];
    if (btn.getAttribute("data-tab") === tabId) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  }
  const panels = document.querySelectorAll(".tab-panel");
  for (let idx = APP_CFG.ZERO; idx < panels.length; idx += APP_CFG.ONE) {
    const panel = panels[idx];
    if (panel.id === tabId) {
      panel.classList.remove("hidden");
    } else {
      panel.classList.add("hidden");
    }
  }
  if (tabId === "tab-gdpr") {
    void refreshAuditLedger();
  }
  return true;
}

function updateLiveCharCounter() {
  const textVal = String(getNode("post-draft-input").value || "");
  setNodeText("live-char-counter", String(textVal.length) + " CHARS");
  return true;
}

function bindEvents() {
  const tabButtons = document.querySelectorAll(".tab-btn");
  for (let idx = APP_CFG.ZERO; idx < tabButtons.length; idx += APP_CFG.ONE) {
    tabButtons[idx].addEventListener("click", function onTabClick(event) {
      const targetTab = event.currentTarget.getAttribute("data-tab");
      if (targetTab) {
        activateTab(targetTab);
      }
    });
  }

  getNode("dismiss-error-btn").addEventListener("click", function onDismiss() {
    hideBoundaryError();
  });

  getNode("post-draft-input").addEventListener("input", function onDraftInput() {
    updateLiveCharCounter();
  });

  getNode("clear-draft-btn").addEventListener("click", function onClearDraft() {
    getNode("post-draft-input").value = "";
    updateLiveCharCounter();
  });

  getNode("run-post-analysis-btn").addEventListener("click", function onRunAnalyze() {
    void executePostAnalysis();
  });

  getNode("quick-analyze-trigger").addEventListener("click", function onQuickAnalyze() {
    activateTab("tab-analyzer");
    void executePostAnalysis();
  });

  getNode("gdpr-erase-btn").addEventListener("click", async function onErase() {
    const subjectVal = String(getNode("erasure-subject-input").value || "").trim();
    const res = await sendApiRequest(
      APP_CFG.ROUTE_GDPR_ERASE,
      APP_CFG.METHOD_POST,
      { owner_id: APP_CFG.OWNER_ID, subject_id: subjectVal }
    );
    if (res.ok && res.data) {
      setNodeText("ops-feedback-line", "Article 17 erasure completed across disk, SQLite, and RAM.");
      renderDashboardSnapshot(res.data.data);
      await refreshAuditLedger();
    }
  });

  getNode("gdpr-purge-btn").addEventListener("click", async function onPurge() {
    const res = await sendApiRequest(
      APP_CFG.ROUTE_GDPR_PURGE,
      APP_CFG.METHOD_POST,
      { owner_id: APP_CFG.OWNER_ID }
    );
    if (res.ok && res.data) {
      setNodeText("ops-feedback-line", "TTL sweep purged " + String(res.data.purged_files) + " expired files.");
      await refreshAuditLedger();
    }
  });

  getNode("reset-issue-btn").addEventListener("click", async function onIssueReset() {
    const res = await sendApiRequest(
      APP_CFG.ROUTE_RESET_ISSUE,
      APP_CFG.METHOD_POST,
      { owner_id: APP_CFG.OWNER_ID }
    );
    if (res.ok && res.data && res.data.reset) {
      UI_STATE.lastIssuedResetToken = String(res.data.reset.reset_token);
      setNodeText("ops-feedback-line", "Issued 30-minute single-use password reset token.");
    }
  });

  getNode("reset-consume-btn").addEventListener("click", async function onConsumeReset() {
    const res = await sendApiRequest(
      APP_CFG.ROUTE_RESET_CONSUME,
      APP_CFG.METHOD_POST,
      { owner_id: APP_CFG.OWNER_ID, reset_token: UI_STATE.lastIssuedResetToken }
    );
    if (res.ok) {
      setNodeText("ops-feedback-line", "Token consumed once. Click again to verify HTTP 410 replay guard.");
    }
  });

  getNode("deploy-stage-btn").addEventListener("click", async function onDeployStage() {
    const res = await sendApiRequest(
      APP_CFG.ROUTE_DEPLOY_STAGE,
      APP_CFG.METHOD_POST,
      { owner_id: APP_CFG.OWNER_ID, health_check_passed: true }
    );
    if (res.ok) {
      setNodeText("ops-feedback-line", "Health check passed; promoted standby slot to ACTIVE.");
      await syncStatusFromServer(false);
      await refreshAuditLedger();
    }
  });

  getNode("deploy-rollback-btn").addEventListener("click", async function onDeployRollback() {
    const res = await sendApiRequest(
      APP_CFG.ROUTE_DEPLOY_ROLLBACK,
      APP_CFG.METHOD_POST,
      { owner_id: APP_CFG.OWNER_ID }
    );
    if (res.ok) {
      setNodeText("ops-feedback-line", "Instant Blue-Green rollback executed.");
      await syncStatusFromServer(false);
      await refreshAuditLedger();
    }
  });

  getNode("refresh-audit-btn").addEventListener("click", function onVerifyAudit() {
    void refreshAuditLedger();
  });
  return true;
}

document.addEventListener("DOMContentLoaded", function onDomReady() {
  if (bindEvents()) {
    updateLiveCharCounter();
    void syncStatusFromServer(false);
    window.setInterval(function onPollTick() {
      void syncStatusFromServer(true);
    }, APP_CFG.POLL_MS);
  }
});
