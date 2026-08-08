const claimState = { data: null, pollTimer: null, countdownTimer: null };
const $ = (selector) => document.querySelector(selector);

async function publicApi(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  if (!response.ok) {
    let message = response.status === 410 ? "链接或接码窗口已结束" : "链接验证失败";
    try { const payload = await response.json(); if (typeof payload.detail === "string") message = payload.detail; } catch (_) { /* no-op */ }
    const error = new Error(message); error.status = response.status; throw error;
  }
  return response.json();
}

function claimToast(message, isError = false) {
  const toast = $("#claim-toast"); toast.textContent = message; toast.className = `toast visible${isError ? " error" : ""}`;
  window.clearTimeout(claimToast.timer); claimToast.timer = window.setTimeout(() => { toast.className = "toast"; }, 2600);
}

function showError(message, title = "链接不可用") {
  window.clearInterval(claimState.pollTimer); window.clearInterval(claimState.countdownTimer);
  $("#claim-loading").hidden = true; $("#claim-app").hidden = true; $("#claim-error").hidden = false;
  $("#claim-error-title").textContent = title; $("#claim-error-message").textContent = message;
}

function render(data) {
  claimState.data = data;
  $("#claim-loading").hidden = true; $("#claim-error").hidden = true; $("#claim-app").hidden = false;
  $("#claim-notice").textContent = data.lease_minutes % 60 === 0 ? `打开后 ${data.lease_minutes / 60} 小时有效` : `打开后 ${data.lease_minutes} 分钟有效`;
  $("#claim-number").textContent = data.number;
  const codes = data.codes || [];
  const received = codes.length > 0;
  const active = data.status === "active";
  $("#polling-state").textContent = received ? "成功接收" : (active ? "等待短信" : (data.status === "completed" ? "接收完成" : "已结束"));
  $("#polling-state").className = `live-pill${received ? " success" : (active ? " active" : " done")}`;
  $(".status-cell").classList.toggle("success", received);
  renderCodes(codes);
  startCountdown(data.expires_at);
  if (active) startPolling(); else window.clearInterval(claimState.pollTimer);
}

function renderCodes(codes) {
  const list = $("#code-list"); list.replaceChildren();
  if (!codes.length) return;
  codes.forEach((item) => {
    const row = document.createElement("div"); row.className = "code-row";
    const code = document.createElement("strong"); code.className = "code-value"; code.textContent = item.code;
    const button = document.createElement("button"); button.type = "button"; button.className = "mini-copy"; button.textContent = "复制"; button.addEventListener("click", () => copy(item.code, "验证码已复制", code));
    row.append(code, button); list.append(row);
  });
}

function startCountdown(expiresAt) {
  window.clearInterval(claimState.countdownTimer);
  const update = () => {
    const seconds = Math.max(0, Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000));
    const hours = Math.floor(seconds / 3600); const minutes = Math.floor((seconds % 3600) / 60); const remainder = seconds % 60;
    $("#claim-countdown").textContent = `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(remainder).padStart(2, "0")}`;
    if (seconds === 0) { const received = Boolean(claimState.data?.codes?.length); window.clearInterval(claimState.countdownTimer); window.clearInterval(claimState.pollTimer); $("#polling-state").textContent = received ? "成功接收" : "已结束"; $("#polling-state").className = received ? "live-pill success" : "live-pill done"; }
  };
  update(); claimState.countdownTimer = window.setInterval(update, 1000);
}

function startPolling() {
  if (claimState.pollTimer) return;
  claimState.pollTimer = window.setInterval(async () => {
    if (document.hidden) return;
    try { render(await publicApi("/api/public/state")); }
    catch (error) { if (error.status === 410 || error.status === 401) showError(error.message, "接码已结束"); }
  }, 3000);
}

function legacyCopy(value) {
  const textarea = document.createElement("textarea");
  textarea.value = value; textarea.readOnly = true; textarea.setAttribute("aria-hidden", "true");
  Object.assign(textarea.style, { position: "fixed", top: "0", left: "0", width: "1px", height: "1px", padding: "0", border: "0", opacity: "0", fontSize: "16px" });
  document.body.append(textarea);
  try {
    textarea.focus(); textarea.select(); textarea.setSelectionRange(0, value.length);
    return document.execCommand("copy");
  } catch (_) {
    return false;
  } finally {
    textarea.remove();
  }
}

function selectForManualCopy(target) {
  if (!target) return;
  const selection = window.getSelection(); const range = document.createRange();
  range.selectNodeContents(target); selection.removeAllRanges(); selection.addRange(range);
}

function isAppleTouchDevice() {
  return /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
}

async function copy(value, success, fallbackTarget) {
  const hasClipboardApi = Boolean(navigator.clipboard?.writeText);
  const useLegacyFirst = isAppleTouchDevice() || !window.isSecureContext || !hasClipboardApi;
  if (useLegacyFirst && legacyCopy(value)) { claimToast(success); return; }
  if (hasClipboardApi) {
    try { await navigator.clipboard.writeText(value); claimToast(success); return; }
    catch (_) { /* fall through to the compatibility path */ }
  }
  if (!useLegacyFirst && legacyCopy(value)) { claimToast(success); return; }
  selectForManualCopy(fallbackTarget); claimToast("请长按已选中的内容复制", true);
}

$("#copy-service-qq").addEventListener("click", (event) => {
  const button = event.currentTarget;
  copy(button.dataset.qq, "客服 QQ 已复制", $("#service-qq-value"));
});

$("#copy-number").addEventListener("click", () => copy($("#claim-number").textContent, "号码已复制", $("#claim-number")));

(async function start() {
  const token = new URLSearchParams(window.location.hash.slice(1)).get("t");
  try {
    let data;
    if (token) {
      data = await publicApi("/api/public/session", { method: "POST", headers: { Authorization: `Bearer ${token}` } });
    } else {
      data = await publicApi("/api/public/state");
    }
    if (!data.assigned) data = await publicApi("/api/public/claim", { method: "POST" });
    render(data);
  } catch (error) {
    const title = error.status === 409 ? "暂无可用号码" : "链接不可用";
    showError(error.message, title);
  }
})();
