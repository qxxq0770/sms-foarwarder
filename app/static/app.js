const state = {
  messages: { items: [], total: 0, offset: 0, limit: 20, query: "" },
  keys: { items: [], total: 0, offset: 0, limit: 20, status: "" },
  numbers: [], numberPage: { offset: 0, limit: 20 }, numberEditor: null, settings: null, selectedMessageId: null,
};

const $ = (selector) => document.querySelector(selector);
const views = new Set(["dashboard", "numbers", "keys", "settings"]);
const elements = {
  loginView: $("#login-view"), appView: $("#app-view"), loginForm: $("#login-form"),
  loginError: $("#login-error"), dialog: $("#message-dialog"), accountMenu: $("#account-menu"),
  accountButton: $("#account-button"), logoutButton: $("#logout-button"),
};

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { "Content-Type": "application/json", ...(options.headers || {}) } });
  if (response.status === 401 && path !== "/api/session") { showLogin(); throw new Error("登录已过期"); }
  if (!response.ok) {
    let message = "请求失败";
    try { const payload = await response.json(); if (typeof payload.detail === "string") message = payload.detail; } catch (_) { /* no-op */ }
    throw new Error(message);
  }
  return response.status === 204 ? null : response.json();
}

function setAccountMenu(open) { elements.logoutButton.hidden = !open; elements.accountButton.setAttribute("aria-expanded", String(open)); }
function setAccountIdentity(username) { const displayName = username ? `${username.charAt(0).toUpperCase()}${username.slice(1)}` : "Admin"; $("#account-name").textContent = displayName; }
function clearWebhookToken() { $("#webhook-token-value").textContent = ""; $("#webhook-token-result").hidden = true; }
function showLogin() { setAccountMenu(false); clearWebhookToken(); elements.appView.hidden = true; elements.loginView.hidden = false; }
function currentView() { const view = window.location.hash.slice(1); return views.has(view) ? view : "dashboard"; }
function showApp(username) { setAccountIdentity(username); elements.loginView.hidden = true; elements.appView.hidden = false; switchView(currentView()); }
function toast(message, isError = false) { const item = $("#toast"); item.textContent = message; item.className = `toast visible${isError ? " error" : ""}`; clearTimeout(toast.timer); toast.timer = setTimeout(() => { item.className = "toast"; }, 2600); }
function node(tag, className, text) { const item = document.createElement(tag); if (className) item.className = className; if (text !== undefined) item.textContent = text; return item; }
function mobileLabel(item, label) { item.dataset.label = label; return item; }
function formatTime(value) { if (!value) return "—"; return new Intl.DateTimeFormat("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(new Date(value)); }
function formatValidity(minutes) { return minutes % 60 === 0 ? `${minutes / 60} 小时` : `${minutes} 分钟`; }
function statusBadge(value) { const labels = { active: "使用中", ready: "待使用", used: "已使用", completed: "已完成", expired: "已结束", revoked: "已撤销", enabled: "已启用", disabled: "已停用" }; return node("span", `status-badge ${value || "muted"}`, labels[value] || "未知"); }
function actionButton(label, handler, danger = false) { const button = node("button", `table-action${danger ? " danger-text" : ""}`, label); button.type = "button"; button.addEventListener("click", handler); return button; }
async function copyText(value, success) { try { await navigator.clipboard.writeText(value); toast(success); } catch (_) { toast("浏览器不允许访问剪贴板", true); } }
function setPagination(prefix, collection) { const pages = Math.max(1, Math.ceil(collection.total / collection.limit)); const current = Math.floor(collection.offset / collection.limit) + 1; $(`#${prefix}-pagination`).hidden = collection.total <= collection.limit; $(`#${prefix}-page`).textContent = `${current} / ${pages}`; $(`#${prefix}-previous`).disabled = collection.offset === 0; $(`#${prefix}-next`).disabled = collection.offset + collection.limit >= collection.total; }

function switchView(view) { if (!views.has(view)) return; document.querySelectorAll(".view-section").forEach((section) => { section.hidden = true; }); $(`#${view}-section`).hidden = false; document.querySelectorAll(".nav-item").forEach((link) => { const active = link.dataset.view === view; link.classList.toggle("active", active); if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current"); }); window.scrollTo({ top: 0, behavior: "smooth" }); if (view === "dashboard") refreshDashboard(); }

async function loadStats() { const data = await api("/api/stats"); $("#available-count").textContent = data.available_numbers; $("#available-uses-count").textContent = data.available_uses; $("#active-count").textContent = data.active_assignments; $("#ready-count").textContent = data.ready_keys; $("#today-count").textContent = data.messages_today; }

function renderMessages() {
  const list = $("#message-list"); list.replaceChildren(); $("#message-empty").hidden = state.messages.items.length !== 0; list.hidden = state.messages.items.length === 0; $("#message-count").textContent = state.messages.total ? `共 ${state.messages.total} 条` : "";
  state.messages.items.forEach((item) => {
    const row = node("button", "message-row record-grid"); row.type = "button";
    const key = mobileLabel(node("code", "record-key mono", item.key || "—"), "Key");
    const phone = mobileLabel(node("span", "record-phone mono", item.recipient || "—"), "手机号");
    const message = mobileLabel(node("span", "record-message", item.message_preview), "短信");
    const time = mobileLabel(node("time", "record-time", formatTime(item.received_at)), "时间"); time.dateTime = item.received_at;
    row.append(key, phone, message, time); row.addEventListener("click", () => openMessage(item.id)); list.append(row);
  });
  setPagination("message", state.messages);
}
async function loadMessages() { const params = new URLSearchParams({ limit: state.messages.limit, offset: state.messages.offset, q: state.messages.query }); const data = await api(`/api/messages?${params}`); Object.assign(state.messages, { items: data.items, total: data.total }); renderMessages(); }
async function openMessage(id) { try { const item = await api(`/api/messages/${id}`); state.selectedMessageId = id; $("#dialog-rule").textContent = item.is_test ? "测试" : item.rule_id; $("#dialog-sender").textContent = item.sender; $("#dialog-recipient").textContent = item.recipient ? `接收号码 ${item.recipient}` : "未提供接收号码"; $("#dialog-message").textContent = item.message; $("#dialog-time").textContent = formatTime(item.received_at); $("#dialog-delivery").textContent = item.delivery_id; $("#dialog-routed").textContent = item.routed ? "公开接码任务" : "仅管理端"; elements.dialog.showModal(); } catch (error) { toast(error.message, true); } }

function inputField(type, value, placeholder, label) { const input = document.createElement("input"); input.type = type; input.value = value ?? ""; input.placeholder = placeholder; input.setAttribute("aria-label", label); return input; }
function editorField(input, label) { const field = node("label", "mobile-editor-field"); field.append(node("span", "mobile-cell-label", label), input); return field; }
function renderNumberEditor(list) { const editor = state.numberEditor; if (!editor) return; const row = node("div", "table-row number-grid number-editor"); const numberInput = inputField("tel", editor.number, "+8613800000000", "完整号码"); numberInput.dataset.field = "number"; const limitInput = inputField("number", editor.max_assignments, "1", "最大分配次数"); limitInput.min = "1"; limitInput.className = "inline-limit"; limitInput.dataset.field = "max_assignments"; const actions = mobileLabel(node("div", "table-actions"), "操作"); actions.append(actionButton("保存", saveNumberEditor), actionButton("取消", cancelNumberEditor)); row.append(editorField(numberInput, "号码"), editorField(limitInput, "分配上限"), mobileLabel(statusBadge(editor.id ? (editor.enabled ? "enabled" : "disabled") : "ready"), "状态"), actions); row.addEventListener("keydown", (event) => { if (event.key === "Enter") { event.preventDefault(); saveNumberEditor(); } if (event.key === "Escape") cancelNumberEditor(); }); list.append(row); setTimeout(() => numberInput.focus(), 0); }
function renderNumbers() { const list = $("#number-list"); list.replaceChildren(); renderNumberEditor(list); if (!state.numbers.length && !state.numberEditor) list.append(node("div", "table-empty", "号池为空，点击右上角新增号码。")); const visibleNumbers = state.numbers.slice(state.numberPage.offset, state.numberPage.offset + state.numberPage.limit); visibleNumbers.forEach((item) => { if (state.numberEditor?.id === item.id) return; const row = node("div", "table-row number-grid"); row.append(mobileLabel(node("strong", "mono", item.number), "号码"), mobileLabel(node("strong", "", `${item.assignment_count} / ${item.max_assignments}`), "使用次数"), mobileLabel(statusBadge(item.enabled ? "enabled" : "disabled"), "状态")); const actions = mobileLabel(node("div", "table-actions"), "操作"); actions.append(actionButton("编辑", () => beginNumberEdit(item)), actionButton("重置次数", () => resetNumberUsage(item)), actionButton(item.enabled ? "停用" : "启用", () => toggleNumber(item), item.enabled)); row.append(actions); list.append(row); }); setPagination("number", { ...state.numberPage, total: state.numbers.length }); $("#add-number-row").disabled = Boolean(state.numberEditor); }
async function loadNumbers() { state.numbers = await api("/api/numbers"); const lastOffset = Math.max(0, Math.floor((state.numbers.length - 1) / state.numberPage.limit) * state.numberPage.limit); state.numberPage.offset = Math.min(state.numberPage.offset, lastOffset); renderNumbers(); }
function beginNumberCreate() { state.numberEditor = { id: null, number: "", country_code: "CN", country_name: "中国大陆", max_assignments: 1, enabled: true }; renderNumbers(); }
function beginNumberEdit(item) { state.numberEditor = { ...item }; renderNumbers(); }
function cancelNumberEditor() { state.numberEditor = null; renderNumbers(); }
async function saveNumberEditor() { const row = $("#number-list .number-editor"); if (!row || !state.numberEditor) return; const value = (field) => row.querySelector(`[data-field="${field}"]`).value.trim(); const payload = { number: value("number"), country_code: state.numberEditor.country_code || "CN", country_name: state.numberEditor.country_name || "中国大陆", max_assignments: Number(value("max_assignments")) }; if (!payload.number || payload.max_assignments < 1) { toast("请填写号码和分配上限", true); return; } const id = state.numberEditor.id; try { await api(id ? `/api/numbers/${id}` : "/api/numbers", { method: id ? "PATCH" : "POST", body: JSON.stringify(payload) }); state.numberEditor = null; toast(id ? "号码已更新" : "号码已添加"); await Promise.all([loadNumbers(), loadStats()]); } catch (error) { toast(error.message, true); } }
async function toggleNumber(item) { try { await api(`/api/numbers/${item.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !item.enabled }) }); toast(item.enabled ? "号码已停用" : "号码已启用"); await Promise.all([loadNumbers(), loadStats()]); } catch (error) { toast(error.message, true); } }
async function resetNumberUsage(item) { if (!window.confirm("重置后，该号码当前接码任务会立即结束，使用次数清零。确定继续吗？")) return; try { const result = await api(`/api/numbers/${item.id}/reset-usage`, { method: "POST" }); toast(result.reset_assignments ? "使用次数已重置" : "使用次数已经是 0"); await Promise.all([loadNumbers(), loadStats()]); } catch (error) { toast(error.message, true); } }

function renderKeys() { const list = $("#key-list"); list.replaceChildren(); if (!state.keys.items.length) list.append(node("div", "table-empty", state.keys.status ? "当前状态下暂无密钥。" : "暂无密钥。")); state.keys.items.forEach((item) => { const row = node("div", "table-row key-grid"); const linkCell = mobileLabel(node("div", "key-link-cell"), "领取链接"); linkCell.append(node("code", "key-token", item.share_url || "旧密钥不可恢复")); if (item.share_url) { const copyButton = node("button", "button secondary compact", "复制"); copyButton.type = "button"; copyButton.addEventListener("click", () => copyText(item.share_url, "领取链接已复制")); linkCell.append(copyButton); } row.append(linkCell, mobileLabel(node("span", "", formatValidity(item.lease_minutes)), "有效期"), mobileLabel(statusBadge(item.display_status), "状态")); list.append(row); }); $("#key-result-count").textContent = `共 ${state.keys.total} 个`; setPagination("key", state.keys); }
async function loadKeys() { const params = new URLSearchParams({ limit: state.keys.limit, offset: state.keys.offset, status: state.keys.status }); const data = await api(`/api/share-links?${params}`); Object.assign(state.keys, { items: data.items, total: data.total }); renderKeys(); }
async function copyFilteredKeys() { const button = $("#copy-filtered-keys"); button.disabled = true; try { const params = new URLSearchParams({ status: state.keys.status }); const data = await api(`/api/share-links/copy?${params}`); if (!data.count) { toast("当前筛选下暂无可复制链接"); return; } await copyText(data.text, `已复制 ${data.count} 个链接`); } catch (error) { toast(error.message, true); } finally { button.disabled = false; } }
async function loadSettings() { state.settings = await api("/api/settings"); $("#default-validity-hours").value = state.settings.default_validity_hours; $("#webhook-url").textContent = state.settings.webhook_url; setDefaultKeyValues(); }
function setDefaultKeyValues() { if (!state.settings) return; $("#key-validity").value = state.settings.default_validity_hours; $("#key-count").value = "1"; }
async function refreshAll() { const results = await Promise.allSettled([loadStats(), loadMessages(), loadNumbers(), loadKeys(), loadSettings()]); const failed = results.find((result) => result.status === "rejected"); if (failed) toast(failed.reason.message, true); }
let dashboardRefreshPending = false;
async function refreshDashboard() { if (dashboardRefreshPending || document.hidden || elements.appView.hidden || $("#dashboard-section").hidden) return; dashboardRefreshPending = true; try { await Promise.all([loadStats(), loadMessages()]); } catch (_) { /* api() handles expired sessions */ } finally { dashboardRefreshPending = false; } }
window.setInterval(refreshDashboard, 5000);

elements.loginForm.addEventListener("submit", async (event) => { event.preventDefault(); elements.loginError.hidden = true; const button = event.currentTarget.querySelector("button"); button.disabled = true; try { const session = await api("/api/session", { method: "POST", body: JSON.stringify({ username: $("#username").value, password: $("#password").value }) }); $("#password").value = ""; showApp(session.username); await refreshAll(); } catch (error) { elements.loginError.textContent = error.message; elements.loginError.hidden = false; } finally { button.disabled = false; } });
elements.accountButton.addEventListener("click", () => setAccountMenu(elements.logoutButton.hidden));
elements.logoutButton.addEventListener("click", async () => { setAccountMenu(false); await api("/api/session", { method: "DELETE" }).catch(() => null); showLogin(); });
document.addEventListener("click", (event) => { if (!elements.accountMenu.contains(event.target)) setAccountMenu(false); });
document.addEventListener("keydown", (event) => { if (event.key === "Escape") { setAccountMenu(false); elements.accountButton.focus(); } });
window.addEventListener("hashchange", () => { if (!elements.appView.hidden) switchView(currentView()); });
document.querySelectorAll("[data-toggle-panel]").forEach((button) => button.addEventListener("click", () => { const panel = $(`#${button.dataset.togglePanel}`); panel.hidden = !panel.hidden; }));
document.querySelectorAll("[data-close-panel]").forEach((button) => button.addEventListener("click", () => { $(`#${button.dataset.closePanel}`).hidden = true; }));
let searchTimer; $("#search-input").addEventListener("input", (event) => { clearTimeout(searchTimer); searchTimer = setTimeout(() => { state.messages.query = event.target.value.trim(); state.messages.offset = 0; loadMessages().catch((error) => toast(error.message, true)); }, 250); });
$("#message-previous").addEventListener("click", () => { state.messages.offset = Math.max(0, state.messages.offset - state.messages.limit); loadMessages(); }); $("#message-next").addEventListener("click", () => { state.messages.offset += state.messages.limit; loadMessages(); });
$("#key-previous").addEventListener("click", () => { state.keys.offset = Math.max(0, state.keys.offset - state.keys.limit); loadKeys(); }); $("#key-next").addEventListener("click", () => { state.keys.offset += state.keys.limit; loadKeys(); });
$("#number-previous").addEventListener("click", () => { state.numberPage.offset = Math.max(0, state.numberPage.offset - state.numberPage.limit); renderNumbers(); }); $("#number-next").addEventListener("click", () => { state.numberPage.offset += state.numberPage.limit; renderNumbers(); });
$("#key-status").addEventListener("change", (event) => { state.keys.status = event.target.value; state.keys.offset = 0; loadKeys().catch((error) => toast(error.message, true)); });
$("#copy-filtered-keys").addEventListener("click", copyFilteredKeys);
$("#add-number-row").addEventListener("click", beginNumberCreate);
$("#key-form").addEventListener("submit", async (event) => { event.preventDefault(); const payload = { count: Number($("#key-count").value), validity_hours: Number($("#key-validity").value) }; try { const data = await api("/api/share-links/batch", { method: "POST", body: JSON.stringify(payload) }); $("#key-form-panel").hidden = true; setDefaultKeyValues(); toast(`已生成 ${data.items.length} 个密钥`); await Promise.all([loadKeys(), loadStats()]); } catch (error) { toast(error.message, true); } });
$("#defaults-form").addEventListener("submit", async (event) => { event.preventDefault(); const payload = { default_validity_hours: Number($("#default-validity-hours").value) }; try { state.settings = await api("/api/settings", { method: "PATCH", body: JSON.stringify(payload) }); setDefaultKeyValues(); toast("接码设置已保存"); } catch (error) { toast(error.message, true); } });
$("#password-form").addEventListener("submit", async (event) => { event.preventDefault(); const payload = { current_password: $("#current-password").value, new_password: $("#new-password").value, confirm_password: $("#confirm-password").value }; try { await api("/api/settings/password", { method: "POST", body: JSON.stringify(payload) }); event.currentTarget.reset(); toast("密码已更新"); } catch (error) { toast(error.message, true); } });
$("#copy-webhook").addEventListener("click", () => copyText($("#webhook-url").textContent, "Webhook 地址已复制"));
$("#generate-webhook-token").addEventListener("click", async (event) => { if (!window.confirm("生成新 Token 后旧 Token 会立即失效，确定继续吗？")) return; const button = event.currentTarget; button.disabled = true; try { const data = await api("/api/settings/webhook-token", { method: "POST" }); $("#webhook-token-value").textContent = data.token; $("#webhook-token-result").hidden = false; toast("新 Token 已生成，请立即复制"); } catch (error) { toast(error.message, true); } finally { button.disabled = false; } });
$("#copy-webhook-token").addEventListener("click", () => copyText($("#webhook-token-value").textContent, "Webhook Token 已复制"));
$("#close-dialog").addEventListener("click", () => elements.dialog.close()); $("#done-dialog").addEventListener("click", () => elements.dialog.close()); elements.dialog.addEventListener("click", (event) => { if (event.target === elements.dialog) elements.dialog.close(); });
$("#delete-message").addEventListener("click", async () => { if (!state.selectedMessageId || !window.confirm("确定删除这条短信吗？")) return; try { await api(`/api/messages/${state.selectedMessageId}`, { method: "DELETE" }); elements.dialog.close(); toast("短信已删除"); await Promise.all([loadMessages(), loadStats()]); } catch (error) { toast(error.message, true); } });

(async function start() { try { const session = await api("/api/session"); showApp(session.username); await refreshAll(); } catch (_) { showLogin(); } })();
