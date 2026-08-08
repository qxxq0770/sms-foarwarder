import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import MAX_REQUEST_BODY_BYTES, SESSION_COOKIE, SlidingWindowLimiter, create_app


def webhook_headers(settings: Settings) -> dict[str, str]:
    return {"Authorization": f"Bearer {settings.webhook_token}"}


def test_password_change_hashes_password_and_invalidates_other_session(client: TestClient, settings: Settings) -> None:
    updated_password = "Updated-password-123"
    first = client.post("/api/session", json={"username": "admin", "password": settings.admin_password})
    old_cookie = first.cookies[SESSION_COOKIE]
    changed = client.post("/api/settings/password", json={"current_password": settings.admin_password, "new_password": updated_password, "confirm_password": updated_password})
    assert changed.status_code == 200
    current_cookie = changed.cookies[SESSION_COOKIE]
    with TestClient(client.app, base_url=settings.public_base_url) as other:
        other.cookies.set(SESSION_COOKIE, old_cookie)
        assert other.get("/api/session").status_code == 401
        assert other.post("/api/session", json={"username": "admin", "password": settings.admin_password}).status_code == 401
        assert other.post("/api/session", json={"username": "admin", "password": updated_password}).status_code == 200
    client.cookies.set(SESSION_COOKIE, current_cookie)
    assert client.get("/api/session").status_code == 200
    with sqlite3.connect(settings.database_path) as connection:
        row = connection.execute("SELECT password_salt, password_hash FROM admin_credentials").fetchone()
    assert updated_password not in row


def test_local_password_recovery_invalidates_sessions(client: TestClient, settings: Settings) -> None:
    recovered_password = "Recovered-password-123"
    logged_in = client.post(
        "/api/session",
        json={"username": "admin", "password": settings.admin_password},
    )
    old_cookie = logged_in.cookies[SESSION_COOKIE]
    client.app.state.store.reset_admin_password(recovered_password)

    with TestClient(client.app, base_url=settings.public_base_url) as other:
        other.cookies.set(SESSION_COOKIE, old_cookie)
        assert other.get("/api/session").status_code == 401
        assert other.post(
            "/api/session",
            json={"username": "admin", "password": recovered_password},
        ).status_code == 200


def test_webhook_requires_valid_token(client: TestClient, sms_payload: dict[str, object]) -> None:
    response = client.post("/api/webhooks/sms", json=sms_payload)
    assert response.status_code == 401
    assert "message" not in response.text


def test_webhook_body_only_requires_message_and_recipient(
    authenticated_client: TestClient, settings: Settings
) -> None:
    response = authenticated_client.post(
        "/api/webhooks/sms",
        headers=webhook_headers(settings),
        json={"message": "验证码 123456", "recipient": "+8613900000000"},
    )
    assert response.status_code == 200
    detail = authenticated_client.get(
        f"/api/messages/{response.json()['id']}"
    ).json()
    assert detail["message"] == "验证码 123456"
    assert detail["recipient"] == "+8613900000000"
    assert detail["sender"] == "Webhook"
    assert detail["delivery_id"].startswith("auto-")
    assert datetime.fromisoformat(detail["received_at"]).tzinfo is not None

    missing_recipient = authenticated_client.post(
        "/api/webhooks/sms",
        headers=webhook_headers(settings),
        json={"message": "验证码 123456"},
    )
    missing_message = authenticated_client.post(
        "/api/webhooks/sms",
        headers=webhook_headers(settings),
        json={"recipient": "+8613900000000"},
    )
    assert missing_recipient.status_code == 422
    assert missing_message.status_code == 422


def test_admin_can_rotate_webhook_token(
    authenticated_client: TestClient,
    settings: Settings,
    sms_payload: dict[str, object],
) -> None:
    rotated = authenticated_client.post("/api/settings/webhook-token")
    assert rotated.status_code == 200
    token = rotated.json()["token"]
    assert len(token) >= 40

    old_token = authenticated_client.post(
        "/api/webhooks/sms", json=sms_payload, headers=webhook_headers(settings)
    )
    assert old_token.status_code == 401
    accepted = authenticated_client.post(
        "/api/webhooks/sms",
        json=sms_payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert accepted.status_code == 200

    with sqlite3.connect(settings.database_path) as connection:
        stored = connection.execute(
            "SELECT webhook_token_digest FROM app_settings WHERE id = 1"
        ).fetchone()[0]
    assert token not in stored
    assert len(stored) == 64


def test_message_list_is_summarized_and_detail_is_authorized(authenticated_client: TestClient, settings: Settings, sms_payload: dict[str, object]) -> None:
    authenticated_client.post("/api/webhooks/sms", json=sms_payload, headers=webhook_headers(settings))
    response = authenticated_client.get("/api/messages?q=测试交易")
    item = response.json()["items"][0]
    assert item["sender_masked"] == "****8000"
    assert item["share_link_id"] is None
    assert item["key"] is None
    assert item["recipient"] == sms_payload["recipient"]
    assert "message" not in item and item["message_preview"] == sms_payload["message"]
    detail = authenticated_client.get(f"/api/messages/{item['id']}").json()
    assert detail["sender"] == sms_payload["sender"]
    assert detail["message"] == sms_payload["message"]
    unauthenticated = TestClient(
        authenticated_client.app, base_url=settings.public_base_url
    )
    assert unauthenticated.get(f"/api/messages/{item['id']}").status_code == 401


def test_ingest_is_idempotent_and_encrypted(client: TestClient, settings: Settings, sms_payload: dict[str, object]) -> None:
    first = client.post("/api/webhooks/sms", json=sms_payload, headers=webhook_headers(settings))
    second = client.post("/api/webhooks/sms", json=sms_payload, headers=webhook_headers(settings))
    assert first.json()["duplicate"] is False and second.json()["duplicate"] is True
    with sqlite3.connect(settings.database_path) as connection:
        row = connection.execute("SELECT sender_encrypted, message_encrypted FROM messages").fetchone()
    assert sms_payload["sender"] not in row[0] and sms_payload["message"] not in row[1]


def test_settings_validation_and_messages_are_retained(authenticated_client: TestClient, settings: Settings, sms_payload: dict[str, object]) -> None:
    visible_settings = authenticated_client.get("/api/settings").json()
    assert "sender_pattern" not in visible_settings
    assert "code_pattern" not in visible_settings
    assert "retention_days" not in visible_settings
    assert authenticated_client.patch("/api/settings", json={"retention_days": 1}).status_code == 422
    updated = authenticated_client.patch("/api/settings", json={"default_validity_hours": 24})
    assert updated.json()["default_validity_hours"] == 24
    assert "default_lease_minutes" not in updated.json()
    assert "default_link_hours" not in updated.json()
    sms_payload["received_at"] = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    authenticated_client.post("/api/webhooks/sms", json=sms_payload, headers=webhook_headers(settings))
    assert authenticated_client.get("/api/messages").json()["total"] == 1
    assert authenticated_client.delete("/api/messages").status_code == 405


def test_admin_api_rejects_missing_session(client: TestClient) -> None:
    for path in ("/api/messages", "/api/stats", "/api/settings", "/api/numbers", "/api/share-links", "/api/share-links/copy"):
        assert client.get(path).status_code == 401
    assert client.post("/api/settings/webhook-token").status_code == 401
    assert client.post("/api/numbers/1/reset-usage").status_code == 401


def test_payload_requires_timezone(client: TestClient, settings: Settings, sms_payload: dict[str, object]) -> None:
    sms_payload["received_at"] = "2026-08-07T08:30:00"
    assert client.post("/api/webhooks/sms", json=sms_payload, headers=webhook_headers(settings)).status_code == 422


def test_health_and_security_headers(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.json() == {"status": "ok"}
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "base-uri 'none'" in response.headers["content-security-policy"]
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    assert response.headers["x-permitted-cross-domain-policies"] == "none"


def test_untrusted_host_and_oversized_request_are_rejected(client: TestClient) -> None:
    assert client.get("/healthz", headers={"Host": "attacker.example"}).status_code == 400
    assert client.get("/healthz", headers={"Host": "127.0.0.1"}).status_code == 200
    oversized = client.post(
        "/api/webhooks/sms",
        content=b"x" * (MAX_REQUEST_BODY_BYTES + 1),
        headers={"Content-Type": "application/json"},
    )
    assert oversized.status_code == 413
    assert oversized.json() == {"detail": "请求体过大"}
    assert oversized.headers["x-content-type-options"] == "nosniff"
    chunked = client.post(
        "/api/webhooks/sms",
        content=b"{}",
        headers={
            "Content-Type": "application/json",
            "Transfer-Encoding": "chunked",
        },
    )
    assert chunked.status_code == 411
    assert chunked.json() == {"detail": "不支持分块请求"}


def test_authorization_header_parser_is_strict(
    client: TestClient, settings: Settings, sms_payload: dict[str, object]
) -> None:
    malformed = client.post(
        "/api/webhooks/sms",
        json=sms_payload,
        headers={"Authorization": f"Bearer  {settings.webhook_token}"},
    )
    assert malformed.status_code == 401
    accepted = client.post(
        "/api/webhooks/sms",
        json=sms_payload | {"delivery_id": "lowercase-bearer"},
        headers={"Authorization": f"bearer {settings.webhook_token}"},
    )
    assert accepted.status_code == 200


def test_logout_rejects_cross_origin_request(
    authenticated_client: TestClient,
) -> None:
    blocked = authenticated_client.delete(
        "/api/session", headers={"Origin": "https://attacker.example"}
    )
    assert blocked.status_code == 403
    assert authenticated_client.get("/api/session").status_code == 200


def test_security_configuration_rejects_unsafe_values(settings: Settings) -> None:
    values = settings.model_dump()
    with pytest.raises(ValueError):
        Settings(**(values | {"public_base_url": "http://localhost.attacker.example"}))
    with pytest.raises(ValueError):
        Settings(
            **(
                values
                | {
                    "public_base_url": "https://sms.example.com",
                    "cookie_secure": False,
                }
            )
        )
    with pytest.raises(ValueError):
        Settings(**(values | {"session_secret": "replace-with-a-long-random-session-secret"}))


def test_https_configuration_enables_hsts(settings: Settings) -> None:
    secure_settings = Settings(
        **(
            settings.model_dump()
            | {
                "public_base_url": "https://sms.example.com",
                "cookie_secure": True,
                "database_path": settings.database_path.with_name("secure.db"),
            }
        )
    )
    with TestClient(
        create_app(secure_settings), base_url=secure_settings.public_base_url
    ) as secure_client:
        response = secure_client.get("/healthz")
    assert response.headers["strict-transport-security"] == "max-age=31536000"


def test_rate_limiter_bounds_tracked_clients() -> None:
    limiter = SlidingWindowLimiter(maximum=1, window_seconds=300, max_keys=2)
    assert limiter.allow("first") is True
    assert limiter.allow("second") is True
    assert limiter.allow("third") is False
    assert len(limiter._attempts) == 2


def test_database_files_are_owner_only(client: TestClient, settings: Settings) -> None:
    client.get("/healthz")
    assert settings.database_path.stat().st_mode & 0o777 == 0o600


def test_admin_page_has_exactly_four_chinese_navigation_modules(client: TestClient) -> None:
    page = client.get("/")
    assert page.headers["cache-control"] == "no-store"
    icon = client.get("/static/app-icon.png")
    assert icon.status_code == 200
    assert icon.headers["content-type"] == "image/png"
    assert '/static/app-icon.png?v=1' in page.text
    assert '/static/styles.css?v=44' in page.text
    assert 'class="login-brand"' in page.text
    assert "SMS Forwarder" in page.text
    assert "自托管短信工作台" not in page.text
    assert "欢迎回来" not in page.text
    assert "登录后管理号码、密钥与短信流转。" not in page.text
    assert page.text.count('class="brand-mark') == 2
    assert 'id="refresh-button"' not in page.text
    assert '/static/app.js?v=35' in page.text
    assert 'class="record-table-head record-grid"' in page.text
    for label in ("Key", "手机号", "短信", "时间"):
        assert f"<span>{label}</span>" in page.text
    assert '<span>可用次数</span><strong id="available-uses-count">—</strong>' in page.text
    assert 'class="record-heading"><h2>使用记录</h2>' in page.text
    assert 'data-dashboard-tab' not in page.text
    assert 'id="usage-tab"' not in page.text
    assert 'placeholder="搜索使用记录"' in page.text
    assert 'id="generated-keys"' not in page.text
    assert 'id="copy-all-keys"' not in page.text
    assert 'id="generate-webhook-token"' in page.text
    assert 'id="webhook-token-result" class="token-result" hidden' in page.text
    script = client.get("/static/app.js")
    styles = client.get("/static/styles.css")
    assert 'data.available_uses' in script.text
    assert 'node("code", "record-key mono", item.key || "—")' in script.text
    assert 'actionButton("重置次数", () => resetNumberUsage(item))' in script.text
    assert '/reset-usage`' in script.text
    assert 'id="key-status"' in page.text
    assert 'id="copy-filtered-keys"' in page.text
    assert '>一键复制</button>' in page.text
    assert 'id="key-result-count"' in page.text
    assert '/api/share-links/copy?' in script.text
    assert 'status: state.keys.status' in script.text
    assert 'copyText(data.text, `已复制 ${data.count} 个链接`)' in script.text
    assert 'export.csv' not in script.text
    for prefix in ("message", "number", "key"):
        assert f'id="{prefix}-pagination"' in page.text
        assert f'id="{prefix}-previous"' in page.text
        assert f'id="{prefix}-page"' in page.text
        assert f'id="{prefix}-next"' in page.text
    assert 'messages: { items: [], total: 0, offset: 0, limit: 20' in script.text
    assert 'keys: { items: [], total: 0, offset: 0, limit: 20' in script.text
    assert 'numberPage: { offset: 0, limit: 20 }' in script.text
    assert 'state.numbers.slice(state.numberPage.offset, state.numberPage.offset + state.numberPage.limit)' in script.text
    assert ".status-badge.used, .status-badge.revoked { background: var(--danger-soft); color: var(--danger); }" in styles.text
    assert ".key-toolbar { margin-top: 5px;" in styles.text
    assert ".key-token { min-width: 0; flex: 0 1 auto; max-width: 100%;" in styles.text
    assert ".key-link-cell { min-width: 0; display: flex; flex-wrap: wrap; align-items: center; justify-content: flex-start; gap: 8px; }" in styles.text
    assert "minmax(110px, 0.72fr) minmax(90px, 0.55fr); column-gap: 30px;" in styles.text
    assert ".key-grid > :nth-child(2), .key-grid > :nth-child(3) { justify-self: center; text-align: center; }" in styles.text
    assert ".key-grid > :nth-child(2), .key-grid > :nth-child(3) { justify-self: start; text-align: left; }" in styles.text
    assert 'api(`/api/usage?' not in script.text
    assert client.get("/api/usage").status_code == 404
    assert client.get("/api/unknown-route").status_code == 404
    assert 'window.location.hash.slice(1)' in script.text
    assert 'window.addEventListener("hashchange"' in script.text
    assert 'id="account-button" class="account-trigger"' in page.text
    assert 'id="account-avatar"' not in page.text
    assert 'id="logout-button" class="logout-card" type="button" hidden' in page.text
    assert '<aside class="sidebar">' in page.text
    assert 'class="topbar"' not in page.text
    assert page.text.count('class="nav-item') == 4
    for anchor, label in (("dashboard", "看板"), ("numbers", "号池"), ("keys", "密钥"), ("settings", "设置")):
        assert f'href="#{anchor}"' in page.text
        assert f">{label}</a>" in page.text
    for english_label in ("Dashboard", "NumberPool", "KeyFactory", "Settings"):
        assert f">{english_label}</a>" not in page.text
    assert "发件人正则" not in page.text and "验证码正则" not in page.text
    for category in ("接码设置", "Webhook 接入", "账户安全"):
        assert category in page.text
    assert "短信数据" not in page.text
    assert 'id="retention-form"' not in page.text
    assert 'id="retention-days"' not in page.text
    assert 'id="clear-messages"' not in page.text
    assert 'id="add-number-row"' in page.text
    assert 'id="number-form-panel"' not in page.text
    assert "地区代码" not in page.text
    assert "<span>地区</span>" not in page.text
    assert "剩余次数" not in page.text
    assert "<span>使用次数</span>" in page.text
    assert "领取截止时间" not in page.text
    assert 'id="key-expiry"' not in page.text
    assert 'id="default-link-hours"' not in page.text
    assert 'id="key-validity"' in page.text
    assert 'id="default-validity-hours"' in page.text
    assert "12 小时" in page.text and "24 小时" in page.text
    assert 'id="revoke-selected"' not in page.text
    assert '<div class="table-head key-grid"><span>领取链接</span><span>有效期</span><span>状态</span></div>' in page.text
    assert "service-form" not in page.text and "service_id" not in page.text
