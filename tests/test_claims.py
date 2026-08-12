import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

from app.database import MessageStore
from app.security import Vault


def create_inventory(client: TestClient, *, max_assignments: int = 2, number: str = "+44 7700 900123") -> dict[str, object]:
    response = client.post(
        "/api/numbers",
        json={"number": number, "country_code": "GB", "country_name": "英国", "max_assignments": max_assignments},
    )
    assert response.status_code == 201
    return response.json()


def create_key(client: TestClient) -> tuple[dict[str, object], str]:
    response = client.post(
        "/api/share-links/batch",
        json={"count": 1, "validity_hours": 12},
    )
    assert response.status_code == 201
    item = response.json()["items"][0]
    token = parse_qs(urlsplit(item["share_url"]).query)["t"][0]
    return item, token


def public_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def exchange_and_claim(client: TestClient, token: str) -> dict[str, object]:
    exchange = client.post("/api/public/session", headers=public_headers(token))
    assert exchange.status_code == 200
    assert exchange.json()["assigned"] is False
    claim = client.post("/api/public/claim")
    assert claim.status_code == 200
    return claim.json()


def ingest_code(
    client: TestClient,
    settings,
    *,
    delivery_id: str,
    code: str,
    sender: str = "Example",
    recipient: str = "+447700900123",
    received_at: datetime | None = None,
) -> None:
    timestamp = received_at or datetime.now(UTC)
    response = client.post(
        "/api/webhooks/sms",
        headers={"Authorization": f"Bearer {settings.webhook_token}"},
        json={"version": "1", "event": "sms.received", "delivery_id": delivery_id, "rule_id": "public-code", "sender": sender, "recipient": recipient, "message": f"Private message. code: {code}.", "received_at": timestamp.isoformat(), "is_test": False},
    )
    assert response.status_code == 200


def test_claim_page_is_automatic_and_has_no_service_metadata(client: TestClient) -> None:
    page = client.get("/c")
    script = client.get("/static/claim.js")
    assert 'id="claim-button"' not in page.text
    assert "claim-service" not in page.text
    assert "claim-country" not in page.text
    assert "来源" not in page.text and "接收时间" not in page.text
    assert "安全连接" not in page.text
    table_header = page.text.split('class="claim-table-head"', 1)[1].split("</div>", 1)[0]
    assert table_header.index("手机号码") < table_header.index("状况") < table_header.index("时间")
    assert "验证码" not in table_header
    assert "成本" not in table_header
    assert 'class="codes-panel' not in page.text
    assert 'id="code-list" class="code-list"' in page.text
    assert "等待短信" in page.text
    assert "短信验证码：" in page.text
    assert 'id="claim-count"' not in page.text
    assert "暂未收到验证码" not in page.text
    assert '/static/app-icon.png?v=1' in page.text
    assert '/static/styles.css?v=43' in page.text
    assert 'new URLSearchParams(window.location.search).get("t")' in script.text
    assert 'new URLSearchParams(window.location.hash.slice(1)).get("t")' in script.text
    assert 'publicApi("/api/public/claim", { method: "POST", headers: publicAuthHeaders() })' in script.text
    assert 'publicApi("/api/public/state", { headers: publicAuthHeaders() })' in script.text
    assert 'window.history.replaceState' not in script.text
    assert '/static/claim.css?v=38' in page.text
    assert '/static/claim.js?v=20' in page.text
    assert 'document.execCommand("copy")' in script.text
    assert 'navigator.maxTouchPoints > 1' in script.text
    assert '请长按已选中的内容复制' in script.text
    assert 'class="service-note" aria-label="客服提示"' in page.text
    assert "祝您观影愉快" in page.text
    assert "如遇问题，请联系在线客服" in page.text
    assert 'class="service-note-help"' in page.text
    assert "QQ：2865629869" in page.text
    assert '<meta name="format-detection" content="telephone=no" />' in page.text
    assert 'id="copy-service-qq"' in page.text
    assert 'data-qq="2865629869"' in page.text
    assert 'copy(button.dataset.qq, "客服 QQ 已复制", $("#service-qq-value"))' in script.text
    assert 'state.textContent = expired ? "已过期" : "NEW"' in script.text
    assert 'data.latest_code || latestFromCodes(data.codes || [])' in script.text
    assert 'classList.toggle("success", !expired)' in script.text
    assert 'classList.toggle("expired", expired)' in script.text
    assert ".live-pill.success" in client.get("/static/claim.css").text
    assert ".status-cell.success" in client.get("/static/claim.css").text
    assert ".status-cell.success {\n  background: #fff;" in client.get("/static/claim.css").text
    assert ".status-content {\n  width: 100%;\n  display: flex;\n  align-items: center;" in client.get("/static/claim.css").text
    assert ".code-label {\n    min-height: 44px;\n    display: inline-flex;\n    align-items: center;" in client.get("/static/claim.css").text
    assert "linear-gradient(90deg, #4169d8 0 4px, transparent 4px)" not in client.get("/static/claim.css").text
    assert "font-weight: 500;" in client.get("/static/claim.css").text
    assert ".number-line .copy-button" in client.get("/static/claim.css").text
    assert ".claim-table-head {\n  min-height: 54px;" in client.get("/static/claim.css").text
    assert "font-size: 15px;" in client.get("/static/claim.css").text
    assert "grid-row: 1 / span 2;" in client.get("/static/claim.css").text


def test_claim_page_includes_three_step_login_tutorial(client: TestClient) -> None:
    page = client.get("/c")
    assert page.status_code == 200
    assert "手机号登录教程" not in page.text
    assert 'class="tutorial" aria-label="手机号登录步骤"' in page.text
    assert "选择手机号登录" in page.text
    assert "选择其他手机号" in page.text
    assert "输入上方号码并获取验证码" in page.text
    assert "温馨提示" in page.text
    assert "请先参考教程完成验证码发送，再耐心等待上方显示验证码。" in page.text
    assert "请先完成验证码发送，再耐心等待上方显示验证码。" not in page.text
    assert "按顺序完成以下 3 步" not in page.text
    claim_css = client.get("/static/claim.css").text
    assert ".tutorial-note-label" in claim_css
    assert ".tutorial-card figcaption span" in claim_css
    assert ".tutorial-card figcaption strong" in claim_css
    assert claim_css.count("font-size: 13px;") >= 3
    assert page.text.count("/static/tutorial/step-") == 3
    assert "17521104217" not in page.text


def test_batch_tokens_are_encrypted_and_visible_to_admin(authenticated_client: TestClient, settings) -> None:
    create_inventory(authenticated_client)
    response = authenticated_client.post("/api/share-links/batch", json={"count": 3})
    assert response.status_code == 201
    items = response.json()["items"]
    assert len(items) == 3
    assert all(item["lease_minutes"] == 720 for item in items)
    assert all("/c?t=" in item["share_url"] for item in items)
    tokens = [parse_qs(urlsplit(item["share_url"]).query)["t"][0] for item in items]
    listed = authenticated_client.get("/api/share-links").json()
    assert listed["total"] == 3
    assert {
        parse_qs(urlsplit(item["share_url"]).query)["t"][0]
        for item in listed["items"]
    } == set(tokens)
    assert all(item["share_url"].startswith(settings.public_base_url) for item in listed["items"])
    assert "expires_at" not in listed["items"][0]
    assert "assigned_number_masked" not in listed["items"][0]
    assert {item["token"] for item in listed["items"]} == set(tokens)
    with sqlite3.connect(settings.database_path) as connection:
        stored = list(connection.execute("SELECT token_digest, token_encrypted FROM share_links"))
        link_columns = {row[1] for row in connection.execute("PRAGMA table_info(share_links)")}
    assert all(token not in str(stored) for token in tokens)
    assert all(encrypted for _, encrypted in stored)
    assert "expires_at" not in link_columns
    assert "assigned_number_id" not in link_columns
    assert "assignment_id" not in link_columns


def test_ready_share_links_filter_by_validity_and_accept_webhook_token(
    authenticated_client: TestClient, settings
) -> None:
    twelve_hour = authenticated_client.post(
        "/api/share-links/batch", json={"count": 1, "validity_hours": 12}
    ).json()["items"][0]
    twenty_four_hour_items = authenticated_client.post(
        "/api/share-links/batch", json={"count": 2, "validity_hours": 24}
    ).json()["items"]
    expected_links = {item["share_url"] for item in twenty_four_hour_items}
    headers = {"Authorization": f"Bearer {settings.webhook_token}"}

    with TestClient(
        authenticated_client.app, base_url=settings.public_base_url
    ) as bearer_client:
        listed = bearer_client.get(
            "/api/share-links",
            params={"status": "ready", "validity_hours": 24, "limit": 100},
            headers=headers,
        )
        copied = bearer_client.get(
            "/api/share-links/copy",
            params={"status": "ready", "validity_hours": 24},
            headers=headers,
        )
        invalid_validity = bearer_client.get(
            "/api/share-links",
            params={"status": "ready", "validity_hours": 6},
            headers=headers,
        )
        invalid_token = bearer_client.get(
            "/api/share-links",
            params={"status": "ready", "validity_hours": 24},
            headers={"Authorization": "Bearer invalid-token"},
        )

    assert listed.status_code == 200
    assert listed.json()["total"] == 2
    assert {item["share_url"] for item in listed.json()["items"]} == expected_links
    assert {item["lease_minutes"] for item in listed.json()["items"]} == {1440}
    assert all(item["display_status"] == "ready" for item in listed.json()["items"])
    assert twelve_hour["share_url"] not in {
        item["share_url"] for item in listed.json()["items"]
    }
    assert copied.status_code == 200
    assert copied.json()["count"] == 2
    assert set(copied.json()["content"]) == expected_links
    assert "text" not in copied.json()
    assert invalid_validity.status_code == 422
    assert invalid_token.status_code == 401


def test_claim_is_idempotent_and_uses_least_used_across_regions(authenticated_client: TestClient) -> None:
    first = create_inventory(authenticated_client, number="+44 7700 900123")
    assert first["assignment_count"] == 0
    create_inventory(authenticated_client, number="+1 202 555 0101")
    key, token = create_key(authenticated_client)
    authenticated_client.post("/api/public/session", headers={"Authorization": f"Bearer {token}"})
    store = authenticated_client.app.state.store
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: store.claim_number(int(key["id"])), range(2)))
    assert results[0]["number"] == results[1]["number"] == first["number"]
    started_at = datetime.fromisoformat(str(results[0]["started_at"]))
    expires_at = datetime.fromisoformat(str(results[0]["expires_at"]))
    assert expires_at - started_at == timedelta(hours=12)
    numbers = authenticated_client.get("/api/numbers").json()
    assert next(item for item in numbers if item["id"] == first["id"])["assignment_count"] == 1


def test_same_number_active_links_share_latest_code(
    authenticated_client: TestClient, settings
) -> None:
    create_inventory(authenticated_client, max_assignments=2)
    _, token_a = create_key(authenticated_client)
    _, token_b = create_key(authenticated_client)

    assert authenticated_client.post(
        "/api/public/session", headers=public_headers(token_a)
    ).status_code == 200
    claim_a = authenticated_client.post(
        "/api/public/claim", headers=public_headers(token_a)
    )
    assert claim_a.status_code == 200

    assert authenticated_client.post(
        "/api/public/session", headers=public_headers(token_b)
    ).status_code == 200
    claim_b = authenticated_client.post(
        "/api/public/claim", headers=public_headers(token_b)
    )
    assert claim_b.status_code == 200
    assert claim_b.json()["number"] == claim_a.json()["number"]

    ingest_code(authenticated_client, settings, delivery_id="shared-code-1", code="111111")
    state_a = authenticated_client.get(
        "/api/public/state", headers=public_headers(token_a)
    ).json()
    state_b = authenticated_client.get(
        "/api/public/state", headers=public_headers(token_b)
    ).json()
    assert state_a["latest_code"]["code"] == "111111"
    assert state_b["latest_code"]["code"] == "111111"
    assert state_a["codes"] == [{"code": "111111"}]
    assert state_b["codes"] == [{"code": "111111"}]

    ingest_code(authenticated_client, settings, delivery_id="shared-code-2", code="222222")

    cookie_state = authenticated_client.get("/api/public/state").json()
    state_a = authenticated_client.get(
        "/api/public/state", headers=public_headers(token_a)
    ).json()
    state_b = authenticated_client.get(
        "/api/public/state", headers=public_headers(token_b)
    ).json()

    assert cookie_state["latest_code"]["code"] == "222222"
    assert cookie_state["status"] == "active"
    assert state_a["latest_code"]["code"] == "222222"
    assert state_a["codes"] == [{"code": "111111"}, {"code": "222222"}]
    assert state_b["latest_code"]["code"] == "222222"
    assert state_b["codes"] == [{"code": "111111"}, {"code": "222222"}]
    assert state_a["status"] == "active"
    assert state_b["status"] == "active"
    assert authenticated_client.get("/api/numbers").json()[0]["assignment_count"] == 2

    ingest_code(authenticated_client, settings, delivery_id="shared-code-3", code="333333")
    ingest_code(authenticated_client, settings, delivery_id="shared-code-4", code="444444")
    state_a = authenticated_client.get(
        "/api/public/state", headers=public_headers(token_a)
    ).json()
    state_b = authenticated_client.get(
        "/api/public/state", headers=public_headers(token_b)
    ).json()

    expected_codes = [{"code": "222222"}, {"code": "333333"}, {"code": "444444"}]
    assert state_a["status"] == "active"
    assert state_b["status"] == "active"
    assert state_a["code_count"] == 4
    assert state_b["code_count"] == 4
    assert state_a["latest_code"]["code"] == "444444"
    assert state_b["latest_code"]["code"] == "444444"
    assert state_a["codes"] == expected_codes
    assert state_b["codes"] == expected_codes


def test_expired_link_releases_number_usage(authenticated_client: TestClient, settings) -> None:
    number = create_inventory(authenticated_client, max_assignments=1)
    _, token = create_key(authenticated_client)
    claimed = exchange_and_claim(authenticated_client, token)
    assert claimed["number"] == number["number"]
    assert authenticated_client.get("/api/numbers").json()[0]["assignment_count"] == 1

    expired_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    with sqlite3.connect(settings.database_path) as connection:
        connection.execute(
            "UPDATE assignments SET expires_at = ? WHERE status = 'active'",
            (expired_at,),
        )

    refreshed = authenticated_client.get("/api/numbers").json()
    assert refreshed[0]["assignment_count"] == 0
    _, replacement_token = create_key(authenticated_client)
    replacement = exchange_and_claim(authenticated_client, replacement_token)
    assert replacement["number"] == number["number"]


def test_number_can_be_shared_until_assignment_limit(authenticated_client: TestClient) -> None:
    number = create_inventory(authenticated_client, max_assignments=2)

    _, first_token = create_key(authenticated_client)
    first = exchange_and_claim(authenticated_client, first_token)
    assert first["number"] == number["number"]
    first_stats = authenticated_client.get("/api/stats").json()
    assert first_stats["available_numbers"] == 1
    assert first_stats["available_uses"] == 1

    _, second_token = create_key(authenticated_client)
    second = exchange_and_claim(authenticated_client, second_token)
    assert second["number"] == number["number"]
    inventory = authenticated_client.get("/api/numbers").json()[0]
    assert inventory["assignment_count"] == 2
    assert inventory["remaining_assignments"] == 0
    full_stats = authenticated_client.get("/api/stats").json()
    assert full_stats["available_numbers"] == 0
    assert full_stats["available_uses"] == 0

    _, third_token = create_key(authenticated_client)
    authenticated_client.post(
        "/api/public/session",
        headers={"Authorization": f"Bearer {third_token}"},
    )
    assert authenticated_client.post("/api/public/claim").status_code == 409


def test_number_usage_can_be_reset(authenticated_client: TestClient) -> None:
    number = create_inventory(authenticated_client, max_assignments=2)
    tokens = []
    for _ in range(2):
        _, token = create_key(authenticated_client)
        tokens.append(token)
        exchange_and_claim(authenticated_client, token)

    reset = authenticated_client.post(f"/api/numbers/{number['id']}/reset-usage")
    assert reset.status_code == 200
    assert reset.json()["assignment_count"] == 0
    assert reset.json()["reset_assignments"] == 2
    assert authenticated_client.get("/api/stats").json()["active_assignments"] == 0

    authenticated_client.post(
        "/api/public/session", headers={"Authorization": f"Bearer {tokens[0]}"}
    )
    assert authenticated_client.get("/api/public/state").json()["status"] == "revoked"

    _, replacement_token = create_key(authenticated_client)
    replacement = exchange_and_claim(authenticated_client, replacement_token)
    assert replacement["number"] == number["number"]
    assert authenticated_client.get("/api/numbers").json()[0]["assignment_count"] == 1


def test_builtin_rule_routes_independent_four_to_eight_digit_codes(authenticated_client: TestClient, settings) -> None:
    create_inventory(authenticated_client)
    key, token = create_key(authenticated_client)
    exchange_and_claim(authenticated_client, token)
    ingest_code(authenticated_client, settings, delivery_id="too-short", code="111", sender="Other")
    ingest_code(authenticated_client, settings, delivery_id="right", code="333333", sender="Other")
    state = authenticated_client.get("/api/public/state")
    assert state.json()["code_count"] == 1
    assert state.json()["codes"][0]["code"] == "333333"
    assert state.json()["latest_code"]["code"] == "333333"
    assert "expires_at" in state.json()["latest_code"]
    assert "Private message" not in state.text
    assert "Example" not in state.text
    assert "sender_masked" not in state.text and "received_at" not in state.text
    assert "link_id" not in state.text and "token_version" not in state.text
    record = authenticated_client.get("/api/messages").json()["items"][0]
    assert record["share_link_id"] == key["id"]
    assert record["key"] == f"{settings.public_base_url}/c?t={token}"
    assert record["recipient"] == "+447700900123"
    searched = authenticated_client.get("/api/messages", params={"q": record["key"]}).json()
    assert searched["total"] == 1
    assert searched["items"][0]["key"] == record["key"]
    legacy_searched = authenticated_client.get(
        "/api/messages", params={"q": f"{settings.public_base_url}/c#t={token}"}
    ).json()
    assert legacy_searched["total"] == 1
    assert legacy_searched["items"][0]["key"] == record["key"]
    ingest_code(authenticated_client, settings, delivery_id="newest", code="444444", sender="Other")
    state = authenticated_client.get("/api/public/state").json()
    assert state["codes"][-1]["code"] == "444444"
    assert state["latest_code"]["code"] == "444444"


def test_duplicate_extracted_codes_do_not_count_twice(authenticated_client: TestClient, settings) -> None:
    create_inventory(authenticated_client)
    _, token = create_key(authenticated_client)
    exchange_and_claim(authenticated_client, token)
    ingest_code(authenticated_client, settings, delivery_id="same-code-1", code="445566")
    ingest_code(authenticated_client, settings, delivery_id="same-code-2", code="445566")

    state = authenticated_client.get("/api/public/state").json()
    assert state["code_count"] == 1
    assert state["codes"] == [{"code": "445566"}]


def test_codes_continue_until_number_usage_releases_on_expiry(
    authenticated_client: TestClient, settings
) -> None:
    create_inventory(authenticated_client, max_assignments=1)
    _, token = create_key(authenticated_client)
    first = exchange_and_claim(authenticated_client, token)
    for index, code in enumerate(("100001", "100002", "100003", "100004"), 1):
        ingest_code(authenticated_client, settings, delivery_id=f"code-{index}", code=code)
    state = authenticated_client.get("/api/public/state").json()
    assert state["status"] == "active"
    assert state["code_count"] == 4
    assert state["latest_code"]["code"] == "100004"
    assert state["codes"] == [
        {"code": "100002"},
        {"code": "100003"},
        {"code": "100004"},
    ]
    assert authenticated_client.get("/api/numbers").json()[0]["assignment_count"] == 1
    _, token2 = create_key(authenticated_client)
    authenticated_client.post("/api/public/session", headers=public_headers(token2))
    assert (
        authenticated_client.post(
            "/api/public/claim", headers=public_headers(token2)
        ).status_code
        == 409
    )

    expired_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    with sqlite3.connect(settings.database_path) as connection:
        connection.execute(
            "UPDATE assignments SET expires_at = ? WHERE status = 'active'",
            (expired_at,),
        )

    assert authenticated_client.get("/api/numbers").json()[0]["assignment_count"] == 0
    replacement = authenticated_client.post(
        "/api/public/claim", headers=public_headers(token2)
    )
    assert replacement.status_code == 200
    assert replacement.json()["number"] == first["number"]


def test_batch_revoke_and_status_pagination(authenticated_client: TestClient) -> None:
    response = authenticated_client.post("/api/share-links/batch", json={"count": 3})
    items = response.json()["items"]
    ids = [item["id"] for item in items]
    revoked = authenticated_client.post("/api/share-links/revoke-batch", json={"ids": ids[:2]})
    assert revoked.json() == {"revoked": 2}
    listed = authenticated_client.get("/api/share-links?status=used&limit=1")
    assert listed.json()["total"] == 2
    assert len(listed.json()["items"]) == 1
    copied = authenticated_client.get("/api/share-links/copy?status=used")
    assert copied.status_code == 200
    assert copied.json()["count"] == 2
    copied_links = copied.json()["content"]
    assert set(copied_links) == {items[0]["share_url"], items[1]["share_url"]}
    assert items[2]["share_url"] not in copied.json()["content"]
    assert "text" not in copied.json()
    assert (
        authenticated_client.get("/api/share-links/copy?status=invalid").status_code
        == 422
    )


def test_invalid_batch_and_cross_origin_are_rejected(authenticated_client: TestClient) -> None:
    max_batch = authenticated_client.post(
        "/api/share-links/batch", json={"count": 200}
    )
    assert max_batch.status_code == 201
    assert len(max_batch.json()["items"]) == 200
    assert authenticated_client.post("/api/share-links/batch", json={"count": 201}).status_code == 422
    assert authenticated_client.post("/api/share-links/batch", json={"count": 1, "validity_hours": 6}).status_code == 422
    blocked = authenticated_client.post(
        "/api/numbers",
        headers={"Origin": "https://attacker.example"},
        json={"number": "+447700900123", "country_code": "GB", "country_name": "英国", "max_assignments": 1},
    )
    assert blocked.status_code == 403
    assert authenticated_client.post(
        "/api/numbers/1/reset-usage",
        headers={"Origin": "https://attacker.example"},
    ).status_code == 403


def test_legacy_database_migrates_without_losing_messages(tmp_path, settings) -> None:
    path = tmp_path / "legacy.db"
    vault = Vault(settings.encryption_key)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, delivery_id TEXT NOT NULL UNIQUE, rule_id TEXT NOT NULL, sender_encrypted TEXT NOT NULL, sender_suffix TEXT NOT NULL, message_encrypted TEXT NOT NULL, received_at TEXT NOT NULL, is_test INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)")
        connection.execute("INSERT INTO messages (delivery_id, rule_id, sender_encrypted, sender_suffix, message_encrypted, received_at, is_test, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)", ("legacy-1", "legacy", vault.encrypt("+8613800000000"), "0000", vault.encrypt("历史短信"), datetime.now(UTC).isoformat(), datetime.now(UTC).isoformat()))
    store = MessageStore(path, vault)
    store.initialize()
    store.ensure_bootstrap(settings.admin_password, settings.webhook_token)
    items, total = store.list_messages(limit=10, offset=0)
    assert total == 1
    assert items[0]["message_preview"] == "历史短信"
    with sqlite3.connect(path) as connection:
        versions = connection.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        indexes = {
            row[1]
            for row in connection.execute("PRAGMA index_list(codes)")
        }
    assert versions == [
        (1,),
        (2,),
        (3,),
        (4,),
        (5,),
        (6,),
        (7,),
        (8,),
        (9,),
        (10,),
        (11,),
        (12,),
        (13,),
        (14,),
    ]
    assert "services" not in tables and "number_services" not in tables
    assert "idx_codes_assignment_message" in indexes
