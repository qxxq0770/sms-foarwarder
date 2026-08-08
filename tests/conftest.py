import os
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

os.environ.setdefault("ADMIN_PASSWORD", "a-strong-import-password")
os.environ.setdefault("WEBHOOK_TOKEN", "import-webhook-token-that-is-long-enough")
os.environ.setdefault("ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
os.environ.setdefault("SESSION_SECRET", "import-session-secret-that-is-long-enough")
os.environ.setdefault("DATABASE_PATH", "/tmp/sms-forwarder-import.db")
os.environ.setdefault("COOKIE_SECURE", "false")

from app.config import Settings
from app.main import create_app


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        admin_username="admin",
        admin_password="a-strong-test-password",
        webhook_token="webhook-token-that-is-long-enough-123456",
        encryption_key=Fernet.generate_key().decode("ascii"),
        session_secret="session-secret-that-is-long-enough-123456",
        database_path=tmp_path / "test.db",
        public_base_url="http://localhost:8000",
        cookie_secure=False,
    )


@pytest.fixture
def client(settings: Settings):
    app = create_app(settings)
    with TestClient(app, base_url=settings.public_base_url) as test_client:
        yield test_client


@pytest.fixture
def authenticated_client(client: TestClient, settings: Settings) -> TestClient:
    response = client.post(
        "/api/session",
        json={"username": settings.admin_username, "password": settings.admin_password},
    )
    assert response.status_code == 200
    return client


@pytest.fixture
def sms_payload() -> dict[str, object]:
    return {
        "version": "1",
        "event": "sms.received",
        "delivery_id": "delivery-001",
        "rule_id": "bank-alert",
        "sender": "+8613800138000",
        "recipient": "+8613900000000",
        "message": "您的账户发生一笔测试交易。",
        "received_at": "2026-08-07T08:30:00Z",
        "is_test": False,
    }
