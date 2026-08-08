from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    admin_username: str = "admin"
    admin_password: str
    webhook_token: str
    encryption_key: str
    session_secret: str
    database_path: Path = Path("/data/sms-forwarder.db")
    public_base_url: str = "http://localhost:8000"
    cookie_secure: bool = True
    session_hours: int = Field(default=12, ge=1, le=168)

    @field_validator("admin_password")
    @classmethod
    def password_is_long_enough(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("ADMIN_PASSWORD must contain at least 8 characters")
        if value.startswith("replace-with-"):
            raise ValueError("ADMIN_PASSWORD must not use the example placeholder")
        return value

    @field_validator("webhook_token", "session_secret")
    @classmethod
    def secret_is_long_enough(cls, value: str) -> str:
        if len(value) < 32:
            raise ValueError("secret values must contain at least 32 characters")
        if value.startswith("replace-with-"):
            raise ValueError("secret values must not use the example placeholders")
        return value

    @field_validator("encryption_key")
    @classmethod
    def encryption_key_is_valid(cls, value: str) -> str:
        try:
            Fernet(value.encode("ascii"))
        except (ValueError, TypeError) as exc:
            raise ValueError("ENCRYPTION_KEY must be a valid Fernet key") from exc
        return value

    @field_validator("public_base_url")
    @classmethod
    def public_url_is_valid(cls, value: str) -> str:
        value = value.rstrip("/")
        parsed = urlsplit(value)
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("PUBLIC_BASE_URL contains an invalid port") from exc
        if (
            not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("PUBLIC_BASE_URL must be an origin without credentials, path, query, or fragment")
        is_local_http = parsed.scheme == "http" and parsed.hostname in {
            "localhost",
            "127.0.0.1",
            "::1",
        }
        if parsed.scheme != "https" and not is_local_http:
            raise ValueError("PUBLIC_BASE_URL must use HTTPS, except on localhost")
        return value

    @model_validator(mode="after")
    def secure_cookie_is_required_for_https(self):
        if urlsplit(self.public_base_url).scheme == "https" and not self.cookie_secure:
            raise ValueError("COOKIE_SECURE must be true when PUBLIC_BASE_URL uses HTTPS")
        return self
