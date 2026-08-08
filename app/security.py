import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken


class Vault:
    def __init__(self, encryption_key: str):
        self._fernet = Fernet(encryption_key.encode("ascii"))
        raw_key = base64.urlsafe_b64decode(encryption_key.encode("ascii"))
        self._fingerprint_key = hashlib.sha256(raw_key + b"\0fingerprint").digest()

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str) -> str:
        try:
            return self._fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Unable to decrypt stored message") from exc

    def fingerprint(self, value: str) -> str:
        return hmac.new(
            self._fingerprint_key, value.encode("utf-8"), hashlib.sha256
        ).hexdigest()


@dataclass(frozen=True)
class SessionSigner:
    secret: bytes
    lifetime_seconds: int

    def create(self, username: str, auth_version: int) -> str:
        payload = {
            "sub": username,
            "version": auth_version,
            "exp": int(time.time()) + self.lifetime_seconds,
            "nonce": secrets.token_urlsafe(12),
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=")
        signature = hmac.new(self.secret, encoded, hashlib.sha256).digest()
        return f"{encoded.decode('ascii')}.{base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')}"

    def verify(self, token: str) -> tuple[str, int] | None:
        try:
            encoded_text, signature_text = token.split(".", 1)
            encoded = encoded_text.encode("ascii")
            expected = hmac.new(self.secret, encoded, hashlib.sha256).digest()
            signature = base64.urlsafe_b64decode(_pad(signature_text))
            if not hmac.compare_digest(signature, expected):
                return None
            payload = json.loads(base64.urlsafe_b64decode(_pad(encoded_text)))
            if int(payload["exp"]) < int(time.time()):
                return None
            return str(payload["sub"]), int(payload["version"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None


@dataclass(frozen=True)
class PublicSessionSigner:
    secret: bytes

    def create(self, link_id: int, token_version: int, expires_at: datetime) -> str:
        payload = {
            "aud": "public-claim",
            "link_id": link_id,
            "version": token_version,
            "exp": int(expires_at.timestamp()),
            "nonce": secrets.token_urlsafe(12),
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=")
        signature = hmac.new(self.secret, encoded, hashlib.sha256).digest()
        return (
            f"{encoded.decode('ascii')}."
            f"{base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')}"
        )

    def verify(self, token: str) -> tuple[int, int] | None:
        try:
            encoded_text, signature_text = token.split(".", 1)
            encoded = encoded_text.encode("ascii")
            expected = hmac.new(self.secret, encoded, hashlib.sha256).digest()
            signature = base64.urlsafe_b64decode(_pad(signature_text))
            if not hmac.compare_digest(signature, expected):
                return None
            payload = json.loads(base64.urlsafe_b64decode(_pad(encoded_text)))
            if payload.get("aud") != "public-claim":
                return None
            if int(payload["exp"]) < int(time.time()):
                return None
            return int(payload["link_id"]), int(payload["version"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    actual_salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=actual_salt, n=2**14, r=8, p=1, dklen=32
    )
    return actual_salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, digest_hex: str) -> bool:
    try:
        _, calculated = hash_password(password, bytes.fromhex(salt_hex))
        return hmac.compare_digest(calculated, digest_hex)
    except ValueError:
        return False


def _pad(value: str) -> bytes:
    return (value + "=" * (-len(value) % 4)).encode("ascii")
