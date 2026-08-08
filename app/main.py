import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
)
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import Settings
from app.database import MessageStore, StoreConflict, StoreGone, StoreNotFound
from app.security import PublicSessionSigner, SessionSigner, Vault, token_digest

STATIC_DIR = Path(__file__).parent / "static"
SESSION_COOKIE = "sms_session"
PUBLIC_SESSION_COOKIE = "sms_claim_session"
MAX_REQUEST_BODY_BYTES = 64 * 1024


class LoginRequest(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=500)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=500)
    new_password: str = Field(min_length=8, max_length=500)
    confirm_password: str = Field(min_length=8, max_length=500)

    @model_validator(mode="after")
    def passwords_match(self):
        self.current_password = self.current_password.strip()
        self.new_password = self.new_password.strip()
        self.confirm_password = self.confirm_password.strip()
        if self.new_password != self.confirm_password:
            raise ValueError("两次输入的新密码不一致")
        if self.new_password == self.current_password:
            raise ValueError("新密码不能与当前密码相同")
        return self


class SmsPayload(BaseModel):
    version: str = Field(default="1", max_length=8)
    event: str = Field(default="sms.received", max_length=40)
    delivery_id: str = Field(
        default_factory=lambda: f"auto-{secrets.token_urlsafe(18)}", max_length=128
    )
    rule_id: str = Field(default="default", min_length=1, max_length=128)
    sender: str = Field(default="Webhook", min_length=1, max_length=128)
    recipient: str = Field(min_length=3, max_length=128)
    message: str = Field(min_length=1, max_length=20_000)
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    is_test: bool = False

    @field_validator("received_at")
    @classmethod
    def timestamp_has_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("received_at must include a timezone")
        return value


class NumberCreate(BaseModel):
    number: str = Field(min_length=3, max_length=128)
    country_code: str = Field(min_length=2, max_length=2, pattern=r"^[A-Za-z]{2}$")
    country_name: str = Field(min_length=1, max_length=80)
    max_assignments: int = Field(default=1, ge=1, le=100_000)


class NumberUpdate(BaseModel):
    number: str | None = Field(default=None, min_length=3, max_length=128)
    country_code: str | None = Field(default=None, min_length=2, max_length=2, pattern=r"^[A-Za-z]{2}$")
    country_name: str | None = Field(default=None, min_length=1, max_length=80)
    max_assignments: int | None = Field(default=None, ge=1, le=100_000)
    enabled: bool | None = None


class KeyBatchCreate(BaseModel):
    count: int = Field(default=1, ge=1, le=20)
    validity_hours: Literal[12, 24] | None = None


class KeyBatchRevoke(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=20)


class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_validity_hours: Literal[12, 24] | None = None


class SlidingWindowLimiter:
    def __init__(self, maximum: int, window_seconds: int, max_keys: int = 10_000) -> None:
        self._maximum = maximum
        self._window_seconds = window_seconds
        self._max_keys = max_keys
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            attempts = self._attempts.get(key)
            if attempts is None:
                stale_keys = [
                    tracked_key
                    for tracked_key, tracked_attempts in self._attempts.items()
                    if not tracked_attempts
                    or tracked_attempts[-1] < now - self._window_seconds
                ]
                for stale_key in stale_keys:
                    self._attempts.pop(stale_key, None)
                if len(self._attempts) >= self._max_keys:
                    return False
                attempts = deque()
                self._attempts[key] = attempts
            while attempts and attempts[0] < now - self._window_seconds:
                attempts.popleft()
            if len(attempts) >= self._maximum:
                return False
            attempts.append(now)
            return True

    def clear(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings()  # type: ignore[call-arg]
    vault = Vault(config.encryption_key)
    store = MessageStore(config.database_path, vault)
    admin_session_key = hashlib.sha256(
        f"{config.session_secret}\0admin-session".encode("utf-8")
    ).digest()
    public_session_key = hashlib.sha256(
        f"{config.session_secret}\0public-claim".encode("utf-8")
    ).digest()
    signer = SessionSigner(admin_session_key, config.session_hours * 60 * 60)
    public_signer = PublicSessionSigner(public_session_key)
    login_limiter = SlidingWindowLimiter(5, 300)
    exchange_limiter = SlidingWindowLimiter(20, 60)
    claim_limiter = SlidingWindowLimiter(20, 60)
    state_limiter = SlidingWindowLimiter(180, 60)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        store.initialize()
        store.ensure_bootstrap(config.admin_password, config.webhook_token)
        yield

    app = FastAPI(
        title="SMS Forwarder",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = config
    app.state.store = store
    public_host = urlsplit(config.public_base_url).hostname
    trusted_hosts = [public_host] if public_host else []
    if public_host in {"localhost", "127.0.0.1", "::1"}:
        trusted_hosts = ["localhost", "127.0.0.1", "::1", "[::1]"]
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=trusted_hosts,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if request.headers.get("transfer-encoding"):
            response = JSONResponse(
                status_code=411, content={"detail": "不支持分块请求"}
            )
        elif request.method in {"POST", "PUT", "PATCH"} and content_length is None:
            response = JSONResponse(
                status_code=411, content={"detail": "缺少 Content-Length"}
            )
        elif content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                response = JSONResponse(
                    status_code=400, content={"detail": "Content-Length 无效"}
                )
            else:
                if declared_length < 0:
                    response = JSONResponse(
                        status_code=400, content={"detail": "Content-Length 无效"}
                    )
                elif declared_length > MAX_REQUEST_BODY_BYTES:
                    response = JSONResponse(
                        status_code=413, content={"detail": "请求体过大"}
                    )
                else:
                    response = await call_next(request)
        else:
            response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
        if urlsplit(config.public_base_url).scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if (
            request.url.path.startswith("/api/")
            or request.url.path in {"/", "/c"}
            or response.headers.get("content-type", "").startswith("text/html")
        ):
            response.headers["Cache-Control"] = "no-store"
        return response

    def set_admin_cookie(response: Response, version: int) -> None:
        response.set_cookie(
            SESSION_COOKIE,
            signer.create(config.admin_username, version),
            max_age=config.session_hours * 60 * 60,
            httponly=True,
            secure=config.cookie_secure,
            samesite="strict",
            path="/",
        )

    def current_user(sms_session: Annotated[str | None, Cookie()] = None) -> str:
        session_data = signer.verify(sms_session or "")
        if session_data is None:
            raise HTTPException(status_code=401, detail="请先登录")
        username, version = session_data
        if username != config.admin_username or version != store.auth_version():
            raise HTTPException(status_code=401, detail="登录已过期")
        return username

    def current_public_link(
        sms_claim_session: Annotated[str | None, Cookie(alias=PUBLIC_SESSION_COOKIE)] = None,
    ) -> int:
        session_data = public_signer.verify(sms_claim_session or "")
        if session_data is None:
            raise HTTPException(status_code=401, detail="访问会话无效或已过期")
        link_id, token_version = session_data
        try:
            current_version = store.public_session_version(link_id)
        except StoreNotFound as exc:
            raise HTTPException(status_code=401, detail="访问会话无效或已过期") from exc
        if token_version != current_version:
            raise HTTPException(status_code=401, detail="访问会话无效或已过期")
        return link_id

    def extract_bearer_token(authorization: str | None) -> str | None:
        if not authorization or len(authorization) > 512:
            return None
        scheme, separator, token = authorization.partition(" ")
        if (
            separator != " "
            or scheme.casefold() != "bearer"
            or not token
            or token.strip() != token
            or any(character.isspace() for character in token)
        ):
            return None
        return token

    def verify_webhook(authorization: Annotated[str | None, Header()] = None) -> None:
        token = extract_bearer_token(authorization)
        if token is None or not store.verify_webhook_token(token):
            raise HTTPException(status_code=401, detail="令牌无效")

    def verify_same_origin(request: Request) -> None:
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") != config.public_base_url.rstrip("/"):
            raise HTTPException(status_code=403, detail="请求来源无效")

    def client_address(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def set_public_cookie(response: Response, state_payload: dict[str, Any]) -> None:
        deadline_text = state_payload.get("expires_at")
        deadline = (
            datetime.fromisoformat(deadline_text.replace("Z", "+00:00"))
            if deadline_text
            else datetime.now(UTC) + timedelta(hours=24)
        )
        response.set_cookie(
            PUBLIC_SESSION_COOKIE,
            public_signer.create(
                int(state_payload["link_id"]), int(state_payload["token_version"]), deadline
            ),
            max_age=max(1, int((deadline - datetime.now(UTC)).total_seconds())),
            httponly=True,
            secure=config.cookie_secure,
            samesite="strict",
            path="/api/public",
        )

    def public_response(payload: dict[str, Any]) -> dict[str, Any]:
        exposed = {
            "status",
            "assigned",
            "lease_minutes",
            "max_codes",
            "number",
            "started_at",
            "expires_at",
            "code_count",
            "codes",
        }
        return {key: value for key, value in payload.items() if key in exposed}

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/session")
    def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, str]:
        client = client_address(request)
        if not login_limiter.allow(client):
            raise HTTPException(status_code=429, detail="登录尝试过多，请稍后重试")
        password_valid, version = store.verify_admin_password(payload.password)
        valid = hmac.compare_digest(payload.username, config.admin_username) and password_valid
        if not valid:
            raise HTTPException(status_code=401, detail="用户名或密码错误")
        login_limiter.clear(client)
        set_admin_cookie(response, version)
        return {"username": payload.username}

    @app.delete(
        "/api/session",
        dependencies=[Depends(current_user), Depends(verify_same_origin)],
    )
    def logout(response: Response) -> Response:
        response.delete_cookie(
            SESSION_COOKIE,
            path="/",
            secure=config.cookie_secure,
            httponly=True,
            samesite="strict",
        )
        response.status_code = 204
        return response

    @app.get("/api/session")
    def session(username: Annotated[str, Depends(current_user)]) -> dict[str, str]:
        return {"username": username}

    @app.post("/api/webhooks/sms", dependencies=[Depends(verify_webhook)])
    def ingest(payload: SmsPayload) -> dict[str, object]:
        if payload.version != "1" or payload.event != "sms.received":
            raise HTTPException(status_code=422, detail="不支持的事件版本或类型")
        message_id, created = store.add(
            delivery_id=payload.delivery_id,
            rule_id=payload.rule_id,
            sender=payload.sender,
            recipient=payload.recipient,
            message=payload.message,
            received_at=payload.received_at,
            is_test=payload.is_test,
        )
        if created and not payload.is_test:
            store.route_message(
                message_id=message_id,
                sender=payload.sender,
                recipient=payload.recipient,
                message=payload.message,
                received_at=payload.received_at,
            )
        return {"accepted": True, "duplicate": not created, "id": message_id}

    @app.get("/api/messages")
    def messages(
        _: Annotated[str, Depends(current_user)],
        limit: int = 20,
        offset: int = 0,
        q: str = "",
    ) -> dict[str, object]:
        limit = min(max(limit, 1), 100)
        offset = max(offset, 0)
        query = q[:200]
        share_url_prefix = f"{config.public_base_url}/c#t="
        store_query = (
            query[len(share_url_prefix) :]
            if query.startswith(share_url_prefix)
            else query
        )
        items, total = store.list_messages(limit=limit, offset=offset, query=store_query)
        items = [
            item
            | {
                "key": f"{share_url_prefix}{item['key']}" if item.get("key") else None
            }
            for item in items
        ]
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @app.get("/api/messages/{message_id}")
    def message_detail(
        message_id: int, _: Annotated[str, Depends(current_user)]
    ) -> dict[str, Any]:
        return _store_call(store.get_message, message_id)

    @app.delete(
        "/api/messages/{message_id}",
        status_code=204,
        dependencies=[Depends(current_user), Depends(verify_same_origin)],
    )
    def delete_message(message_id: int) -> Response:
        if not store.delete(message_id):
            raise HTTPException(status_code=404, detail="短信不存在")
        return Response(status_code=204)

    @app.get("/api/stats")
    def stats(_: Annotated[str, Depends(current_user)]) -> dict[str, object]:
        return store.stats()

    @app.get("/api/numbers")
    def numbers(_: Annotated[str, Depends(current_user)]) -> list[dict[str, Any]]:
        return store.list_numbers()

    @app.post(
        "/api/numbers",
        status_code=201,
        dependencies=[Depends(current_user), Depends(verify_same_origin)],
    )
    def create_number(payload: NumberCreate) -> dict[str, Any]:
        return _store_call(store.create_number, **payload.model_dump())

    @app.patch(
        "/api/numbers/{number_id}",
        dependencies=[Depends(current_user), Depends(verify_same_origin)],
    )
    def update_number(number_id: int, payload: NumberUpdate) -> dict[str, Any]:
        return _store_call(
            store.update_number,
            number_id,
            payload.model_dump(exclude_unset=True, exclude_none=True),
        )

    @app.post(
        "/api/numbers/{number_id}/reset-usage",
        dependencies=[Depends(current_user), Depends(verify_same_origin)],
    )
    def reset_number_usage(number_id: int) -> dict[str, Any]:
        return _store_call(store.reset_number_usage, number_id)

    @app.get("/api/share-links")
    def share_links(
        _: Annotated[str, Depends(current_user)],
        limit: int = 20,
        offset: int = 0,
        key_status: Annotated[str, Query(alias="status")] = "",
    ) -> dict[str, object]:
        allowed = {"", "ready", "used"}
        if key_status not in allowed:
            raise HTTPException(status_code=422, detail="Key 状态无效")
        limit = min(max(limit, 1), 100)
        offset = max(offset, 0)
        items, total = store.list_share_links(
            limit=limit, offset=offset, status_filter=key_status
        )
        items = [
            item
            | {
                "share_url": (
                    f"{config.public_base_url}/c#t={item['token']}"
                    if item.get("token")
                    else None
                )
            }
            for item in items
        ]
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @app.get("/api/share-links/copy")
    def copy_share_links(
        _: Annotated[str, Depends(current_user)],
        key_status: Annotated[str, Query(alias="status")] = "",
    ) -> dict[str, str | int]:
        allowed = {"", "ready", "used"}
        if key_status not in allowed:
            raise HTTPException(status_code=422, detail="Key 状态无效")
        items, _ = store.list_share_links(
            limit=1_000_000, offset=0, status_filter=key_status
        )
        links = [
            f"{config.public_base_url}/c#t={item['token']}"
            for item in items
            if item.get("token")
        ]
        return {"text": "\t".join(links), "count": len(links)}

    @app.post(
        "/api/share-links/batch",
        status_code=201,
        dependencies=[Depends(current_user), Depends(verify_same_origin)],
    )
    def create_share_links(payload: KeyBatchCreate) -> dict[str, list[dict[str, Any]]]:
        current_settings = store.get_settings()
        lease_minutes = (
            payload.validity_hours * 60
            if payload.validity_hours
            else int(current_settings["default_lease_minutes"])
        )
        raw_tokens = [secrets.token_urlsafe(32) for _ in range(payload.count)]
        links = _store_call(
            store.create_share_links,
            digests=[token_digest(token) for token in raw_tokens],
            encrypted_tokens=[vault.encrypt(token) for token in raw_tokens],
            lease_minutes=lease_minutes,
        )
        return {
            "items": [
                link | {"share_url": f"{config.public_base_url}/c#t={token}"}
                for link, token in zip(links, raw_tokens, strict=True)
            ]
        }

    @app.post(
        "/api/share-links/revoke-batch",
        dependencies=[Depends(current_user), Depends(verify_same_origin)],
    )
    def revoke_share_links(payload: KeyBatchRevoke) -> dict[str, int]:
        return {"revoked": _store_call(store.revoke_share_links, payload.ids)}

    @app.post(
        "/api/share-links/{link_id}/revoke",
        status_code=204,
        dependencies=[Depends(current_user), Depends(verify_same_origin)],
    )
    def revoke_share_link(link_id: int) -> Response:
        _store_call(store.revoke_share_link, link_id)
        return Response(status_code=204)

    @app.get("/api/settings")
    def get_settings(_: Annotated[str, Depends(current_user)]) -> dict[str, Any]:
        current = store.get_settings()
        return {
            "default_validity_hours": int(current["default_lease_minutes"]) // 60,
            "webhook_url": f"{config.public_base_url}/api/webhooks/sms",
            "cookie_secure": config.cookie_secure,
            "max_codes": 3,
        }

    @app.patch(
        "/api/settings",
        dependencies=[Depends(current_user), Depends(verify_same_origin)],
    )
    def update_settings(payload: SettingsUpdate) -> dict[str, Any]:
        values = payload.model_dump(exclude_unset=True, exclude_none=True)
        validity_hours = values.pop("default_validity_hours", None)
        if validity_hours is not None:
            values["default_lease_minutes"] = validity_hours * 60
        result = store.update_settings(values)
        return {
            "default_validity_hours": int(result["default_lease_minutes"]) // 60,
            "webhook_url": f"{config.public_base_url}/api/webhooks/sms",
            "cookie_secure": config.cookie_secure,
            "max_codes": 3,
        }

    @app.post(
        "/api/settings/password",
        dependencies=[Depends(current_user), Depends(verify_same_origin)],
    )
    def change_password(payload: PasswordChange, response: Response) -> dict[str, str]:
        version = _store_call(
            store.change_admin_password, payload.current_password, payload.new_password
        )
        set_admin_cookie(response, version)
        return {"status": "updated"}

    @app.post(
        "/api/settings/webhook-token",
        dependencies=[Depends(current_user), Depends(verify_same_origin)],
    )
    def rotate_webhook_token() -> dict[str, str]:
        token = secrets.token_urlsafe(32)
        store.set_webhook_token(token)
        return {"token": token}

    @app.post("/api/public/session")
    def exchange_public_token(
        request: Request,
        response: Response,
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, Any]:
        client = client_address(request)
        if not exchange_limiter.allow(client):
            raise HTTPException(status_code=429, detail="请求过于频繁，请稍后重试")
        raw_token = extract_bearer_token(authorization)
        if raw_token is None:
            raise HTTPException(status_code=401, detail="链接无效")
        if not 32 <= len(raw_token) <= 128:
            raise HTTPException(status_code=401, detail="链接无效")
        try:
            state_payload = store.public_link_from_digest(token_digest(raw_token))
        except StoreGone as exc:
            raise HTTPException(status_code=410, detail=str(exc)) from exc
        except StoreNotFound as exc:
            raise HTTPException(status_code=401, detail="链接无效") from exc
        set_public_cookie(response, state_payload)
        return public_response(state_payload)

    @app.post("/api/public/claim")
    def claim_public_number(
        request: Request,
        response: Response,
        link_id: Annotated[int, Depends(current_public_link)],
    ) -> dict[str, Any]:
        key = f"{client_address(request)}:{link_id}"
        if not claim_limiter.allow(key):
            raise HTTPException(status_code=429, detail="请求过于频繁，请稍后重试")
        state_payload = _store_call(store.claim_number, link_id)
        set_public_cookie(response, state_payload)
        return public_response(state_payload)

    @app.get("/api/public/state")
    def get_public_state(
        request: Request,
        link_id: Annotated[int, Depends(current_public_link)],
    ) -> dict[str, Any]:
        key = f"{client_address(request)}:{link_id}"
        if not state_limiter.allow(key):
            raise HTTPException(status_code=429, detail="刷新过于频繁，请稍后重试")
        return public_response(_store_call(store.public_state, link_id))

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/c", include_in_schema=False)
    def claim_frontend() -> FileResponse:
        return FileResponse(STATIC_DIR / "claim.html")

    @app.get("/{path:path}", include_in_schema=False)
    def frontend(path: str) -> FileResponse:
        if path == "api" or path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not Found")
        return FileResponse(STATIC_DIR / "index.html")

    return app


def _store_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except StoreNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except StoreConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except StoreGone as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc


app = create_app()
