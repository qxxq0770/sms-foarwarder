from __future__ import annotations

import hmac
import re
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from app.security import Vault, hash_password, token_digest, verify_password


DEFAULT_CODE_PATTERN = r"(?<!\d)(\d{4,8})(?!\d)"
MAX_PUBLIC_CODES = 2


class StoreNotFound(Exception):
    pass


class StoreConflict(Exception):
    pass


class StoreGone(Exception):
    pass


class MessageStore:
    def __init__(self, path: Path, vault: Vault):
        self._path = path
        self._vault = vault

    def initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )
                """
            )
            applied = {
                int(row["version"])
                for row in connection.execute("SELECT version FROM schema_migrations")
            }
            for version, migration in (
                (1, self._migration_1),
                (2, self._migration_2),
                (3, self._migration_3),
                (4, self._migration_4),
                (5, self._migration_5),
                (6, self._migration_6),
                (7, self._migration_7),
                (8, self._migration_8),
                (9, self._migration_9),
                (10, self._migration_10),
                (11, self._migration_11),
                (12, self._migration_12),
                (13, self._migration_13),
            ):
                if version not in applied:
                    migration(connection)
                    self._record_migration(connection, version)
                    connection.commit()

    def _migration_1(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                delivery_id TEXT NOT NULL UNIQUE,
                rule_id TEXT NOT NULL,
                sender_encrypted TEXT NOT NULL,
                sender_suffix TEXT NOT NULL,
                message_encrypted TEXT NOT NULL,
                received_at TEXT NOT NULL,
                is_test INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at DESC)"
        )

    def _migration_2(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                country_code TEXT NOT NULL,
                country_name TEXT NOT NULL,
                sender_pattern TEXT NOT NULL,
                code_pattern TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(name, country_code)
            );
            CREATE TABLE IF NOT EXISTS numbers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                number_encrypted TEXT NOT NULL,
                number_fingerprint TEXT NOT NULL UNIQUE,
                number_suffix TEXT NOT NULL,
                country_code TEXT NOT NULL,
                country_name TEXT NOT NULL,
                max_assignments INTEGER NOT NULL,
                assignment_count INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS number_services (
                number_id INTEGER NOT NULL REFERENCES numbers(id) ON DELETE CASCADE,
                service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE RESTRICT,
                PRIMARY KEY(number_id, service_id)
            );
            CREATE TABLE IF NOT EXISTS share_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_digest TEXT NOT NULL UNIQUE,
                service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE RESTRICT,
                expires_at TEXT NOT NULL,
                lease_minutes INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                assigned_number_id INTEGER REFERENCES numbers(id) ON DELETE RESTRICT,
                assignment_id INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                share_link_id INTEGER NOT NULL UNIQUE REFERENCES share_links(id) ON DELETE RESTRICT,
                number_id INTEGER NOT NULL REFERENCES numbers(id) ON DELETE RESTRICT,
                service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE RESTRICT,
                started_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ended_at TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                code_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assignment_id INTEGER NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
                message_id INTEGER NOT NULL UNIQUE REFERENCES messages(id) ON DELETE CASCADE,
                code_encrypted TEXT NOT NULL,
                sender_masked TEXT NOT NULL,
                received_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_numbers_inventory
                ON numbers(country_code, enabled, assignment_count);
            CREATE INDEX IF NOT EXISTS idx_assignments_number_status
                ON assignments(number_id, status, expires_at);
            CREATE INDEX IF NOT EXISTS idx_share_links_digest ON share_links(token_digest);
            """
        )
        self._add_column(connection, "messages", "recipient_encrypted", "TEXT")
        self._add_column(connection, "messages", "recipient_fingerprint", "TEXT")
        self._add_column(connection, "messages", "recipient_suffix", "TEXT")
        self._add_column(connection, "messages", "assignment_id", "INTEGER")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_fingerprint)"
        )

    def _migration_3(self, connection: sqlite3.Connection) -> None:
        self._add_column(
            connection, "share_links", "token_version", "INTEGER NOT NULL DEFAULT 1"
        )

    def _migration_4(self, connection: sqlite3.Connection) -> None:
        connection.commit()
        connection.execute("PRAGMA foreign_keys=OFF")
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE share_links_v4 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_digest TEXT NOT NULL UNIQUE,
                    expires_at TEXT NOT NULL,
                    lease_minutes INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    assigned_number_id INTEGER REFERENCES numbers(id) ON DELETE RESTRICT,
                    assignment_id INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    token_version INTEGER NOT NULL DEFAULT 1
                );
                INSERT INTO share_links_v4 (
                    id, token_digest, expires_at, lease_minutes, status,
                    assigned_number_id, assignment_id, created_at, updated_at, token_version
                )
                SELECT id, token_digest, expires_at, lease_minutes, status,
                       assigned_number_id, assignment_id, created_at, updated_at, token_version
                FROM share_links;

                CREATE TABLE assignments_v4 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    share_link_id INTEGER NOT NULL UNIQUE REFERENCES share_links_v4(id) ON DELETE RESTRICT,
                    number_id INTEGER NOT NULL REFERENCES numbers(id) ON DELETE RESTRICT,
                    started_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    ended_at TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    code_count INTEGER NOT NULL DEFAULT 0
                );
                INSERT INTO assignments_v4 (
                    id, share_link_id, number_id, started_at, expires_at,
                    ended_at, status, code_count
                )
                SELECT id, share_link_id, number_id, started_at, expires_at,
                       ended_at, status, code_count
                FROM assignments;

                CREATE TABLE codes_v4 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assignment_id INTEGER NOT NULL REFERENCES assignments_v4(id) ON DELETE CASCADE,
                    message_id INTEGER NOT NULL UNIQUE REFERENCES messages(id) ON DELETE CASCADE,
                    code_encrypted TEXT NOT NULL,
                    sender_masked TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                INSERT INTO codes_v4
                SELECT id, assignment_id, message_id, code_encrypted,
                       sender_masked, received_at, created_at
                FROM codes;

                DROP TABLE codes;
                DROP TABLE assignments;
                DROP TABLE share_links;
                DROP TABLE number_services;
                DROP TABLE services;
                ALTER TABLE share_links_v4 RENAME TO share_links;
                ALTER TABLE assignments_v4 RENAME TO assignments;
                ALTER TABLE codes_v4 RENAME TO codes;

                CREATE INDEX idx_assignments_number_status
                    ON assignments(number_id, status, expires_at);
                CREATE INDEX idx_share_links_digest ON share_links(token_digest);

                CREATE TABLE app_settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    sender_pattern TEXT NOT NULL,
                    code_pattern TEXT NOT NULL,
                    default_link_hours INTEGER NOT NULL,
                    default_lease_minutes INTEGER NOT NULL,
                    retention_days INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE admin_credentials (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    auth_version INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL
                );
                COMMIT;
                """
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.execute("PRAGMA foreign_keys=ON")

    def _migration_5(self, connection: sqlite3.Connection) -> None:
        connection.commit()
        connection.execute("PRAGMA foreign_keys=OFF")
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE share_links_v5 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_digest TEXT NOT NULL UNIQUE,
                    lease_minutes INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    token_version INTEGER NOT NULL DEFAULT 1
                );
                INSERT INTO share_links_v5 (
                    id, token_digest, lease_minutes, status,
                    created_at, updated_at, token_version
                )
                SELECT id, token_digest, lease_minutes, status,
                       created_at, updated_at, token_version
                FROM share_links;

                CREATE TABLE assignments_v5 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    share_link_id INTEGER NOT NULL UNIQUE REFERENCES share_links_v5(id) ON DELETE RESTRICT,
                    number_id INTEGER NOT NULL REFERENCES numbers(id) ON DELETE RESTRICT,
                    started_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    ended_at TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    code_count INTEGER NOT NULL DEFAULT 0
                );
                INSERT INTO assignments_v5 (
                    id, share_link_id, number_id, started_at, expires_at,
                    ended_at, status, code_count
                )
                SELECT id, share_link_id, number_id, started_at, expires_at,
                       ended_at, status, code_count
                FROM assignments;

                CREATE TABLE codes_v5 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assignment_id INTEGER NOT NULL REFERENCES assignments_v5(id) ON DELETE CASCADE,
                    message_id INTEGER NOT NULL UNIQUE REFERENCES messages(id) ON DELETE CASCADE,
                    code_encrypted TEXT NOT NULL,
                    sender_masked TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                INSERT INTO codes_v5
                SELECT id, assignment_id, message_id, code_encrypted,
                       sender_masked, received_at, created_at
                FROM codes;

                DROP TABLE codes;
                DROP TABLE assignments;
                DROP TABLE share_links;
                ALTER TABLE share_links_v5 RENAME TO share_links;
                ALTER TABLE assignments_v5 RENAME TO assignments;
                ALTER TABLE codes_v5 RENAME TO codes;

                CREATE INDEX idx_assignments_number_status
                    ON assignments(number_id, status, expires_at);
                CREATE INDEX idx_share_links_digest ON share_links(token_digest);
                COMMIT;
                """
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.execute("PRAGMA foreign_keys=ON")

    @staticmethod
    def _migration_6(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            UPDATE app_settings
            SET default_lease_minutes = 720, updated_at = ?
            WHERE default_lease_minutes NOT IN (720, 1440)
            """,
            (_iso(_utc_now()),),
        )

    def _migration_7(self, connection: sqlite3.Connection) -> None:
        self._add_column(connection, "share_links", "token_encrypted", "TEXT")

    def _migration_8(self, connection: sqlite3.Connection) -> None:
        self._refresh_expired(connection, _iso(_utc_now()))

    def _migration_9(self, connection: sqlite3.Connection) -> None:
        self._add_column(connection, "app_settings", "webhook_token_digest", "TEXT")

    def _migration_10(self, connection: sqlite3.Connection) -> None:
        connection.commit()
        connection.execute("PRAGMA foreign_keys=OFF")
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE codes_v10 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assignment_id INTEGER NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
                    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                    code_encrypted TEXT NOT NULL,
                    sender_masked TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                INSERT INTO codes_v10
                SELECT id, assignment_id, message_id, code_encrypted,
                       sender_masked, received_at, created_at
                FROM codes;
                DROP TABLE codes;
                ALTER TABLE codes_v10 RENAME TO codes;
                CREATE UNIQUE INDEX idx_codes_assignment_message
                    ON codes(assignment_id, message_id);
                CREATE INDEX idx_codes_message ON codes(message_id);
                COMMIT;
                """
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.execute("PRAGMA foreign_keys=ON")

    def _migration_11(self, connection: sqlite3.Connection) -> None:
        now = _iso(_utc_now())
        connection.execute(
            """
            UPDATE assignments
            SET status = 'active', ended_at = NULL
            WHERE status = 'completed' AND expires_at > ?
            """,
            (now,),
        )
        self._sync_assignment_counts(connection, now)

    def _migration_12(self, connection: sqlite3.Connection) -> None:
        now = _iso(_utc_now())
        connection.execute(
            """
            UPDATE assignments
            SET code_count = MIN((
                    SELECT COUNT(*) FROM codes c
                    WHERE c.assignment_id = assignments.id
                ), ?)
            """,
            (MAX_PUBLIC_CODES,),
        )
        connection.execute(
            """
            UPDATE assignments
            SET status = 'completed', ended_at = COALESCE(ended_at, ?)
            WHERE status = 'active'
              AND expires_at > ?
              AND (
                  SELECT COUNT(*) FROM codes c
                  WHERE c.assignment_id = assignments.id
              ) >= ?
            """,
            (now, now, MAX_PUBLIC_CODES),
        )
        self._sync_assignment_counts(connection, now)

    def _migration_13(self, connection: sqlite3.Connection) -> None:
        self._refresh_expired(connection, _iso(_utc_now()))

    @staticmethod
    def _add_column(
        connection: sqlite3.Connection, table: str, column: str, definition: str
    ) -> None:
        columns = {
            row["name"] for row in connection.execute(f"PRAGMA table_info({table})")
        }
        if column not in columns:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    @staticmethod
    def _record_migration(connection: sqlite3.Connection, version: int) -> None:
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (version, _iso(_utc_now())),
        )

    def ensure_bootstrap(self, password: str, webhook_token: str) -> None:
        now = _iso(_utc_now())
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO app_settings (
                    id, sender_pattern, code_pattern, default_link_hours,
                    default_lease_minutes, retention_days, updated_at
                ) VALUES (1, '.*', ?, 24, 720, ?, ?)
                """,
                (DEFAULT_CODE_PATTERN, 30, now),
            )
            connection.execute(
                """
                UPDATE app_settings
                SET webhook_token_digest = ?, updated_at = ?
                WHERE id = 1 AND webhook_token_digest IS NULL
                """,
                (token_digest(webhook_token), now),
            )
            row = connection.execute(
                "SELECT 1 FROM admin_credentials WHERE id = 1"
            ).fetchone()
            if row is None:
                salt, digest = hash_password(password)
                connection.execute(
                    """
                    INSERT INTO admin_credentials (
                        id, password_salt, password_hash, auth_version, updated_at
                    ) VALUES (1, ?, ?, 1, ?)
                    """,
                    (salt, digest, now),
                )

    def verify_webhook_token(self, token: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT webhook_token_digest FROM app_settings WHERE id = 1"
            ).fetchone()
            if row is None or not row["webhook_token_digest"]:
                return False
            return hmac.compare_digest(
                token_digest(token), str(row["webhook_token_digest"])
            )

    def set_webhook_token(self, token: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE app_settings
                SET webhook_token_digest = ?, updated_at = ?
                WHERE id = 1
                """,
                (token_digest(token), _iso(_utc_now())),
            )

    def get_settings(self) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM app_settings WHERE id = 1").fetchone()
            if row is None:
                raise StoreNotFound("系统设置不存在")
            return dict(row)

    def update_settings(self, values: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "sender_pattern",
            "code_pattern",
            "default_lease_minutes",
        }
        changes = {key: value for key, value in values.items() if key in allowed}
        if not changes:
            return self.get_settings()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE app_settings
                SET sender_pattern = COALESCE(?, sender_pattern),
                    code_pattern = COALESCE(?, code_pattern),
                    default_lease_minutes = COALESCE(?, default_lease_minutes),
                    updated_at = ?
                WHERE id = 1
                """,
                (
                    changes.get("sender_pattern"),
                    changes.get("code_pattern"),
                    changes.get("default_lease_minutes"),
                    _iso(_utc_now()),
                ),
            )
            row = connection.execute("SELECT * FROM app_settings WHERE id = 1").fetchone()
            return dict(row)

    def verify_admin_password(self, password: str) -> tuple[bool, int]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT password_salt, password_hash, auth_version FROM admin_credentials WHERE id = 1"
            ).fetchone()
            if row is None:
                return False, 0
            return (
                verify_password(password, row["password_salt"], row["password_hash"]),
                int(row["auth_version"]),
            )

    def auth_version(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT auth_version FROM admin_credentials WHERE id = 1"
            ).fetchone()
            if row is None:
                raise StoreNotFound("管理员凭据不存在")
            return int(row["auth_version"])

    def change_admin_password(self, current_password: str, new_password: str) -> int:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM admin_credentials WHERE id = 1"
            ).fetchone()
            if row is None or not verify_password(
                current_password, row["password_salt"], row["password_hash"]
            ):
                raise StoreConflict("当前密码错误")
            salt, digest = hash_password(new_password)
            version = int(row["auth_version"]) + 1
            connection.execute(
                """
                UPDATE admin_credentials
                SET password_salt = ?, password_hash = ?, auth_version = ?, updated_at = ?
                WHERE id = 1
                """,
                (salt, digest, version, _iso(_utc_now())),
            )
            return version

    def reset_admin_password(self, new_password: str) -> int:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            salt, digest = hash_password(new_password)
            row = connection.execute(
                "SELECT auth_version FROM admin_credentials WHERE id = 1"
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO admin_credentials
                    (id, password_salt, password_hash, auth_version, updated_at)
                    VALUES (1, ?, ?, 1, ?)
                    """,
                    (salt, digest, _iso(_utc_now())),
                )
                return 1
            version = int(row["auth_version"]) + 1
            connection.execute(
                """
                UPDATE admin_credentials
                SET password_salt = ?, password_hash = ?, auth_version = ?, updated_at = ?
                WHERE id = 1
                """,
                (salt, digest, version, _iso(_utc_now())),
            )
            return version

    def add(
        self,
        *,
        delivery_id: str,
        rule_id: str,
        sender: str,
        message: str,
        received_at: datetime,
        is_test: bool,
        recipient: str | None = None,
    ) -> tuple[int, bool]:
        now = _iso(_utc_now())
        normalized_recipient = normalize_number(recipient) if recipient else None
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO messages (
                    delivery_id, rule_id, sender_encrypted, sender_suffix,
                    message_encrypted, received_at, is_test, created_at,
                    recipient_encrypted, recipient_fingerprint, recipient_suffix
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    delivery_id,
                    rule_id,
                    self._vault.encrypt(sender),
                    _sender_suffix(sender),
                    self._vault.encrypt(message),
                    _iso(received_at.astimezone(UTC)),
                    int(is_test),
                    now,
                    self._vault.encrypt(recipient) if recipient else None,
                    self._vault.fingerprint(normalized_recipient)
                    if normalized_recipient
                    else None,
                    _sender_suffix(recipient) if recipient else None,
                ),
            )
            if cursor.rowcount == 1:
                return int(cursor.lastrowid), True
            row = connection.execute(
                "SELECT id FROM messages WHERE delivery_id = ?", (delivery_id,)
            ).fetchone()
            return int(row["id"]), False

    def route_message(
        self,
        *,
        message_id: int,
        sender: str,
        recipient: str,
        message: str,
        received_at: datetime,
    ) -> bool:
        normalized = normalize_number(recipient)
        if not normalized:
            return False
        try:
            match = re.search(DEFAULT_CODE_PATTERN, message)
        except re.error:
            return False
        if match is None:
            return False
        code = (match.group(1) if match.lastindex else match.group(0)).strip()
        if not code or len(code) > 64:
            return False
        recipient_fingerprint = self._vault.fingerprint(normalized)
        received_iso = _iso(received_at.astimezone(UTC))
        now_iso = _iso(_utc_now())
        with self._connect() as connection:
            self._refresh_expired(connection, now_iso)
            rows = connection.execute(
                """
                SELECT a.id AS assignment_id, a.number_id, a.code_count
                FROM assignments a
                JOIN numbers n ON n.id = a.number_id
                JOIN share_links l ON l.id = a.share_link_id
                WHERE n.number_fingerprint = ?
                  AND a.status = 'active'
                  AND l.status = 'active'
                  AND a.started_at <= ? AND a.expires_at >= ?
                ORDER BY a.started_at DESC
                """,
                (recipient_fingerprint, received_iso, received_iso),
            ).fetchall()
            routed_assignment_id: int | None = None
            completed_any = False
            for row in rows:
                existing_codes = connection.execute(
                    "SELECT code_encrypted FROM codes WHERE assignment_id = ?",
                    (row["assignment_id"],),
                ).fetchall()
                if len(existing_codes) >= MAX_PUBLIC_CODES:
                    connection.execute(
                        """
                        UPDATE assignments
                        SET code_count = ?, status = 'completed',
                            ended_at = COALESCE(ended_at, ?)
                        WHERE id = ? AND status = 'active'
                        """,
                        (MAX_PUBLIC_CODES, now_iso, row["assignment_id"]),
                    )
                    completed_any = True
                    continue
                if any(
                    self._vault.decrypt(existing["code_encrypted"]) == code
                    for existing in existing_codes
                ):
                    continue
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO codes (
                        assignment_id, message_id, code_encrypted,
                        sender_masked, received_at, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["assignment_id"],
                        message_id,
                        self._vault.encrypt(code),
                        f"****{_sender_suffix(sender)}" if sender else "未知来源",
                        received_iso,
                        now_iso,
                    ),
                )
                if cursor.rowcount != 1:
                    continue
                if routed_assignment_id is None:
                    routed_assignment_id = int(row["assignment_id"])
                code_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM codes WHERE assignment_id = ?",
                        (row["assignment_id"],),
                    ).fetchone()[0]
                )
                if code_count >= MAX_PUBLIC_CODES:
                    connection.execute(
                        """
                        UPDATE assignments
                        SET code_count = ?, status = 'completed', ended_at = ?
                        WHERE id = ?
                        """,
                        (MAX_PUBLIC_CODES, now_iso, row["assignment_id"]),
                    )
                    completed_any = True
                else:
                    connection.execute(
                        "UPDATE assignments SET code_count = ? WHERE id = ?",
                        (code_count, row["assignment_id"]),
                    )
            if routed_assignment_id is not None:
                connection.execute(
                    "UPDATE messages SET assignment_id = ? WHERE id = ?",
                    (routed_assignment_id, message_id),
                )
                if completed_any:
                    self._sync_assignment_counts(connection, now_iso)
                return True
        return False

    def list_messages(
        self, *, limit: int, offset: int, query: str = ""
    ) -> tuple[list[dict[str, Any]], int]:
        with self._connect() as connection:
            if query:
                rows = connection.execute(
                    """
                    SELECT m.*, a.share_link_id,
                           l.token_encrypted AS share_token_encrypted
                    FROM messages m
                    LEFT JOIN assignments a ON a.id = m.assignment_id
                    LEFT JOIN share_links l ON l.id = a.share_link_id
                    ORDER BY m.received_at DESC
                    LIMIT 1000
                    """
                ).fetchall()
                needle = query.casefold()
                matches = []
                for row in rows:
                    full = self._decode_message(row)
                    if (
                        needle in full["sender"].casefold()
                        or needle in full["message"].casefold()
                        or needle in full["rule_id"].casefold()
                        or needle in (full["recipient"] or "").casefold()
                        or needle in (full["key"] or "").casefold()
                        or needle in (str(full["share_link_id"]) if full["share_link_id"] else "")
                    ):
                        matches.append(self._message_summary(full))
                return matches[offset : offset + limit], len(matches)
            total = int(connection.execute("SELECT COUNT(*) FROM messages").fetchone()[0])
            rows = connection.execute(
                """
                SELECT m.*, a.share_link_id,
                       l.token_encrypted AS share_token_encrypted
                FROM messages m
                LEFT JOIN assignments a ON a.id = m.assignment_id
                LEFT JOIN share_links l ON l.id = a.share_link_id
                ORDER BY m.received_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
            return [self._message_summary(self._decode_message(row)) for row in rows], total

    def get_message(self, message_id: int) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT m.*, a.share_link_id,
                       l.token_encrypted AS share_token_encrypted
                FROM messages m
                LEFT JOIN assignments a ON a.id = m.assignment_id
                LEFT JOIN share_links l ON l.id = a.share_link_id
                WHERE m.id = ?
                """,
                (message_id,),
            ).fetchone()
            if row is None:
                raise StoreNotFound("短信不存在")
            return self._decode_message(row)

    def stats(self) -> dict[str, Any]:
        today = _utc_now().date().isoformat()
        now = _iso(_utc_now())
        with self._connect() as connection:
            self._refresh_expired(connection, now)
            return {
                "available_numbers": int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM numbers n
                        WHERE n.enabled = 1
                          AND n.assignment_count < n.max_assignments
                        """
                    ).fetchone()[0]
                ),
                "available_uses": int(
                    connection.execute(
                        """
                        SELECT COALESCE(SUM(MAX(0, max_assignments - assignment_count)), 0)
                        FROM numbers
                        WHERE enabled = 1
                        """
                    ).fetchone()[0]
                ),
                "active_assignments": int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM assignments
                        WHERE status IN ('active', 'completed') AND expires_at > ?
                        """,
                        (now,),
                    ).fetchone()[0]
                ),
                "ready_keys": int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM share_links l
                        WHERE l.status = 'active' AND NOT EXISTS (
                            SELECT 1 FROM assignments a WHERE a.share_link_id = l.id
                        )
                        """,
                    ).fetchone()[0]
                ),
                "messages_today": int(
                    connection.execute(
                        "SELECT COUNT(*) FROM messages WHERE received_at >= ?", (today,)
                    ).fetchone()[0]
                ),
            }

    def delete(self, message_id: int) -> bool:
        with self._connect() as connection:
            return connection.execute(
                "DELETE FROM messages WHERE id = ?", (message_id,)
            ).rowcount == 1

    def create_number(
        self,
        *,
        number: str,
        country_code: str,
        country_name: str,
        max_assignments: int,
    ) -> dict[str, Any]:
        normalized = normalize_number(number)
        if not normalized:
            raise StoreConflict("号码格式无效")
        now = _iso(_utc_now())
        with self._connect() as connection:
            try:
                cursor = connection.execute(
                    """
                    INSERT INTO numbers (
                        number_encrypted, number_fingerprint, number_suffix,
                        country_code, country_name, max_assignments,
                        assignment_count, enabled, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, ?)
                    """,
                    (
                        self._vault.encrypt(number),
                        self._vault.fingerprint(normalized),
                        _sender_suffix(number),
                        country_code.upper(),
                        country_name,
                        max_assignments,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreConflict("该号码已存在") from exc
            return self._number_by_id(connection, int(cursor.lastrowid))

    def list_numbers(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            self._refresh_expired(connection, _iso(_utc_now()))
            rows = connection.execute(
                "SELECT * FROM numbers ORDER BY enabled DESC, assignment_count, id"
            ).fetchall()
            return [self._decode_number(row) for row in rows]

    def update_number(self, number_id: int, values: dict[str, Any]) -> dict[str, Any]:
        allowed = {"number", "country_code", "country_name", "max_assignments", "enabled"}
        changes = {key: value for key, value in values.items() if key in allowed}
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM numbers WHERE id = ?", (number_id,)).fetchone()
            if row is None:
                raise StoreNotFound("号码不存在")
            if "number" in changes:
                number = changes.pop("number")
                normalized = normalize_number(number)
                if not normalized:
                    raise StoreConflict("号码格式无效")
                changes.update(
                    {
                        "number_encrypted": self._vault.encrypt(number),
                        "number_fingerprint": self._vault.fingerprint(normalized),
                        "number_suffix": _sender_suffix(number),
                    }
                )
            if "country_code" in changes:
                changes["country_code"] = str(changes["country_code"]).upper()
            if "enabled" in changes:
                changes["enabled"] = int(changes["enabled"])
            try:
                connection.execute(
                    """
                    UPDATE numbers
                    SET number_encrypted = ?, number_fingerprint = ?, number_suffix = ?,
                        country_code = ?, country_name = ?, max_assignments = ?,
                        enabled = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        changes.get("number_encrypted", row["number_encrypted"]),
                        changes.get("number_fingerprint", row["number_fingerprint"]),
                        changes.get("number_suffix", row["number_suffix"]),
                        changes.get("country_code", row["country_code"]),
                        changes.get("country_name", row["country_name"]),
                        changes.get("max_assignments", row["max_assignments"]),
                        changes.get("enabled", row["enabled"]),
                        _iso(_utc_now()),
                        number_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreConflict("该号码已存在") from exc
            return self._number_by_id(connection, number_id)

    def reset_number_usage(self, number_id: int) -> dict[str, Any]:
        now = _iso(_utc_now())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._refresh_expired(connection, now)
            self._number_by_id(connection, number_id)
            cursor = connection.execute(
                """
                UPDATE assignments
                SET status = 'revoked', ended_at = ?
                WHERE number_id = ? AND status IN ('active', 'completed')
                """,
                (now, number_id),
            )
            self._sync_assignment_counts(connection, now)
            return self._number_by_id(connection, number_id) | {
                "reset_assignments": cursor.rowcount
            }

    def create_share_links(
        self, *, digests: list[str], encrypted_tokens: list[str], lease_minutes: int
    ) -> list[dict[str, Any]]:
        if len(digests) != len(encrypted_tokens):
            raise StoreConflict("密钥数据不完整")
        now = _iso(_utc_now())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            ids = []
            for digest, encrypted_token in zip(digests, encrypted_tokens, strict=True):
                cursor = connection.execute(
                    """
                    INSERT INTO share_links (
                        token_digest, token_encrypted, lease_minutes, status, created_at, updated_at
                    ) VALUES (?, ?, ?, 'active', ?, ?)
                    """,
                    (digest, encrypted_token, lease_minutes, now, now),
                )
                ids.append(int(cursor.lastrowid))
            return [self._share_link_by_id(connection, link_id) for link_id in ids]

    def list_share_links(
        self,
        *,
        limit: int,
        offset: int,
        status_filter: str = "",
        lease_minutes_filter: int | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        now = _iso(_utc_now())
        with self._connect() as connection:
            self._refresh_expired(connection, now)
            rows = connection.execute(
                """
                SELECT l.*, a.id AS assignment_id, a.started_at,
                       a.expires_at AS assignment_expires_at,
                       a.status AS assignment_status, a.code_count
                FROM share_links l
                LEFT JOIN assignments a ON a.share_link_id = l.id
                WHERE (? IS NULL OR l.lease_minutes = ?)
                ORDER BY l.created_at DESC, l.id DESC
                """,
                (lease_minutes_filter, lease_minutes_filter),
            ).fetchall()
            decoded = [self._decode_share_link(row) for row in rows]
            if status_filter:
                decoded = [item for item in decoded if item["display_status"] == status_filter]
            return decoded[offset : offset + limit], len(decoded)

    def revoke_share_links(self, link_ids: list[int]) -> int:
        now = _iso(_utc_now())
        unique_ids = list(dict.fromkeys(link_ids))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._refresh_expired(connection, now)
            changed = 0
            for link_id in unique_ids:
                row = connection.execute(
                    "SELECT status FROM share_links WHERE id = ?", (link_id,)
                ).fetchone()
                if row is None:
                    raise StoreNotFound("Key 不存在")
                if row["status"] == "revoked":
                    continue
                connection.execute(
                    "UPDATE share_links SET status = 'revoked', updated_at = ? WHERE id = ?",
                    (now, link_id),
                )
                connection.execute(
                    """
                    UPDATE assignments SET status = 'revoked', ended_at = ?
                    WHERE share_link_id = ? AND status IN ('active', 'completed')
                    """,
                    (now, link_id),
                )
                changed += 1
            self._sync_assignment_counts(connection, now)
            return changed

    def revoke_share_link(self, link_id: int) -> None:
        self.revoke_share_links([link_id])

    def public_link_from_digest(self, digest: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT id FROM share_links WHERE token_digest = ?", (digest,)
            ).fetchone()
            if row is None:
                raise StoreNotFound("链接无效")
            return self._public_state(connection, int(row["id"]))

    def public_link_id_from_digest(self, digest: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT id, status FROM share_links WHERE token_digest = ?", (digest,)
            ).fetchone()
            if row is None:
                raise StoreNotFound("链接无效")
            if row["status"] != "active":
                raise StoreGone("链接已撤销")
            return int(row["id"])

    def public_state(self, link_id: int) -> dict[str, Any]:
        with self._connect() as connection:
            return self._public_state(connection, link_id)

    def public_session_version(self, link_id: int) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT token_version FROM share_links WHERE id = ?", (link_id,)
            ).fetchone()
            if row is None:
                raise StoreNotFound("链接无效")
            return int(row["token_version"])

    def claim_number(self, link_id: int) -> dict[str, Any]:
        now = _utc_now()
        now_iso = _iso(now)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._refresh_expired(connection, now_iso)
            link = connection.execute(
                "SELECT * FROM share_links WHERE id = ?", (link_id,)
            ).fetchone()
            if link is None:
                raise StoreNotFound("链接无效")
            if link["status"] != "active":
                raise StoreGone("链接已撤销")
            existing = connection.execute(
                "SELECT id FROM assignments WHERE share_link_id = ?", (link_id,)
            ).fetchone()
            if existing is not None:
                return self._public_state(connection, link_id)
            number = connection.execute(
                """
                SELECT n.* FROM numbers n
                WHERE n.enabled = 1
                  AND n.assignment_count < n.max_assignments
                ORDER BY n.assignment_count ASC, n.id ASC
                LIMIT 1
                """
            ).fetchone()
            if number is None:
                raise StoreConflict("当前没有可用号码，请稍后重试")
            expires_at = now + timedelta(minutes=int(link["lease_minutes"]))
            connection.execute(
                """
                INSERT INTO assignments (
                    share_link_id, number_id, started_at, expires_at, status, code_count
                ) VALUES (?, ?, ?, ?, 'active', 0)
                """,
                (link_id, number["id"], now_iso, _iso(expires_at)),
            )
            connection.execute(
                "UPDATE share_links SET updated_at = ? WHERE id = ?",
                (now_iso, link_id),
            )
            self._sync_assignment_counts(connection, now_iso)
            return self._public_state(connection, link_id)

    def _public_state(self, connection: sqlite3.Connection, link_id: int) -> dict[str, Any]:
        now = _utc_now()
        self._refresh_expired(connection, _iso(now))
        row = connection.execute(
            """
            SELECT l.*, a.id AS assignment_id, n.number_encrypted, n.number_suffix,
                   a.started_at, a.expires_at AS assignment_expires_at,
                   a.status AS assignment_status, a.code_count
            FROM share_links l
            LEFT JOIN assignments a ON a.share_link_id = l.id
            LEFT JOIN numbers n ON n.id = a.number_id
            WHERE l.id = ?
            """,
            (link_id,),
        ).fetchone()
        if row is None:
            raise StoreNotFound("链接无效")
        if row["status"] != "active":
            raise StoreGone("链接已撤销")
        if row["assignment_id"] is not None and _parse(row["assignment_expires_at"]) <= now:
            raise StoreGone("接码窗口已结束")
        result: dict[str, Any] = {
            "link_id": row["id"],
            "token_version": row["token_version"],
            "lease_minutes": row["lease_minutes"],
            "assigned": row["assignment_id"] is not None,
            "max_codes": MAX_PUBLIC_CODES,
        }
        if row["assignment_id"] is None:
            result.update({"status": "ready", "codes": [], "code_count": 0})
            return result
        codes = connection.execute(
            """
            SELECT code_encrypted, received_at
            FROM codes
            WHERE assignment_id = ?
            ORDER BY received_at DESC, id DESC
            LIMIT ?
            """,
            (row["assignment_id"], MAX_PUBLIC_CODES),
        ).fetchall()
        codes = list(reversed(codes))
        latest_code = codes[-1] if codes else None
        result.update(
            {
                "status": row["assignment_status"],
                "number": self._vault.decrypt(row["number_encrypted"]),
                "started_at": row["started_at"],
                "expires_at": row["assignment_expires_at"],
                "code_count": len(codes),
                "latest_code": (
                    {
                        "code": self._vault.decrypt(latest_code["code_encrypted"]),
                        "expires_at": _iso(
                            _parse(latest_code["received_at"]) + timedelta(seconds=60)
                        ),
                    }
                    if latest_code
                    else None
                ),
                "codes": [
                    {"code": self._vault.decrypt(code["code_encrypted"])}
                    for code in codes
                ],
            }
        )
        return result

    @staticmethod
    def _refresh_expired(connection: sqlite3.Connection, now_iso: str) -> None:
        connection.execute(
            """
            UPDATE assignments SET status = 'expired', ended_at = expires_at
            WHERE status IN ('active', 'completed') AND expires_at <= ?
            """,
            (now_iso,),
        )
        MessageStore._sync_assignment_counts(connection, now_iso)

    @staticmethod
    def _sync_assignment_counts(connection: sqlite3.Connection, now_iso: str) -> None:
        connection.execute(
            """
            UPDATE numbers
            SET assignment_count = (
                    SELECT COUNT(*) FROM assignments a
                    WHERE a.number_id = numbers.id
                      AND a.status IN ('active', 'completed')
                      AND a.expires_at > ?
                ),
                updated_at = CASE
                    WHEN assignment_count != (
                        SELECT COUNT(*) FROM assignments a
                        WHERE a.number_id = numbers.id
                          AND a.status IN ('active', 'completed')
                          AND a.expires_at > ?
                    ) THEN ?
                    ELSE updated_at
                END
            """,
            (now_iso, now_iso, now_iso),
        )

    def _number_by_id(self, connection: sqlite3.Connection, number_id: int) -> dict[str, Any]:
        row = connection.execute("SELECT * FROM numbers WHERE id = ?", (number_id,)).fetchone()
        if row is None:
            raise StoreNotFound("号码不存在")
        return self._decode_number(row)

    def _decode_number(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "number": self._vault.decrypt(row["number_encrypted"]),
            "number_masked": f"****{row['number_suffix']}",
            "country_code": row["country_code"],
            "country_name": row["country_name"],
            "max_assignments": row["max_assignments"],
            "assignment_count": row["assignment_count"],
            "remaining_assignments": max(0, row["max_assignments"] - row["assignment_count"]),
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _share_link_by_id(self, connection: sqlite3.Connection, link_id: int) -> dict[str, Any]:
        row = connection.execute(
            """
            SELECT l.*, a.id AS assignment_id, a.started_at,
                   a.expires_at AS assignment_expires_at,
                   a.status AS assignment_status, a.code_count
            FROM share_links l
            LEFT JOIN assignments a ON a.share_link_id = l.id
            WHERE l.id = ?
            """,
            (link_id,),
        ).fetchone()
        if row is None:
            raise StoreNotFound("Key 不存在")
        return self._decode_share_link(row)

    def _decode_share_link(self, row: sqlite3.Row) -> dict[str, Any]:
        display_status = (
            "ready"
            if row["status"] == "active" and row["assignment_id"] is None
            else "used"
        )
        return {
            "id": row["id"],
            "token": self._vault.decrypt(row["token_encrypted"]) if row["token_encrypted"] else None,
            "lease_minutes": row["lease_minutes"],
            "status": row["status"],
            "display_status": display_status,
            "assigned": row["assignment_id"] is not None,
            "assignment_status": row["assignment_status"],
            "assignment_started_at": row["started_at"],
            "assignment_expires_at": row["assignment_expires_at"],
            "code_count": row["code_count"] or 0,
            "created_at": row["created_at"],
        }

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._path, timeout=10)
        self._restrict_database_permissions()
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
            self._restrict_database_permissions()

    def _restrict_database_permissions(self) -> None:
        for path in (
            self._path,
            self._path.with_name(f"{self._path.name}-wal"),
            self._path.with_name(f"{self._path.name}-shm"),
        ):
            try:
                path.chmod(0o600)
            except FileNotFoundError:
                continue

    def _decode_message(self, row: sqlite3.Row) -> dict[str, Any]:
        recipient = self._vault.decrypt(row["recipient_encrypted"]) if row["recipient_encrypted"] else None
        token_encrypted = (
            row["share_token_encrypted"]
            if "share_token_encrypted" in row.keys()
            else None
        )
        return {
            "id": row["id"],
            "delivery_id": row["delivery_id"],
            "rule_id": row["rule_id"],
            "sender": self._vault.decrypt(row["sender_encrypted"]),
            "sender_masked": f"****{row['sender_suffix']}" if row["sender_suffix"] else "未知号码",
            "recipient": recipient,
            "recipient_masked": f"****{row['recipient_suffix']}" if row["recipient_suffix"] else None,
            "message": self._vault.decrypt(row["message_encrypted"]),
            "received_at": row["received_at"],
            "is_test": bool(row["is_test"]),
            "routed": row["assignment_id"] is not None,
            "share_link_id": row["share_link_id"] if "share_link_id" in row.keys() else None,
            "key": self._vault.decrypt(token_encrypted) if token_encrypted else None,
        }

    @staticmethod
    def _message_summary(full: dict[str, Any]) -> dict[str, Any]:
        preview = " ".join(full["message"].split())
        return {
            "id": full["id"],
            "rule_id": full["rule_id"],
            "sender_masked": full["sender_masked"],
            "recipient_masked": full["recipient_masked"],
            "recipient": full["recipient"],
            "message_preview": preview[:120] + ("…" if len(preview) > 120 else ""),
            "received_at": full["received_at"],
            "is_test": full["is_test"],
            "routed": full["routed"],
            "share_link_id": full["share_link_id"],
            "key": full["key"],
        }


def normalize_number(number: str | None) -> str:
    if not number:
        return ""
    digits = "".join(character for character in number if character.isdigit())
    return digits[2:] if digits.startswith("00") else digits


def _sender_suffix(sender: str | None) -> str:
    if not sender:
        return ""
    alphanumeric = "".join(character for character in sender if character.isalnum())
    return alphanumeric[-4:]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
