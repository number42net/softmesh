"""SQLite store for the room server (posts + per-client sync cursors).

Schema versioning is home-rolled via SQLite's `PRAGMA user_version` — no Alembic.
Bump `SCHEMA_VERSION` and add a migration branch in `_migrate` when the schema
changes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

import aiosqlite

SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class Post:
    id: int
    author_pubkey: str  # hex
    author_prefix: int  # first byte of the author pubkey (path hash)
    ts: int  # post timestamp (client clock)
    body: str
    txt_type: int


@dataclass(frozen=True, slots=True)
class Client:
    pubkey: str  # hex
    name: str
    is_admin: bool
    last_timestamp: int
    last_login: int


class RoomStore:
    """Async SQLite-backed store. Call `open()` before use and `close()` after."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._db: aiosqlite.Connection | None = None

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("RoomStore is not open")
        return self._db

    async def open(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self._path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._migrate()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    async def _migrate(self) -> None:
        cur = await self.db.execute("PRAGMA user_version")
        row = await cur.fetchone()
        version = row[0] if row else 0
        if version < 1:
            await self.db.executescript(
                """
                CREATE TABLE IF NOT EXISTS posts (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    author_pubkey TEXT    NOT NULL,
                    author_prefix INTEGER NOT NULL,
                    ts            INTEGER NOT NULL,
                    body          TEXT    NOT NULL,
                    txt_type      INTEGER NOT NULL DEFAULT 0,
                    created_at    INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_posts_ts ON posts (ts);
                CREATE TABLE IF NOT EXISTS clients (
                    pubkey         TEXT    PRIMARY KEY,
                    name           TEXT    NOT NULL DEFAULT '',
                    is_admin       INTEGER NOT NULL DEFAULT 0,
                    last_timestamp INTEGER NOT NULL DEFAULT 0,
                    last_login     INTEGER NOT NULL DEFAULT 0
                );
                """
            )
        await self.db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        await self.db.commit()

    # --- posts -------------------------------------------------------------- #
    async def add_post(
        self, author_pubkey: bytes, ts: int, body: str, txt_type: int = 0
    ) -> Post:
        author_hex = author_pubkey.hex()
        prefix = author_pubkey[0]
        created = int(time.time())
        cur = await self.db.execute(
            "INSERT INTO posts (author_pubkey, author_prefix, ts, body, txt_type, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (author_hex, prefix, ts, body, txt_type, created),
        )
        await self.db.commit()
        return Post(
            id=cur.lastrowid or 0,
            author_pubkey=author_hex,
            author_prefix=prefix,
            ts=ts,
            body=body,
            txt_type=txt_type,
        )

    async def posts_since(self, since_ts: int, exclude_pubkey: bytes | None = None) -> list[Post]:
        """Posts strictly newer than `since_ts`, oldest first, excluding the
        caller's own posts (so a client doesn't get its own messages echoed)."""
        query = "SELECT * FROM posts WHERE ts > ?"
        params: list[object] = [since_ts]
        if exclude_pubkey is not None:
            query += " AND author_pubkey != ?"
            params.append(exclude_pubkey.hex())
        query += " ORDER BY ts ASC, id ASC"
        cur = await self.db.execute(query, params)
        rows = await cur.fetchall()
        return [
            Post(
                id=r["id"],
                author_pubkey=r["author_pubkey"],
                author_prefix=r["author_prefix"],
                ts=r["ts"],
                body=r["body"],
                txt_type=r["txt_type"],
            )
            for r in rows
        ]

    # --- clients ------------------------------------------------------------ #
    async def upsert_client(self, pubkey: bytes, name: str, is_admin: bool) -> None:
        now = int(time.time())
        await self.db.execute(
            """
            INSERT INTO clients (pubkey, name, is_admin, last_timestamp, last_login)
            VALUES (?, ?, ?, 0, ?)
            ON CONFLICT(pubkey) DO UPDATE SET
                name = excluded.name,
                is_admin = excluded.is_admin,
                last_login = excluded.last_login
            """,
            (pubkey.hex(), name, 1 if is_admin else 0, now),
        )
        await self.db.commit()

    async def get_client(self, pubkey: bytes) -> Client | None:
        cur = await self.db.execute("SELECT * FROM clients WHERE pubkey = ?", (pubkey.hex(),))
        r = await cur.fetchone()
        if r is None:
            return None
        return Client(
            pubkey=r["pubkey"],
            name=r["name"],
            is_admin=bool(r["is_admin"]),
            last_timestamp=r["last_timestamp"],
            last_login=r["last_login"],
        )

    async def set_client_cursor(self, pubkey: bytes, last_timestamp: int) -> None:
        await self.db.execute(
            "UPDATE clients SET last_timestamp = ? WHERE pubkey = ? AND last_timestamp < ?",
            (last_timestamp, pubkey.hex(), last_timestamp),
        )
        await self.db.commit()
