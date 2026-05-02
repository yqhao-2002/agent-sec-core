"""Fire-and-forget SQLite writer for security events.

Runs alongside the existing JSONL writer (dual-write pattern).
Thread-safe, corruption-resilient, self-pruning.
All exceptions are swallowed — never raises to callers.
"""

import json
import re
import sqlite3
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from agent_sec_cli.security_events.config import get_db_path
from agent_sec_cli.security_events.schema import SecurityEvent

# ---------------------------------------------------------------------------
# Schema constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = 1

_CREATE_TABLE_SQL = """\
PRAGMA auto_vacuum = INCREMENTAL;

CREATE TABLE IF NOT EXISTS security_events (
    event_id        TEXT PRIMARY KEY,
    event_type      TEXT NOT NULL,
    category        TEXT NOT NULL,
    result          TEXT NOT NULL DEFAULT 'succeeded',
    timestamp       TEXT NOT NULL,
    timestamp_epoch REAL NOT NULL,
    trace_id        TEXT NOT NULL DEFAULT '',
    pid             INTEGER NOT NULL,
    uid             INTEGER NOT NULL,
    session_id      TEXT,
    details         TEXT NOT NULL
);
"""

_CREATE_INDEXES_SQL = """\
CREATE INDEX IF NOT EXISTS idx_event_type      ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_category_epoch  ON security_events(category, timestamp_epoch);
CREATE INDEX IF NOT EXISTS idx_trace_id        ON security_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_timestamp_epoch ON security_events(timestamp_epoch);
"""

# Declarative column registry for convergent migration.
# To add a column: insert an entry and bump _SCHEMA_VERSION.
_COLUMNS: dict[str, str] = {
    # "severity": "TEXT DEFAULT 'info'",  # Future: uncomment and bump version
}


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------
# Only TRUE on-disk corruption markers justify a destructive rebuild.
# Everything else (lock, busy, full, readonly, protocol, I/O) is transient
# or environmental — skipping is mandatory, or concurrent writers wipe
# legitimate data via false-positive rebuilds.
_CORRUPTION_MARKERS: tuple[str, ...] = (
    "malformed",  # SQLITE_CORRUPT: "database disk image is malformed"
    "not a database",  # SQLITE_NOTADB: "file is not a database"
    "file is encrypted",  # SQLITE_NOTADB variant: encrypted DB without key
    "disk image",  # SQLITE_CORRUPT variant
)


def _is_corruption(exc: Exception) -> bool:
    """Return True only for messages indicating true on-disk corruption."""
    msg = str(exc).lower()
    return any(marker in msg for marker in _CORRUPTION_MARKERS)


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


class SqliteEventWriter:
    """Fire-and-forget SQLite writer for security events.

    Thread-safe, corruption-resilient, self-pruning.
    All exceptions are swallowed — never raises to callers.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        max_age_days: int = 30,
    ) -> None:
        self._path = Path(path) if path else Path(get_db_path())
        self._max_age_days = max_age_days
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        # Per-process flag: prevents futile repeated rename attempts within
        # a single CLI invocation (e.g. batch scan writing 200 events).
        # Resets naturally on next process — allows retry if the filesystem
        # issue was transient.
        self._disabled = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, event: SecurityEvent) -> None:
        """Insert *event* into SQLite.  Fire-and-forget — never raises."""
        if self._disabled:
            return

        # Validate event params BEFORE acquiring lock to avoid holding lock
        # during potentially failing serialization
        try:
            params = self._event_params(event)
        except (ValueError, TypeError) as exc:
            print(
                f"[security_events] invalid event params: {exc}",
                file=sys.stderr,
            )
            return

        with self._lock:
            try:
                self._ensure_connection()
                if self._conn is None:
                    return
                self._conn.execute(
                    "INSERT OR IGNORE INTO security_events "
                    "(event_id, event_type, category, result, timestamp, timestamp_epoch, "
                    "trace_id, pid, uid, session_id, details) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    params,
                )
            except sqlite3.DatabaseError as exc:
                # Only true on-disk corruption triggers destructive rebuild;
                # transient errors (lock/busy/full/readonly) are skipped to
                # avoid catastrophic data loss from false-positive rebuilds.
                if not _is_corruption(exc):
                    return

                # True database corruption — delete and retry once with fresh DB
                self._handle_corruption(exc)
                if self._disabled:
                    return
                try:
                    self._ensure_connection()
                    if self._conn is None:
                        return
                    self._conn.execute(
                        "INSERT OR IGNORE INTO security_events "
                        "(event_id, event_type, category, result, timestamp, timestamp_epoch, "
                        "trace_id, pid, uid, session_id, details) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        params,
                    )
                except Exception:  # noqa: BLE001
                    pass  # Best effort — give up silently on second failure
            except (sqlite3.Error, OSError) as exc:
                print(
                    f"[security_events] sqlite write error: {exc}",
                    file=sys.stderr,
                )
                self._conn = None  # Reset connection for next retry

    @staticmethod
    def _event_params(event: SecurityEvent) -> tuple:
        """Build the parameter tuple for INSERT."""
        return (
            event.event_id,
            event.event_type,
            event.category,
            event.result,
            event.timestamp,
            datetime.fromisoformat(event.timestamp).timestamp(),
            event.trace_id,
            event.pid,
            event.uid,
            event.session_id,
            json.dumps(event.details, ensure_ascii=False),
        )

    def close(self) -> None:
        """Best-effort prune, WAL checkpoint, and close.  Lock-free — safe for atexit.

        Pruning is done here (not inside write()) because agent-sec-cli is a
        short-lived CLI: each invocation is a separate process, so an in-process
        write counter would never accumulate across invocations.  Pruning at
        close() guarantees exactly one prune attempt per process lifetime,
        regardless of how many events were written.
        """
        conn = self._conn
        if conn is None:
            return
        # Prune expired events — bounded cost (single DELETE by indexed epoch)
        try:
            cutoff = time.time() - (self._max_age_days * 86400)
            conn.execute(
                "DELETE FROM security_events WHERE timestamp_epoch < ?", (cutoff,)
            )
        except Exception:  # noqa: BLE001
            pass
        # WAL checkpoint — TRUNCATE is safe at exit (exclusive lock likely)
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:  # noqa: BLE001
            pass
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
        self._conn = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_connection(self) -> None:
        """Lazily open the database and apply schema migrations.

        If corruption is detected, deletes the corrupt file and retries once
        to create a fresh DB — so the current write is not lost.
        """
        if self._conn is not None:
            return
        for attempt in range(
            2
        ):  # noqa: B007 — at most one retry after corruption cleanup
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                conn = sqlite3.connect(
                    str(self._path),
                    check_same_thread=False,
                    isolation_level=None,
                )
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA busy_timeout=200")
                conn.execute("PRAGMA wal_autocheckpoint=100")
                self._ensure_schema(conn)
                self._conn = conn

                # Set restrictive file permissions on first creation
                # 0o600 = owner read/write only (no group/others access)
                try:
                    self._path.chmod(0o600)
                except OSError:
                    pass  # Best effort — may fail on some filesystems

                return
            except sqlite3.DatabaseError as exc:
                # Under concurrent load, PRAGMA/schema statements can raise
                # OperationalError("database is locked"); treat any non-corruption
                # error as transient and skip — only true corruption rebuilds.
                if not _is_corruption(exc):
                    self._conn = None
                    return
                self._handle_corruption(exc)
                if self._disabled:
                    return  # unlink failed — give up

    @staticmethod
    def _ensure_schema(conn: sqlite3.Connection) -> None:
        """Create tables/indexes and apply convergent column migrations."""
        conn.executescript(_CREATE_TABLE_SQL)
        conn.executescript(_CREATE_INDEXES_SQL)

        # Introspect existing columns for convergent migration
        existing = {
            row[1] for row in conn.execute("PRAGMA table_info(security_events)")
        }
        for col, typedef in _COLUMNS.items():
            if col not in existing:
                # Validate column name is safe for dynamic SQL
                if not re.match(r"^[a-z_]+$", col):
                    raise ValueError(f"Invalid column name in schema: {col!r}")
                conn.execute(f"ALTER TABLE security_events ADD COLUMN {col} {typedef}")

        # Version-gated escape hatch
        current = conn.execute("PRAGMA user_version").fetchone()[0]  # noqa: F841
        # if current < 2: ...

        # Stamp current version
        conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

        # Currently no-op under autocommit, retained for future DML migrations
        conn.commit()

    def _handle_corruption(self, exc: Exception) -> None:
        """Delete the corrupt database and prepare for a fresh start.

        The SQLite DB is an expendable queryable index — JSONL is the source
        of truth.  A corrupt DB has no forensic value (it's unreadable), so we
        simply delete it rather than renaming/accumulating corrupt copies.
        """
        print(
            f"[security_events] corrupt DB detected, recreating: {exc}",
            file=sys.stderr,
        )
        # Close existing connection
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001
            pass
        self._conn = None

        # Delete corrupt file — next _ensure_connection() will create fresh
        try:
            self._path.unlink(missing_ok=True)
            # Also remove orphaned WAL/SHM files
            # Use string concatenation instead of with_suffix() to handle
            # paths with any extension (or no extension) correctly
            wal = Path(str(self._path) + "-wal")
            shm = Path(str(self._path) + "-shm")
            wal.unlink(missing_ok=True)
            shm.unlink(missing_ok=True)
        except OSError as delete_exc:
            self._disabled = True
            print(
                f"[security_events] cannot delete corrupt db, "
                f"writer disabled: {delete_exc}",
                file=sys.stderr,
            )
