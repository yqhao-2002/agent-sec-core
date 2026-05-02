"""Read-only SQLite reader for querying security events."""

import json
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_sec_cli.security_events.config import get_db_path
from agent_sec_cli.security_events.schema import SecurityEvent


class SqliteEventReader:
    """Read-only SQLite reader for security events.

    Uses per-call connections via URI mode (?mode=ro).
    Thread-safe by design — no shared state between calls.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else Path(get_db_path())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """Open a read-only connection. Raises OperationalError if DB missing."""
        conn = sqlite3.connect(f"file:{self._path}?mode=ro", uri=True)
        conn.execute("PRAGMA query_only=ON")
        conn.row_factory = sqlite3.Row
        return conn

    def _build_where(
        self,
        *,
        event_type: str | None = None,
        category: str | None = None,
        trace_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> tuple[str, list[Any]]:
        """Build WHERE clause and params list from non-None filters."""
        conditions: list[str] = []
        params: list[Any] = []
        if event_type is not None:
            conditions.append("event_type = ?")
            params.append(event_type)
        if category is not None:
            conditions.append("category = ?")
            params.append(category)
        if trace_id is not None:
            conditions.append("trace_id = ?")
            params.append(trace_id)
        if since is not None:
            conditions.append("timestamp_epoch >= ?")
            dt = datetime.fromisoformat(since)
            # If naive (no timezone), assume UTC to match event storage
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            params.append(dt.timestamp())
        if until is not None:
            conditions.append("timestamp_epoch < ?")
            dt = datetime.fromisoformat(until)
            # If naive (no timezone), assume UTC to match event storage
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            params.append(dt.timestamp())
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        return where, params

    def _row_to_event(self, row: sqlite3.Row) -> SecurityEvent | None:
        """Convert a DB row to SecurityEvent. Returns None on parse error."""
        try:
            return SecurityEvent(
                event_id=row["event_id"],
                event_type=row["event_type"],
                category=row["category"],
                result=row["result"],
                timestamp=row["timestamp"],
                trace_id=row["trace_id"],
                pid=row["pid"],
                uid=row["uid"],
                session_id=row["session_id"],
                details=json.loads(row["details"]),
            )
        except (json.JSONDecodeError, IndexError, KeyError, TypeError) as exc:
            print(f"[security_events] malformed row skipped: {exc}", file=sys.stderr)
            return None

    # ------------------------------------------------------------------
    # Public query API
    # ------------------------------------------------------------------

    def query(
        self,
        event_type: str | None = None,
        category: str | None = None,
        trace_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[SecurityEvent]:
        """Query security events with optional filters.

        Parameters
        ----------
        event_type : str, optional
            Filter by event type.
        category : str, optional
            Filter by category.
        trace_id : str, optional
            Filter by trace ID.
        since : str, optional
            Inclusive lower bound (ISO-8601 timestamp).
        until : str, optional
            Exclusive upper bound (ISO-8601 timestamp).
        limit : int
            Maximum number of results (default 1000).
        offset : int
            Number of results to skip (default 0).

        Returns
        -------
        list[SecurityEvent]
            Matching events ordered by timestamp descending.
        """
        try:
            conn = self._connect()
            try:
                where, params = self._build_where(
                    event_type=event_type,
                    category=category,
                    trace_id=trace_id,
                    since=since,
                    until=until,
                )
                sql = (
                    "SELECT event_id, event_type, category, result, timestamp, "
                    "timestamp_epoch, trace_id, pid, uid, session_id, details "
                    f"FROM security_events{where} "
                    "ORDER BY timestamp_epoch DESC "
                    "LIMIT ? OFFSET ?"
                )
                params.extend([limit, offset])
                cursor = conn.execute(sql, params)
                rows = cursor.fetchall()
            finally:
                conn.close()
        except sqlite3.OperationalError:
            return []

        events: list[SecurityEvent] = []
        for row in rows:
            event = self._row_to_event(row)
            if event is not None:
                events.append(event)
        return events

    def count(
        self,
        event_type: str | None = None,
        category: str | None = None,
        since: str | None = None,
        until: str | None = None,
        offset: int = 0,
    ) -> int:
        """Count events matching the given filters.

        Parameters
        ----------
        event_type : str, optional
            Filter by event type.
        category : str, optional
            Filter by category.
        since : str, optional
            Inclusive lower bound (ISO-8601 timestamp).
        until : str, optional
            Exclusive upper bound (ISO-8601 timestamp).
        offset : int
            Number of results to skip (default 0).

        Returns
        -------
        int
            Number of matching events after applying offset.
        """
        try:
            conn = self._connect()
            try:
                where, params = self._build_where(
                    event_type=event_type,
                    category=category,
                    since=since,
                    until=until,
                )
                # Use subquery to apply OFFSET before counting
                # COUNT(*) on the full set returns 1 row, which OFFSET would skip
                sql = (
                    f"SELECT COUNT(*) FROM ("
                    f"SELECT 1 FROM security_events{where} "
                    f"LIMIT -1 OFFSET ?)"
                )
                params.append(offset)
                cursor = conn.execute(sql, params)
                result = cursor.fetchone()
                return result[0] if result else 0
            finally:
                conn.close()
        except sqlite3.OperationalError:
            return 0

    def count_by(
        self,
        group_field: str,
        since: str | None = None,
        until: str | None = None,
        offset: int = 0,
    ) -> dict[str, int]:
        """Count events grouped by a specific field.

        Parameters
        ----------
        group_field : str
            Field to group by. Must be one of: category, event_type, trace_id.
        since : str, optional
            Inclusive lower bound (ISO-8601 timestamp).
        until : str, optional
            Exclusive upper bound (ISO-8601 timestamp).
        offset : int
            Number of results to skip (default 0).

        Returns
        -------
        dict[str, int]
            Mapping of field value to event count after applying offset.

        Raises
        ------
        ValueError
            If group_field is not in the allowlist.
        """
        # Explicit column mapping for defense-in-depth — prevents SQL injection
        # even if allowlist validation is accidentally bypassed
        allowed_columns = {"category", "event_type", "trace_id"}
        if group_field not in allowed_columns:
            raise ValueError(
                f"Invalid group_field: {group_field!r}. "
                "Must be one of: category, event_type, trace_id"
            )

        # Validate column name is a safe identifier
        # This is a belt-and-suspenders check — the allowlist above already
        # guarantees safety, but this prevents future regressions if the
        # allowlist is modified incorrectly
        if not re.match(r"^[a-z_]+$", group_field):
            raise ValueError(
                f"group_field contains invalid characters: {group_field!r}"
            )

        try:
            conn = self._connect()
            try:
                where, params = self._build_where(since=since, until=until)

                if offset == 0:
                    # No offset: use simple GROUP BY
                    sql = (
                        f"SELECT {group_field}, COUNT(*) "
                        f"FROM security_events{where} "
                        f"GROUP BY {group_field}"
                    )
                else:
                    # With offset: apply offset to individual events before grouping
                    # Use subquery to skip 'offset' events, then group the remainder
                    sql = (
                        f"SELECT {group_field}, COUNT(*) FROM ("
                        f"SELECT {group_field} FROM security_events{where} "
                        f"LIMIT -1 OFFSET ?) "
                        f"GROUP BY {group_field}"
                    )
                    params.append(offset)

                cursor = conn.execute(sql, params)
                rows = cursor.fetchall()
                return {row[0]: row[1] for row in rows}
            finally:
                conn.close()
        except sqlite3.OperationalError:
            return {}
