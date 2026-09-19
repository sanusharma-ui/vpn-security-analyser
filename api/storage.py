"""Atomic persisted job snapshots and exclusive ownership of a data directory."""
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path


class JobStore:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self._lock_file = (self.directory / "backend.lock").open("a+b")
        try:
            if os.fstat(self._lock_file.fileno()).st_size == 0:
                self._lock_file.write(b"0")
                self._lock_file.flush()
            self._lock_file.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._lock_file.close()
            raise RuntimeError("Data directory is in use. Run exactly one backend worker.") from None
        self.path = self.directory / "jobs.sqlite3"
        with self.connection() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, state TEXT NOT NULL, source_type TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, finished_at TEXT,
                parameters TEXT NOT NULL, error TEXT, revision INTEGER NOT NULL DEFAULT 0,
                report TEXT, explanation TEXT)""")

    @contextmanager
    def connection(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def insert(self, job):
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO jobs(id,state,source_type,created_at,updated_at,parameters) VALUES(?,?,?,?,?,?)",
                (job["id"], job["state"], job["source_type"], job["created_at"], job["updated_at"],
                 json.dumps(job["parameters"])))

    def update(self, job_id, **fields):
        allowed = {"state", "updated_at", "finished_at", "report", "error", "explanation"}
        if not fields or not set(fields) <= allowed:
            raise ValueError("Invalid job update")
        values = [json.dumps(v) if k in ("report", "explanation") and v is not None else v
                  for k, v in fields.items()]
        assignments = ",".join(k + "=?" for k in fields)
        with self.connection() as connection:
            connection.execute(f"UPDATE jobs SET {assignments},revision=revision+1 WHERE id=?", (*values, job_id))

    def get(self, job_id):
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        result = dict(row)
        for name in ("parameters", "report", "explanation"):
            result[name] = json.loads(result[name]) if result[name] is not None else None
        return result

    def list_ids(self, limit=100, offset=0):
        with self.connection() as connection:
            return [row[0] for row in connection.execute(
                "SELECT id FROM jobs ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset))]

    def count(self):
        with self.connection() as connection:
            return connection.execute("SELECT count(*) FROM jobs").fetchone()[0]

    def delete(self, job_id):
        with self.connection() as connection:
            connection.execute("DELETE FROM jobs WHERE id=?", (job_id,))

    def close(self):
        if not self._lock_file.closed:
            if os.name == "nt":
                import msvcrt
                self._lock_file.seek(0)
                msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lock_file, fcntl.LOCK_UN)
            self._lock_file.close()
