import sqlite3
import threading
import uuid
from datetime import UTC, datetime

MAX_FILES = 128
MAX_STORAGE = 128 * 1024 * 1024
FIELDS = "id, name, owner, size, digest, created"


class Store:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.db:
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY, name TEXT, owner TEXT, size INTEGER,
                    digest TEXT, created TEXT, data BLOB
                )
            """)

    def put(self, name, owner, digest, data):
        entry = {
            "id": uuid.uuid4().hex,
            "name": name,
            "owner": owner,
            "size": len(data),
            "digest": digest,
            "created": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        with self.lock, self.db:
            count, total = self.db.execute(
                "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM files"
            ).fetchone()
            if count >= MAX_FILES or total + len(data) > MAX_STORAGE:
                raise ValueError("Server file storage is full")
            self.db.execute(
                f"INSERT INTO files ({FIELDS}, data) VALUES "
                "(:id, :name, :owner, :size, :digest, :created, :data)",
                {**entry, "data": data},
            )
        return entry

    def list(self):
        with self.lock:
            return [
                dict(row)
                for row in self.db.execute(
                    f"SELECT {FIELDS} FROM files ORDER BY rowid DESC"
                )
            ]

    def get(self, file_id):
        with self.lock:
            row = self.db.execute(
                f"SELECT {FIELDS}, data FROM files WHERE id = ?", (file_id,)
            ).fetchone()
        if row is None:
            raise ValueError("File not found. Use /files to list available files")
        entry = dict(row)
        payload = entry.pop("data")
        return entry, payload
