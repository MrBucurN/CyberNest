"""Small, user-scoped persistent cache for validated advisory data."""

import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path


class PersistentSeverityCache:
    SCHEMA_VERSION = 1
    MAX_CACHE_BYTES = 5 * 1024 * 1024
    MAX_ENTRIES = 10000
    LOCK_TIMEOUT_SECONDS = 3.0
    _thread_lock = threading.RLock()

    def __init__(self, path: str | Path | None, ttl_seconds: int):
        self.path = Path(path) if path is not None else self.default_path()
        self.ttl_seconds = ttl_seconds

    @staticmethod
    def default_path() -> Path:
        if os.name == "nt":
            app_data = os.environ.get("LOCALAPPDATA")
            base = Path(app_data) if app_data else Path.home() / "AppData" / "Local"
            return base / "CyberNest" / "cvss-cache-v1.json"
        data_home = os.environ.get("XDG_DATA_HOME")
        base = Path(data_home) if data_home else Path.home() / ".local" / "share"
        return base / "cybernest" / "cvss-cache-v1.json"

    def get(self, identifier: str, *, now: float | None = None) -> tuple[dict | None, float | None]:
        now = time.time() if now is None else now
        try:
            with self._locked():
                payload = self._read_unlocked()
        except (OSError, TimeoutError):
            return None, None
        if not isinstance(payload, dict) or payload.get("schema_version") != self.SCHEMA_VERSION:
            return None, None
        entries = payload.get("entries")
        if not isinstance(entries, dict):
            return None, None
        entry = entries.get(identifier)
        if not isinstance(entry, dict):
            return None, None
        fetched_at = entry.get("fetched_at")
        expires_at = entry.get("expires_at")
        if (
            isinstance(fetched_at, bool) or not isinstance(fetched_at, (int, float))
            or isinstance(expires_at, bool) or not isinstance(expires_at, (int, float))
        ):
            return None, None
        age = now - float(fetched_at)
        if age < 0 or age >= self.ttl_seconds or now >= float(expires_at):
            return None, None
        return dict(entry), age

    def put(self, identifier: str, entry: dict, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._locked():
            payload = self._read_unlocked()
            if not isinstance(payload, dict) or payload.get("schema_version") != self.SCHEMA_VERSION:
                payload = {"schema_version": self.SCHEMA_VERSION, "entries": {}}
            entries = payload.get("entries")
            if not isinstance(entries, dict):
                entries = {}
            retained = {}
            for key, value in entries.items():
                if not isinstance(key, str) or not isinstance(value, dict):
                    continue
                fetched_at = value.get("fetched_at")
                expires_at = value.get("expires_at")
                if (
                    isinstance(fetched_at, (int, float)) and not isinstance(fetched_at, bool)
                    and isinstance(expires_at, (int, float)) and not isinstance(expires_at, bool)
                    and 0 <= now - float(fetched_at) < self.ttl_seconds
                    and now < float(expires_at)
                ):
                    retained[key] = value
            row = dict(entry)
            row["fetched_at"] = now
            row["expires_at"] = now + self.ttl_seconds
            retained[identifier] = row
            if len(retained) > self.MAX_ENTRIES:
                retained = dict(list(retained.items())[-self.MAX_ENTRIES:])
            serialized = json.dumps(
                {"schema_version": self.SCHEMA_VERSION, "entries": retained},
                ensure_ascii=False,
                indent=2,
                allow_nan=False,
            )
            self._atomic_write(serialized)

    def _read_unlocked(self):
        try:
            if self.path.stat().st_size > self.MAX_CACHE_BYTES:
                return None
            return json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"schema_version": self.SCHEMA_VERSION, "entries": {}}
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None

    def _atomic_write(self, serialized: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                prefix=".cvss-cache-",
                suffix=".tmp",
                dir=self.path.parent,
                delete=False,
            ) as temporary:
                temp_path = Path(temporary.name)
                temporary.write(serialized)
                temporary.flush()
                os.fsync(temporary.fileno())
            if os.name != "nt":
                os.chmod(temp_path, 0o600)
            os.replace(temp_path, self.path)
            if os.name != "nt":
                os.chmod(self.path, 0o600)
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    @contextmanager
    def _locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        with self._thread_lock:
            with open(lock_path, "a+b") as lock_file:
                if os.name == "nt":
                    import msvcrt

                    lock_file.seek(0, os.SEEK_END)
                    if lock_file.tell() == 0:
                        lock_file.write(b"\0")
                        lock_file.flush()
                    deadline = time.monotonic() + self.LOCK_TIMEOUT_SECONDS
                    while True:
                        try:
                            lock_file.seek(0)
                            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise TimeoutError("Timed out waiting for the CVSS cache lock.")
                            time.sleep(0.05)
                    try:
                        yield
                    finally:
                        lock_file.seek(0)
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                    try:
                        yield
                    finally:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
