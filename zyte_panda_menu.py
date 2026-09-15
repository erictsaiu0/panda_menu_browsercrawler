#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Foodpanda menu crawler powered by Zyte API (Smart Proxy Manager backend).

This variant mirrors the Bright Data Unlocker workflow but uses Zyte's hosted
REST API to fetch/render each restaurant page server-side. The JSON extraction
helpers stay untouched so downstream payloads remain identical.
"""

import argparse
import base64
import certifi
import concurrent.futures
import csv
import fcntl
import heapq
import json
import logging
import os
import random
import re
import shutil
import sys
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import dotenv
import requests
import urllib3
from requests.exceptions import RequestException, SSLError

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from menu_opening_scheduler import OpeningHoursIndex, TAIPEI_TZ


FORCE_RELOAD_DOTENV = os.environ.get("PANDA_FORCE_RELOAD_DOTENV", "0") in ("1", "true", "True")
dotenv.load_dotenv(BASE_DIR / ".env", override=FORCE_RELOAD_DOTENV)


class AccessDeniedError(RuntimeError):
    """Raised when Foodpanda serves a captcha/block page."""

    pass


class CrawlWindowClosed(RuntimeError):
    """Raised before a new request when the safe dispatch window has closed."""

    pass


# ============================================
# Basic configuration
# ============================================

DEBUG_MODE = False
PER_REQUEST_DELAY_MIN_SEC = float(os.environ.get("PANDA_DELAY_MIN", "0"))
PER_REQUEST_DELAY_MAX_SEC = float(os.environ.get("PANDA_DELAY_MAX", "0"))
PANDA_WORKERS = max(1, int(os.environ.get("PANDA_WORKERS", "1")))
CRAWL_HTML_ONLY = True

RECAPTCHA_WAIT = int(os.environ.get("RECAPTCHA_WAIT", "60"))
MAX_ACCESS_DENIED_RETRIES = int(os.environ.get("MAX_ACCESS_DENIED_RETRIES", "2"))
SKIP_EXISTING_OUTPUT = os.environ.get("PANDA_SKIP_EXISTING", "1") not in ("0", "false", "False")
DEDUP_SHOP_CODES = os.environ.get("PANDA_DEDUP_SHOPS", "1") not in ("0", "false", "False")
DEFAULT_OPENING_TYPE = os.environ.get("PANDA_OPENING_TYPE", "delivery").strip().lower() or "delivery"
if DEFAULT_OPENING_TYPE not in {"delivery", "pickup", "both"}:
    DEFAULT_OPENING_TYPE = "delivery"
NTFY_SERVER = os.environ.get("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
NTFY_TOPIC = os.environ.get("PANDA_MENU_NTFY_TOPIC", "fp-menu-97241")
NTFY_TOKEN = os.environ.get("NTFY_TOKEN")

# ============================================
# Path & logging setup
# ============================================

LOCATION_CSV_PATH = Path(
    os.environ.get(
        "PANDA_ROLLING_CSV",
        str(PROJECT_DIR / "panda_data" / "shopLst" / "rolling.csv"),
    )
).resolve()
TODAY = datetime.now(TAIPEI_TZ).strftime("%Y-%m-%d")
OUTPUT_BASE = Path(
    os.environ.get(
        "PANDA_MENU_OUTPUT_BASE",
        str(PROJECT_DIR / "panda_data_js" / "panda_menu"),
    )
).resolve()
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / f"{TODAY}.log"
RUN_LOCK_FILE = OUTPUT_BASE / ".zyte_panda_menu.lock"
OPENING_HOURS_CSV = Path(
    os.environ.get(
        "MENU_OPENING_HOURS_CSV",
        str(PROJECT_DIR / "menu_opening_hour_wide.csv"),
    )
).resolve()
OPENING_CLOSING_BUFFER = timedelta(
    minutes=max(0.0, float(os.environ.get("PANDA_CLOSING_BUFFER_MINUTES", "5")))
)
OPENING_MINIMUM_BUFFER = timedelta(
    minutes=max(0.0, float(os.environ.get("MENU_MINIMUM_BUFFER_MINUTES", "2")))
)
SCHEDULER_POLL_SECONDS = max(
    1.0, float(os.environ.get("MENU_SCHEDULER_POLL_SECONDS", "60"))
)

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(OUTPUT_BASE, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    encoding="utf-8",
)
logger = logging.getLogger("panda_menu_zyte")


def acquire_run_lock() -> Any:
    RUN_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    handle = RUN_LOCK_FILE.open("a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise RuntimeError(
            f"Another Foodpanda menu crawler is already running ({RUN_LOCK_FILE})"
        )
    handle.seek(0)
    handle.truncate()
    handle.write(f"pid={os.getpid()} started={datetime.now(TAIPEI_TZ).isoformat()}\n")
    handle.flush()
    return handle


def load_json_file(path: Path) -> Optional[dict]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, separators=(",", ":"))
    os.replace(temp_path, path)


def active_run_file(opening_type: str) -> Path:
    return OUTPUT_BASE / f"active_run_{opening_type}.json"


def resolve_run_date(opening_type: str, is_test: bool) -> str:
    if not is_test:
        active = load_json_file(active_run_file(opening_type))
        if active and active.get("status") == "running":
            if active.get("runDate"):
                return str(active["runDate"])
    return datetime.now(TAIPEI_TZ).strftime("%Y-%m-%d")


def update_active_run(
    run_date: str,
    opening_type: str,
    status: str,
    **extra: Any,
) -> None:
    payload = {
        "version": 1,
        "runDate": run_date,
        "openingType": opening_type,
        "status": status,
        "updatedAt": datetime.now(TAIPEI_TZ).isoformat(),
    }
    payload.update(extra)
    atomic_write_json(active_run_file(opening_type), payload)


def prepare_input_snapshot(run_date: str) -> Path:
    snapshot = OUTPUT_BASE / ".runs" / run_date / "rolling.csv"
    if snapshot.exists():
        logger.info("[INFO] Using run-locked rolling.csv snapshot: %s", snapshot)
        return snapshot
    if not LOCATION_CSV_PATH.exists():
        raise FileNotFoundError(f"CSV not found: {LOCATION_CSV_PATH}")
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(LOCATION_CSV_PATH, snapshot)
    logger.info("[INFO] Locked rolling.csv for this run: %s", snapshot)
    return snapshot


# ============================================
# Zyte API configuration
# ============================================

ZYTE_API_KEY = (
    os.environ.get("ZYTE_API_KEY")
    or os.environ.get("CRAWLERA_API_KEY")
    or os.environ.get("CRAWLERA_APIKEY")
)
if not ZYTE_API_KEY:
    raise RuntimeError("ZYTE_API_KEY (or legacy CRAWLERA_API_KEY) is required.")

ZYTE_API_ENDPOINT = os.environ.get("ZYTE_API_ENDPOINT", "https://api.zyte.com/v1/extract")
ZYTE_FOLLOW_REDIRECT = os.environ.get("ZYTE_FOLLOW_REDIRECT", "1") not in ("0", "false", "False")
ZYTE_GEO_LOCATION = os.environ.get("ZYTE_REGION") or os.environ.get("ZYTE_COUNTRY")
ZYTE_MAX_FETCH_RETRIES = int(os.environ.get("ZYTE_MAX_FETCH_RETRIES", "3"))
ZYTE_TIMEOUT = float(os.environ.get("ZYTE_TIMEOUT", "60"))
ZYTE_VERIFY_SSL = os.environ.get("ZYTE_VERIFY_SSL", "1") not in ("0", "false", "False")
ZYTE_CA_BUNDLE = os.environ.get("ZYTE_CA_BUNDLE")
ZYTE_SERVER_ERROR_SLEEP = float(os.environ.get("ZYTE_SERVER_ERROR_SLEEP", "15"))
ZYTE_SSL_AUTO_FALLBACK = os.environ.get("ZYTE_SSL_AUTO_FALLBACK", "1") not in ("0", "false", "False")
ZYTE_SUPPRESS_INSECURE_WARNING = (
    os.environ.get("ZYTE_SUPPRESS_INSECURE_WARNING", "1") not in ("0", "false", "False")
)
ZYTE_REQUEST_BROWSER_HTML = os.environ.get("ZYTE_BROWSER_HTML", "0") not in ("0", "false", "False")
ZYTE_DOM_MENUS = os.environ.get("ZYTE_DOM_MENUS", "0") not in ("0", "false", "False")
ZYTE_VENDOR_API_FALLBACK = os.environ.get("ZYTE_VENDOR_API_FALLBACK", "0") not in ("0", "false", "False")
ZYTE_SKIP_VENDOR_API_FALLBACK = os.environ.get("ZYTE_SKIP_VENDOR_API_FALLBACK", "1") not in ("0", "false", "False")
DEFAULT_ZYTE_CA_PATH = BASE_DIR / "zyte-ca-982.crt"
if not ZYTE_CA_BUNDLE and DEFAULT_ZYTE_CA_PATH.exists():
    ZYTE_CA_BUNDLE = str(DEFAULT_ZYTE_CA_PATH)


def set_browser_rendering(enabled: bool) -> None:
    """Toggle Zyte browserHtml rendering at runtime (used by zyte_test)."""
    global ZYTE_REQUEST_BROWSER_HTML
    ZYTE_REQUEST_BROWSER_HTML = enabled
    logger.info("[CONFIG] Zyte browserHtml rendering = %s", enabled)


def set_dom_menus(enabled: bool) -> None:
    """Toggle DOM menu extraction at runtime."""
    global ZYTE_DOM_MENUS
    ZYTE_DOM_MENUS = enabled
    logger.info("[CONFIG] DOM menu extraction = %s", enabled)


def _mask_secret(value: Optional[str], head: int = 4, tail: int = 4) -> str:
    if not value:
        return "(missing)"
    if len(value) <= head + tail:
        return "*" * len(value)
    return f"{value[:head]}...{value[-tail:]}"


def _compose_verify_bundle() -> Optional[str]:
    """
    Requests relies on certifi CA store and ignores OS additions. When a Zyte CA
    is provided, append it to certifi's bundle so TLS verification succeeds.
    """
    if not ZYTE_CA_BUNDLE:
        return certifi.where()

    zyte_path = Path(ZYTE_CA_BUNDLE)
    if not zyte_path.exists():
        logger.warning("[SSL] ZYTE_CA_BUNDLE not found at %s", zyte_path)
        return certifi.where()

    merged_path = BASE_DIR / ".zyte_certifi_bundle.pem"
    try:
        with open(certifi.where(), "rb") as base_fp, open(zyte_path, "rb") as zyte_fp:
            base_data = base_fp.read()
            custom_data = zyte_fp.read()
        with open(merged_path, "wb") as out_fp:
            out_fp.write(base_data)
            if not base_data.endswith(b"\n"):
                out_fp.write(b"\n")
            out_fp.write(custom_data)
            if not custom_data.endswith(b"\n"):
                out_fp.write(b"\n")
        logger.info("[SSL] Composed certifi bundle with Zyte CA -> %s", merged_path)
        return str(merged_path)
    except Exception as exc:
        logger.warning("[SSL] Failed to compose Zyte CA bundle: %s", exc)
        return certifi.where()

session = requests.Session()
session.auth = (ZYTE_API_KEY, "")
session.headers.update({"Content-Type": "application/json"})
verify_path = _compose_verify_bundle()
if verify_path and ZYTE_VERIFY_SSL:
    session.verify = verify_path
elif not ZYTE_VERIFY_SSL:
    session.verify = False
if isinstance(session.verify, bool) and session.verify is False and ZYTE_SUPPRESS_INSECURE_WARNING:
    try:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

SSL_FALLBACK_ACTIVE = isinstance(session.verify, bool) and session.verify is False
_ZYTE_METRICS_LOCK = threading.Lock()
ZYTE_REQUEST_ATTEMPTS = 0
ZYTE_SUCCESSFUL_RESPONSES = 0
ZYTE_RESPONSE_SECONDS = 0.0

verify_label = ZYTE_CA_BUNDLE if ZYTE_CA_BUNDLE else str(ZYTE_VERIFY_SSL)
logger.info(
    "[CONFIG] Zyte API endpoint=%s geo=%s retries=%s timeout=%.0fs verify_ssl=%s render_html=%s",
    ZYTE_API_ENDPOINT,
    ZYTE_GEO_LOCATION or "(default)",
    ZYTE_MAX_FETCH_RETRIES,
    ZYTE_TIMEOUT,
    verify_label,
    ZYTE_REQUEST_BROWSER_HTML,
)
logger.info(
    "[CONFIG] dom_menus=%s vendor_api_fallback=%s skip_vendor_api_fallback=%s",
    ZYTE_DOM_MENUS,
    ZYTE_VENDOR_API_FALLBACK,
    ZYTE_SKIP_VENDOR_API_FALLBACK,
)
logger.info("[CONFIG] workers=%s delay=%.2f..%.2fs", PANDA_WORKERS, PER_REQUEST_DELAY_MIN_SEC, PER_REQUEST_DELAY_MAX_SEC)
logger.info(
    "[CONFIG] zyte_api_key=%s dotenv_override=%s",
    _mask_secret(ZYTE_API_KEY),
    FORCE_RELOAD_DOTENV,
)

# NOTE: requests.Session is not guaranteed thread-safe. When running with
# concurrency, use a per-thread Session that tracks the current global verify
# setting (which may switch to insecure mode after SSL errors).
_THREAD_LOCAL = threading.local()
_VERIFY_LOCK = threading.Lock()
SESSION_VERIFY = session.verify


def _new_session() -> requests.Session:
    s = requests.Session()
    s.auth = (ZYTE_API_KEY, "")
    s.headers.update({"Content-Type": "application/json"})
    s.verify = SESSION_VERIFY
    return s


def _get_session() -> requests.Session:
    current = getattr(_THREAD_LOCAL, "session", None)
    current_verify = getattr(_THREAD_LOCAL, "verify", None)
    if current is None or current_verify != SESSION_VERIFY:
        current = _new_session()
        _THREAD_LOCAL.session = current
        _THREAD_LOCAL.verify = SESSION_VERIFY
    return current


# ============================================
# Helper utilities
# ============================================

ACCESS_DENIED_MARKERS = (
    "Access to this page has been denied",
    "px-captcha",
)


def output_dir_for(run_opening_type: str, opening_type: str) -> Path:
    if run_opening_type == "both":
        return OUTPUT_BASE / f"{TODAY}-{opening_type}"
    return OUTPUT_BASE / TODAY


def output_file_for(
    lat: float,
    lng: float,
    shop_code: str,
    opening_type: str = "delivery",
    run_opening_type: str = "delivery",
    ext: str = "json",
) -> Path:
    out_dir = output_dir_for(run_opening_type, opening_type)
    suffix = "" if opening_type == "delivery" else f"_{opening_type}"
    return out_dir / f"{lat}_{lng}_{shop_code}{suffix}.{ext}"


def is_successful_output(
    path: Path,
    require_menu: bool = False,
    opening_type: Optional[str] = None,
    expected_shop_code: Optional[str] = None,
) -> bool:
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            return False
        if expected_shop_code:
            actual_shop_code = _payload_vendor_code(payload)
            if actual_shop_code and actual_shop_code != str(expected_shop_code):
                return False
        return not require_menu or _has_complete_menu(payload, opening_type)
    except (OSError, ValueError):
        return False


def build_restaurant_url(shop_code: str, opening_type: str, redirection_url: Optional[str] = None) -> str:
    base_url = (redirection_url or "").strip() or f"https://www.foodpanda.com.tw/restaurant/{shop_code}"
    parts = urlsplit(base_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["opening_type"] = opening_type
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def resolve_opening_types(opening_type: str) -> List[str]:
    if opening_type == "both":
        return ["delivery", "pickup"]
    return [opening_type]


def _dump_access_denied_html(page_source: str, url: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = url.rstrip("/").split("/")[-1] or "homepage"
    dump_path = LOG_DIR / f"access_denied_{suffix}_{timestamp}.html"
    try:
        # dump_path.write_text(page_source, encoding="utf-8")
        # logger.error(
        #     "[BLOCKED] Access denied / captcha detected for %s. Dumped HTML to %s",
        #     url,
        #     dump_path,
        # )
        pass
    except Exception as dump_err:
        # logger.error(
        #     "[BLOCKED] Access denied for %s, but failed to dump HTML: %s",
        #     url,
        #     dump_err,
        # )
        pass
    return dump_path


def _dump_json_debug(payload: str, url: str, suffix: str = "debug") -> None:
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = url.rstrip("/").split("/")[-1] or "homepage"
        out = LOG_DIR / f"json_{slug}_{suffix}_{timestamp}.txt"
        # out.write_text(
        #     payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False),
        #     encoding="utf-8",
        # )
        # logger.info("[DEBUG] Dumped JSON payload for %s to %s", url, out)
        pass
    except Exception as e:
        # logger.warning("[DEBUG] Failed to dump JSON payload for %s: %s", url, e)
        pass


def is_access_denied(page_source: str) -> bool:
    if not page_source:
        return False
    return any(marker in page_source for marker in ACCESS_DENIED_MARKERS)


def ensure_not_blocked(page_source: str, url: str) -> None:
    if not is_access_denied(page_source):
        return
    _dump_access_denied_html(page_source, url)
    raise AccessDeniedError(
        "Foodpanda returned an Access Denied / captcha page. "
        "Slow down, try a residential IP, or wait before retrying."
    )


# ============================================
# SSL fallback helper
# ============================================


def _enable_ssl_insecure_mode(reason: str) -> bool:
    """Disable certificate verification mid-run if allowed."""
    global SSL_FALLBACK_ACTIVE
    global SESSION_VERIFY
    if SSL_FALLBACK_ACTIVE or not ZYTE_SSL_AUTO_FALLBACK:
        return False
    with _VERIFY_LOCK:
        if SSL_FALLBACK_ACTIVE:
            return False
        logger.warning(
            "[SSL] Disabling certificate verification due to error: %s. "
            "Provide a valid ZYTE_CA_BUNDLE or set ZYTE_VERIFY_SSL=0 to keep this setting.",
            reason,
        )
        SESSION_VERIFY = False
        if ZYTE_SUPPRESS_INSECURE_WARNING:
            try:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        SSL_FALLBACK_ACTIVE = True
        return True


# ============================================
# JSON extraction helpers
# ============================================


def _extract_balanced_js_objects(html: str, marker: str) -> List[str]:
    """Return object literals assigned after every occurrence of ``marker``.

    Foodpanda embeds JavaScript objects rather than strict JSON.  Looking for
    ``</script>`` is too broad because the script can contain more statements;
    this scanner stops at the matching closing brace while respecting quoted
    strings.
    """
    if not html:
        return []

    objects: List[str] = []
    search_from = 0
    while True:
        marker_index = html.find(marker, search_from)
        if marker_index == -1:
            break
        start = marker_index + len(marker)
        while start < len(html) and html[start].isspace():
            start += 1
        if start >= len(html) or html[start] != "{":
            search_from = marker_index + len(marker)
            continue

        depth = 0
        quote: Optional[str] = None
        escaped = False
        object_end: Optional[int] = None
        for index in range(start, len(html)):
            char = html[index]
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in ('"', "'"):
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    object_end = index + 1
                    objects.append(html[start:object_end])
                    break
        search_from = object_end or (marker_index + len(marker))
    return objects


def _extract_balanced_js_object(html: str, marker: str) -> Optional[str]:
    objects = _extract_balanced_js_objects(html, marker)
    return objects[0] if objects else None


def _normalize_js_undefined(snippet: str) -> str:
    """Replace bare JavaScript ``undefined`` values with JSON ``null``.

    The replacement is token-aware so text inside quoted strings is never
    changed.
    """
    output: List[str] = []
    index = 0
    quote: Optional[str] = None
    escaped = False
    length = len(snippet)
    while index < length:
        char = snippet[index]
        if quote is not None:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ('"', "'"):
            quote = char
            output.append(char)
            index += 1
            continue
        if snippet.startswith("undefined", index):
            previous = index - 1
            while previous >= 0 and snippet[previous].isspace():
                previous -= 1
            following = index + len("undefined")
            while following < length and snippet[following].isspace():
                following += 1
            previous_char = snippet[previous] if previous >= 0 else ""
            following_char = snippet[following] if following < length else ""
            if previous_char in ":[," and following_char in ",}]":
                output.append("null")
                index += len("undefined")
                continue
        output.append(char)
        index += 1
    return "".join(output)


def _extract_json_from_html(html: str, marker: str) -> Optional[dict]:
    snippet = _extract_balanced_js_object(html, marker)
    if not snippet:
        return None
    for candidate in (snippet, _normalize_js_undefined(snippet)):
        try:
            value = json.loads(candidate)
            return value if isinstance(value, dict) else None
        except (TypeError, ValueError):
            continue
    return None


def extract_vendor_payload(html: str) -> Optional[dict]:
    return _extract_json_from_html(html, "window.__PRELOADED_STATE__=") or _extract_json_from_html(
        html, "window.__NEXT_DATA__="
    )


def extract_provider_payload(html: str) -> Optional[dict]:
    """Extract the rendered page's hydration state without calling vendor API."""
    fragments: List[dict] = []
    markers = (
        "window.__PROVIDER_PROPS__=",
        "window.__PROVIDER_PROPS__=Object.assign(window.__PROVIDER_PROPS__||{},",
    )
    for marker in markers:
        for snippet in _extract_balanced_js_objects(html, marker):
            parsed: Optional[dict] = None
            for candidate in (snippet, _normalize_js_undefined(snippet)):
                try:
                    value = json.loads(candidate)
                    if isinstance(value, dict):
                        parsed = value
                        break
                except (TypeError, ValueError):
                    continue
            if parsed is not None:
                fragments.append(parsed)

    if not fragments:
        return None

    def merge_dicts(target: Dict[str, Any], incoming: Dict[str, Any]) -> None:
        for key, value in incoming.items():
            if isinstance(target.get(key), dict) and isinstance(value, dict):
                merge_dicts(target[key], value)
            else:
                target[key] = value

    merged: Dict[str, Any] = {}
    for fragment in fragments:
        merge_dicts(merged, fragment)
    return merged


def _has_menus(payload: Optional[dict]) -> bool:
    if not isinstance(payload, dict):
        return False
    if isinstance(payload.get("menus"), list) and payload.get("menus"):
        return True

    vendor_wrapper = payload.get("vendor")
    if isinstance(vendor_wrapper, dict):
        vendor_data = vendor_wrapper.get("data")
        if isinstance(vendor_data, dict) and isinstance(vendor_data.get("menus"), list) and vendor_data.get("menus"):
            return True

    restaurant = payload.get("restaurant")
    if isinstance(restaurant, dict) and isinstance(restaurant.get("menus"), list) and restaurant.get("menus"):
        return True
    return False


def _menus_from_payload(payload: Optional[dict]) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    candidates: List[Any] = [payload.get("menus")]
    vendor_wrapper = payload.get("vendor")
    if isinstance(vendor_wrapper, dict) and isinstance(vendor_wrapper.get("data"), dict):
        candidates.append(vendor_wrapper["data"].get("menus"))
    if isinstance(payload.get("data"), dict):
        candidates.append(payload["data"].get("menus"))
    restaurant = payload.get("restaurant")
    if isinstance(restaurant, dict):
        candidates.append(restaurant.get("menus"))
    for candidate in candidates:
        if isinstance(candidate, list):
            return [menu for menu in candidate if isinstance(menu, dict)]
    return []


def _menu_product_metrics(payload: Optional[dict]) -> Tuple[int, int, int]:
    menus = _menus_from_payload(payload)
    category_count = 0
    product_count = 0
    for menu in menus:
        categories = menu.get("menu_categories") or menu.get("categories") or []
        if not isinstance(categories, list):
            continue
        category_count += sum(isinstance(category, dict) for category in categories)
        for category in categories:
            if not isinstance(category, dict):
                continue
            products = category.get("products") or []
            if isinstance(products, list):
                product_count += sum(isinstance(product, dict) for product in products)
    return len(menus), category_count, product_count


def _has_complete_menu(payload: Optional[dict], opening_type: Optional[str] = None) -> bool:
    menus = _menus_from_payload(payload)
    if not menus or _menu_product_metrics(payload)[2] <= 0:
        return False
    if not opening_type:
        return True

    expected = opening_type.upper()
    declared_types = {
        str(value).upper()
        for menu in menus
        for value in (
            menu.get("expedition_type"),
            menu.get("expeditionType"),
            menu.get("opening_type"),
        )
        if value
    }
    return not declared_types or expected in declared_types


def _coerce_numeric_id(value: Any) -> Any:
    if isinstance(value, str) and value.isdigit():
        try:
            return int(value)
        except ValueError:
            return value
    return value


def _apollo_initial_state(provider_payload: Optional[dict]) -> Optional[Dict[str, Any]]:
    if not isinstance(provider_payload, dict):
        return None
    apollo = provider_payload.get("apollo")
    if not isinstance(apollo, dict):
        return None
    state = apollo.get("initialState")
    return state if isinstance(state, dict) else None


def _apollo_dereference(state: Dict[str, Any], value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict):
        return None
    reference = value.get("__ref")
    if isinstance(reference, str):
        target = state.get(reference)
        return target if isinstance(target, dict) else None
    return value


def _provider_identity(provider_payload: Optional[dict]) -> Dict[str, Any]:
    state = _apollo_initial_state(provider_payload)
    if not state:
        return {}
    root = state.get("ROOT_QUERY")
    if not isinstance(root, dict):
        return {}
    for key, value in root.items():
        if not str(key).startswith("restaurantDetailsPage(") or not isinstance(value, dict):
            continue
        vendor = value.get("vendorData")
        if isinstance(vendor, dict):
            return {
                "code": vendor.get("code"),
                "name": vendor.get("name"),
            }
    return {}


def _payload_vendor_code(payload: Optional[dict]) -> Optional[str]:
    if not isinstance(payload, dict):
        return None
    vendor = payload.get("vendor")
    if isinstance(vendor, dict) and isinstance(vendor.get("data"), dict):
        code = vendor["data"].get("code")
        if code:
            return str(code)
    data = payload.get("data")
    if isinstance(data, dict) and data.get("code"):
        return str(data["code"])
    return None


def _provider_menus_to_panda(
    provider_payload: Optional[dict],
    shop_code: str,
    opening_type: str,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Convert Apollo's normalized cache into the legacy menu shape.

    The result intentionally mirrors the vendor API keys consumed by existing
    downstream code, while retaining additional fields available in the page.
    """
    state = _apollo_initial_state(provider_payload)
    if not state:
        return [], []

    expected_type = opening_type.upper()
    available_types: List[str] = []
    menus_out: List[Dict[str, Any]] = []
    seen_menus = set()

    for state_key, menu in state.items():
        if not str(state_key).startswith("RestaurantMenu:") or not isinstance(menu, dict):
            continue
        expedition_type = str(menu.get("expeditionType") or "").upper()
        if expedition_type and expedition_type not in available_types:
            available_types.append(expedition_type)
        menu_vendor_code = str(menu.get("vendorCode") or "")
        if expedition_type != expected_type:
            continue
        if shop_code and menu_vendor_code and menu_vendor_code != str(shop_code):
            continue
        menu_identity = (str(menu.get("id") or state_key), expedition_type)
        if menu_identity in seen_menus:
            continue
        seen_menus.add(menu_identity)

        categories_out: List[Dict[str, Any]] = []
        category_refs = menu.get("categories") or []
        if not isinstance(category_refs, list):
            category_refs = []
        for category_ref in category_refs:
            category = _apollo_dereference(state, category_ref)
            if not category:
                continue
            products_out: List[Dict[str, Any]] = []
            product_refs = category.get("products") or []
            if not isinstance(product_refs, list):
                product_refs = []
            for product_ref in product_refs:
                product = _apollo_dereference(state, product_ref)
                if not product:
                    continue

                price_attributes = product.get("priceAttributes")
                if not isinstance(price_attributes, dict):
                    price_attributes = {}
                original_price = price_attributes.get("originalPrice")
                discounted_price = price_attributes.get("discountedPrice")
                display_price = discounted_price if discounted_price is not None else original_price
                price_before_discount = original_price if discounted_price is not None else None

                variations_out: List[Dict[str, Any]] = []
                variation_refs = product.get("variations") or []
                if not isinstance(variation_refs, list):
                    variation_refs = []
                resolved_variations = [
                    variation
                    for variation in (
                        _apollo_dereference(state, variation_ref)
                        for variation_ref in variation_refs
                    )
                    if variation
                ]
                for variation in resolved_variations:
                    variation_price = variation.get("price")
                    variation_before_discount = None
                    if discounted_price is not None and len(resolved_variations) == 1:
                        variation_before_discount = variation_price
                        variation_price = discounted_price
                    variations_out.append(
                        {
                            "id": _coerce_numeric_id(variation.get("id")),
                            "code": variation.get("code"),
                            "remote_code": variation.get("remoteCode"),
                            "name": None,
                            "price": variation_price,
                            "price_before_discount": variation_before_discount,
                            "container_price": variation.get("containerPrice"),
                            "unit_pricing_info": variation.get("unitPricingInfo"),
                        }
                    )

                image = product.get("image")
                image_url = image.get("url") if isinstance(image, dict) else None
                products_out.append(
                    {
                        "id": _coerce_numeric_id(product.get("id")),
                        "code": product.get("code"),
                        "name": product.get("title"),
                        "description": product.get("description"),
                        "image_url": image_url,
                        "is_sold_out": bool(product.get("isSoldOut")),
                        "is_customizable": bool(product.get("isCustomizable")),
                        "is_bundle": bool(product.get("isBundle")),
                        "is_alcoholic_item": bool(product.get("isAlcoholicItem")),
                        "dietary_attributes": product.get("dietaryAttributes") or [],
                        "tags": product.get("tags") or [],
                        "price": display_price,
                        "price_before_discount": price_before_discount,
                        "container_price": price_attributes.get("containerPrice"),
                        "product_variations": variations_out,
                    }
                )

            master_category = _apollo_dereference(state, category.get("masterCategory"))
            categories_out.append(
                {
                    "id": _coerce_numeric_id(category.get("id")),
                    "code": category.get("code"),
                    "name": category.get("title"),
                    "description": category.get("description"),
                    "master_category_id": (
                        _coerce_numeric_id(master_category.get("id"))
                        if master_category
                        else None
                    ),
                    "products": products_out,
                }
            )

        menus_out.append(
            {
                "id": _coerce_numeric_id(menu.get("id")),
                "code": menu.get("code"),
                "name": menu.get("title"),
                "description": menu.get("description"),
                "opening_time": menu.get("startTime"),
                "closing_time": menu.get("endTime"),
                "expedition_type": expedition_type,
                "vendor_code": menu.get("vendorCode"),
                "menu_categories": categories_out,
            }
        )

    return menus_out, available_types


def _parse_price_to_int(raw: Optional[str]) -> Optional[int]:
    if not raw:
        return None
    digits = "".join(ch for ch in raw if ch.isdigit())
    if not digits:
        return None
    try:
        return int(digits)
    except Exception:
        return None


class _FoodpandaMenuDomParser(HTMLParser):
    _VOID_TAGS = {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._tag_stack: List[str] = []

        self.categories: List[Dict[str, Any]] = []
        self._category: Optional[Dict[str, Any]] = None
        self._category_depth: Optional[int] = None

        self._product: Optional[Dict[str, Any]] = None
        self._product_depth: Optional[int] = None

        self._capture_key: Optional[str] = None
        self._capture_buf: List[str] = []
        self._capture_depth: Optional[int] = None

    @staticmethod
    def _attrs_to_dict(attrs: List[Tuple[str, Optional[str]]]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for key, val in attrs:
            if key and val is not None:
                out[key] = val
        return out

    def _start_capture(self, key: str) -> None:
        if self._capture_key and self._capture_key != key:
            self._finish_capture()
        self._capture_key = key
        self._capture_buf = []
        self._capture_depth = len(self._tag_stack)

    def _finish_capture(self) -> None:
        if not self._capture_key:
            return
        key = self._capture_key
        text = unescape("".join(self._capture_buf)).strip()
        self._capture_key = None
        self._capture_buf = []
        self._capture_depth = None
        if not text:
            return
        if self._product is not None:
            if self._product.get(key):
                return
            self._product[key] = text
        elif self._category is not None:
            if self._category.get(key):
                return
            self._category[key] = text

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        if tag not in self._VOID_TAGS:
            self._tag_stack.append(tag)
        attr_map = self._attrs_to_dict(attrs)
        test_id = attr_map.get("data-testid")

        if tag == "div" and test_id == "menu-category-section":
            raw_category_id = attr_map.get("id")
            category_id: Any = raw_category_id
            if raw_category_id:
                category_suffix = raw_category_id.rsplit("-", 1)[-1]
                if category_suffix.isdigit():
                    category_id = int(category_suffix)
            self._category = {
                "id": category_id,
                "name": None,
                "description": None,
                "products": [],
            }
            self._category_depth = len(self._tag_stack)
            return

        if self._category is None:
            return

        if test_id == "menu-category-section-title" or (
            tag == "h2" and "dish-category-title" in (attr_map.get("class") or "")
        ):
            self._start_capture("name")
            return

        if test_id == "menu-category-section-description":
            self._start_capture("description")
            return

        if tag == "li" and test_id == "menu-product":
            self._product = {
                "id": None,
                "name": None,
                "description": None,
                "price": None,
                "price_before_discount": None,
            }
            self._product_depth = len(self._tag_stack)
            self._category["products"].append(self._product)
            return

        if self._product is None:
            return

        if test_id == "menu-quantity-stepper":
            raw_id = attr_map.get("id", "")
            # Example: quantity-stepper-0-142032330
            if raw_id.startswith("quantity-stepper-"):
                parts = raw_id.split("-")
                if parts and parts[-1].isdigit():
                    self._product["id"] = int(parts[-1])
            return

        if test_id == "menu-product-name":
            self._start_capture("name")
            return

        if test_id == "menu-product-description":
            self._start_capture("description")
            return

        if test_id == "menu-product-price":
            self._start_capture("price")
            return

        if test_id == "menu-product-price-before-discount":
            self._start_capture("price_before_discount")
            return

        if tag == "img" and test_id == "menu-product-image":
            image_url = attr_map.get("src") or attr_map.get("data-src")
            if image_url and not self._product.get("image_url"):
                self._product["image_url"] = image_url
            return

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        for index in range(len(self._tag_stack) - 1, -1, -1):
            if self._tag_stack[index] == tag:
                del self._tag_stack[index:]
                break

        if (
            self._capture_key
            and self._capture_depth is not None
            and len(self._tag_stack) < self._capture_depth
        ):
            self._finish_capture()

        if self._product is not None and self._product_depth is not None and len(self._tag_stack) < self._product_depth:
            if isinstance(self._product.get("price"), str):
                self._product["price_value"] = _parse_price_to_int(self._product.get("price"))
            if isinstance(self._product.get("price_before_discount"), str):
                self._product["price_before_discount_value"] = _parse_price_to_int(
                    self._product.get("price_before_discount")
                )
            self._product = None
            self._product_depth = None

        if self._category is not None and self._category_depth is not None and len(self._tag_stack) < self._category_depth:
            self.categories.append(self._category)
            self._category = None
            self._category_depth = None

    def finish_open_nodes(self) -> None:
        if self._capture_key:
            self._finish_capture()
        if self._product is not None:
            if isinstance(self._product.get("price"), str):
                self._product["price_value"] = _parse_price_to_int(self._product.get("price"))
            if isinstance(self._product.get("price_before_discount"), str):
                self._product["price_before_discount_value"] = _parse_price_to_int(
                    self._product.get("price_before_discount")
                )
            self._product = None
            self._product_depth = None
        if self._category is not None:
            self.categories.append(self._category)
            self._category = None
            self._category_depth = None

    def handle_data(self, data: str) -> None:
        if not self._capture_key:
            return
        if data and data.strip():
            self._capture_buf.append(data)


def _extract_dom_menu_categories(html: str) -> Optional[List[Dict[str, Any]]]:
    if not html:
        return None
    parser = _FoodpandaMenuDomParser()
    try:
        parser.feed(html)
        parser.close()
        parser.finish_open_nodes()
    except Exception:
        return None

    categories = [c for c in parser.categories if c.get("name") or c.get("products")]
    return categories or None


def _dom_categories_to_panda_menus(categories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convert rendered DOM categories into a structure that panda_menu_postprocess.py can consume.

    Target shape: {"menus":[{"menu_categories":[{"products":[{"product_variations":[...]}]}]}]}
    """
    menu_categories: List[Dict[str, Any]] = []
    for cat in categories:
        cat_name = cat.get("name")
        if not cat_name:
            continue

        products_out: List[Dict[str, Any]] = []
        for p in cat.get("products") or []:
            if not isinstance(p, dict):
                continue
            name = p.get("name")
            if not name:
                continue
            pid = p.get("id")
            pid_int = pid if isinstance(pid, int) else None
            code = str(pid_int) if pid_int is not None else None
            price_val = p.get("price_value") if isinstance(p.get("price_value"), int) else _parse_price_to_int(p.get("price"))
            pre_val = (
                p.get("price_before_discount_value")
                if isinstance(p.get("price_before_discount_value"), int)
                else _parse_price_to_int(p.get("price_before_discount"))
            )

            products_out.append(
                {
                    "id": pid_int,
                    "code": code,
                    "name": name,
                    "description": p.get("description"),
                    "image_url": p.get("image_url"),
                    "is_sold_out": False,
                    "tags": [],
                    "price": price_val,
                    "price_before_discount": pre_val,
                    "product_variations": [
                        {
                            "code": code,
                            "name": None,
                            "price": price_val,
                            "price_before_discount": pre_val,
                        }
                    ],
                }
            )

        if not products_out:
            continue

        menu_categories.append(
            {
                "id": cat.get("id"),
                "name": cat_name,
                "description": cat.get("description"),
                "products": products_out,
            }
        )

    if not menu_categories:
        return []
    return [{"menu_categories": menu_categories}]


def _merge_menus_for_postprocess(payload: dict, menus: List[Dict[str, Any]]) -> bool:
    """
    Ensure menus appear in the dict returned by panda_menu_postprocess.load_response_json().

    That function prioritizes `raw["vendor"]["data"]` when present, so we attach
    menus under `vendor.data.menus` if possible.
    """
    if not menus:
        return False

    vendor_wrapper = payload.get("vendor")
    if isinstance(vendor_wrapper, dict) and isinstance(vendor_wrapper.get("data"), dict):
        vendor_wrapper["data"]["menus"] = menus
        return True

    if isinstance(payload.get("data"), dict):
        payload["data"]["menus"] = menus
        return True

    payload["menus"] = menus
    return True


def _infer_vendor_code(payload: Optional[dict], url: str, html: str) -> Optional[str]:
    if isinstance(payload, dict):
        vendor_code = (payload.get("vendor") or {}).get("data", {}).get("code")
        if vendor_code:
            return str(vendor_code)
    match = re.search(r'data-vendor-code="([a-zA-Z0-9_-]+)"', html)
    if match:
        return match.group(1)
    match = re.search(r"/restaurant/([^/]+)/", url)
    if match:
        return match.group(1)
    return None


def _infer_coords(payload: Optional[dict], html: str) -> Tuple[Optional[float], Optional[float]]:
    if isinstance(payload, dict):
        data = (payload.get("vendor") or {}).get("data") or {}
        if isinstance(data, dict):
            lat = data.get("latitude")
            lng = data.get("longitude")
            try:
                if lat is not None and lng is not None:
                    return float(lat), float(lng)
            except Exception:
                pass
    lat_lng_match = re.search(r'"latitude":\s*([0-9]+\.[0-9]+).*?"longitude":\s*([0-9]+\.[0-9]+)', html, re.DOTALL)
    if lat_lng_match:
        try:
            return float(lat_lng_match.group(1)), float(lat_lng_match.group(2))
        except Exception:
            pass
    return None, None


def _fetch_menus_via_api(
    vendor_code: str,
    lat: Optional[float],
    lng: Optional[float],
    opening_type: str = "delivery",
) -> Optional[List[Dict[str, Any]]]:
    base_url = f"https://tw.fd-api.com/api/v5/vendors/{vendor_code}"
    params: Dict[str, object] = {
        "include": "menus,bundles,multiple_discounts",
        "language_id": "6",
        "opening_type": opening_type,
        "basket_currency": "TWD",
    }
    if lat is not None and lng is not None:
        params["latitude"] = lat
        params["longitude"] = lng
    headers = {
        "Accept": "application/json, text/plain, */*",
        "X-PD-Language-ID": "6",
        "X-FP-API-KEY": "volo",
        "Api-Version": "7",
    }
    try:
        _ensure_within_dispatch_window()
        resp = requests.get(base_url, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        menus = data.get("data", {}).get("menus")
        return menus if isinstance(menus, list) else None
    except CrawlWindowClosed:
        raise
    except Exception as exc:
        logger.warning("[MENU_API] Vendor API fetch failed for %s: %s", vendor_code, exc)
        return None


# ============================================
# Zyte API fetch logic
# ============================================


def _ensure_within_dispatch_window() -> None:
    dispatch_deadline = getattr(_THREAD_LOCAL, "dispatch_deadline", None)
    if dispatch_deadline and datetime.now(TAIPEI_TZ) >= dispatch_deadline:
        raise CrawlWindowClosed("safe dispatch window closed before network request")


def _build_zyte_request_payload(url: str) -> dict:
    payload: Dict[str, object] = {"url": url}
    # Zyte API treats browserHtml and httpResponseBody as mutually exclusive,
    # and followRedirect is not allowed with browser parameters.
    if ZYTE_REQUEST_BROWSER_HTML:
        payload["browserHtml"] = True
    else:
        payload["httpResponseBody"] = True
        payload["followRedirect"] = ZYTE_FOLLOW_REDIRECT
        if not ZYTE_FOLLOW_REDIRECT:
            payload["followRedirect"] = False
    if ZYTE_GEO_LOCATION:
        payload["geolocation"] = ZYTE_GEO_LOCATION
    query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
    payload["tags"] = {
        "crawler": "zyte-panda-menu",
        "response": "browser-html" if ZYTE_REQUEST_BROWSER_HTML else "http-response-body",
        "opening-type": str(query.get("opening_type") or "unknown"),
    }
    return payload


def _maybe_decode_base64(value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return value


def _extract_target_status(data: dict) -> Optional[int]:
    for key in (
        "httpResponseStatus",
        "httpResponseStatusCode",
        "status_code",
        "statusCode",
    ):
        val = data.get(key)
        if isinstance(val, int):
            return val
    response = data.get("httpResponse")
    if isinstance(response, dict):
        for key in ("status", "status_code"):
            if isinstance(response.get(key), int):
                return response[key]
    return None


def _extract_html_from_api_response(data: dict) -> Optional[str]:
    payload = data.get("result") if isinstance(data.get("result"), dict) else data
    if not isinstance(payload, dict):
        return None

    html = payload.get("browserHtml")
    if isinstance(html, str) and html.strip():
        return html

    body = payload.get("httpResponseBody")
    if isinstance(body, str) and body.strip():
        return _maybe_decode_base64(body)

    body_b64 = payload.get("httpResponseBodyBase64")
    if isinstance(body_b64, str) and body_b64.strip():
        return _maybe_decode_base64(body_b64)
    return None


def fetch_page_via_zyte(url: str) -> str:
    global ZYTE_REQUEST_ATTEMPTS, ZYTE_RESPONSE_SECONDS, ZYTE_SUCCESSFUL_RESPONSES

    last_error: Optional[Exception] = None
    for attempt in range(1, ZYTE_MAX_FETCH_RETRIES + 1):
        _ensure_within_dispatch_window()
        payload = _build_zyte_request_payload(url)
        with _ZYTE_METRICS_LOCK:
            ZYTE_REQUEST_ATTEMPTS += 1
        try:
            start = time.perf_counter()
            response = _get_session().post(ZYTE_API_ENDPOINT, json=payload, timeout=ZYTE_TIMEOUT)
            elapsed = time.perf_counter() - start
        except SSLError as exc:
            last_error = exc
            if _enable_ssl_insecure_mode(str(exc)):
                continue
            logger.warning("[FETCH] %s SSL error (attempt %s/%s): %s", url, attempt, ZYTE_MAX_FETCH_RETRIES, exc)
            time.sleep(min(5, RECAPTCHA_WAIT))
            continue

        except RequestException as exc:
            last_error = exc
            logger.warning("[FETCH] %s request error (attempt %s/%s): %s", url, attempt, ZYTE_MAX_FETCH_RETRIES, exc)
            time.sleep(min(5, RECAPTCHA_WAIT))
            continue

        with _ZYTE_METRICS_LOCK:
            ZYTE_RESPONSE_SECONDS += elapsed
            if 200 <= response.status_code < 300:
                ZYTE_SUCCESSFUL_RESPONSES += 1

        logger.info(
            "[FETCH] %s via Zyte API (status=%s) took %.1fs",
            url,
            response.status_code,
            elapsed,
        )

        if response.status_code == 401:
            raise RuntimeError("Zyte API authentication failed. Check ZYTE_API_KEY.")
        if response.status_code >= 500 or response.status_code in (408, 429):
            logger.warning(
                "[FETCH] %s retryable Zyte API HTTP %s (attempt %s/%s) -> sleeping %.1fs",
                url,
                response.status_code,
                attempt,
                ZYTE_MAX_FETCH_RETRIES,
                ZYTE_SERVER_ERROR_SLEEP,
            )
            time.sleep(max(1.0, min(RECAPTCHA_WAIT, ZYTE_SERVER_ERROR_SLEEP)))
            continue
        if response.status_code >= 400:
            raise RuntimeError(f"Zyte API error {response.status_code}: {response.text[:400]}")

        try:
            data = response.json()
        except ValueError as exc:
            last_error = exc
            logger.error("[FETCH] %s invalid JSON response: %s", url, exc)
            time.sleep(5)
            continue

        target_status = _extract_target_status(data) or 200
        if target_status >= 500 or target_status in (408, 429):
            logger.warning(
                "[FETCH] %s upstream HTTP %s via Zyte API (attempt %s/%s) -> sleeping %.1fs",
                url,
                target_status,
                attempt,
                ZYTE_MAX_FETCH_RETRIES,
                ZYTE_SERVER_ERROR_SLEEP,
            )
            time.sleep(max(1.0, min(RECAPTCHA_WAIT, ZYTE_SERVER_ERROR_SLEEP)))
            continue

        html = _extract_html_from_api_response(data)
        if not html:
            last_error = RuntimeError("Zyte API returned no HTML content.")
            _dump_json_debug(data, url, suffix="no_html")
            time.sleep(3)
            continue

        ensure_not_blocked(html, url)
        return html

    raise RuntimeError(f"Failed to fetch {url} via Zyte API after {ZYTE_MAX_FETCH_RETRIES} attempts: {last_error}")


# ============================================
# CSV and progress helpers
# ============================================


def read_store_list(csv_path: Path) -> List[Dict[str, float]]:
    stores: List[Dict[str, float]] = []
    seen_codes = set()
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                shop_code = row.get("shopCode") or row.get("shop_uuid") or row.get("code")
                shop_name = row.get("shopName") or row.get("name")
                lat = float(row.get("latitude"))
                lng = float(row.get("longitude"))
            except Exception as e:
                logger.warning("[SKIP] bad row %s: %s", row, e)
                continue

            if DEDUP_SHOP_CODES:
                key = shop_code or f"{lat},{lng}"
                if key in seen_codes:
                    logger.debug("[SKIP] Duplicate shop entry ignored: %s", shop_code)
                    continue
                seen_codes.add(key)

            stores.append(
                {
                    "shopCode": shop_code,
                    "shopName": shop_name,
                    "redirection_url": row.get("redirection_url"),
                    "lat": lat,
                    "lng": lng,
                }
            )
    logger.info("[INFO] Loaded %d shops from %s", len(stores), csv_path)
    return stores


def progress_snapshot(run_start_time: float, success_count: int, skip_count: int, total_count: int) -> str:
    processed = success_count + skip_count
    elapsed = time.perf_counter() - run_start_time
    avg_seconds = elapsed / processed if processed else 0.0
    remaining = max(0, total_count - processed)
    eta_seconds = remaining * avg_seconds
    days = int(eta_seconds // 86400)
    hours = int((eta_seconds % 86400) // 3600)
    minutes = int((eta_seconds % 3600) // 60)
    eta_str = f"{days}:{hours:02}:{minutes:02}"
    return f"success={success_count} skip={skip_count} avg={avg_seconds:.1f}s ETA={eta_str}"


def send_notification(title: str, message: str, priority: str = "default") -> None:
    if not NTFY_TOPIC:
        return
    headers = {"Title": title, "Priority": priority}
    if NTFY_TOKEN:
        headers["Authorization"] = f"Bearer {NTFY_TOKEN}"
    try:
        response = requests.post(
            f"{NTFY_SERVER}/{NTFY_TOPIC}",
            data=message.encode("utf-8"),
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
        logger.info("Sent ntfy notification topic=%s title=%s", NTFY_TOPIC, title)
    except RequestException as error:
        logger.warning("ntfy notification failed: %s", error)


# ============================================
# Crawl logic
# ============================================


def crawl_shop(shop_code: str, shop_name: str, url: str, opening_type: str = "delivery") -> Optional[dict]:
    for attempt in range(1, MAX_ACCESS_DENIED_RETRIES + 1):
        try:
            html = fetch_page_via_zyte(url)
            payload = extract_vendor_payload(html)
            provider_payload = extract_provider_payload(html) if ZYTE_DOM_MENUS else None
            provider_identity = _provider_identity(provider_payload)
            actual_vendor_codes = {
                code
                for code in (
                    _payload_vendor_code(payload),
                    str(provider_identity.get("code")) if provider_identity.get("code") else None,
                )
                if code
            }
            if actual_vendor_codes and any(
                code != str(shop_code) for code in actual_vendor_codes
            ):
                logger.warning(
                    "[VENDOR_MISMATCH] requested=%s (%s) rendered_vendor_codes=%s; "
                    "rejecting redirected page",
                    shop_code,
                    shop_name,
                    sorted(actual_vendor_codes),
                )
                return None
            if payload is None:
                if provider_payload:
                    payload = {
                        "vendor": {
                            "data": {
                                "code": provider_identity.get("code") or shop_code,
                                "name": provider_identity.get("name") or shop_name,
                            }
                        }
                    }
                    logger.warning(
                        "[META_FALLBACK] %s (%s) PRELOADED_STATE unavailable; "
                        "using Provider identity",
                        shop_code,
                        shop_name,
                    )
                else:
                    logger.warning(
                        "[NO_DATA] %s (%s) -> embedded state parse failed (attempt %s)",
                        shop_code,
                        shop_name,
                        attempt,
                    )
                    _dump_json_debug(html, url, suffix="html_parse_failed")
                    return None

            provider_type_mismatch = False
            if ZYTE_DOM_MENUS and not _has_complete_menu(payload, opening_type):
                provider_menus, provider_types = _provider_menus_to_panda(
                    provider_payload,
                    str(shop_code),
                    opening_type,
                )
                if provider_menus and _menu_product_metrics({"menus": provider_menus})[2] > 0:
                    _merge_menus_for_postprocess(payload, provider_menus)
                    menu_count, category_count, product_count = _menu_product_metrics(payload)
                    logger.info(
                        "[MENU_PROVIDER] %s (%s) merged Apollo menu "
                        "(opening_type=%s menus=%s categories=%s products=%s)",
                        shop_code,
                        shop_name,
                        opening_type,
                        menu_count,
                        category_count,
                        product_count,
                    )
                elif provider_types and opening_type.upper() not in provider_types:
                    provider_type_mismatch = True
                    logger.warning(
                        "[MENU_TYPE_MISMATCH] %s (%s) requested=%s provider_types=%s",
                        shop_code,
                        shop_name,
                        opening_type.upper(),
                        provider_types,
                    )

                if not _has_complete_menu(payload, opening_type) and not provider_type_mismatch:
                    categories = _extract_dom_menu_categories(html)
                    if categories:
                        menus = _dom_categories_to_panda_menus(categories)
                        if menus:
                            for menu in menus:
                                menu["expedition_type"] = opening_type.upper()
                                menu["vendor_code"] = shop_code
                            _merge_menus_for_postprocess(payload, menus)
                            _, category_count, product_count = _menu_product_metrics(payload)
                            logger.info(
                                "[MENU_DOM] %s (%s) merged menus from visible DOM "
                                "(categories=%s products=%s)",
                                shop_code,
                                shop_name,
                                category_count,
                                product_count,
                            )

                if (
                    not _has_complete_menu(payload, opening_type)
                    and not provider_type_mismatch
                    and ZYTE_VENDOR_API_FALLBACK
                    and not ZYTE_SKIP_VENDOR_API_FALLBACK
                ):
                    vendor_code = _infer_vendor_code(payload, url, html)
                    lat, lng = _infer_coords(payload, html)
                    if vendor_code:
                        menus = _fetch_menus_via_api(vendor_code, lat, lng, opening_type=opening_type)
                        if menus:
                            _merge_menus_for_postprocess(payload, menus)
                            logger.info(
                                "[MENU_API] %s (%s) merged menus from vendor API (%s, opening_type=%s)",
                                shop_code,
                                shop_name,
                                vendor_code,
                                opening_type,
                            )

                if not _has_complete_menu(payload, opening_type):
                    logger.warning(
                        "[NO_MENU] %s (%s) no complete %s menu after Provider/DOM "
                        "parsing (attempt %s/%s)",
                        shop_code,
                        shop_name,
                        opening_type,
                        attempt,
                        MAX_ACCESS_DENIED_RETRIES,
                    )
                    return None

            return payload
        except AccessDeniedError:
            if attempt == MAX_ACCESS_DENIED_RETRIES:
                logger.warning(
                    "[BLOCKED] %s (%s) -> reached max captcha retries (%s).",
                    shop_code,
                    shop_name,
                    MAX_ACCESS_DENIED_RETRIES,
                )
            else:
                logger.warning(
                    "[BLOCKED] %s (%s) -> captcha detected (attempt %s/%s). Cooling down %.0fs.",
                    shop_code,
                    shop_name,
                    attempt,
                    MAX_ACCESS_DENIED_RETRIES,
                    RECAPTCHA_WAIT,
                )
                time.sleep(RECAPTCHA_WAIT)
            continue
        except CrawlWindowClosed:
            raise
        except Exception as e:
            logger.error("[ERROR] %s (%s) fetch failed: %s", shop_code, shop_name, e)
            break
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Foodpanda menu crawler (Zyte API).")
    parser.add_argument(
        "--opening-type",
        choices=["delivery", "pickup", "both"],
        default=DEFAULT_OPENING_TYPE,
        help="Restaurant opening type to crawl (default: delivery). Use 'both' to crawl both delivery and pickup.",
    )
    parser.add_argument(
        "--item-parse",
        action="store_true",
        help="Enable item parsing (forces browser rendering to fetch full menus).",
    )
    parser.add_argument(
        "--num-workers",
        type=int,
        default=1,
        help="Number of worker threads (default: 1).",
    )
    parser.add_argument(
        "--parse-part",
        choices=["A", "B"],
        help="Split rolling.csv into two halves when item parsing (A or B).",
    )
    parser.add_argument(
        "--limit-for-testing",
        type=int,
        default=0,
        help="Limit the number of shops for testing after any parse-part filtering (default: 0 = no limit).",
    )
    args = parser.parse_args()
    if args.parse_part and not args.item_parse:
        parser.error("--parse-part is only valid when --item-parse is enabled.")
    if args.limit_for_testing < 0:
        parser.error("--limit-for-testing must be >= 0.")
    return args


def main() -> int:
    global PANDA_WORKERS, TODAY

    args = parse_args()
    run_lock = acquire_run_lock()
    PANDA_WORKERS = max(1, args.num_workers)
    TODAY = resolve_run_date(args.opening_type, bool(args.limit_for_testing))

    if args.item_parse:
        warn_msg = "[WARN] item_parse enabled -> forcing browser rendering for full menu items."
        print(warn_msg)
        logger.warning(warn_msg)
        if not ZYTE_REQUEST_BROWSER_HTML:
            set_browser_rendering(True)
        if not ZYTE_DOM_MENUS:
            set_dom_menus(True)
    else:
        if ZYTE_DOM_MENUS:
            set_dom_menus(False)

    input_csv = (
        LOCATION_CSV_PATH
        if args.limit_for_testing
        else prepare_input_snapshot(TODAY)
    )
    if not OPENING_HOURS_CSV.exists():
        raise FileNotFoundError(
            f"opening-hours CSV not found: {OPENING_HOURS_CSV}"
        )

    opening_hours = OpeningHoursIndex.load(OPENING_HOURS_CSV, "foodpanda")
    source_date = opening_hours.latest_source_date
    logger.info(
        "[SCHEDULE] Loaded opening hours: known=%d status_rows=%d "
        "invalid=%d source_date=%s",
        len(opening_hours.schedules),
        len(opening_hours.statuses),
        opening_hours.invalid_rows,
        source_date or "unknown",
    )
    if source_date:
        age_days = (datetime.now(TAIPEI_TZ).date() - source_date).days
        if age_days > 14:
            logger.warning(
                "[SCHEDULE] Opening-hours data is %d days old (source_date=%s)",
                age_days,
                source_date,
            )

    stores = read_store_list(input_csv)
    if args.item_parse and args.parse_part:
        target_mod = 0 if args.parse_part == "A" else 1
        total_before = len(stores)
        stores = [store for idx, store in enumerate(stores) if idx % 2 == target_mod]
        logger.info(
            "[INFO] item_parse parse_part=%s -> processing %d/%d shops",
            args.parse_part,
            len(stores),
            total_before,
        )
    if args.limit_for_testing:
        total_before = len(stores)
        stores = stores[: args.limit_for_testing]
        logger.info(
            "[INFO] limit_for_testing=%s -> processing %d/%d shops",
            args.limit_for_testing,
            len(stores),
            total_before,
        )
    if DEBUG_MODE and stores:
        stores = [stores[0]]
        logger.info("[DEBUG] Only crawling first store: %s", stores[0])

    total_stores = len(stores)
    success_count = 0
    cache_count = 0
    skip_count = 0
    deferred_count = 0
    run_start = time.perf_counter()
    opening_types = resolve_opening_types(args.opening_type)
    total_jobs = total_stores * len(opening_types)

    if not args.limit_for_testing:
        update_active_run(
            TODAY,
            args.opening_type,
            "running",
            input=str(input_csv),
            totalStores=total_stores,
            totalJobs=total_jobs,
        )

    for opening_type in opening_types:
        os.makedirs(output_dir_for(args.opening_type, opening_type), exist_ok=True)

    def _process_store(store: Dict[str, float], opening_type: str) -> str:
        shop_code = store["shopCode"]
        shop_name = store["shopName"]
        redirection_url = store.get("redirection_url")
        lat = store["lat"]
        lng = store["lng"]

        url = build_restaurant_url(shop_code, opening_type, redirection_url=redirection_url)
        out_file = output_file_for(
            lat,
            lng,
            shop_code,
            opening_type=opening_type,
            run_opening_type=args.opening_type,
            ext="json",
        )

        if SKIP_EXISTING_OUTPUT and is_successful_output(
            out_file,
            require_menu=args.item_parse,
            opening_type=opening_type,
            expected_shop_code=str(shop_code),
        ):
            return "cache"

        decision = opening_hours.decision(
            str(shop_code),
            closing_buffer=OPENING_CLOSING_BUFFER,
            minimum_buffer=OPENING_MINIMUM_BUFFER,
        )
        if decision.known and not decision.eligible:
            return "deferred"

        delay_sec = random.uniform(PER_REQUEST_DELAY_MIN_SEC, PER_REQUEST_DELAY_MAX_SEC)
        if delay_sec > 0:
            time.sleep(delay_sec)

        decision = opening_hours.decision(
            str(shop_code),
            closing_buffer=OPENING_CLOSING_BUFFER,
            minimum_buffer=OPENING_MINIMUM_BUFFER,
        )
        if decision.known and not decision.eligible:
            return "deferred"

        _THREAD_LOCAL.dispatch_deadline = decision.deadline if decision.known else None
        try:
            data = crawl_shop(shop_code, shop_name, url, opening_type=opening_type)
            if data is None:
                return "fail"
            if args.item_parse and not _has_complete_menu(data, opening_type):
                logger.warning(
                    "[INCOMPLETE] %s (%s, %s) result has no complete menu",
                    shop_code,
                    shop_name,
                    opening_type,
                )
                return "fail"
        except CrawlWindowClosed:
            return "deferred"
        finally:
            _THREAD_LOCAL.dispatch_deadline = None

        try:
            with open(out_file, "w", encoding="utf-8") as fw:
                json.dump(data, fw, ensure_ascii=False, indent=2)
            return "ok"
        except Exception as e:
            logger.error("[ERROR] write %s: %s", out_file, e)
            return "fail"

    def _record_result(store: Dict[str, float], opening_type: str, result: str) -> None:
        nonlocal success_count, cache_count, skip_count
        shop_code = store["shopCode"]
        shop_name = store["shopName"]
        out_file = output_file_for(
            store["lat"],
            store["lng"],
            shop_code,
            opening_type=opening_type,
            run_opening_type=args.opening_type,
            ext="json",
        )
        if result == "cache":
            success_count += 1
            cache_count += 1
            status_line = progress_snapshot(run_start, success_count, skip_count, total_jobs)
            logger.info(
                "[CACHE] Using existing JSON for %s (%s, %s) -> %s | %s",
                shop_code,
                shop_name,
                opening_type,
                out_file,
                status_line,
            )
        elif result == "ok":
            success_count += 1
            status_line = progress_snapshot(run_start, success_count, skip_count, total_jobs)
            logger.info(
                "[OK] Saved JSON for %s (%s) to %s | %s",
                shop_code,
                opening_type,
                out_file,
                status_line,
            )
        else:
            skip_count += 1
            status_line = progress_snapshot(run_start, success_count, skip_count, total_jobs)
            logger.info(
                "[SKIP] %s (%s, %s) failed | %s",
                shop_code,
                shop_name,
                opening_type,
                status_line,
            )

    ready: List[Tuple[float, int, Tuple[Dict[str, float], str]]] = []
    waiting: List[Tuple[float, int, Tuple[Dict[str, float], str]]] = []
    unknown: Deque[Tuple[Dict[str, float], str]] = deque()
    sequence = 0

    def _enqueue_job(
        job: Tuple[Dict[str, float], str],
        now: Optional[datetime] = None,
    ) -> None:
        nonlocal sequence
        store, _ = job
        decision = opening_hours.decision(
            str(store["shopCode"]),
            now=now,
            closing_buffer=OPENING_CLOSING_BUFFER,
            minimum_buffer=OPENING_MINIMUM_BUFFER,
        )
        sequence += 1
        if not decision.known:
            unknown.append(job)
        elif decision.eligible and decision.deadline:
            heapq.heappush(
                ready, (decision.deadline.timestamp(), sequence, job)
            )
        elif decision.next_open:
            heapq.heappush(
                waiting, (decision.next_open.timestamp(), sequence, job)
            )
        else:
            unknown.append(job)

    initial_now = datetime.now(TAIPEI_TZ)
    for store in stores:
        for opening_type in opening_types:
            out_file = output_file_for(
                store["lat"],
                store["lng"],
                store["shopCode"],
                opening_type=opening_type,
                run_opening_type=args.opening_type,
                ext="json",
            )
            if SKIP_EXISTING_OUTPUT and is_successful_output(
                out_file,
                require_menu=args.item_parse,
                opening_type=opening_type,
                expected_shop_code=str(store["shopCode"]),
            ):
                success_count += 1
                cache_count += 1
            else:
                _enqueue_job((store, opening_type), initial_now)

    logger.info(
        "[SCHEDULE] Plan cache=%d ready_open=%d waiting=%d unknown=%d "
        "closing_buffer=%.1fm workers=%d",
        cache_count,
        len(ready),
        len(waiting),
        len(unknown),
        OPENING_CLOSING_BUFFER.total_seconds() / 60,
        PANDA_WORKERS,
    )

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=PANDA_WORKERS) as executor:
            future_to_job: Dict[
                concurrent.futures.Future, Tuple[Dict[str, float], str]
            ] = {}
            last_wait_target: Optional[int] = None
            while ready or waiting or unknown or future_to_job:
                now = datetime.now(TAIPEI_TZ)

                while waiting and waiting[0][0] <= now.timestamp():
                    _, _, job = heapq.heappop(waiting)
                    _enqueue_job(job, now)

                while len(future_to_job) < PANDA_WORKERS:
                    job: Optional[Tuple[Dict[str, float], str]] = None
                    while ready and job is None:
                        _, _, candidate = heapq.heappop(ready)
                        candidate_store, _ = candidate
                        decision = opening_hours.decision(
                            str(candidate_store["shopCode"]),
                            now=now,
                            closing_buffer=OPENING_CLOSING_BUFFER,
                            minimum_buffer=OPENING_MINIMUM_BUFFER,
                        )
                        if decision.known and decision.eligible:
                            job = candidate
                        else:
                            _enqueue_job(candidate, now)

                    opening_soon = bool(
                        waiting
                        and waiting[0][0] - now.timestamp()
                        <= OPENING_CLOSING_BUFFER.total_seconds()
                    )
                    if job is None and unknown and not opening_soon:
                        job = unknown.popleft()
                    if job is None:
                        break

                    store, opening_type = job
                    future = executor.submit(_process_store, store, opening_type)
                    future_to_job[future] = job

                if not future_to_job:
                    if not (ready or waiting or unknown):
                        break
                    sleep_seconds = SCHEDULER_POLL_SECONDS
                    if waiting:
                        sleep_seconds = min(
                            sleep_seconds,
                            max(0.1, waiting[0][0] - time.time()),
                        )
                        wait_target = int(waiting[0][0])
                        if wait_target != last_wait_target:
                            logger.info(
                                "[SCHEDULE] No eligible known store; waiting "
                                "until %s (waiting=%d unknown=%d)",
                                datetime.fromtimestamp(
                                    wait_target, TAIPEI_TZ
                                ).isoformat(),
                                len(waiting),
                                len(unknown),
                            )
                            last_wait_target = wait_target
                    time.sleep(sleep_seconds)
                    continue

                wait_timeout = SCHEDULER_POLL_SECONDS
                if waiting:
                    wait_timeout = min(
                        wait_timeout,
                        max(0.1, waiting[0][0] - time.time()),
                    )
                completed, _ = concurrent.futures.wait(
                    future_to_job,
                    timeout=wait_timeout,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for future in completed:
                    store, opening_type = future_to_job.pop(future)
                    try:
                        result = future.result()
                    except Exception as exc:
                        logger.error(
                            "[ERROR] %s (%s) worker crashed: %s",
                            store["shopCode"],
                            store["shopName"],
                            exc,
                        )
                        result = "fail"

                    if result == "deferred":
                        deferred_count += 1
                        _enqueue_job((store, opening_type))
                    else:
                        _record_result(store, opening_type, result)
    except KeyboardInterrupt:
        elapsed = time.perf_counter() - run_start
        logger.warning("Interrupted; completed JSON files remain available as checkpoints")
        send_notification(
            "Foodpanda Zyte menu crawler paused",
            (
                f"Run date: {TODAY}\n"
                f"Opening type: {args.opening_type}\n"
                f"Completed jobs: {success_count}/{total_jobs}\n"
                f"Failed jobs: {skip_count}\n"
                f"Deferred dispatches: {deferred_count}\n"
                f"Elapsed: {elapsed / 3600:.2f} hours\n"
                f"Output: {OUTPUT_BASE}"
            ),
            "high",
        )
        if not args.limit_for_testing:
            update_active_run(
                TODAY,
                args.opening_type,
                "running",
                input=str(input_csv),
                totalStores=total_stores,
                totalJobs=total_jobs,
                completedJobs=success_count,
                failedJobs=skip_count,
                interrupted=True,
            )
        run_lock.close()
        return 130

    elapsed = time.perf_counter() - run_start
    summary = (
        f"Run date: {TODAY}\n"
        f"Opening type: {args.opening_type}\n"
        f"Stores: {total_stores}\n"
        f"Jobs: {total_jobs}\n"
        f"Fresh success: {success_count - cache_count}\n"
        f"Cache: {cache_count}\n"
        f"Failed: {skip_count}\n"
        f"Deferred dispatches: {deferred_count}\n"
        f"Zyte request attempts: {ZYTE_REQUEST_ATTEMPTS}\n"
        f"Zyte successful responses: {ZYTE_SUCCESSFUL_RESPONSES}\n"
        f"Zyte response seconds: {ZYTE_RESPONSE_SECONDS:.1f}\n"
        f"Elapsed: {elapsed / 3600:.2f} hours\n"
        f"Output: {OUTPUT_BASE}"
    )
    logger.info(summary.replace("\n", " | "))
    if not args.limit_for_testing:
        update_active_run(
            TODAY,
            args.opening_type,
            "complete" if skip_count == 0 else "running",
            input=str(input_csv),
            totalStores=total_stores,
            totalJobs=total_jobs,
            successfulJobs=success_count,
            cachedJobs=cache_count,
            failedJobs=skip_count,
            deferredDispatches=deferred_count,
        )
    if args.limit_for_testing:
        title = "Foodpanda Zyte menu crawler test completed"
        priority = "default" if skip_count == 0 else "high"
    elif skip_count == 0:
        title = "Foodpanda Zyte menu crawler completed"
        priority = "high"
    else:
        title = "Foodpanda Zyte menu crawler incomplete"
        priority = "urgent"
    send_notification(title, summary, priority)
    run_lock.close()
    return 0 if skip_count == 0 or args.limit_for_testing else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        logger.warning("Interrupted before crawl progress was initialized")
        send_notification(
            "Foodpanda Zyte menu crawler paused",
            f"Run date: {TODAY}\nOutput: {OUTPUT_BASE}",
            "high",
        )
        raise SystemExit(130)
    except Exception as e:
        logger.exception("Fatal error: %s", e)
        send_notification(
            "Foodpanda Zyte menu crawler failed",
            f"Run date: {TODAY}\nError: {e}\nOutput: {OUTPUT_BASE}",
            "urgent",
        )
        raise SystemExit(1)


# example usage:
# without menu item parsing:
#   python zyte_panda_menu.py --opening-type delivery
# crawl pickup menus:
#   python zyte_panda_menu.py --opening-type pickup --item-parse
# crawl both delivery and pickup menus:
#   python zyte_panda_menu.py --opening-type both --item-parse
# crawl only first 5 shops for testing:
#   python zyte_panda_menu.py --opening-type both --limit-for-testing 5
# with menu item parsing, part A: (侑霖)
#   python zyte_panda_menu.py --item-parse --parse-part A --num-workers 16
# with menu item parsing, part B: (友承)
#   python zyte_panda_menu.py --item-parse --parse-part B --num-workers 16

# 友承已不再協作，因此現在的指令為
#  python zyte_panda_menu.py --item-parse --opening-type both --num-workers 16
