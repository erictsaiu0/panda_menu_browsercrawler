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
import json
import logging
import os
import random
import re
import threading
import time
from datetime import datetime
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import dotenv
import requests
import urllib3
from requests.exceptions import RequestException, SSLError

dotenv.load_dotenv()


class AccessDeniedError(RuntimeError):
    """Raised when Foodpanda serves a captcha/block page."""

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

# ============================================
# Path & logging setup
# ============================================

BASE_DIR = Path(__file__).resolve().parent
LOCATION_CSV_PATH = Path("../panda_data") / "shopLst" / "rolling.csv"
TODAY = datetime.now().strftime("%Y-%m-%d")
OUTPUT_BASE = Path("../panda_data_js") / "panda_menu"
OUTPUT_DIR = OUTPUT_BASE / TODAY
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / f"{TODAY}.log"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    encoding="utf-8",
)
logger = logging.getLogger("panda_menu_zyte")


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


def output_file_for(lat: float, lng: float, shop_code: str, ext: str = "json") -> Path:
    return OUTPUT_DIR / f"{lat}_{lng}_{shop_code}.{ext}"


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


def _extract_json_from_html(html: str, marker: str) -> Optional[dict]:
    if not html:
        return None
    idx = html.find(marker)
    if idx == -1:
        return None
    idx += len(marker)
    end = html.find("</script>", idx)
    if end == -1:
        return None
    snippet = html[idx:end].strip()
    if snippet.endswith(";"):
        snippet = snippet[:-1]
    try:
        return json.loads(snippet)
    except Exception:
        return None


def extract_vendor_payload(html: str) -> Optional[dict]:
    return _extract_json_from_html(html, "window.__PRELOADED_STATE__=") or _extract_json_from_html(
        html, "window.__NEXT_DATA__="
    )


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

    def _finish_capture(self) -> None:
        if not self._capture_key:
            return
        key = self._capture_key
        text = unescape("".join(self._capture_buf)).strip()
        self._capture_key = None
        self._capture_buf = []
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
        self._tag_stack.append(tag)
        attr_map = self._attrs_to_dict(attrs)
        test_id = attr_map.get("data-testid")

        if tag == "div" and test_id == "menu-category-section":
            self._category = {
                "id": attr_map.get("id"),
                "name": None,
                "description": None,
                "products": [],
            }
            self._category_depth = len(self._tag_stack)
            return

        if self._category is None:
            return

        if tag == "h2" and "dish-category-title" in (attr_map.get("class") or ""):
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

    def handle_endtag(self, tag: str) -> None:
        if self._capture_key:
            self._finish_capture()

        if self._tag_stack:
            self._tag_stack.pop()

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
                "id": None,
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


def _fetch_menus_via_api(vendor_code: str, lat: Optional[float], lng: Optional[float]) -> Optional[List[Dict[str, Any]]]:
    base_url = f"https://tw.fd-api.com/api/v5/vendors/{vendor_code}"
    params: Dict[str, object] = {
        "include": "menus,bundles,multiple_discounts",
        "language_id": "6",
        "opening_type": "delivery",
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
        resp = requests.get(base_url, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        menus = data.get("data", {}).get("menus")
        return menus if isinstance(menus, list) else None
    except Exception as exc:
        logger.warning("[MENU_API] Vendor API fetch failed for %s: %s", vendor_code, exc)
        return None


# ============================================
# Zyte API fetch logic
# ============================================


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
    last_error: Optional[Exception] = None
    for attempt in range(1, ZYTE_MAX_FETCH_RETRIES + 1):
        payload = _build_zyte_request_payload(url)
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
    with open(csv_path, "r", encoding="utf-8") as f:
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


# ============================================
# Crawl logic
# ============================================


def crawl_shop(shop_code: str, shop_name: str, url: str) -> Optional[dict]:
    for attempt in range(1, MAX_ACCESS_DENIED_RETRIES + 1):
        try:
            html = fetch_page_via_zyte(url)
            payload = extract_vendor_payload(html)
            if payload is None:
                logger.warning(
                    "[NO_DATA] %s (%s) -> HTML parse failed (attempt %s)",
                    shop_code,
                    shop_name,
                    attempt,
                )
                _dump_json_debug(html, url, suffix="html_parse_failed")
                continue
            if not _has_menus(payload):
                if ZYTE_DOM_MENUS:
                    categories = _extract_dom_menu_categories(html)
                    if categories:
                        menus = _dom_categories_to_panda_menus(categories)
                        if menus:
                            _merge_menus_for_postprocess(payload, menus)
                            logger.info(
                                "[MENU_DOM] %s (%s) merged menus from DOM (categories=%s)",
                                shop_code,
                                shop_name,
                                len(categories),
                            )

                if not _has_menus(payload) and ZYTE_VENDOR_API_FALLBACK and not ZYTE_SKIP_VENDOR_API_FALLBACK:
                    vendor_code = _infer_vendor_code(payload, url, html)
                    lat, lng = _infer_coords(payload, html)
                    if vendor_code:
                        menus = _fetch_menus_via_api(vendor_code, lat, lng)
                        if menus:
                            _merge_menus_for_postprocess(payload, menus)
                            logger.info(
                                "[MENU_API] %s (%s) merged menus from vendor API (%s)",
                                shop_code,
                                shop_name,
                                vendor_code,
                            )

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
        except Exception as e:
            logger.error("[ERROR] %s (%s) fetch failed: %s", shop_code, shop_name, e)
            break
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Foodpanda menu crawler (Zyte API).")
    parser.add_argument(
        "--item-parse",
        action="store_true",
        help="Enable item parsing (forces browser rendering to fetch full menus).",
    )
    parser.add_argument(
        "--parse-part",
        choices=["A", "B"],
        help="Split rolling.csv into two halves when item parsing (A or B).",
    )
    args = parser.parse_args()
    if args.parse_part and not args.item_parse:
        parser.error("--parse-part is only valid when --item-parse is enabled.")
    return args


def main() -> None:
    args = parse_args()

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

    if not LOCATION_CSV_PATH.exists():
        raise FileNotFoundError(f"CSV not found: {LOCATION_CSV_PATH}")

    stores = read_store_list(LOCATION_CSV_PATH)
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
    if DEBUG_MODE and stores:
        stores = [stores[0]]
        logger.info("[DEBUG] Only crawling first store: %s", stores[0])

    total_stores = len(stores)
    success_count = 0
    skip_count = 0
    run_start = time.perf_counter()

    def _process_store(store: Dict[str, float]) -> str:
        shop_code = store["shopCode"]
        shop_name = store["shopName"]
        lat = store["lat"]
        lng = store["lng"]

        url = f"https://www.foodpanda.com.tw/restaurant/{shop_code}"
        out_file = output_file_for(lat, lng, shop_code, ext="json")

        if SKIP_EXISTING_OUTPUT and out_file.exists():
            return "cache"

        delay_sec = random.uniform(PER_REQUEST_DELAY_MIN_SEC, PER_REQUEST_DELAY_MAX_SEC)
        if delay_sec > 0:
            time.sleep(delay_sec)

        data = crawl_shop(shop_code, shop_name, url)
        if data is None:
            return "fail"

        try:
            with open(out_file, "w", encoding="utf-8") as fw:
                json.dump(data, fw, ensure_ascii=False, indent=2)
            return "ok"
        except Exception as e:
            logger.error("[ERROR] write %s: %s", out_file, e)
            return "fail"

    if PANDA_WORKERS <= 1:
        for store in stores:
            shop_code = store["shopCode"]
            shop_name = store["shopName"]
            lat = store["lat"]
            lng = store["lng"]
            out_file = output_file_for(lat, lng, shop_code, ext="json")

            result = _process_store(store)
            if result == "cache":
                success_count += 1
                status_line = progress_snapshot(run_start, success_count, skip_count, total_stores)
                logger.info("[CACHE] Using existing JSON for %s (%s) -> %s | %s", shop_code, shop_name, out_file, status_line)
            elif result == "ok":
                success_count += 1
                status_line = progress_snapshot(run_start, success_count, skip_count, total_stores)
                logger.info("[OK] Saved JSON for %s to %s | %s", shop_code, out_file, status_line)
            else:
                skip_count += 1
        return

    logger.info("[INFO] Running with %d workers (concurrent)", PANDA_WORKERS)
    with concurrent.futures.ThreadPoolExecutor(max_workers=PANDA_WORKERS) as executor:
        future_to_store = {executor.submit(_process_store, store): store for store in stores}
        for future in concurrent.futures.as_completed(future_to_store):
            store = future_to_store[future]
            shop_code = store["shopCode"]
            shop_name = store["shopName"]
            lat = store["lat"]
            lng = store["lng"]
            out_file = output_file_for(lat, lng, shop_code, ext="json")
            try:
                result = future.result()
            except Exception as exc:
                logger.error("[ERROR] %s (%s) worker crashed: %s", shop_code, shop_name, exc)
                result = "fail"

            if result == "cache":
                success_count += 1
                status_line = progress_snapshot(run_start, success_count, skip_count, total_stores)
                logger.info("[CACHE] Using existing JSON for %s (%s) -> %s | %s", shop_code, shop_name, out_file, status_line)
            elif result == "ok":
                success_count += 1
                status_line = progress_snapshot(run_start, success_count, skip_count, total_stores)
                logger.info("[OK] Saved JSON for %s to %s | %s", shop_code, out_file, status_line)
            else:
                skip_count += 1
                status_line = progress_snapshot(run_start, success_count, skip_count, total_stores)
                logger.info("[SKIP] %s (%s) failed | %s", shop_code, shop_name, status_line)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception("Fatal error: %s", e)


# example usage:
# without menu item parsing:
#   python zyte_panda_menu.py
# with menu item parsing, part A: (侑霖)
#   python zyte_panda_menu.py --item-parse --parse-part A
# with menu item parsing, part B: (友承)
#   python zyte_panda_menu.py --item-parse --parse-part B
