#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
用 Playwright 模擬瀏覽器，在瀏覽器內用 fetch 打 tw.fd-api.com API，
流程對應現在的 main.js + sendReqMenu.js，但改成由瀏覽器出手。

功能：
- 讀取 rolling.csv (shopCode, shopName, latitude, longitude)
- 對每一家店，在瀏覽器裡呼叫 vendors API
- 把完整 JSON 存成 {lat}_{lng}_{shopCode}.json
"""

import csv
import json
import logging
import os
import random
import time
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import urljoin

from playwright.sync_api import (
    Browser,
    BrowserContext,
    Error as PlaywrightError,
    Page,
    TimeoutError as PlaywrightTimeoutError,
    sync_playwright,
)
from playwright_stealth import stealth_sync

# =========================
# 參數設定
# =========================

# 只抓一間店測試用
DEBUG_MODE = False

# 為了排查 / 手動處理任何驗證，預設建議先開啟有畫面
HEADLESS = False

# 是否阻擋重量級資源（圖片 / 外掛）以加速載入
BLOCK_HEAVY_ASSETS = False
CURRENT_FAST_MODE = BLOCK_HEAVY_ASSETS
CURRENT_BROWSER = os.environ.get("SELENIUM_BROWSER", "firefox").lower()

# 在開始前先開 foodpanda 首頁，讓瀏覽器建好 session / cookie
HOME_URL = "https://www.foodpanda.com.tw/"
INIT_URL = HOME_URL

# 每間店之間隨機 delay（秒）
PER_REQUEST_DELAY_MIN_SEC = 5
PER_REQUEST_DELAY_MAX_SEC = 10

# 瀏覽器載入 timeout（秒）
PAGE_LOAD_TIMEOUT = 60

PAUSE_ON_PERIMETERX = True
PERIMETERX_MAX_RETRIES = 3
PERIMETERX_AUTO_SOLVE = True
PERIMETERX_AUTO_WAIT_SEC = 8
SESSION_COOKIES_FILE = Path("session_cookies.json")
SESSION_COOKIES_AUTO_SAVE = True
SESSION_STATE_FILE = Path("session_state.json")

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/118.0.0.0 Safari/537.36"
)
DEFAULT_VIEWPORT = {"width": 1280, "height": 720}

# =========================
# 路徑設定（對齊 JS 相對路徑）
# =========================

BASE_DIR = Path(__file__).resolve().parent

now = datetime.now()
TODAY = f"{now.year:04d}-{now.month:02d}-{now.day:02d}"

LOCATION_CSV_PATH = Path.home() / "panda_data" / "shopLst" / "rolling.csv"

OUTPUT_BASE = Path("panda_data_py") / "panda_menu"
OUTPUT_DIR = OUTPUT_BASE / TODAY

LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / f"{TODAY}.log"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("panda_menu_selenium_api")


def _launch_browser(playwright, browser_name: str) -> Browser:
    launch_kwargs = {"headless": HEADLESS}
    if browser_name in ("chrome", "chromium"):
        return playwright.chromium.launch(**launch_kwargs)
    if browser_name == "webkit":
        return playwright.webkit.launch(**launch_kwargs)
    return playwright.firefox.launch(**launch_kwargs)


def create_browser_page() -> Tuple:
    """啟動 Playwright browser + context + page。"""
    global CURRENT_BROWSER
    playwright = sync_playwright().start()
    browser: Optional[Browser] = None
    context: Optional[BrowserContext] = None
    storage_seed: Dict[str, str] = {}
    try:
        target = CURRENT_BROWSER
        try:
            browser = _launch_browser(playwright, target)
        except PlaywrightError as err:
            logger.warning(f"[BROWSER] 無法啟動 {target}, fallback chrome: {err}")
            browser = _launch_browser(playwright, "chrome")
            CURRENT_BROWSER = "chrome"

        context = browser.new_context(
            user_agent=USER_AGENT,
            viewport=DEFAULT_VIEWPORT,
            locale="zh-TW",
            storage_state=str(SESSION_STATE_FILE) if SESSION_STATE_FILE.exists() else None,
        )
        context.set_default_navigation_timeout(PAGE_LOAD_TIMEOUT * 1000)
        context.set_default_timeout(PAGE_LOAD_TIMEOUT * 1000)
        if not SESSION_STATE_FILE.exists():
            storage_seed = load_session_cookies(context)
            seed_storage_from_cookies(context, storage_seed)
        page = context.new_page()
        stealth_sync(page)
        if storage_seed:
            apply_storage_to_page(page, storage_seed)

        _reset_asset_routing_state()
        if BLOCK_HEAVY_ASSETS:
            _setup_asset_blocking(context)
            set_driver_assets(page, enable_heavy_assets=False)

        return playwright, browser, context, page
    except Exception:
        if context:
            context.close()
        if browser:
            browser.close()
        playwright.stop()
        raise


FAST_BLOCKED_URLS = tuple(
    pattern.lower()
    for pattern in [
        "*.png",
        "*.jpg",
        "*.jpeg",
        "*.gif",
        "*.webp",
        "*.svg",
        "*.mp4",
        "*.m4v",
        "*.avi",
        "*doubleclick*",
        "*googletagmanager*",
    ]
)


_asset_route_initialized = False
BLOCKED_RESOURCE_TYPES = {"image", "media", "font"}


def _reset_asset_routing_state():
    global _asset_route_initialized
    _asset_route_initialized = False


def _setup_asset_blocking(context: BrowserContext):
    """在 context 上註冊 route handler，動態阻擋重量資產。"""
    global _asset_route_initialized
    if _asset_route_initialized or not BLOCK_HEAVY_ASSETS:
        return

    def _should_block(request) -> bool:
        if request.resource_type in BLOCKED_RESOURCE_TYPES:
            return True
        url = request.url.lower()
        for pattern in FAST_BLOCKED_URLS:
            if fnmatch(url, pattern.lower()):
                return True
        return False

    def _route_handler(route):
        try:
            if CURRENT_FAST_MODE and _should_block(route.request):
                route.abort()
            else:
                route.continue_()
        except Exception as route_err:
            logger.debug(f"[ASSETS] route error: {route_err}")

    context.route("**/*", _route_handler)
    _asset_route_initialized = True


def set_driver_assets(page: Page, enable_heavy_assets: bool):
    """Playwright 版本的 asset 切換，只改變 FAST flag。"""
    global CURRENT_FAST_MODE
    if not BLOCK_HEAVY_ASSETS:
        return
    CURRENT_FAST_MODE = not enable_heavy_assets
    mode = "FAST" if CURRENT_FAST_MODE else "NORMAL"
    logger.info(f"[ASSETS] {mode} mode enabled")


def load_session_cookies(context: BrowserContext) -> Dict[str, str]:
    """將 session_cookies.json 的 cookies 匯入到 context, 並回傳可用的 storage seed。"""
    storage_seed: Dict[str, str] = {}
    if not SESSION_COOKIES_FILE.exists():
        logger.debug("[COOKIE] 沒有預先儲存的 session cookies")
        return storage_seed
    try:
        raw = json.loads(SESSION_COOKIES_FILE.read_text(encoding="utf-8"))
    except Exception as err:
        logger.warning(f"[COOKIE] 讀取 {SESSION_COOKIES_FILE} 失敗: {err}")
        return storage_seed

    cookies = []
    for entry in raw:
        if not isinstance(entry, dict) or not entry.get("name"):
            continue
        cookie = entry.copy()
        expiry = cookie.pop("expiry", None)
        if expiry is not None and "expires" not in cookie:
            try:
                cookie["expires"] = float(expiry)
            except (TypeError, ValueError):
                pass
        cookies.append(cookie)

        name_lower = entry.get("name", "").lower()
        value = entry.get("value")
        if not value:
            continue
        if name_lower == "dhhperseusguestid":
            storage_seed.setdefault("perseus.userId", value)
            storage_seed.setdefault("perseus.guestId", value)
        elif name_lower == "dhhperseussessionid":
            storage_seed.setdefault("perseus.sessionId", value)
        elif name_lower == "dhhperseushitid":
            storage_seed.setdefault("perseus.hitId", value)

    if not cookies:
        logger.debug("[COOKIE] 檔案裡沒有有效的 cookies")
        return storage_seed

    try:
        context.add_cookies(cookies)
        logger.info(f"[COOKIE] 載入 {len(cookies)} 筆 session cookies")
    except Exception as err:
        logger.warning(f"[COOKIE] 匯入 cookies 失敗: {err}")
        return storage_seed
    return storage_seed


def save_session_cookies(context: BrowserContext):
    """把目前 context 的 cookies 存到 session_cookies.json。"""
    if not SESSION_COOKIES_AUTO_SAVE:
        return
    try:
        context.storage_state(path=str(SESSION_STATE_FILE))
        logger.info(f"[COOKIE] 已更新 {SESSION_STATE_FILE}")
    except Exception as err:
        logger.warning(f"[COOKIE] 儲存 storage_state 失敗: {err}")

    try:
        cookies = context.cookies()
    except Exception as err:
        logger.warning(f"[COOKIE] 無法取得 cookies: {err}")
        return

    payload = []
    for cookie in cookies:
        entry = dict(cookie)
        expires = entry.pop("expires", None)
        if expires is not None:
            entry["expiry"] = expires
        payload.append(entry)

    try:
        SESSION_COOKIES_FILE.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info(f"[COOKIE] 已更新 {SESSION_COOKIES_FILE}（{len(payload)} 筆）")
    except Exception as err:
        logger.warning(f"[COOKIE] 寫入 {SESSION_COOKIES_FILE} 失敗: {err}")


def seed_storage_from_cookies(context: BrowserContext, storage_seed: Dict[str, str]):
    """透過 add_init_script 把需要的 storage 預先寫入。"""
    if not storage_seed:
        return

    script = """
    (data) => {
      if (!data || typeof data !== 'object') {
        return;
      }
      const apply = (storage) => {
        if (!storage) {
          return;
        }
        for (const [key, value] of Object.entries(data)) {
          if (typeof value === 'string' && value.length > 0) {
            try {
              storage.setItem(key, value);
            } catch (err) {
              // ignore quota errors
            }
          }
        }
      };
      try { apply(window.localStorage); } catch (err) {}
      try { apply(window.sessionStorage); } catch (err) {}
    }
    """
    try:
        context.add_init_script(script, storage_seed)
    except Exception as err:
        logger.debug(f"[COOKIE] 無法註冊 storage seed: {err}")


def apply_storage_to_page(page: Page, storage_seed: Dict[str, str]):
    if not storage_seed:
        return
    try:
        page.evaluate(
            """
            (data) => {
              if (!data || typeof data !== 'object') {
                return;
              }
              const apply = (storage) => {
                if (!storage) {
                  return;
                }
                for (const [key, value] of Object.entries(data)) {
                  if (typeof value === 'string' && value.length > 0) {
                    try { storage.setItem(key, value); } catch (err) {}
                  }
                }
              };
              try { apply(window.localStorage); } catch (err) {}
              try { apply(window.sessionStorage); } catch (err) {}
            }
            """,
            storage_seed,
        )
    except Exception as err:
        logger.debug(f"[COOKIE] 無法把 storage seed 寫入頁面: {err}")


def ensure_perseus_storage(page: Page):
    """確保 localStorage/sessionStorage 內有必要的 perseus 值。"""
    try:
        cookies = page.context.cookies()
    except Exception as err:
        logger.debug(f"[COOKIE] 無法讀取 cookies 以同步 storage: {err}")
        return

    mapping: Dict[str, str] = {}
    for cookie in cookies:
        name = cookie.get("name", "")
        value = cookie.get("value")
        if not name or not value:
            continue
        lower = name.lower()
        if lower == "dhhperseusguestid":
            mapping["perseus.userId"] = value
            mapping.setdefault("perseus.guestId", value)
        elif lower == "dhhperseussessionid":
            mapping["perseus.sessionId"] = value
        elif lower == "dhhperseushitid":
            mapping["perseus.hitId"] = value
    if mapping:
        apply_storage_to_page(page, mapping)


# =========================
# 在瀏覽器內叫 vendors API 的 JS
# （模擬 sendReqMenu.js 但由瀏覽器發出）
# =========================

FETCH_VENDOR_JS = """
async ({ shopUuid, latitude, longitude }) => {
  const url = `https://tw.fd-api.com/api/v5/vendors/${shopUuid}?`
    + "include=menus,bundles,multiple_discounts&language_id=6&"
    + "opening_type=delivery&basket_currency=TWD&"
    + `latitude=${latitude}&longitude=${longitude}`;

  const headers = {
    'Accept': 'application/json, text/plain, */*',
    'X-PD-Language-ID': '6',
    'X-FP-API-KEY': 'volo',
    'Api-Version': '7'
  };

  const readStorage = (key) => {
    try {
      return window.localStorage.getItem(key)
        || window.sessionStorage.getItem(key)
        || null;
    } catch (err) {
      return null;
    }
  };

  const readCookie = (name) => {
    try {
      const needle = `${name}=`;
      const match = document.cookie.split('; ').find((row) => row.startsWith(needle));
      if (!match) {
        return null;
      }
      return decodeURIComponent(match.substring(needle.length));
    } catch (err) {
      return null;
    }
  };

  const setHeaderIfValue = (key, value) => {
    if (value && String(value).length > 0) {
      headers[key] = value;
    }
  };

  const attachDeviceInfo = () => {
    const deviceId = readStorage('fp-deviceId')
      || readStorage('fp-device-id')
      || readStorage('fp-deviceId-ses');
    setHeaderIfValue('X-FP-Device-Id', deviceId);
    setHeaderIfValue('X-Device-Serial', deviceId);
  };

  const attachSessionInfo = () => {
    const dpsSession = readStorage('dps-session-id') || readCookie('dps-session-id');
    const fpSession = readStorage('fp-session-id')
      || readStorage('fp-sessionId')
      || readCookie('fp-session-id');
    const sessionId = fpSession || dpsSession;
    setHeaderIfValue('X-FP-Session-Id', sessionId);
    setHeaderIfValue('X-DPS-SESSION-ID', dpsSession);
    setHeaderIfValue('dps-session-id', dpsSession);
    setHeaderIfValue('fp-session-id', sessionId);
  };

  const attachMiscHeaders = () => {
    const appInfo = readStorage('fp-appInfo');
    setHeaderIfValue('X-FP-App-Info', appInfo);

    const csrfToken = readStorage('fp-csrfToken') || readCookie('fp-csrfToken');
    setHeaderIfValue('X-CSRF-Token', csrfToken);

    const locale = readStorage('fp-locale')
      || readCookie('countryCode')
      || (navigator.language || navigator.userLanguage);
    setHeaderIfValue('X-FP-Locale', locale);

    const trackingId = readStorage('perseus.userId') || readCookie('dhhPerseusGuestId');
    setHeaderIfValue('X-FP-Tracking-Id', trackingId);
    setHeaderIfValue('X-PERSEUS-USER-ID', trackingId);

    const perseusGuest = readCookie('dhhPerseusGuestId') || readStorage('perseus.guestId');
    const perseusSession = readCookie('dhhPerseusSessionId') || readStorage('perseus.sessionId');
    const perseusHit = readCookie('dhhPerseusHitId') || readStorage('perseus.hitId');

    setHeaderIfValue('X-FP-PERSEUS-GUEST-ID', perseusGuest);
    setHeaderIfValue('X-FP-PERSEUS-SESSION-ID', perseusSession);
    setHeaderIfValue('X-FP-PERSEUS-HIT-ID', perseusHit);
    setHeaderIfValue('X-PERSEUS-GUEST-ID', perseusGuest);
    setHeaderIfValue('X-PERSEUS-SESSION-ID', perseusSession);
    setHeaderIfValue('X-PERSEUS-HIT-ID', perseusHit);
    setHeaderIfValue('X-DHH-PERSEUS-GUEST-ID', perseusGuest);
    setHeaderIfValue('X-DHH-PERSEUS-SESSION-ID', perseusSession);
    setHeaderIfValue('X-DHH-PERSEUS-HIT-ID', perseusHit);

    if (window.crypto && window.crypto.randomUUID) {
      setHeaderIfValue('X-FP-Request-Id', window.crypto.randomUUID());
    } else {
      setHeaderIfValue(
        'X-FP-Request-Id',
        `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
      );
    }
  };

  try {
    attachDeviceInfo();
    attachSessionInfo();
    attachMiscHeaders();
  } catch (metaErr) {
    console.warn('[FETCH_VENDOR_JS] Failed to attach FP headers', metaErr);
  }

  if (!headers['Accept-Language']) {
    const languages = navigator.languages && navigator.languages.length
      ? navigator.languages.join(',')
      : (navigator.language || 'en-US');
    headers['Accept-Language'] = languages;
  }

  try {
    const resp = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers
    });
    const text = await resp.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch (err) {
      // ignore parse error
    }
    return {
      ok: resp.ok,
      status: resp.status,
      statusText: resp.statusText,
      data,
      bodyText: text,
      sentHeaders: headers
    };
  } catch (err) {
    return {
      ok: false,
      error: err && err.toString ? err.toString() : String(err),
      sentHeaders: headers
    };
  }
}
"""


def init_browser_session(page: Page):
    """
    先開首頁，建立 session / cookie。
    如果網站有顯示任何驗證頁面，需要在這裡人工處理完再繼續。
    """
    logger.info(f"[INIT] 打開首頁 {INIT_URL}")
    try:
        page.goto(INIT_URL, wait_until="networkidle", timeout=PAGE_LOAD_TIMEOUT * 1000)
    except PlaywrightTimeoutError as err:
        logger.warning(f"[INIT] 首頁載入 timeout/錯誤: {err}")

    # 如果你看到有任何驗證畫面（captcha 等），這邊可以暫停人工處理。
    print("\n如果瀏覽器目前有任何驗證畫面，請先在瀏覽器中處理完，再回到終端機按 Enter 繼續。")
    try:
        input("(如果沒有驗證畫面也可以直接按 Enter 繼續) > ")
    except EOFError:
        logger.warning("無法等待使用者輸入，繼續執行。")


def fetch_vendor_in_browser(page: Page, shop_uuid, lat, lng):
    """
    在瀏覽器中執行 FETCH_VENDOR_JS，呼叫 vendors API。
    回傳 vendors API 的 data（或 None 表示失敗）。
    """
    logger.info(f"[API] 呼叫 vendor {shop_uuid} at ({lat}, {lng})")
    attempts = 0

    while attempts < PERIMETERX_MAX_RETRIES:
        attempts += 1
        try:
            ensure_perseus_storage(page)
            result = page.evaluate(
                FETCH_VENDOR_JS,
                {
                    "shopUuid": shop_uuid,
                    "latitude": float(lat),
                    "longitude": float(lng),
                },
            )
        except Exception as e:
            logger.error(f"[API_ERROR] Playwright evaluate 失敗: {e}")
            return None

        if not isinstance(result, dict):
            logger.error(f"[API_ERROR] 非預期回傳: {result}")
            return None

        if not result.get("ok", False):
            body_preview = result.get("bodyText")
            if body_preview:
                preview = body_preview[:200].replace("\n", " ")
                logger.warning(f"[API_FAIL_BODY] {shop_uuid} snippet: {preview}")
            sent_headers = result.get("sentHeaders")
            if sent_headers:
                logger.debug(f"[API_FAIL_HEADERS] {shop_uuid}: {sent_headers}")

            px_payload = _extract_perimeterx_payload(result)
            if px_payload:
                logger.warning(f"[BLOCKED] {shop_uuid} 被 PerimeterX 擋住 (retry {attempts}/{PERIMETERX_MAX_RETRIES})")
                action = handle_perimeterx_block(page, shop_uuid, px_payload)
                if action == "retry":
                    continue
                if action == "skip":
                    return None
            logger.warning(
                f"[API_FAIL] {shop_uuid} status={result.get('status')} "
                f"err={result.get('error')}"
            )
            return None

        status = result.get("status")
        if status and status != 200:
            body_preview = result.get("bodyText")
            if body_preview:
                preview = body_preview[:200].replace("\n", " ")
                logger.warning(f"[API_STATUS_BODY] {shop_uuid} snippet: {preview}")

            px_payload = _extract_perimeterx_payload(result)
            if status == 403 and px_payload:
                logger.warning(f"[BLOCKED] {shop_uuid} HTTP 403 (retry {attempts}/{PERIMETERX_MAX_RETRIES})")
                action = handle_perimeterx_block(page, shop_uuid, px_payload)
                if action == "retry":
                    continue
                if action == "skip":
                    return None

            logger.warning(f"[API_STATUS] {shop_uuid} HTTP {status} {result.get('statusText')}")
            # 即使不是 200，你也可視情況把 body 存起來
            # 這裡就直接回傳 data/bodyText，交給上層決定
        data = result.get("data")

        # 參考 getMenu.js 的 blockedByPerimeterX 判斷（可能回傳 blockScript）
        try:
            if (
                isinstance(data, dict)
                and data.get("appId")
                and data.get("jsClientSrc")
                and data.get("blockScript")
            ):
                logger.warning(f"[BLOCKED] {shop_uuid} 看起來被 PerimeterX 或類似機制擋住")
                action = handle_perimeterx_block(page, shop_uuid, data)
                if action == "retry":
                    continue
                if action == "skip":
                    return None
        except Exception:
            pass

        return data if data is not None else result.get("bodyText")

    logger.error(f"[PERIMETERX] {shop_uuid} 達到最大重試次數，放棄")
    return None


def _extract_perimeterx_payload(result):
    """從 API 回應中找出可能的 PerimeterX payload。"""
    candidates = []
    data = result.get("data")
    if isinstance(data, dict):
        candidates.append(data)
    body_text = result.get("bodyText")
    if body_text:
        try:
            parsed = json.loads(body_text)
            if isinstance(parsed, dict):
                candidates.append(parsed)
        except (ValueError, TypeError):
            pass
    for payload in candidates:
        if (
            isinstance(payload, dict)
            and payload.get("blockScript")
            and payload.get("appId")
        ):
            return payload
    return None


def _collect_perimeterx_tokens(context: BrowserContext):
    """回傳目前已知的 PerimeterX cookies (name -> value)。"""
    tokens = {}
    try:
        cookies = context.cookies()
    except Exception as err:
        logger.debug(f"[PERIMETERX] 無法讀取 cookies: {err}")
        return tokens

    for cookie in cookies:
        name = (cookie.get("name") or "").strip()
        if not name:
            continue
        lower_name = name.lower()
        if lower_name.startswith("_px") or "perimeterx" in lower_name:
            tokens[name] = cookie.get("value")
    return tokens


def _resolve_perimeterx_url(payload):
    px_urls = [
        payload.get("hostUrl"),
        payload.get("blockScript"),
    ]
    for candidate in px_urls:
        if not candidate:
            continue
        if candidate.startswith("http"):
            return candidate
        return urljoin(HOME_URL, candidate)
    return HOME_URL


def _auto_resolve_perimeterx(page: Page, payload) -> bool:
    if not PERIMETERX_AUTO_SOLVE:
        return False

    context = page.context
    before_tokens = _collect_perimeterx_tokens(context)
    target_url = _resolve_perimeterx_url(payload)
    helper_page = context.new_page()
    logger.info(f"[PERIMETERX] 自動嘗試驗證: {target_url}")
    prev_fast_mode = CURRENT_FAST_MODE
    if BLOCK_HEAVY_ASSETS and CURRENT_FAST_MODE:
        set_driver_assets(helper_page, enable_heavy_assets=True)

    try:
        helper_page.goto(target_url, wait_until="domcontentloaded", timeout=PAGE_LOAD_TIMEOUT * 1000)
        block_snippet = payload.get("blockScript") or ""
        snippet = block_snippet.strip()
        if snippet.startswith("<") and "</" in snippet:
            helper_page.set_content(block_snippet, wait_until="domcontentloaded")
        wait_sec = max(PERIMETERX_AUTO_WAIT_SEC, 3)
        helper_page.wait_for_timeout(wait_sec * 1000)
    except Exception as auto_err:
        logger.warning(f"[PERIMETERX] 自動驗證過程錯誤: {auto_err}")
    finally:
        try:
            helper_page.close()
        except Exception:
            pass
        if BLOCK_HEAVY_ASSETS and prev_fast_mode:
            set_driver_assets(page, enable_heavy_assets=False)

    after_tokens = _collect_perimeterx_tokens(context)
    if after_tokens != before_tokens and after_tokens:
        logger.info("[PERIMETERX] 自動驗證後 cookie 更新，準備重試。")
        save_session_cookies(context)
        return True
    logger.info("[PERIMETERX] 自動驗證未能取得新的 cookie。")
    return False


def handle_perimeterx_block(page: Page, shop_uuid, payload):
    """提示使用者手動處理 PerimeterX captcha，並決定重試 / 跳過。"""
    if _auto_resolve_perimeterx(page, payload):
        return "retry"

    if not PAUSE_ON_PERIMETERX:
        return "abort"

    logger.warning(f"[PERIMETERX] {shop_uuid} 遭遇驗證，需要手動處理。")
    target_url = _resolve_perimeterx_url(payload)

    prev_fast_mode = CURRENT_FAST_MODE
    if BLOCK_HEAVY_ASSETS and CURRENT_FAST_MODE:
        set_driver_assets(page, enable_heavy_assets=True)

    try:
        page.goto(target_url, wait_until="domcontentloaded", timeout=PAGE_LOAD_TIMEOUT * 1000)
    except Exception as nav_err:
        logger.warning(f"[PERIMETERX] 無法自動開啟 {target_url}: {nav_err}")

    print(
        "\n[PerimeterX] API 被擋住，請在瀏覽器裡完成顯示的驗證（例如圖片 / checkbox）。\n"
        "完成後輸入 done 重新嘗試，輸入 skip 跳過這間店，或輸入 quit 結束程式。\n"
    )

    while True:
        try:
            answer = input("PerimeterX captcha (done/skip/quit) > ").strip().lower()
        except EOFError:
            logger.warning("[PERIMETERX] 無法取得輸入，預設重試一次。")
            answer = "done"

        if answer in ("done", "d", "retry", "r", "continue", "c"):
            logger.info("[PERIMETERX] 使用者完成驗證，準備重試。")
            if BLOCK_HEAVY_ASSETS and prev_fast_mode:
                set_driver_assets(page, enable_heavy_assets=False)
            save_session_cookies(page.context)
            return "retry"
        if answer == "skip":
            logger.info("[PERIMETERX] 使用者選擇跳過。")
            if BLOCK_HEAVY_ASSETS and prev_fast_mode:
                set_driver_assets(page, enable_heavy_assets=False)
            return "skip"
        if answer in ("quit", "exit", "abort", "q"):
            raise KeyboardInterrupt("使用者在 PerimeterX 驗證階段終止程式。")

        print("請輸入 done、skip 或 quit。")


# =========================
# 讀 rolling.csv（對應 main.js readCSV）
# =========================

def read_store_list(csv_path: Path):
    stores = []
    if not csv_path.exists():
        raise FileNotFoundError(f"找不到 CSV: {csv_path}")

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                shop_code = (
                    row.get("shopCode") or row.get("shop_uuid") or row.get("code")
                )
                shop_name = row.get("shopName") or row.get("name")
                lat = float(row.get("latitude"))
                lng = float(row.get("longitude"))
            except Exception as e:
                logger.warning(f"[SKIP] 壞掉的 row {row}: {e}")
                continue

            stores.append(
                {
                    "shopCode": shop_code,
                    "shopName": shop_name,
                    "lat": lat,
                    "lng": lng,
                }
            )

    if stores:
        logger.info(
            f"({stores[0]['lat']}, {stores[0]['lng']}): 共 {len(stores)} 間店（來自 {csv_path}）"
        )
    else:
        logger.warning(f"{csv_path} 裡沒有店家資料")

    return stores


# =========================
# 主流程（類似 main.js 的 main()）
# =========================

def main():
    stores = read_store_list(LOCATION_CSV_PATH)

    if DEBUG_MODE and stores:
        stores = [stores[0]]
        logger.info(f"[DEBUG] 只抓第一間店: {stores[0]}")

    playwright = browser = context = page = None
    try:
        playwright, browser, context, page = create_browser_page()
        init_browser_session(page)

        for idx, store in enumerate(stores, start=1):
            shop_code = store["shopCode"]
            shop_name = store["shopName"]
            lat = store["lat"]
            lng = store["lng"]

            delay_sec = random.uniform(
                PER_REQUEST_DELAY_MIN_SEC, PER_REQUEST_DELAY_MAX_SEC
            )
            logger.info(
                f"[SLEEP] {delay_sec:.1f}s before {shop_code} ({idx}/{len(stores)})"
            )
            time.sleep(delay_sec)

            try:
                data = fetch_vendor_in_browser(page, shop_code, lat, lng)
                if data is None:
                    logger.warning(f"[NO_DATA] {shop_code} ({shop_name}) -> 沒有拿到資料")
                    continue

                out_file = OUTPUT_DIR / f"{lat}_{lng}_{shop_code}.json"
                try:
                    with open(out_file, "w", encoding="utf-8") as fw:
                        json.dump(data, fw, ensure_ascii=False)
                    logger.info(f"[OK] {shop_code} JSON -> {out_file}")
                except Exception as e:
                    logger.error(f"[WRITE_ERR] 無法寫入 {out_file}: {e}")

            except Exception as e:
                logger.error(
                    f"[ERROR] {shop_code} ({shop_name}) at ({lat}, {lng}): {e}"
                )
    finally:
        try:
            if context:
                save_session_cookies(context)
                context.close()
            if browser:
                browser.close()
            if playwright:
                playwright.stop()
        finally:
            logger.info("Browser 關閉，流程結束。")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        print(f"發生嚴重錯誤，詳情請看 log 檔：{LOG_FILE}")
