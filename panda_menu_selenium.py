#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import json
import logging
import os
import random
import time
from datetime import datetime
from pathlib import Path
import platform
import shutil

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.support.ui import WebDriverWait


class AccessDeniedError(RuntimeError):
    """Raised when Foodpanda serves a captcha/block page."""

    pass

# ============================================
# 基本設定
# ============================================

# 是否只測試一間店（方便 debug）
DEBUG_MODE = False

# 是否 headless（如果被擋嚴重，可以改成 False 看看）
HEADLESS = False

# 是否偵測到 captcha 時暫停，讓你手動處理後再繼續
PAUSE_ON_ACCESS_DENIED = True

# 隨機 delay（避免太機器人）
PER_REQUEST_DELAY_MIN_SEC = 0
PER_REQUEST_DELAY_MAX_SEC = 1

# 是否直接抓 HTML（跳過 JSON 解析）
CRAWL_HTML_ONLY = True

# 是否阻擋重量級資源（圖片 / 外掛）以加速載入（跑 captcha 時可暫時關閉）
BLOCK_HEAVY_ASSETS = False
CURRENT_FAST_MODE = BLOCK_HEAVY_ASSETS
CURRENT_BROWSER = os.environ.get("SELENIUM_BROWSER", "firefox").lower()

# 遇到 recaptcha 時等候的秒數，之後自動跳過
RECAPTCHA_WAIT = int(os.environ.get("RECAPTCHA_WAIT", "60"))

# Selenium 等待頁面載入的最大秒數
PAGE_LOAD_TIMEOUT = 60

# 被擋時頁面會顯示的關鍵字（PerimeterX captcha）
ACCESS_DENIED_MARKERS = (
    "Access to this page has been denied",
    "px-captcha",
)

# ============================================
# 路徑設定（對齊你現有 JS 相對位置）
# ============================================

BASE_DIR = Path(__file__).resolve().parent

SYSTEM = platform.system().lower()
MACHINE = platform.machine().lower()
IS_RPI = SYSTEM == "linux" and ("arm" in MACHINE or "aarch64" in MACHINE)

# 輸入的店家清單（跟 main.js 一樣）
LOCATION_CSV_PATH = BASE_DIR / "panda_data" / "shopLst" / "rolling.csv"

# 輸出的 JSON 目錄（用 python 版，避免和 js 混在一起）
TODAY = datetime.now().strftime("%Y-%m-%d")
OUTPUT_BASE = BASE_DIR / "panda_data_py" / "panda_menu"
OUTPUT_DIR = OUTPUT_BASE / TODAY

# log 檔
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / f"{TODAY}.log"

# cookie / session 相關設定
HOME_URL = "https://www.foodpanda.com.tw/"
COOKIES_PATH = BASE_DIR / "session_cookies.json"
MAX_ACCESS_DENIED_RETRIES = 2
COOKIE_ALLOWED_KEYS = {"name", "value", "domain", "path", "expiry", "secure", "httpOnly"}
FIRST_MANUAL_CAPTCHA_WAIT_SEC = 20
FIRST_MANUAL_CAPTCHA_PENDING = True

# 自動偵測各平臺的瀏覽器與 driver 路徑
def _build_binary_candidates():
    driver_dir = BASE_DIR / "drivers"
    candidates = {
        "chromium": [],
        "chromedriver": [driver_dir / "chromedriver", driver_dir / "chromedriver.exe"],
        "geckodriver": [driver_dir / "geckodriver", driver_dir / "geckodriver.exe"],
        "firefox": [],
    }

    if SYSTEM == "windows":
        program_files = Path(os.environ.get("PROGRAMFILES", r"C:\\Program Files"))
        program_files_x86 = Path(os.environ.get("PROGRAMFILES(X86)", r"C:\\Program Files (x86)"))
        candidates["chromium"] += [
            program_files / "Google" / "Chrome" / "Application" / "chrome.exe",
            program_files_x86 / "Google" / "Chrome" / "Application" / "chrome.exe",
            program_files / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe",
        ]
        candidates["chromedriver"] += [
            program_files / "Google" / "Chrome" / "Application" / "chromedriver.exe",
            program_files_x86 / "Google" / "Chrome" / "Application" / "chromedriver.exe",
        ]
        candidates["firefox"] += [
            program_files / "Mozilla Firefox" / "firefox.exe",
            program_files_x86 / "Mozilla Firefox" / "firefox.exe",
        ]
        candidates["geckodriver"] += [
            program_files / "Mozilla Firefox" / "geckodriver.exe",
            program_files_x86 / "Mozilla Firefox" / "geckodriver.exe",
        ]
    elif SYSTEM == "darwin":
        candidates["chromium"] += [
            Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            Path("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
        ]
        candidates["chromedriver"] += [
            Path("/usr/local/bin/chromedriver"),
            Path("/opt/homebrew/bin/chromedriver"),
        ]
        candidates["firefox"] += [
            Path("/Applications/Firefox.app/Contents/MacOS/firefox"),
        ]
        candidates["geckodriver"] += [
            Path("/usr/local/bin/geckodriver"),
            Path("/opt/homebrew/bin/geckodriver"),
        ]
    else:
        linux_chromium = [
            Path("/usr/bin/chromium-browser"),
            Path("/usr/bin/chromium"),
            Path("/usr/bin/google-chrome"),
            Path("/usr/bin/google-chrome-stable"),
        ]
        if IS_RPI:
            linux_chromium.insert(0, Path("/usr/bin/chromium-browser"))
        candidates["chromium"] += linux_chromium
        candidates["chromedriver"] += [
            Path("/usr/bin/chromedriver"),
            Path("/usr/local/bin/chromedriver"),
        ]
        candidates["firefox"] += [
            Path("/usr/bin/firefox"),
            Path("/snap/bin/firefox"),
        ]
        candidates["geckodriver"] += [
            Path("/usr/bin/geckodriver"),
            Path("/usr/local/bin/geckodriver"),
        ]

    return candidates


def _resolve_binary(env_key, candidates, which_names):
    override = os.environ.get(env_key)
    if override:
        return Path(override)

    for name in which_names:
        found = shutil.which(name)
        if found:
            return Path(found)

    for path_candidate in candidates:
        if path_candidate and Path(path_candidate).exists():
            return Path(path_candidate)

    if candidates:
        return Path(candidates[0])
    return Path(override or which_names[0])

BINARY_CANDIDATES = _build_binary_candidates()

# Chromium / chromedriver 路徑
CHROMIUM_BINARY = _resolve_binary(
    "CHROMIUM_BINARY",
    BINARY_CANDIDATES["chromium"],
    ["chromium-browser", "chromium", "google-chrome", "chrome"],
)
CHROMEDRIVER_BINARY = _resolve_binary(
    "CHROMEDRIVER_BINARY",
    BINARY_CANDIDATES["chromedriver"],
    ["chromedriver"],
)
CHROME_FAST_SETTINGS = {}
GECKODRIVER_BINARY = _resolve_binary(
    "GECKODRIVER_BINARY",
    BINARY_CANDIDATES["geckodriver"],
    ["geckodriver"],
)
FIREFOX_BINARY = _resolve_binary(
    "FIREFOX_BINARY",
    BINARY_CANDIDATES["firefox"],
    ["firefox"],
)


def switch_to_chrome():
    global CURRENT_BROWSER, BLOCK_HEAVY_ASSETS, CURRENT_FAST_MODE
    CURRENT_BROWSER = "chrome"
    BLOCK_HEAVY_ASSETS = True
    CURRENT_FAST_MODE = True

# ============================================
# Logging 設定
# ============================================

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    encoding="utf-8",
)

logger = logging.getLogger("panda_menu_selenium")
logger.info(
    "[CONFIG] Detected platform=%s machine=%s browser=%s",
    SYSTEM,
    MACHINE,
    CURRENT_BROWSER,
)
logger.info(
    "[CONFIG] chromium=%s chromedriver=%s firefox=%s geckodriver=%s",
    CHROMIUM_BINARY,
    CHROMEDRIVER_BINARY,
    FIREFOX_BINARY,
    GECKODRIVER_BINARY,
)


# ============================================
# Selenium 初始化
# ============================================

def create_webdriver():
    """建立一個 Selenium WebDriver（Chromium / Chrome 或 Firefox）"""
    if CURRENT_BROWSER == "chrome":
        chrome_options = ChromeOptions()

        if HEADLESS:
            chrome_options.add_argument("--headless=new")

        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument(
            "--user-agent=Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/118.0.0.0 Safari/537.36"
        )

        if CHROMIUM_BINARY.exists():
            chrome_options.binary_location = str(CHROMIUM_BINARY)
        else:
            logger.warning(f"Chromium binary not found at {CHROMIUM_BINARY}")

        if not CHROMEDRIVER_BINARY.exists():
            raise FileNotFoundError(f"chromedriver not found at {CHROMEDRIVER_BINARY}")

        service = ChromeService(executable_path=str(CHROMEDRIVER_BINARY))
        driver = webdriver.Chrome(service=service, options=chrome_options)
    else:
        firefox_options = FirefoxOptions()
        if HEADLESS:
            firefox_options.add_argument("-headless")
        firefox_options.set_preference("general.useragent.override",
                                       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36")
        if BLOCK_HEAVY_ASSETS:
            firefox_options.set_preference("permissions.default.image", 2)
            firefox_options.set_preference("dom.ipc.plugins.enabled.libflashplayer.so", False)
            firefox_options.set_preference("media.autoplay.default", 5)

        if FIREFOX_BINARY.exists():
            firefox_options.binary_location = str(FIREFOX_BINARY)
        else:
            logger.warning("Firefox binary not found; falling back to Chrome")
            switch_to_chrome()
            return create_webdriver()
        if not GECKODRIVER_BINARY.exists():
            logger.warning("geckodriver not found; falling back to Chrome")
            switch_to_chrome()
            return create_webdriver()
        service = FirefoxService(executable_path=str(GECKODRIVER_BINARY))
        driver = webdriver.Firefox(service=service, options=firefox_options)

    if BLOCK_HEAVY_ASSETS:
        set_driver_assets(driver, enable_heavy_assets=False)
    driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
    return driver


# ============================================
# Session / Cookie 管理
# ============================================

def is_access_denied(page_source):
    if not page_source:
        return False
    return any(marker in page_source for marker in ACCESS_DENIED_MARKERS)


def _sanitize_cookie(cookie):
    sanitized = {}
    for key in COOKIE_ALLOWED_KEYS:
        if key in cookie and cookie[key] is not None:
            sanitized[key] = cookie[key]
    if "expiry" in sanitized:
        try:
            sanitized["expiry"] = int(sanitized["expiry"])
        except (TypeError, ValueError):
            sanitized.pop("expiry", None)
    if not sanitized.get("name") or sanitized.get("value") is None:
        return None
    sanitized.setdefault("domain", ".foodpanda.com.tw")
    sanitized.setdefault("path", "/")
    return sanitized


def _dump_access_denied_html(page_source, url):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = url.rstrip("/").split("/")[-1] or "homepage"
    dump_path = LOG_DIR / f"access_denied_{suffix}_{timestamp}.html"
    try:
        dump_path.write_text(page_source, encoding="utf-8")
        logger.error(
            f"[BLOCKED] Access denied / captcha detected for {url}. Dumped HTML to {dump_path}"
        )
    except Exception as dump_err:
        logger.error(
            f"[BLOCKED] Access denied for {url}, but failed to dump HTML: {dump_err}"
        )
    return dump_path


def _dump_json_debug(payload, url, suffix="debug"):
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = url.rstrip("/").split("/")[-1] or "homepage"
        out = LOG_DIR / f"json_{slug}_{suffix}_{timestamp}.txt"
        out.write_text(payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        logger.info(f"[DEBUG] Dumped JSON payload for {url} to {out}")
    except Exception as e:
        logger.warning(f"[DEBUG] Failed to dump JSON payload for {url}: {e}")


def _extract_json_from_html(html, marker):
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


def extract_vendor_payload(html):
    return _extract_json_from_html(html, "window.__PRELOADED_STATE__=") or _extract_json_from_html(
        html, "window.__NEXT_DATA__="
    )


def output_file_for(lat, lng, shop_code, ext="json"):
    return OUTPUT_DIR / f"{lat}_{lng}_{shop_code}.{ext}"


def progress_snapshot(run_start_time, success_count, skip_count, total_count):
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


def ensure_not_blocked(page_source, url):
    if not is_access_denied(page_source):
        return
    _dump_access_denied_html(page_source, url)
    raise AccessDeniedError(
        "Foodpanda returned an Access Denied / captcha page. "
        "Slow down, try a residential IP, or solve the captcha manually."
    )


def wait_for_manual_captcha(driver, url):
    if HEADLESS:
        logger.warning(
            "[MANUAL CAPTCHA] Cannot pause for manual captcha while running headless."
        )
        return None

    instructions = (
        "\n[MANUAL CAPTCHA] Browser is currently blocked at:\n"
        f"  {url}\n"
        "Solve the captcha in the visible Chromium window.\n"
        "When the restaurant page loads successfully, return to this terminal.\n"
        "  - Press Enter (or type 'done') to retry the request\n"
        "  - Type 'skip' to skip this restaurant\n"
        "  - Type 'quit' to abort the entire crawl\n"
        "  - Type 'normal' to temporarily enable full assets for captcha\n"
        "  - Type 'fast' to re-enable asset blocking\n"
    )
    print(instructions)

    while True:
        try:
            answer = input("[MANUAL CAPTCHA] Command (done/skip/quit): ").strip().lower()
        except EOFError:
            answer = "done"

        if answer in ("", "done", "retry"):
            time.sleep(1.0)
            if not is_access_denied(driver.page_source):
                logger.info("[MANUAL CAPTCHA] Captcha cleared, resuming crawl.")
                persist_cookies(driver)
                return True
            print("[MANUAL CAPTCHA] Still seeing captcha, please finish solving it.")
            continue
        if answer == "skip":
            logger.info("[MANUAL CAPTCHA] User chose to skip this restaurant.")
            return False
        if answer == "normal":
            set_driver_assets(driver, enable_heavy_assets=True)
            print("[MANUAL CAPTCHA] Enabled full assets for captcha.")
            time.sleep(1.0)
            try:
                driver.refresh()
            except Exception:
                pass
            continue
        if answer == "fast":
            set_driver_assets(driver, enable_heavy_assets=False)
            print("[MANUAL CAPTCHA] Re-enabled fast mode (heavy assets blocked).")
            continue
        if answer in ("quit", "exit", "abort"):
            raise KeyboardInterrupt("User aborted during manual captcha handling.")

        print("Please type 'done', 'skip', or 'quit'.")


FAST_BLOCKED_URLS = [
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


def set_driver_assets(driver, enable_heavy_assets):
    global CURRENT_FAST_MODE
    CURRENT_FAST_MODE = not enable_heavy_assets
    if not BLOCK_HEAVY_ASSETS:
        return
    if CURRENT_BROWSER == "chrome":
        if not hasattr(driver, "execute_cdp_cmd"):
            return
        try:
            driver.execute_cdp_cmd("Network.enable", {})
        except Exception:
            pass
        urls = [] if enable_heavy_assets else FAST_BLOCKED_URLS
        try:
            driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": urls})
        except Exception:
            pass
    else:
        try:
            driver.set_context("chrome")
            level = 1 if enable_heavy_assets else 2
            driver.execute_script(
                "Services.prefs.setIntPref('permissions.default.image', arguments[0]);",
                level,
            )
        except Exception as e:
            logger.debug(f"[ASSETS] Failed to toggle Firefox image setting: {e}")
        finally:
            try:
                driver.set_context("content")
            except Exception:
                pass
    logger.info("[ASSETS] %s mode enabled" % ("FAST" if not enable_heavy_assets else "NORMAL"))


def handle_access_denied(driver, url, allow_skip=False):
    global FIRST_MANUAL_CAPTCHA_PENDING
    if FIRST_MANUAL_CAPTCHA_PENDING:
        wait_seconds = FIRST_MANUAL_CAPTCHA_WAIT_SEC
        FIRST_MANUAL_CAPTCHA_PENDING = False
        logger.info(
            f"[BLOCKED] First captcha encountered at {url}. Please solve it manually in the browser window. Retrying after {wait_seconds}s."
        )
        if HEADLESS:
            logger.warning("[BLOCKED] Running headless makes manual captcha solving impossible.")
    else:
        wait_seconds = max(0, RECAPTCHA_WAIT)
        logger.info(
            f"[BLOCKED] Detected captcha at {url}. Cooling down for {wait_seconds}s before retry."
        )

    if wait_seconds:
        time.sleep(wait_seconds)

    session_reason = f"captcha detected while loading {url}"
    try:
        renew_session(driver, reason=session_reason)
    except AccessDeniedError as renew_err:
        logger.warning(f"[BLOCKED] Session renew after captcha also blocked: {renew_err}")
    except Exception as renew_err:
        logger.warning(f"[BLOCKED] Session renew failed: {renew_err}")

    if allow_skip:
        logger.info(
            f"[BLOCKED] Cooldown finished for {url}, retrying request (skip if captcha persists)."
        )
    else:
        logger.info(f"[BLOCKED] Cooldown finished for {url}, retrying request.")
    if BLOCK_HEAVY_ASSETS:
        set_driver_assets(driver, enable_heavy_assets=False)
    return "retry"


def _read_cookies_from_disk():
    if not COOKIES_PATH.exists():
        return []
    try:
        with open(COOKIES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"[SESSION] Failed to read cookies from {COOKIES_PATH}: {e}")
        return []


def restore_cookies(driver):
    cookies = _read_cookies_from_disk()
    if not cookies:
        return 0
    applied = 0
    for raw_cookie in cookies:
        sanitized = _sanitize_cookie(raw_cookie)
        if not sanitized:
            continue
        try:
            driver.add_cookie(sanitized)
            applied += 1
        except Exception as e:
            logger.debug(f"[SESSION] Unable to apply cookie {sanitized.get('name')}: {e}")
    if applied:
        logger.info(f"[SESSION] Restored {applied} cookies from {COOKIES_PATH}")
    return applied


def persist_cookies(driver):
    try:
        cookies = driver.get_cookies()
    except Exception as e:
        logger.warning(f"[SESSION] Unable to read cookies from driver: {e}")
        return
    try:
        with open(COOKIES_PATH, "w", encoding="utf-8") as f:
            json.dump(cookies, f, ensure_ascii=False, indent=2)
        logger.debug(f"[SESSION] Saved {len(cookies)} cookies to {COOKIES_PATH}")
    except Exception as e:
        logger.warning(f"[SESSION] Failed to save cookies to {COOKIES_PATH}: {e}")


def prepare_session(driver):
    logger.info("[SESSION] Preparing Foodpanda homepage")
    while True:
        driver.get(HOME_URL)
        time.sleep(random.uniform(2, 4))
        try:
            ensure_not_blocked(driver.page_source, HOME_URL)
            break
        except AccessDeniedError as blocked:
            decision = handle_access_denied(driver, HOME_URL, allow_skip=False)
            if decision == "retry":
                continue
            raise blocked

    restored = restore_cookies(driver)
    if restored:
        while True:
            driver.refresh()
            time.sleep(random.uniform(2, 4))
            try:
                ensure_not_blocked(driver.page_source, HOME_URL)
                break
            except AccessDeniedError as blocked:
                decision = handle_access_denied(driver, HOME_URL, allow_skip=False)
                if decision == "retry":
                    continue
                raise blocked

    persist_cookies(driver)


def renew_session(driver, reason=""):
    logger.warning(f"[SESSION] Renewing session cookies ({reason})")
    try:
        driver.delete_all_cookies()
    except Exception as e:
        logger.debug(f"[SESSION] Failed to clear cookies: {e}")
    driver.get(HOME_URL)
    time.sleep(random.uniform(3, 6))
    ensure_not_blocked(driver.page_source, HOME_URL)
    persist_cookies(driver)


# ============================================
# 從瀏覽器裡抽出 JSON state
# ============================================

def perform_random_scrolls(driver, max_scrolls=4):
    """Add some human-like scrolling to trigger lazy-loaded content."""
    try:
        scroll_height = driver.execute_script(
            "return Math.max(document.body.scrollHeight, document.documentElement.scrollHeight);"
        )
    except Exception as e:
        logger.debug(f"[SCROLL] Unable to read scroll height: {e}")
        return

    if not scroll_height or scroll_height <= 0:
        return

    current_y = 0
    steps = random.randint(1, max_scrolls)
    for _ in range(steps):
        # Move up or down by a random chunk of the page height.
        delta = random.randint(max(20, int(scroll_height * 0.05)), max(40, int(scroll_height * 0.25)))
        direction = 1 if random.random() < 0.65 else -1
        current_y = max(0, min(scroll_height, current_y + direction * delta))
        try:
            driver.execute_script("window.scrollTo({top: arguments[0], behavior:'smooth'});", current_y)
        except Exception as e:
            logger.debug(f"[SCROLL] Failed to scroll: {e}")
            break
        time.sleep(random.uniform(0.4, 1.2))


def fetch_page_source(driver, url):
    start_time = time.perf_counter()
    logger.info(f"[OPEN] {url}")
    driver.get(url)

    try:
        WebDriverWait(driver, PAGE_LOAD_TIMEOUT).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )
    except Exception as e:
        logger.warning(f"[TIMEOUT] {url}: {e}")

    extra_sleep = random.uniform(2, 5)
    time.sleep(extra_sleep)
    perform_random_scrolls(driver)

    page_source = driver.page_source
    ensure_not_blocked(page_source, url)
    elapsed = time.perf_counter() - start_time
    logger.info(f"[FETCH] {url} took {elapsed:.1f}s")
    return page_source


EXTRACT_JSON_JS = """
// 盡量嘗試幾種常見 SPA / SSR 的資料掛載方式
(function() {
  let data = null;

  // 1. 常見的 global 變數
  if (window.__NEXT_DATA__) data = window.__NEXT_DATA__;
  else if (window.__NUXT__) data = window.__NUXT__;
  else if (window.__APOLLO_STATE__) data = window.__APOLLO_STATE__;
  else if (window.__INITIAL_STATE__) data = window.__INITIAL_STATE__;
  else if (window.__PRELOADED_STATE__) data = window.__PRELOADED_STATE__;

  // 2. 如果上面都沒有，再去找 script[type="application/json"]
  if (!data) {
    const scripts = Array.from(
      document.querySelectorAll('script[type="application/json"], script[id="__NEXT_DATA__"], script[id="__NUXT_DATA__"]')
    );
    for (const s of scripts) {
      try {
        const txt = s.textContent || s.innerText;
        if (!txt) continue;
        const obj = JSON.parse(txt);
        if (obj) {
          data = obj;
          break;
        }
      } catch (e) {
        // ignore parse error
      }
    }
  }

  if (!data) return null;

  const seen = new WeakSet();
  function normalize(value) {
    if (typeof value === "bigint") {
      return value.toString();
    }
    if (typeof value === "object" && value !== null) {
      if (seen.has(value)) {
        return;
      }
      seen.add(value);
    }
    return value;
  }

  try {
    return JSON.stringify(data, (key, value) => normalize(value));
  } catch (err) {
    try {
      return JSON.stringify(data);
    } catch (err2) {
      return null;
    }
  }
})();
"""


def grab_page_json(driver, url):
    """
    開啟餐廳頁並解析 JSON。
    """
    page_source = fetch_page_source(driver, url)
    try:
        raw = driver.execute_script(EXTRACT_JSON_JS)
    except Exception as e:
        logger.error(f"[ERROR] execute_script on {url}: {e}")
        return None

    if raw is None:
        logger.info(f"[DEBUG] No JSON object returned for {url}, trying HTML fallback.")
        html_data = extract_vendor_payload(page_source)
        if html_data is None:
            _dump_json_debug(page_source, url, suffix="no_json")
            return None
        logger.info(f"[DEBUG] Parsed JSON directly from HTML for {url}")
        return html_data

    if isinstance(raw, str):
        logger.info(f"[DEBUG] Received JSON string ({len(raw)} chars) for {url}")
        try:
            return json.loads(raw)
        except Exception as e:
            logger.error(f"[ERROR] json.loads failed for {url}: {e}")
            _dump_json_debug(raw, url, suffix="parse_error")
            return None

    logger.info(f"[DEBUG] Received JSON object type {type(raw)} for {url}")
    return raw


def grab_page_html(driver, url):
    """
    回傳完整 HTML。
    """
    return fetch_page_source(driver, url)


# ============================================
# 讀取店家清單
# ============================================

def read_store_list(csv_path):
    """
    讀取 rolling.csv，欄位預期為：
      shopCode, shopName, latitude, longitude
    回傳 list[dict]。
    """
    stores = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        # DictReader 會用 header 來 map 欄位名稱
        for row in reader:
            try:
                shop_code = row.get("shopCode") or row.get("shop_uuid") or row.get("code")
                shop_name = row.get("shopName") or row.get("name")
                lat = float(row.get("latitude"))
                lng = float(row.get("longitude"))
            except Exception as e:
                logger.warning(f"[SKIP] bad row {row}: {e}")
                continue

            stores.append(
                {
                    "shopCode": shop_code,
                    "shopName": shop_name,
                    "lat": lat,
                    "lng": lng,
                }
            )

    logger.info(f"[INFO] Loaded {len(stores)} shops from {csv_path}")
    return stores


# ============================================
# 主流程
# ============================================

def main():
    if not LOCATION_CSV_PATH.exists():
        raise FileNotFoundError(f"CSV not found: {LOCATION_CSV_PATH}")

    stores = read_store_list(LOCATION_CSV_PATH)

    if DEBUG_MODE and stores:
        # 只抓第一間做測試
        stores = [stores[0]]
        logger.info(f"[DEBUG] Only crawling first store: {stores[0]}")

    total_stores = len(stores)
    success_count = 0
    skip_count = 0
    run_start = time.perf_counter()

    driver = create_webdriver()

    try:
        prepare_session(driver)
        for idx, store in enumerate(stores, start=1):
            shop_code = store["shopCode"]
            shop_name = store["shopName"]
            lat = store["lat"]
            lng = store["lng"]

            url = f"https://www.foodpanda.com.tw/restaurant/{shop_code}/"

            # 隨機 delay，減少被認出來的機率
            delay_sec = random.uniform(
                PER_REQUEST_DELAY_MIN_SEC, PER_REQUEST_DELAY_MAX_SEC
            )
            logger.info(
                f"[SLEEP] {delay_sec:.1f}s before requesting {shop_code} ({idx}/{total_stores})"
            )
            time.sleep(delay_sec)

            attempt = 1
            data = None
            page_html = None
            skip_reason = None
            while attempt <= MAX_ACCESS_DENIED_RETRIES:
                try:
                    if CRAWL_HTML_ONLY:
                        page_html = grab_page_html(driver, url)
                        data = None
                    else:
                        data = grab_page_json(driver, url)
                    break
                except AccessDeniedError as blocked:
                    handle_access_denied(driver, url, allow_skip=True)
                    attempt += 1
                    if attempt > MAX_ACCESS_DENIED_RETRIES:
                        logger.warning(
                            f"[BLOCKED] {shop_code} ({shop_name}) -> skipping after captcha retries ({MAX_ACCESS_DENIED_RETRIES})."
                        )
                        skip_reason = "captcha"
                        data = None
                        break
                    continue
                except Exception as e:
                    logger.error(f"[ERROR] {shop_code} ({shop_name}) at ({lat}, {lng}): {e}")
                    skip_reason = "error"
                    data = None
                    break

            if skip_reason:
                skip_count += 1
                continue

            if CRAWL_HTML_ONLY:
                if not page_html:
                    logger.warning(f"[NO_HTML] {shop_code} ({shop_name}) -> no HTML captured")
                    skip_count += 1
                    continue
                data = extract_vendor_payload(page_html)
                if data is None:
                    logger.warning(
                        f"[NO_DATA] {shop_code} ({shop_name}) -> HTML parse failed"
                    )
                    _dump_json_debug(page_html, url, suffix="html_parse_failed")
                    skip_count += 1
                    continue
            else:
                if data is None:
                    logger.warning(f"[NO_DATA] {shop_code} ({shop_name}) -> no JSON extracted")
                    skip_count += 1
                    continue

            # 輸出路徑：{lat}_{lng}_{shopCode}.json
            out_file = output_file_for(lat, lng, shop_code, ext="json")
            try:
                with open(out_file, "w", encoding="utf-8") as fw:
                    json.dump(data, fw, ensure_ascii=False, indent=2)
                success_count += 1
                status_line = progress_snapshot(run_start, success_count, skip_count, total_stores)
                logger.info(f"[OK] Saved JSON for {shop_code} to {out_file} | {status_line}")
            except Exception as e:
                logger.error(f"[ERROR] write {out_file}: {e}")
                skip_count += 1

    finally:
        persist_cookies(driver)
        driver.quit()
        logger.info("Driver closed. Job done.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
