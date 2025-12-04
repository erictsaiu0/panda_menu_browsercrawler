# Foodpanda Menu Browser Crawler

Tools for crawling Foodpanda restaurant menu data by driving a real browser. The scripts replay the workflow that used to live in JavaScript (`main.js` + `sendReqMenu.js`) but do it inside Python with Selenium or Playwright so that the payloads look indistinguishable from a real user session.

## Repository Layout
- `panda_menu_selenium.py` &mdash; Selenium crawler that opens each Foodpanda restaurant page, captures the rendered HTML, and extracts the preloaded JSON payload.
- `panda_menu_selenium_api.py` &mdash; Playwright crawler that executes the Foodpanda `tw.fd-api.com` vendor APIs from inside the browser context.
- `panda_data/shopLst/rolling.csv` &mdash; Daily rolling list of shops (must contain at least `shopCode`, `shopName`, `latitude`, `longitude`).

## Requirements
- Python 3.9+
- Google Chrome/Chromium and/or Firefox plus matching drivers (`chromedriver`, `geckodriver`). Paths are auto-detected but can be overridden through env vars noted below.
- Playwright browsers (run `playwright install` after installing Python deps).
- `pip install -r requirements.txt`
- A populated `panda_data/shopLst/rolling.csv` (see sample in repo for required headers).

## Quick Start
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
# install browser binaries once for Playwright
playwright install

# Crawl via Selenium (default Firefox)
python panda_menu_selenium.py

# Crawl via Playwright API mode
python panda_menu_selenium_api.py
```
Each run creates (or reuses) `panda_data_py/panda_menu/<today>/` and `logs/<today>.log`. JSON payloads are written per shop using the store coordinates plus `shopCode`.

## `panda_menu_selenium.py` Workflow
1. Reads `panda_data/shopLst/rolling.csv`.
2. Launches Firefox (or Chrome if `SELENIUM_BROWSER=chrome`) with optional headless mode and asset blocking.
3. Opens the Foodpanda homepage to warm up cookies (`session_cookies.json` is restored/persisted between runs).
4. Iterates every shop, sleeps a random `PER_REQUEST_DELAY_MIN_SEC~MAX_SEC`, and visits `https://www.foodpanda.com.tw/restaurant/{shopCode}/`.
5. Either saves the full HTML (`CRAWL_HTML_ONLY=True`) and extracts `window.__PRELOADED_STATE__`/`window.__NEXT_DATA__`, or returns the JSON injected by the helper script block.
6. Stores `{lat}_{lng}_{shopCode}.json` and logs success/failure with running ETA estimates.

### Captcha handling
- When Foodpanda shows a PerimeterX captcha the script logs `Access Denied`, dumps the HTML under `logs/access_denied_*.html`, cools down, and refreshes cookies.
- If `HEADLESS=False`, you can solve the captcha manually in the real browser window. The prompt accepts `done`, `skip`, `quit`, `normal` (temporarily load all assets), and `fast` (re-enable blocking).
- `session_cookies.json` is always synced before quitting so a solved captcha carries over to the next run.

## `panda_menu_selenium_api.py` Workflow
- Uses Playwright (Firefox by default) plus `playwright-stealth` to look human.
- Calls the Foodpanda vendor API from inside the page context and stores each response to the same `{lat}_{lng}_{shopCode}.json` format.
- Honors similar knobs: `DEBUG_MODE`, `HEADLESS`, `BLOCK_HEAVY_ASSETS`, `PER_REQUEST_DELAY_*`, and captcha mitigation flags (`PAUSE_ON_PERIMETERX`, `PERIMETERX_AUTO_SOLVE`, `SESSION_COOKIES_*`).
- Session data is mirrored to `session_state.json`, letting Playwright contexts resume without re-login.

## Configuration Knobs
Edit the constants near the top of each script or override via environment variables before running:

| Setting | Default | Description |
| --- | --- | --- |
| `SELENIUM_BROWSER` | `firefox` | Set to `chrome` to force Chromium. |
| `HEADLESS` | `False` | Turn on once your IP/cookies are stable; keep off to solve captchas manually. |
| `BLOCK_HEAVY_ASSETS` | `False` | Skip images/plugins for faster loads (Selenium) or register Playwright routing rules. Use `normal` command when stuck on captcha screens. |
| `CRAWL_HTML_ONLY` | `True` | Selenium-only toggle to skip JSON execution and parse the HTML fallback. |
| `PER_REQUEST_DELAY_MIN_SEC/MAX_SEC` | `0 / 1` (Selenium) | Random delay between shops; raise if rate-limited. |
| `RECAPTCHA_WAIT` | `60` | Cooldown before retrying the same shop after captcha (env override supported). |
| `MAX_ACCESS_DENIED_RETRIES` | `2` | Attempts before skipping a store after repeated captcha blocks. |
| `CHROMIUM_BINARY`, `CHROMEDRIVER_BINARY`, `FIREFOX_BINARY`, `GECKODRIVER_BINARY` | auto | Point to custom browser/driver locations if autodetect fails. |

## Data & Logging
- Shop list: `panda_data/shopLst/rolling.csv` (UTF-8). Only `shopCode`, `shopName`, `latitude`, `longitude` are required; extra columns are ignored.
- Outputs: `panda_data_py/panda_menu/<YYYY-MM-DD>/<lat>_<lng>_<shopCode>.json`
- Logs: `logs/<YYYY-MM-DD>.log` plus any extra dumps produced during failures (`access_denied_*.html`, `json_*_debug.txt`).

## Troubleshooting
- **Browser binary missing** &mdash; set `CHROMIUM_BINARY`, `CHROMEDRIVER_BINARY`, `FIREFOX_BINARY`, or `GECKODRIVER_BINARY` to valid executables.
- **PerimeterX loop** &mdash; disable headless, lower crawl speed, or switch IP. Use the manual prompt commands to flip asset blocking on/off.
- **No JSON extracted** &mdash; set `CRAWL_HTML_ONLY=False` to let Selenium execute the helper script, or inspect the dumped HTML under `logs/json_*_html_parse_failed`.
- **Playwright blocked** &mdash; delete `session_state.json`/`session_cookies.json`, rerun to rebuild a fresh session, and consider a higher `PER_REQUEST_DELAY_*`.

Both crawlers can be interrupted safely (Ctrl+C). Partial results remain in `panda_data_py/panda_menu/<date>/`, and rerunning on the same day will only overwrite the JSON files for stores that are crawled again.
