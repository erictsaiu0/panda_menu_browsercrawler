#!/usr/bin/env python3
"""
Fetch a single Foodpanda page via Zyte API for quick inspection.

The session, retries, SSL handling, and parsing logic reuse zyte_panda_menu.py
so the behavior matches the main crawler; this script just targets one URL.
"""

import argparse
import json
import logging
import re
from pathlib import Path
from typing import Optional, Tuple

import requests

from zyte_panda_menu import extract_vendor_payload, fetch_page_via_zyte, set_browser_rendering

logger = logging.getLogger(__name__)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _dump_json(path: Optional[Path], payload: Optional[dict]) -> None:
    if payload is None:
        print("No vendor JSON payload found in the page.")
        return
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[OK] Saved parsed vendor JSON to {path}")
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))


def _extract_state_raw(html: str) -> Optional[str]:
    marker = "window.__PRELOADED_STATE__="
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
    return snippet or None


def _has_menus(payload: Optional[dict]) -> bool:
    if not isinstance(payload, dict):
        return False
    if "menus" in payload:
        return True
    menu_block = payload.get("menu")
    if isinstance(menu_block, dict) and "menus" in menu_block:
        return True
    vendor_block = payload.get("vendor")
    if isinstance(vendor_block, dict):
        data = vendor_block.get("data")
        if isinstance(data, dict) and "menus" in data:
            return True
    return False


def _infer_vendor_code(payload: Optional[dict], url: str, html: str) -> Optional[str]:
    if isinstance(payload, dict):
        code = payload.get("vendor", {}).get("data", {}).get("code")
        if code:
            return str(code)
    # HTML fallback: some templates place data-vendor-code on buttons.
    match = re.search(r'data-vendor-code="([a-zA-Z0-9_-]+)"', html)
    if match:
        return match.group(1)
    match = re.search(r"/restaurant/([^/]+)/", url)
    if match:
        return match.group(1)
    return None


def _infer_coords(
    payload: Optional[dict],
    cli_lat: Optional[float],
    cli_lng: Optional[float],
    html: str,
) -> Tuple[Optional[float], Optional[float]]:
    if cli_lat is not None and cli_lng is not None:
        return cli_lat, cli_lng
    # HTML fallback when payload is missing geolocation.
    # Look for "latitude":<num>,"longitude":<num> close together.
    lat_lng_match = re.search(r'"latitude":\s*([0-9]+\.[0-9]+).*?"longitude":\s*([0-9]+\.[0-9]+)', html, re.DOTALL)
    if lat_lng_match:
        try:
            return float(lat_lng_match.group(1)), float(lat_lng_match.group(2))
        except Exception:
            pass
    if isinstance(payload, dict):
        data = payload.get("vendor", {}).get("data", {})
        lat = data.get("latitude")
        lng = data.get("longitude")
        if lat is not None and lng is not None:
            try:
                return float(lat), float(lng)
            except Exception:
                pass
    return None, None


def _fetch_menus_via_api(vendor_code: str, lat: Optional[float], lng: Optional[float]) -> Optional[dict]:
    base_url = f"https://tw.fd-api.com/api/v5/vendors/{vendor_code}"
    params = {
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
        return resp.json()
    except Exception as exc:
        logger.warning("Vendor API fetch failed: %s", exc)
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch a single Foodpanda page via Zyte API.")
    parser.add_argument("url", help="Target Foodpanda restaurant URL.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Optional path to save the raw HTML response. Prints to stdout if omitted.",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="Optional path to save parsed vendor JSON (from __PRELOADED_STATE__). Printed if omitted.",
    )
    parser.add_argument(
        "--render",
        action="store_true",
        help="Ask Zyte for rendered browserHtml (useful if menus are injected client-side).",
    )
    parser.add_argument("--lat", type=float, help="Optional latitude override for vendor API fallback.")
    parser.add_argument("--lng", type=float, help="Optional longitude override for vendor API fallback.")
    parser.add_argument(
        "--state-output",
        type=Path,
        help="Optional path to save raw window.__PRELOADED_STATE__ string (for debugging completeness).",
    )
    args = parser.parse_args()

    if args.render:
        set_browser_rendering(True)

    html = fetch_page_via_zyte(args.url)

    if args.output:
        _write_text(args.output, html)
        print(f"[OK] Saved HTML to {args.output}")
    else:
        print(html)

    raw_state = _extract_state_raw(html)
    if args.state_output and raw_state:
        _write_text(args.state_output, raw_state)
        print(f"[OK] Saved raw __PRELOADED_STATE__ to {args.state_output}")

    payload = None
    if raw_state:
        try:
            payload = json.loads(raw_state)
        except Exception as exc:
            logger.warning("Failed to parse __PRELOADED_STATE__: %s", exc)
    if payload is None:
        payload = extract_vendor_payload(html)

    if not _has_menus(payload):
        vendor_code = _infer_vendor_code(payload, args.url, html)
        lat, lng = _infer_coords(payload, args.lat, args.lng, html)
        api_data = _fetch_menus_via_api(vendor_code, lat, lng) if vendor_code else None
        if api_data and isinstance(payload, dict):
            menus = api_data.get("data", {}).get("menus")
            if menus:
                payload.setdefault("menu", {})["menus"] = menus
                payload.setdefault("menu_api_raw", api_data)
                print(f"[INFO] Menus filled from vendor API for {vendor_code}.")
        elif not payload and api_data:
            payload = api_data

    _dump_json(args.json_output, payload)


if __name__ == "__main__":
    main()
