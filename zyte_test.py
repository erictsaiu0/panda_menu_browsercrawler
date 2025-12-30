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
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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


def _dump_json_file(path: Path, payload: dict, label: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] Saved {label} to {path}")


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


def extract_dom_menu_categories(html: str) -> Optional[List[Dict[str, Any]]]:
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
    parser.add_argument(
        "--dom-output",
        type=Path,
        help="Optional path to save parsed DOM categories (for debugging).",
    )
    parser.add_argument(
        "--skip-api-fallback",
        action="store_true",
        help="Skip vendor API fallback even if menus are missing (useful when focusing on DOM parsing).",
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

    if args.dom_output or (args.render and not _has_menus(payload)):
        categories = extract_dom_menu_categories(html)
        if categories:
            menus = _dom_categories_to_panda_menus(categories)
            if isinstance(payload, dict) and menus:
                merged = _merge_menus_for_postprocess(payload, menus)
                if merged:
                    print(f"[INFO] Menus merged from DOM: categories={len(categories)}")
            if args.dom_output:
                _dump_json_file(args.dom_output, {"categories": categories}, "DOM categories")
        else:
            print("[INFO] No menu categories found in DOM.")

    if not _has_menus(payload) and not args.skip_api_fallback:
        vendor_code = _infer_vendor_code(payload, args.url, html)
        lat, lng = _infer_coords(payload, args.lat, args.lng, html)
        api_data = _fetch_menus_via_api(vendor_code, lat, lng) if vendor_code else None
        if api_data and isinstance(payload, dict):
            menus = api_data.get("data", {}).get("menus")
            if menus:
                _merge_menus_for_postprocess(payload, menus)
                payload.setdefault("menu_api_raw", api_data)
                print(f"[INFO] Menus filled from vendor API for {vendor_code}.")
        elif not payload and api_data:
            payload = api_data

    _dump_json(args.json_output, payload)


if __name__ == "__main__":
    main()

# python ./zyte_test.py https://foodpanda.com.tw/restaurant/njyd/a-po-mian-dian --output zyte.html --json-output zyte.json --state-output state.json --dom-output dom_menu.json --render
