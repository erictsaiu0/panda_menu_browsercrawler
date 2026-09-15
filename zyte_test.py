#!/usr/bin/env python3
"""Inspect one Foodpanda browserHtml response with the production parsers."""

import argparse
import hashlib
import json
import re
from collections import Counter
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from zyte_panda_menu import (
    _dom_categories_to_panda_menus,
    _extract_dom_menu_categories,
    _fetch_menus_via_api,
    _has_complete_menu,
    _has_menus,
    _infer_coords,
    _infer_vendor_code,
    _menu_product_metrics,
    _merge_menus_for_postprocess,
    _provider_menus_to_panda,
    extract_provider_payload,
    extract_vendor_payload,
    fetch_page_via_zyte,
    is_access_denied,
    set_browser_rendering,
)


STRUCTURE_MARKERS = (
    "window.__PRELOADED_STATE__=",
    "window.__NEXT_DATA__=",
    'id="__NEXT_DATA__"',
    "id='__NEXT_DATA__'",
    "self.__next_f.push",
    "__APOLLO_STATE__",
    'data-testid="menu-category-section"',
    'data-testid="menu-product"',
    'data-testid="menu-product-name"',
    "px-captcha",
    "Access to this page has been denied",
)


class _StructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: List[str] = []
        self.in_title = False
        self.in_script = False
        self.current_script: Optional[Dict[str, Any]] = None
        self.current_script_text: List[str] = []
        self.scripts: List[Dict[str, Any]] = []
        self.test_ids: Counter[str] = Counter()

    def handle_starttag(
        self, tag: str, attrs: List[Tuple[str, Optional[str]]]
    ) -> None:
        attr_map = {key: value or "" for key, value in attrs}
        if attr_map.get("data-testid"):
            self.test_ids[attr_map["data-testid"]] += 1
        if tag == "title":
            self.in_title = True
        if tag == "script":
            self.in_script = True
            self.current_script = {
                "id": attr_map.get("id") or None,
                "type": attr_map.get("type") or None,
                "src": attr_map.get("src") or None,
            }
            self.current_script_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False
        if tag == "script" and self.in_script and self.current_script is not None:
            text = "".join(self.current_script_text).strip()
            self.current_script["inlineLength"] = len(text)
            if text:
                self.current_script["preview"] = text[:160]
            self.scripts.append(self.current_script)
            self.in_script = False
            self.current_script = None
            self.current_script_text = []

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        if self.in_script:
            self.current_script_text.append(data)

    @property
    def title(self) -> str:
        return unescape("".join(self.title_parts)).strip()


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _extract_standard_next_data(html: str) -> Optional[dict]:
    match = re.search(
        r'<script\b[^>]*\bid=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return None
    try:
        value = json.loads(unescape(match.group(1)).strip())
        return value if isinstance(value, dict) else None
    except (TypeError, ValueError):
        return None


def _diagnose_preloaded_state(html: str) -> Tuple[Dict[str, Any], Optional[dict]]:
    marker = "window.__PRELOADED_STATE__="
    start = html.find(marker)
    if start == -1:
        return {"found": False}, None
    start += len(marker)
    end = html.find("</script>", start)
    if end == -1:
        return {"found": True, "closingScriptFound": False}, None

    raw = html[start:end].strip()
    if raw.endswith(";"):
        raw = raw[:-1]
    diagnostic: Dict[str, Any] = {
        "found": True,
        "closingScriptFound": True,
        "characters": len(raw),
        "undefinedTokenCount": len(re.findall(r"\bundefined\b", raw)),
    }
    try:
        value = json.loads(raw)
        diagnostic["strictJsonValid"] = True
        return diagnostic, value if isinstance(value, dict) else None
    except json.JSONDecodeError as error:
        diagnostic.update(
            {
                "strictJsonValid": False,
                "jsonError": str(error),
                "errorPosition": error.pos,
                "errorContext": raw[max(0, error.pos - 120) : error.pos + 120],
            }
        )

    # Diagnostic only: JavaScript state commonly uses bare `undefined`, which
    # is legal JavaScript but invalid JSON. This does not change production
    # parsing; it shows whether that is the only structural blocker.
    normalized = re.sub(r"(?<=[:\[,])undefined(?=[,}\]])", "null", raw)
    try:
        value = json.loads(normalized)
        diagnostic["normalizedUndefinedValid"] = True
        return diagnostic, value if isinstance(value, dict) else None
    except json.JSONDecodeError as error:
        diagnostic["normalizedUndefinedValid"] = False
        diagnostic["normalizedJsonError"] = str(error)
        return diagnostic, None


def _json_shape(value: Optional[dict]) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {"found": False}
    shape: Dict[str, Any] = {
        "found": True,
        "topLevelKeys": sorted(str(key) for key in value)[:100],
        "hasMenusByProductionCheck": _has_menus(value),
    }
    props = value.get("props")
    if isinstance(props, dict):
        shape["propsKeys"] = sorted(str(key) for key in props)[:100]
        page_props = props.get("pageProps")
        if isinstance(page_props, dict):
            shape["pagePropsKeys"] = sorted(str(key) for key in page_props)[:100]
    vendor = value.get("vendor")
    if isinstance(vendor, dict):
        shape["vendorKeys"] = sorted(str(key) for key in vendor)[:100]
        vendor_data = vendor.get("data")
        if isinstance(vendor_data, dict):
            shape["vendorDataKeys"] = sorted(str(key) for key in vendor_data)[:100]
            shape["vendorDataMenuCount"] = len(vendor_data.get("menus") or [])
    return shape


def analyze_html(
    url: str,
    html: str,
    opening_type: str,
) -> Tuple[dict, Optional[dict], list, list]:
    parser = _StructureParser()
    parser.feed(html)
    parser.close()

    production_payload = extract_vendor_payload(html)
    provider_payload = extract_provider_payload(html)
    vendor_code = _infer_vendor_code(production_payload, url, html) or ""
    provider_menus, provider_types = _provider_menus_to_panda(
        provider_payload,
        vendor_code,
        opening_type,
    )
    standard_next_data = _extract_standard_next_data(html)
    preloaded_diagnostic, normalized_preloaded = _diagnose_preloaded_state(html)
    categories = _extract_dom_menu_categories(html) or []
    product_count = sum(len(category.get("products") or []) for category in categories)

    inline_scripts = [script for script in parser.scripts if script.get("inlineLength")]
    script_ids = [script["id"] for script in parser.scripts if script.get("id")]
    script_sources = [script["src"] for script in parser.scripts if script.get("src")]
    interesting_test_ids = {
        key: count
        for key, count in parser.test_ids.most_common()
        if "menu" in key.lower()
        or "vendor" in key.lower()
        or "restaurant" in key.lower()
        or "product" in key.lower()
    }

    report = {
        "url": url,
        "html": {
            "characters": len(html),
            "utf8Bytes": len(html.encode("utf-8")),
            "sha256": hashlib.sha256(html.encode("utf-8")).hexdigest(),
            "title": parser.title,
        },
        "markers": {marker: html.count(marker) for marker in STRUCTURE_MARKERS},
        "scripts": {
            "count": len(parser.scripts),
            "inlineCount": len(inline_scripts),
            "ids": script_ids[:100],
            "sources": script_sources[:100],
            "inlinePreviews": [
                {
                    "id": script.get("id"),
                    "type": script.get("type"),
                    "length": script.get("inlineLength"),
                    "preview": script.get("preview"),
                }
                for script in inline_scripts[:30]
            ],
        },
        "productionPayload": _json_shape(production_payload),
        "preloadedStateDiagnostic": preloaded_diagnostic,
        "normalizedPreloadedState": _json_shape(normalized_preloaded),
        "standardNextData": _json_shape(standard_next_data),
        "providerApollo": {
            "found": provider_payload is not None,
            "vendorCode": vendor_code,
            "availableExpeditionTypes": provider_types,
            "menuMetrics": {
                "menus": _menu_product_metrics({"menus": provider_menus})[0],
                "categories": _menu_product_metrics({"menus": provider_menus})[1],
                "products": _menu_product_metrics({"menus": provider_menus})[2],
            },
        },
        "dom": {
            "categoryCount": len(categories),
            "productCount": product_count,
            "menuRelatedTestIds": interesting_test_ids,
            "allTestIdCount": sum(parser.test_ids.values()),
            "uniqueTestIdCount": len(parser.test_ids),
        },
        "pageSignals": {
            "accessDenied": is_access_denied(html),
            "containsRestaurantPath": "/restaurant/" in html,
            "containsFoodpanda": "foodpanda" in html.lower(),
            "containsLogin": "login" in html.lower(),
            "containsLocation": "location" in html.lower(),
            "containsNotFound": "not found" in html.lower(),
        },
    }
    return report, production_payload, categories, provider_menus


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch one Foodpanda page and diagnose its browserHtml structure."
    )
    parser.add_argument("url", help="Target Foodpanda restaurant URL.")
    parser.add_argument(
        "-o", "--output", type=Path, required=True, help="Save raw HTML here."
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        required=True,
        help="Save the HTML structure report as JSON.",
    )
    parser.add_argument("--json-output", type=Path, help="Save parsed payload JSON.")
    parser.add_argument("--dom-output", type=Path, help="Save parsed DOM categories.")
    parser.add_argument(
        "--render",
        action="store_true",
        help="Request Zyte browserHtml instead of httpResponseBody.",
    )
    parser.add_argument(
        "--opening-type", choices=["delivery", "pickup"], default="delivery"
    )
    parser.add_argument(
        "--api-fallback",
        action="store_true",
        help="Also test the production vendor API fallback when menus are absent.",
    )
    parser.add_argument("--lat", type=float)
    parser.add_argument("--lng", type=float)
    args = parser.parse_args()

    if args.render:
        set_browser_rendering(True)

    html = fetch_page_via_zyte(args.url)
    _write_text(args.output, html)
    report, payload, categories, provider_menus = analyze_html(
        args.url,
        html,
        args.opening_type,
    )

    if args.dom_output:
        _write_json(args.dom_output, {"categories": categories})

    if payload is not None and provider_menus and not _has_complete_menu(payload, args.opening_type):
        _merge_menus_for_postprocess(payload, provider_menus)
        report["providerApollo"]["mergedIntoProductionPayload"] = True

    if payload is not None and categories and not _has_complete_menu(payload, args.opening_type):
        menus = _dom_categories_to_panda_menus(categories)
        if menus:
            for menu in menus:
                menu["expedition_type"] = args.opening_type.upper()
            _merge_menus_for_postprocess(payload, menus)
            report["dom"]["mergedIntoProductionPayload"] = True

    if args.api_fallback and not _has_menus(payload):
        vendor_code = _infer_vendor_code(payload, args.url, html)
        lat, lng = _infer_coords(payload, html)
        if args.lat is not None and args.lng is not None:
            lat, lng = args.lat, args.lng
        menus = (
            _fetch_menus_via_api(
                vendor_code,
                lat,
                lng,
                opening_type=args.opening_type,
            )
            if vendor_code
            else None
        )
        report["vendorApiFallback"] = {
            "vendorCode": vendor_code,
            "latitude": lat,
            "longitude": lng,
            "menuBlockCount": len(menus or []),
        }
        if menus:
            if payload is None:
                payload = {"menus": menus}
            else:
                _merge_menus_for_postprocess(payload, menus)

    report["finalPayload"] = _json_shape(payload)
    _write_json(args.report_output, report)
    if args.json_output and payload is not None:
        _write_json(args.json_output, payload)

    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"[OK] HTML: {args.output}")
    print(f"[OK] Report: {args.report_output}")
    if payload is None:
        print("[NO_DATA] Production payload parser found no supported state object.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
