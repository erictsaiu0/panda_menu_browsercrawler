# Foodpanda Menu Crawler (Zyte)

This repo is mainly used via `zyte_panda_menu.py`, which crawls Foodpanda restaurant pages with Zyte API and outputs menu JSON.

## Requirements
- Python 3.8+
- `pip install -r requirements.txt`

## Zyte API key
Set one of the following environment variables:
- `ZYTE_API_KEY` 

Example:
```bash
export ZYTE_API_KEY="your_zyte_key"
```

You can also put it in a `.env` file (preferred):
```ini
ZYTE_API_KEY=your_zyte_key
```

## Zyte CA bundle
If you need to trust Zyte's custom CA:
- Place the CA file in this repo and set `ZYTE_CA_BUNDLE` to its path, or
- Put the file at `zyte-ca-982.crt` in the repo root (auto-detected), or rename it.

Example:
```bash
export ZYTE_CA_BUNDLE="/path/to/zyte-ca-982.crt" (replace it with your own crt file name.)
```

## Input CSV (rolling.csv)
`zyte_panda_menu.py` reads the shop list from:
```
../panda_data/shopLst/rolling.csv
```
This path is relative to the script location.

Required columns:
- `shopCode` (or `shop_uuid` / `code`)
- `shopName` (or `name`)
- `latitude`
- `longitude`

## Output
- JSON: `../panda_data_js/panda_menu/YYYY-MM-DD/`
- Logs: `logs/YYYY-MM-DD.log`

## Usage
Basic run:
```bash
python zyte_panda_menu.py
```

Enable item parsing (forces browser rendering and DOM menu extraction):
```bash
python zyte_panda_menu.py --item-parse
```

Split item parsing into two halves:
```bash
python zyte_panda_menu.py --item-parse --parse-part A
python zyte_panda_menu.py --item-parse --parse-part B
```

Set worker threads (default: 1):
```bash
python zyte_panda_menu.py --num-workers 4
```
