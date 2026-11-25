#!/usr/bin/env python3
"""Import historical daily JSON files (e.g. ~/Downloads/rainfall_data/daily/*.json)
into the encrypted hourly_store (data/hourly.enc.json) and encrypted daily
dashboard bundle (docs/data.enc.json).
"""

from __future__ import annotations

import glob
import json
import os
import sys
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

# Allow running directly as `python scripts/import_history.py <dir>`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.fetch_rainfall import (
    CITIES,
    CST,
    DAILY_ENC_FILE,
    HOURLY_ENC_FILE,
    build_daily_summary,
    encrypt_json_bundle,
    load_encrypted_json,
    merge_hourly_store,
    parse_float,
    save_json,
)


def parse_daily_file(path: Path) -> dict[str, list[dict[str, Any]]]:
    """Parse one historical daily JSON file into per-city hourly observations."""
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)

    date_str = str(payload.get("date") or path.stem).strip()
    base_date = date.fromisoformat(date_str)
    result: dict[str, list[dict[str, Any]]] = {}

    for city_key in CITIES:
        city_obj = payload.get(city_key)
        if not isinstance(city_obj, dict):
            continue
        hourly_items = city_obj.get("hourly")
        if not isinstance(hourly_items, list):
            continue

        cur_date = base_date
        prev_hour: int | None = None
        obs_list: list[dict[str, Any]] = []

        for item in hourly_items:
            if not isinstance(item, dict):
                continue
            hour_str = str(item.get("od21", "")).strip()
            if not hour_str.isdigit():
                continue
            hour = int(hour_str)
            if not (0 <= hour <= 23):
                continue

            if prev_hour is not None and hour > prev_hour:
                cur_date -= timedelta(days=1)
            prev_hour = hour

            rainfall = parse_float(item.get("od26"))
            if rainfall is not None and rainfall < 0:
                rainfall = None

            temp = parse_float(item.get("od22"))
            humidity = parse_float(item.get("od27"))

            obs_list.append(
                {
                    "timestamp": f"{cur_date.isoformat()} {hour:02d}:00",
                    "date": cur_date.isoformat(),
                    "hour": hour,
                    "rainfall_mm": round(rainfall, 2) if rainfall is not None else None,
                    "temp_c": round(temp, 1) if temp is not None else None,
                    "humidity_pct": round(humidity, 1) if humidity is not None else None,
                    "wind_dir": str(item.get("od24", "")).strip(),
                    "wind_scale": str(item.get("od25", "")).strip(),
                    "source_od0": f"import:{path.name}",
                }
            )

        if obs_list:
            result[city_key] = obs_list

    return result


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python scripts/import_history.py <daily_json_dir>")

    source_dir = Path(sys.argv[1]).expanduser().resolve()
    if not source_dir.is_dir():
        raise SystemExit(f"Directory not found: {source_dir}")

    password = os.environ.get("DATA_ENCRYPT_PASSWORD", "").strip()
    if not password:
        raise SystemExit("DATA_ENCRYPT_PASSWORD environment variable is required.")

    now_cst = datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S+08:00")
    hourly_store = load_encrypted_json(HOURLY_ENC_FILE, password, {})

    files = sorted(Path(p) for p in glob.glob(str(source_dir / "*.json")))
    if not files:
        raise SystemExit(f"No .json files found in {source_dir}")

    total_updates = 0
    for path in files:
        per_city = parse_daily_file(path)
        for city_key, obs_list in per_city.items():
            total_updates += merge_hourly_store(hourly_store, city_key, obs_list, now_cst)

    daily_data = build_daily_summary(hourly_store, now_cst)

    save_json(HOURLY_ENC_FILE, encrypt_json_bundle(hourly_store, password, now_cst))
    save_json(DAILY_ENC_FILE, encrypt_json_bundle(daily_data, password, now_cst))

    dates = daily_data["dates"]
    print(f"[OK] Imported {len(files)} files, merged {total_updates} hourly points.")
    print(f"[OK] Date range: {dates[0]} -> {dates[-1]} ({len(dates)} days)")
    for city_key, meta in CITIES.items():
        city_pts = len(hourly_store.get(city_key, {}))
        city_mm = sum(
            daily_data["records"][d][city_key]["total_mm"]
            for d in dates
            if city_key in daily_data["records"][d]
        )
        print(f"     - {meta['name']}: {city_pts} hourly records, cumulative {city_mm:.1f} mm")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
