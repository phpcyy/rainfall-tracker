#!/usr/bin/env python3
"""Fetch 24h hourly rainfall data from China Weather (weather.com.cn)
for Xuchang, Xiangcheng, and Minhang, deduplicate hourly observations,
aggregate daily summaries, and persist ONLY AES-256-GCM encrypted bundles
(data/hourly.enc.json and docs/data.enc.json) so no plaintext data is stored
in the repository.
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CST = timezone(timedelta(hours=8))

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
DOCS_DIR = ROOT_DIR / "docs"
HOURLY_ENC_FILE = DATA_DIR / "hourly.enc.json"
DAILY_ENC_FILE = DOCS_DIR / "data.enc.json"

CITIES: dict[str, dict[str, str]] = {
    "xuchang": {"name": "许昌市", "province": "河南", "code": "101180401"},
    "xiangcheng": {"name": "襄城县", "province": "河南", "code": "101180403"},
    "minhang": {"name": "闵行区", "province": "上海", "code": "101020200"},
}

WEATHER_URL_TEMPLATE = "https://www.weather.com.cn/weather1d/{code}.shtml"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
PBKDF2_ITERATIONS = 200_000


def classify_rainfall(total_mm: float) -> str:
    """Classify 24-hour rainfall according to CMA (China Meteorological Administration) standards."""
    if total_mm <= 0:
        return "无雨"
    if total_mm < 10.0:
        return "小雨"
    if total_mm < 25.0:
        return "中雨"
    if total_mm < 50.0:
        return "大雨"
    if total_mm < 100.0:
        return "暴雨"
    if total_mm < 250.0:
        return "大暴雨"
    return "特大暴雨"


def parse_float(value: Any) -> float | None:
    """Parse a numeric weather field, returning None for null/empty/invalid sentinel values."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"null", "none", "nan", "-"}:
        return None
    try:
        num = float(text)
    except ValueError:
        return None
    if num < -100 or num > 2000:
        return None
    return num


def fetch_html(url: str, retries: int = 3, timeout: int = 20) -> str:
    """Fetch HTML page with retry and UTF-8 decoding."""
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Referer": "https://www.weather.com.cn/",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                return raw.decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = exc
            if attempt < retries:
                time.sleep(2 * attempt)
    raise RuntimeError(f"Failed to fetch {url} after {retries} attempts: {last_err}")


def extract_observe24h_data(html: str) -> dict[str, Any]:
    """Extract and parse `var observe24h_data = {...};` from China Weather HTML."""
    match = re.search(r"var\s+observe24h_data\s*=\s*(\{.*?\})\s*;", html, re.S)
    if not match:
        raise ValueError("Could not find observe24h_data in page HTML")
    return json.loads(match.group(1))


def parse_hourly_observations(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert observe24h_data payload into timestamped hourly observation dicts."""
    od = payload.get("od")
    if not isinstance(od, dict):
        raise ValueError("Missing 'od' object in observe24h_data")

    od0 = str(od.get("od0", "")).strip()
    if len(od0) < 12 or not od0[:12].isdigit():
        raise ValueError(f"Unexpected od0 timestamp format: {od0!r}")

    anchor_dt = datetime.strptime(od0[:12], "%Y%m%d%H%M").replace(tzinfo=CST)
    cursor_dt = anchor_dt.replace(minute=0, second=0, microsecond=0)

    items = od.get("od2") or []
    observations: list[dict[str, Any]] = []

    for idx, item in enumerate(items):
        hour_str = str(item.get("od21", "")).strip()
        if not hour_str.isdigit():
            continue
        target_hour = int(hour_str)
        if not (0 <= target_hour <= 23):
            continue

        if idx == 0:
            steps = 0
            while cursor_dt.hour != target_hour and steps < 24:
                cursor_dt -= timedelta(hours=1)
                steps += 1
        else:
            cursor_dt -= timedelta(hours=1)
            steps = 0
            while cursor_dt.hour != target_hour and steps < 24:
                cursor_dt -= timedelta(hours=1)
                steps += 1

        rainfall = parse_float(item.get("od26"))
        if rainfall is not None and rainfall < 0:
            rainfall = None

        temp = parse_float(item.get("od22"))
        humidity = parse_float(item.get("od27"))

        observations.append(
            {
                "timestamp": cursor_dt.strftime("%Y-%m-%d %H:00"),
                "date": cursor_dt.strftime("%Y-%m-%d"),
                "hour": cursor_dt.hour,
                "rainfall_mm": round(rainfall, 2) if rainfall is not None else None,
                "temp_c": round(temp, 1) if temp is not None else None,
                "humidity_pct": round(humidity, 1) if humidity is not None else None,
                "wind_dir": str(item.get("od24", "")).strip(),
                "wind_scale": str(item.get("od25", "")).strip(),
                "source_od0": od0,
            }
        )

    return observations


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_json_bundle(data: Any, password: str, updated_at: str) -> dict[str, Any]:
    """Encrypt arbitrary JSON data using PBKDF2-HMAC-SHA256 + AES-256-GCM (Web Crypto compatible)."""
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = _derive_key(password, salt, PBKDF2_ITERATIONS)
    plaintext = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)
    return {
        "version": 1,
        "alg": "AES-256-GCM",
        "kdf": "PBKDF2-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "updated_at": updated_at,
    }


def decrypt_json_bundle(bundle: dict[str, Any], password: str) -> Any:
    """Decrypt a bundle produced by encrypt_json_bundle."""
    salt = base64.b64decode(bundle["salt"])
    iv = base64.b64decode(bundle["iv"])
    ciphertext = base64.b64decode(bundle["ciphertext"])
    iterations = int(bundle.get("iterations", PBKDF2_ITERATIONS))
    key = _derive_key(password, salt, iterations)
    plaintext = AESGCM(key).decrypt(iv, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


def load_encrypted_json(path: Path, password: str, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as f:
        bundle = json.load(f)
    return decrypt_json_bundle(bundle, password)


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")


def merge_hourly_store(
    store: dict[str, dict[str, dict[str, Any]]],
    city_key: str,
    observations: list[dict[str, Any]],
    fetched_at: str,
) -> int:
    """Merge new hourly observations into store without losing valid historical data."""
    city_store = store.setdefault(city_key, {})
    changed = 0
    for obs in observations:
        ts = obs["timestamp"]
        existing = city_store.get(ts)
        if existing is not None:
            if obs["rainfall_mm"] is None and existing.get("rainfall_mm") is not None:
                continue
            if (
                existing.get("rainfall_mm") == obs["rainfall_mm"]
                and existing.get("temp_c") == obs["temp_c"]
                and existing.get("humidity_pct") == obs["humidity_pct"]
            ):
                continue

        city_store[ts] = {
            "rainfall_mm": obs["rainfall_mm"],
            "temp_c": obs["temp_c"],
            "humidity_pct": obs["humidity_pct"],
            "wind_dir": obs["wind_dir"],
            "wind_scale": obs["wind_scale"],
            "source_od0": obs["source_od0"],
            "fetched_at": fetched_at,
        }
        changed += 1
    return changed


def build_daily_summary(
    hourly_store: dict[str, dict[str, dict[str, Any]]],
    updated_at: str,
) -> dict[str, Any]:
    """Aggregate hourly rainfall observations into daily summaries per city."""
    records: dict[str, dict[str, Any]] = {}

    for city_key, ts_map in hourly_store.items():
        by_date: dict[str, list[float | None]] = {}
        for ts, entry in ts_map.items():
            date_str = ts[:10]
            hour = int(ts[11:13])
            hours_arr = by_date.setdefault(date_str, [None] * 24)
            hours_arr[hour] = entry.get("rainfall_mm")

        for date_str, hours_arr in by_date.items():
            valid_vals = [v for v in hours_arr if v is not None]
            total_mm = round(sum(valid_vals), 2) if valid_vals else 0.0
            max_hourly_mm = round(max(valid_vals), 2) if valid_vals else 0.0
            rain_hours = sum(1 for v in valid_vals if v > 0)
            recorded_hours = len(valid_vals)

            records.setdefault(date_str, {})[city_key] = {
                "total_mm": total_mm,
                "max_hourly_mm": max_hourly_mm,
                "rain_hours": rain_hours,
                "recorded_hours": recorded_hours,
                "level": classify_rainfall(total_mm),
                "hourly": hours_arr,
            }

    sorted_dates = sorted(records.keys())
    return {
        "updated_at": updated_at,
        "timezone": "Asia/Shanghai",
        "cities": CITIES,
        "dates": sorted_dates,
        "records": {d: records[d] for d in sorted_dates},
    }


def main() -> int:
    password = os.environ.get("DATA_ENCRYPT_PASSWORD", "").strip()
    if not password:
        raise SystemExit(
            "DATA_ENCRYPT_PASSWORD environment variable is required to encrypt/decrypt rainfall data."
        )

    now_cst = datetime.now(CST)
    fetched_at = now_cst.strftime("%Y-%m-%d %H:%M:%S+08:00")

    hourly_store: dict[str, dict[str, dict[str, Any]]] = load_encrypted_json(
        HOURLY_ENC_FILE, password, {}
    )
    total_changes = 0
    errors: list[str] = []

    for city_key, meta in CITIES.items():
        url = WEATHER_URL_TEMPLATE.format(code=meta["code"])
        try:
            html = fetch_html(url)
            payload = extract_observe24h_data(html)
            od1 = payload.get("od", {}).get("od1", "")
            observations = parse_hourly_observations(payload)
            changed = merge_hourly_store(hourly_store, city_key, observations, fetched_at)
            total_changes += changed
            print(
                f"[OK] {meta['name']} ({meta['code']}, od1={od1}): "
                f"parsed {len(observations)} hourly points, {changed} updated"
            )
        except Exception as exc:
            err_msg = f"[ERROR] {meta['name']} ({meta['code']}): {exc}"
            print(err_msg)
            errors.append(err_msg)

    if len(errors) == len(CITIES):
        raise SystemExit("All cities failed to fetch.")

    daily_data = build_daily_summary(hourly_store, fetched_at)

    save_json(HOURLY_ENC_FILE, encrypt_json_bundle(hourly_store, password, fetched_at))
    save_json(DAILY_ENC_FILE, encrypt_json_bundle(daily_data, password, fetched_at))

    print(
        f"[DONE] Encrypted bundles updated. Total dates={len(daily_data['dates'])}, "
        f"hourly updates={total_changes}, errors={len(errors)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
