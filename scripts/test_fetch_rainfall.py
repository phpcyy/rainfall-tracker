#!/usr/bin/env python3
"""Unit tests for fetch_rainfall.py."""

import unittest
from cryptography.exceptions import InvalidTag
from scripts.fetch_rainfall import (
    build_daily_summary,
    classify_rainfall,
    decrypt_json_bundle,
    encrypt_json_bundle,
    merge_hourly_store,
    parse_hourly_observations,
)


class TestRainfallParser(unittest.TestCase):
    def test_cross_midnight_timestamps(self):
        payload = {
            "od": {
                "od0": "202611250200",
                "od1": "许昌",
                "od2": [
                    {"od21": "02", "od22": "10.0", "od26": "1.2", "od27": "80"},
                    {"od21": "01", "od22": "9.5", "od26": "0.8", "od27": "82"},
                    {"od21": "00", "od22": "9.0", "od26": "0", "od27": "85"},
                    {"od21": "23", "od22": "8.8", "od26": "3.5", "od27": "90"},
                    {"od21": "22", "od22": "8.5", "od26": "null", "od27": "91"},
                ],
            }
        }
        obs = parse_hourly_observations(payload)
        self.assertEqual(
            [o["timestamp"] for o in obs],
            [
                "2026-11-25 02:00",
                "2026-11-25 01:00",
                "2026-11-25 00:00",
                "2026-11-24 23:00",
                "2026-11-24 22:00",
            ],
        )
        self.assertEqual(obs[0]["rainfall_mm"], 1.2)
        self.assertIsNone(obs[4]["rainfall_mm"])

    def test_deduplication_preserves_valid_values(self):
        store = {}
        obs1 = [
            {
                "timestamp": "2026-11-25 08:00",
                "date": "2026-11-25",
                "hour": 8,
                "rainfall_mm": 2.5,
                "temp_c": 12.0,
                "humidity_pct": 70.0,
                "wind_dir": "北风",
                "wind_scale": "2",
                "source_od0": "202611250800",
            }
        ]
        obs2 = [
            {
                "timestamp": "2026-11-25 08:00",
                "date": "2026-11-25",
                "hour": 8,
                "rainfall_mm": None,
                "temp_c": 12.0,
                "humidity_pct": 70.0,
                "wind_dir": "北风",
                "wind_scale": "2",
                "source_od0": "202611252000",
            }
        ]
        merge_hourly_store(store, "xuchang", obs1, "t1")
        merge_hourly_store(store, "xuchang", obs2, "t2")
        self.assertEqual(store["xuchang"]["2026-11-25 08:00"]["rainfall_mm"], 2.5)

    def test_daily_aggregation_and_classification(self):
        store = {
            "minhang": {
                "2026-11-25 08:00": {"rainfall_mm": 6.0},
                "2026-11-25 09:00": {"rainfall_mm": 5.5},
                "2026-11-25 10:00": {"rainfall_mm": 0.0},
            }
        }
        daily = build_daily_summary(store, "2026-11-25 20:00:00+08:00")
        rec = daily["records"]["2026-11-25"]["minhang"]
        self.assertEqual(rec["total_mm"], 11.5)
        self.assertEqual(rec["max_hourly_mm"], 6.0)
        self.assertEqual(rec["rain_hours"], 2)
        self.assertEqual(rec["recorded_hours"], 3)
        self.assertEqual(rec["level"], "中雨")
        self.assertEqual(rec["hourly"][8], 6.0)
        self.assertIsNone(rec["hourly"][0])

    def test_encrypt_decrypt_roundtrip(self):
        sample = {"city": "许昌市", "total_mm": 12.3, "hourly": [0.0, 1.2]}
        bundle = encrypt_json_bundle(sample, "secret-pass-123", "2026-11-25 15:00:00+08:00")
        self.assertEqual(bundle["alg"], "AES-256-GCM")
        self.assertNotIn("许昌市", bundle["ciphertext"])
        restored = decrypt_json_bundle(bundle, "secret-pass-123")
        self.assertEqual(restored, sample)
        with self.assertRaises(InvalidTag):
            decrypt_json_bundle(bundle, "wrong-pass")

    def test_classify_rainfall(self):
        self.assertEqual(classify_rainfall(0), "无雨")
        self.assertEqual(classify_rainfall(3.2), "小雨")
        self.assertEqual(classify_rainfall(15.0), "中雨")
        self.assertEqual(classify_rainfall(30.0), "大雨")
        self.assertEqual(classify_rainfall(75.0), "暴雨")
        self.assertEqual(classify_rainfall(150.0), "大暴雨")
        self.assertEqual(classify_rainfall(260.0), "特大暴雨")


if __name__ == "__main__":
    unittest.main()
