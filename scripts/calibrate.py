#!/usr/bin/env python3
"""Calibrate ZeroTrust.sh scoring constants from labeled scan data.

Reads a CSV with columns:
    surface_id, cvss, classifier_prob, call_depth, label
where label is 1 (vulnerable) or 0 (safe).

Outputs a JSON file (default: tuning_calibrated.json) that can be passed to
`zerotrust scan --calibration <path>`.

Usage:
    python scripts/calibrate.py --input labeled.csv --out tuning_calibrated.json
"""
import argparse
import json
import sys

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve
from sklearn.model_selection import train_test_split


def _best_threshold(y_true, probs, beta: float = 2.0) -> float:
    """Return the classifier_prob threshold maximising F-beta (default F2)."""
    precision, recall, thresholds = precision_recall_curve(y_true, probs)
    # F-beta: higher beta weights recall more than precision.
    with np.errstate(invalid="ignore"):
        fb = (1 + beta**2) * precision * recall / (beta**2 * precision + recall)
    fb = np.nan_to_num(fb)
    idx = np.argmax(fb[:-1])  # last element has no threshold
    return float(thresholds[idx])


def _platt_fit(cvss: np.ndarray, labels: np.ndarray):
    """Fit a logistic regression over CVSS → label and return (slope, intercept)."""
    X = cvss.reshape(-1, 1)
    lr = LogisticRegression(max_iter=1000)
    lr.fit(X, labels)
    return float(lr.coef_[0][0]), float(lr.intercept_[0])


def _budget_weights(df: pd.DataFrame, n_top: int = 10) -> tuple[float, float, float]:
    """Grid-search (w1, w2, w3) maximising recall@n_top on a held-out split."""
    _, test = train_test_split(df, test_size=0.3, random_state=42, stratify=df["label"])

    best_recall, best_w = -1.0, (0.4, 0.4, 0.2)
    step = 0.1
    for w1 in np.arange(0.1, 0.9, step):
        for w2 in np.arange(0.1, 0.9 - w1, step):
            w3 = round(1.0 - w1 - w2, 6)
            if w3 <= 0:
                continue
            test = test.copy()
            test["_score"] = (
                w1 * (test["cvss"] / 10.0)
                + w2 * (1.0 - test["classifier_prob"])
                + w3 * (1.0 / test["call_depth"].clip(lower=1))
            )
            top = test.nlargest(n_top, "_score")
            recall = top["label"].sum() / max(test["label"].sum(), 1)
            if recall > best_recall:
                best_recall, best_w = recall, (round(w1, 2), round(w2, 2), round(w3, 2))

    return best_w


def _severity_thresholds(y_true, confidence: np.ndarray):
    """Return (conf_block, conf_high, conf_medium, conf_low) percentile-based."""
    vuln_conf = confidence[y_true == 1]
    if len(vuln_conf) == 0:
        return 0.92, 0.75, 0.60, 0.30  # defaults
    p95, p75, p50, p20 = (
        float(np.percentile(vuln_conf, 95)),
        float(np.percentile(vuln_conf, 75)),
        float(np.percentile(vuln_conf, 50)),
        float(np.percentile(vuln_conf, 20)),
    )
    return round(p95, 4), round(p75, 4), round(p50, 4), round(p20, 4)


def calibrate(csv_path: str, out_path: str) -> dict:
    df = pd.read_csv(csv_path)
    required = {"surface_id", "cvss", "classifier_prob", "call_depth", "label"}
    if missing := required - set(df.columns):
        print(f"error: missing columns: {missing}", file=sys.stderr)
        sys.exit(1)

    df["call_depth"] = df["call_depth"].clip(lower=1)
    y = df["label"].values

    # 1. Classifier operating point (F2 to favour recall for security).
    vuln_thresh = _best_threshold(y, df["classifier_prob"].values, beta=2.0)
    safe_thresh = _best_threshold(1 - y, 1 - df["classifier_prob"].values, beta=2.0)
    safe_thresh = 1.0 - safe_thresh

    # 2. CVSS → confidence Platt sigmoid.
    slope, intercept = _platt_fit(df["cvss"].values, y)

    # 3. Budget weights.
    w1, w2, w3 = _budget_weights(df)

    # 4. Severity thresholds from confidence score distribution.
    # ponytail: use classifier_prob as proxy for confidence until real confidence scores exist
    conf_block, conf_high, conf_medium, conf_low = _severity_thresholds(y, df["classifier_prob"].values)

    result = {
        "version": 1,
        "classifier_vulnerable_threshold": round(vuln_thresh, 4),
        "classifier_safe_threshold": round(safe_thresh, 4),
        "cvss_platt_slope": round(slope, 6),
        "cvss_platt_intercept": round(intercept, 6),
        "budget_weight_cvss": w1,
        "budget_weight_uncert": w2,
        "budget_weight_depth": w3,
        "conf_block": conf_block,
        "conf_high": conf_high,
        "conf_medium": conf_medium,
        "conf_low": conf_low,
    }

    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"calibration written to {out_path}")
    print(json.dumps(result, indent=2))
    return result


def calibrate_from_eval_probs(probs_csv: str, out_path: str) -> dict:
    """Threshold-only calibration from train_lora.py eval_probs.csv (columns: prob, label).

    Skips Platt / budget fields (no CVSS / call_depth in the training eval set).
    Merges with defaults so the output JSON is always complete.
    """
    df = pd.read_csv(probs_csv)
    if not {"prob", "label"}.issubset(df.columns):
        print("error: --eval-probs CSV must have 'prob' and 'label' columns", file=sys.stderr)
        sys.exit(1)

    y = df["label"].values
    probs = df["prob"].values

    vuln_thresh = _best_threshold(y, probs, beta=2.0)
    safe_thresh = 1.0 - _best_threshold(1 - y, 1 - probs, beta=2.0)
    conf_block, conf_high, conf_medium, conf_low = _severity_thresholds(y, probs)

    result = {
        "classifier_vulnerable_threshold": round(vuln_thresh, 4),
        "classifier_safe_threshold": round(safe_thresh, 4),
        # Platt / budget: carry through defaults (no CVSS in eval_probs)
        "cvss_platt_slope": 0.0,
        "cvss_platt_intercept": 0.0,
        "budget_weight_cvss": 0.33,
        "budget_weight_uncert": 0.33,
        "budget_weight_depth": 0.34,
        "conf_block": conf_block,
        "conf_high": conf_high,
        "conf_medium": conf_medium,
        "conf_low": conf_low,
    }

    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"calibration written to {out_path}")
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", help="labeled CSV (surface_id, cvss, classifier_prob, call_depth, label)")
    group.add_argument("--eval-probs", metavar="CSV", help="eval_probs.csv from train_lora.py (prob, label)")
    parser.add_argument("--out", default="tuning_calibrated.json", help="output JSON path")
    args = parser.parse_args()

    if args.eval_probs:
        calibrate_from_eval_probs(args.eval_probs, args.out)
    else:
        calibrate(args.input, args.out)
