#!/usr/bin/env python3
"""Static validation of evict_classifier model_weights.json artifacts.

Checks that each model JSON is structurally exactly what the
cache_ext_fifo_ml_protect loader and BPF program expect:
  - required top-level keys, n_features == 9, weight_scale == 10000
  - feature_names order matches the BPF feature enum [PD..TSA]
  - per feature: 1 <= n_bins <= MAX_BINS(10), len(bin_edges) == n_bins-1
    (integers, strictly ascending), len(weights_int) == n_bins
  - quantization consistency: |w_int - w_float*scale| <= 1 (the exporter
    truncates toward zero rather than rounding), same for bias/threshold
  - no NaN/Inf in any float field

Usage: validate_model_json.py <model_weights.json> [...]
Exits nonzero if any model fails.
"""

import json
import math
import sys

MAX_BINS = 10
EXPECTED_FEATURES = [
    "pd", "sz", "fq", "sd", "p2", "id", "i2", "ie",
    "time_since_last_access_at_eviction",
]
REQUIRED_KEYS = [
    "feature_names", "n_features", "weight_scale",
    "bias", "bias_int", "threshold", "threshold_int", "features",
]


def validate(path):
    errors = []
    with open(path) as f:
        m = json.load(f)

    for k in REQUIRED_KEYS:
        if k not in m:
            errors.append(f"missing top-level key: {k}")
    if errors:
        return errors

    if m["n_features"] != len(EXPECTED_FEATURES):
        errors.append(f"n_features = {m['n_features']}, expected {len(EXPECTED_FEATURES)}")
    if m["feature_names"] != EXPECTED_FEATURES:
        errors.append(f"feature_names mismatch vs BPF enum order: {m['feature_names']}")
    scale = m["weight_scale"]
    if scale != 10000:
        errors.append(f"weight_scale = {scale}, expected 10000")

    for fname, fval, ival in (("bias", m["bias"], m["bias_int"]),
                              ("threshold", m["threshold"], m["threshold_int"])):
        if not math.isfinite(fval):
            errors.append(f"{fname} is not finite: {fval}")
        elif abs(ival - fval * scale) > 1.0:
            errors.append(f"{fname}_int {ival} != {fname}*scale {fval * scale:.2f} (tol 1)")

    feats = m["features"]
    if len(feats) != m["n_features"]:
        errors.append(f"features array has {len(feats)} entries, expected {m['n_features']}")

    for i, feat in enumerate(feats):
        tag = f"feature[{i}] ({feat.get('name', '?')})"
        if feat.get("index") != i:
            errors.append(f"{tag}: index {feat.get('index')} != position {i}")
        if feat.get("name") != EXPECTED_FEATURES[i]:
            errors.append(f"{tag}: name != expected {EXPECTED_FEATURES[i]}")

        n_bins = feat.get("n_bins")
        edges = feat.get("bin_edges", [])
        w_int = feat.get("weights_int", [])
        w_float = feat.get("weights_float", [])

        if not isinstance(n_bins, int) or not (1 <= n_bins <= MAX_BINS):
            errors.append(f"{tag}: n_bins {n_bins} outside [1, {MAX_BINS}]")
            continue
        if len(edges) != n_bins - 1:
            errors.append(f"{tag}: {len(edges)} bin_edges, expected n_bins-1 = {n_bins - 1}")
        for j, e in enumerate(edges):
            # loader reads edges with json_object_get_uint64: floats would
            # silently truncate, negatives would wrap
            if not isinstance(e, int):
                errors.append(f"{tag}: bin_edges[{j}] = {e!r} is not an integer")
            elif e < 0:
                errors.append(f"{tag}: bin_edges[{j}] = {e} is negative")
        if any(b <= a for a, b in zip(edges, edges[1:])):
            errors.append(f"{tag}: bin_edges not strictly ascending: {edges}")
        if len(w_int) != n_bins:
            errors.append(f"{tag}: {len(w_int)} weights_int, expected n_bins = {n_bins}")
        if len(w_float) != n_bins:
            errors.append(f"{tag}: {len(w_float)} weights_float, expected n_bins = {n_bins}")
        for j, (wi, wf) in enumerate(zip(w_int, w_float)):
            if not math.isfinite(wf):
                errors.append(f"{tag}: weights_float[{j}] not finite: {wf}")
            elif abs(wi - wf * scale) > 1.0:
                errors.append(f"{tag}: weights_int[{j}] {wi} != float*scale {wf * scale:.2f} (tol 1)")

    return errors


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    failed = False
    for path in sys.argv[1:]:
        errs = validate(path)
        if errs:
            failed = True
            print(f"FAIL {path}")
            for e in errs:
                print(f"  - {e}")
        else:
            print(f"OK   {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
