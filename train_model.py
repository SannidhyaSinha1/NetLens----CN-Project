#!/usr/bin/env python3
"""Train the supervised attack classifier (L3 tier 3) on labelled flows.

    python train_model.py                        # 700 flows/class, default seed
    python train_model.py --flows-per-class 1500
    python train_model.py --extra-pcap captures/nmap_lab.pcap:port_scan \
                          --extra-pcap captures/browsing.pcap:benign

Why this exists
---------------
The Isolation Forest in tier 2 is label-free by design — it learns what is
normal for the network it is plugged into.  That tells us a flow is *unusual*;
it cannot tell us the flow is a port scan, because nothing ever showed it one.
Naming an attack requires labelled malicious examples, so this script builds
them: attack scenarios are synthesised as packet records, pushed through the
same `FlowTable` the live dashboard uses, and the resulting labelled feature
vectors train a Random Forest.

Nothing is transmitted anywhere — `netlens/synth.py` writes packet dicts into
memory.  Real lab captures can be folded in with --extra-pcap when they are
available, and the feature layout is identical either way.

Writes: models/netlens_model.joblib, data/netlens_flows.csv, data/train_report.txt
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime

import numpy as np

from netlens import config
from netlens.flows import FEATURE_NAMES, FlowTable


def load_extra_pcaps(specs):
    """--extra-pcap path:label  ->  labelled flows from a real capture."""
    from netlens.synth import replay_pcap

    rows = []
    for spec in specs or []:
        if ":" not in spec:
            sys.exit(f"--extra-pcap expects path:label, got {spec!r}")
        path, label = spec.rsplit(":", 1)
        table = FlowTable()
        n = 0
        for rec in replay_pcap(path, label=label):
            table.add_packet(rec)
            n += 1
        flows = table.flush()
        for f in flows:
            if f.total_packets < 1:
                continue
            feats = f.features()
            feats["label"] = label
            feats["proto_name"] = f.proto
            feats["service"] = f.service
            rows.append(feats)
        print(f"  {path}: {n} packets -> {len(flows)} flows labelled '{label}'")
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flows-per-class", type=int, default=700)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--test-size", type=float, default=0.25)
    ap.add_argument("--trees", type=int, default=300)
    ap.add_argument("--extra-pcap", action="append", default=[],
                    metavar="PATH:LABEL",
                    help="fold a real labelled capture into training")
    ap.add_argument("--no-save", action="store_true")
    args = ap.parse_args()

    import pandas as pd
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.metrics import (classification_report, confusion_matrix,
                                 accuracy_score, f1_score)
    from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
    from sklearn.preprocessing import StandardScaler

    config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 78)
    print("NetLens — supervised attack classifier training")
    print("=" * 78)

    # ---------------------------------------------------------- 1. dataset
    t0 = time.time()
    print(f"\n[1/5] Synthesising labelled traffic "
          f"({args.flows_per_class} flows/class, seed {args.seed})")
    print("      packet records -> real FlowTable -> labelled feature vectors\n")

    from netlens.synth import build_dataset
    df, meta = build_dataset(flows_per_class=args.flows_per_class, seed=args.seed)

    extra = load_extra_pcaps(args.extra_pcap)
    if extra:
        df = pd.concat([df, pd.DataFrame(extra)], ignore_index=True)
        df = df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)

    print(f"\n      {len(df)} flows in {time.time() - t0:.1f}s")
    print(f"      {len(FEATURE_NAMES)} features per flow")
    print("\n      class balance:")
    for label, n in df["label"].value_counts().items():
        print(f"        {label:18s} {n:6d}")

    if not args.no_save:
        df.to_csv(config.DATASET_PATH, index=False)
        print(f"\n      dataset -> {config.DATASET_PATH}")

    # ---------------------------------------------------------- 2. split
    X = df[FEATURE_NAMES].to_numpy(dtype=float)
    y = df["label"].to_numpy()
    classes = sorted(set(y))

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y)
    print(f"\n[2/5] Split: {len(X_tr)} train / {len(X_te)} test (stratified)")

    scaler = StandardScaler().fit(X_tr)
    X_trs, X_tes = scaler.transform(X_tr), scaler.transform(X_te)

    # ---------------------------------------------------------- 3. train
    print(f"\n[3/5] Random Forest — {args.trees} trees, balanced class weights")
    clf = RandomForestClassifier(
        n_estimators=args.trees, max_depth=None, min_samples_leaf=1,
        class_weight="balanced_subsample", random_state=args.seed, n_jobs=-1,
    ).fit(X_trs, y_tr)

    # n_jobs=1 on purpose: the forest itself is already threaded, and a loky
    # process pool here only adds noisy resource-tracker warnings at exit.
    cv = cross_val_score(clf, X_trs, y_tr, cv=StratifiedKFold(5, shuffle=True,
                         random_state=args.seed), scoring="f1_macro", n_jobs=1)
    print(f"      5-fold CV macro-F1 on train: {cv.mean():.4f} +/- {cv.std():.4f}")

    # ---------------------------------------------------------- 4. evaluate
    y_pred = clf.predict(X_tes)
    acc = accuracy_score(y_te, y_pred)
    f1m = f1_score(y_te, y_pred, average="macro")
    report = classification_report(y_te, y_pred, digits=4, zero_division=0)
    cm = confusion_matrix(y_te, y_pred, labels=classes)

    print(f"\n[4/5] Held-out test set")
    print(f"      accuracy  {acc:.4f}     macro-F1  {f1m:.4f}\n")
    print(report)

    print("      confusion matrix (rows = true, cols = predicted)")
    w = max(len(c) for c in classes) + 1
    print("      " + " " * w + "".join(f"{c[:9]:>11s}" for c in classes))
    for i, c in enumerate(classes):
        print(f"      {c:<{w}s}" + "".join(f"{v:>11d}" for v in cm[i]))

    imp = clf.feature_importances_
    order = np.argsort(imp)[::-1]
    print("\n      most informative features")
    for i in order[:12]:
        bar = "#" * int(imp[i] / imp[order[0]] * 34)
        print(f"        {FEATURE_NAMES[i]:22s} {imp[i]:.4f}  {bar}")

    # ------------------------------------------- benign-only Isolation Forest
    print(f"\n[5/5] Isolation Forest fallback baseline (benign flows only)")
    Xb = df.loc[df["label"] == "benign", FEATURE_NAMES].to_numpy(dtype=float)
    if_scaler = StandardScaler().fit(Xb)
    iforest = IsolationForest(n_estimators=200,
                              contamination=config.IFOREST_CONTAMINATION,
                              random_state=args.seed, n_jobs=-1
                              ).fit(if_scaler.transform(Xb))
    attack_mask = df["label"] != "benign"
    Xa = df.loc[attack_mask, FEATURE_NAMES].to_numpy(dtype=float)
    flagged = (iforest.predict(if_scaler.transform(Xa)) == -1).mean()
    benign_fp = (iforest.predict(if_scaler.transform(Xb)) == -1).mean()
    print(f"      flags {flagged:.1%} of attack flows as anomalous "
          f"({benign_fp:.1%} false positives on benign)")
    print(f"      note: the live system re-fits this on the deployment "
          f"network's own first {config.BASELINE_SECONDS:.0f}s (novelty N1);")
    print(f"      this copy is only a cold-start fallback.")

    # ---------------------------------------------------------- save
    if args.no_save:
        print("\n--no-save: nothing written.")
        return 0

    import joblib
    bundle = {
        "algorithm": "RandomForestClassifier",
        "classifier": clf,
        "scaler": scaler,
        "iforest": iforest,
        "iforest_scaler": if_scaler,
        "features": list(FEATURE_NAMES),
        "classes": list(clf.classes_),
        "importances": imp,
        "test_accuracy": float(acc),
        "test_macro_f1": float(f1m),
        "cv_macro_f1": float(cv.mean()),
        "confusion_matrix": cm.tolist(),
        "report": report,
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "n_train": int(len(X_tr)),
        "n_test": int(len(X_te)),
        "flows_per_class": args.flows_per_class,
        "seed": args.seed,
        "extra_pcaps": args.extra_pcap,
        "iforest_attack_recall": float(flagged),
        "iforest_benign_fp": float(benign_fp),
    }
    joblib.dump(bundle, config.MODEL_PATH)
    print(f"\nmodel   -> {config.MODEL_PATH}")

    rp = config.DATA_DIR / "train_report.txt"
    with open(rp, "w") as fh:
        fh.write("NetLens supervised classifier — training report\n")
        fh.write(f"trained_at        {bundle['trained_at']}\n")
        fh.write(f"flows             {len(df)} ({args.flows_per_class}/class)\n")
        fh.write(f"features          {len(FEATURE_NAMES)}\n")
        fh.write(f"train/test        {len(X_tr)}/{len(X_te)}\n")
        fh.write(f"accuracy          {acc:.4f}\n")
        fh.write(f"macro-F1          {f1m:.4f}\n")
        fh.write(f"CV macro-F1       {cv.mean():.4f} +/- {cv.std():.4f}\n\n")
        fh.write(report + "\n")
        fh.write("confusion matrix (rows=true, cols=pred)\n")
        fh.write("labels: " + ", ".join(classes) + "\n")
        for row in cm:
            fh.write("  " + " ".join(f"{v:6d}" for v in row) + "\n")
        fh.write("\nfeature importances\n")
        for i in order:
            fh.write(f"  {FEATURE_NAMES[i]:24s} {imp[i]:.5f}\n")
    print(f"report  -> {rp}")

    with open(config.DATA_DIR / "dataset_meta.json", "w") as fh:
        json.dump({"counts": meta["counts"], "classes": classes,
                   "features": list(FEATURE_NAMES), "seed": args.seed,
                   "extra_pcaps": args.extra_pcap}, fh, indent=2)

    print(f"\nDone in {time.time() - t0:.1f}s. "
          f"The dashboard will load this model automatically.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
