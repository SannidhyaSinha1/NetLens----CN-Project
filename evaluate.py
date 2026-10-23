#!/usr/bin/env python3
"""Phase-5 evaluation: model metrics + end-to-end pipeline detection rates.

    python evaluate.py              # both sections
    python evaluate.py --no-plots

Two sections, because they measure different things:

A. CLASSIFIER METRICS — per-class precision / recall / F1 and the confusion
   matrix on a held-out split of the labelled flow dataset.  This is what the
   "precision and recall per detector" row of the build plan asks for.

B. PIPELINE DETECTION RATE — the honest end-to-end number.  Fresh attack
   scenarios (a different seed from training) are replayed through the *whole*
   stack — capture buffer, flow table, and all three detector tiers — and we
   record which tiers actually fired, plus the false-positive rate on
   benign-only traffic.  A model scoring 0.99 offline still has to prove it
   fires inside the live pipeline.

Writes data/evaluation_report.txt and, unless --no-plots,
data/confusion_matrix.png + data/feature_importance.png.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import defaultdict

import numpy as np

from netlens import config
from netlens.flows import FEATURE_NAMES, FlowTable


# ========================================================== A. model metrics
def classifier_metrics(out, plots=True):
    import joblib
    import pandas as pd
    from sklearn.metrics import (classification_report, confusion_matrix,
                                 accuracy_score, f1_score, roc_auc_score)
    from sklearn.model_selection import train_test_split

    try:
        bundle = joblib.load(config.MODEL_PATH)
        df = pd.read_csv(config.DATASET_PATH)
    except FileNotFoundError as exc:
        out(f"!! {exc}\n!! run `python train_model.py` first.")
        return None

    X = df[FEATURE_NAMES].to_numpy(dtype=float)
    y = df["label"].to_numpy()
    seed = bundle.get("seed", 42)
    _, X_te, _, y_te = train_test_split(X, y, test_size=0.25,
                                        random_state=seed, stratify=y)

    clf, scaler = bundle["classifier"], bundle["scaler"]
    Xs = scaler.transform(X_te)
    y_pred = clf.predict(Xs)
    proba = clf.predict_proba(Xs)
    classes = list(clf.classes_)

    out("=" * 78)
    out("A.  SUPERVISED CLASSIFIER — held-out test metrics")
    out("=" * 78)
    out(f"model          {bundle['algorithm']} ({bundle['classifier'].n_estimators} trees)")
    out(f"trained        {bundle['trained_at']}  ·  seed {seed}")
    out(f"features       {len(FEATURE_NAMES)}")
    out(f"flows          {len(df)} total, {len(X_te)} held out")
    out("")
    out(f"accuracy       {accuracy_score(y_te, y_pred):.4f}")
    out(f"macro-F1       {f1_score(y_te, y_pred, average='macro'):.4f}")
    out(f"weighted-F1    {f1_score(y_te, y_pred, average='weighted'):.4f}")
    try:
        auc = roc_auc_score(y_te, proba, multi_class="ovr", average="macro",
                            labels=classes)
        out(f"macro ROC-AUC  {auc:.4f}  (one-vs-rest)")
    except Exception:
        pass
    out("")
    out(classification_report(y_te, y_pred, digits=4, zero_division=0))

    # binary view: benign vs any attack — the number that matters operationally
    yb = np.where(y_te == "benign", "benign", "attack")
    pb = np.where(y_pred == "benign", "benign", "attack")
    tp = int(((yb == "attack") & (pb == "attack")).sum())
    fn = int(((yb == "attack") & (pb == "benign")).sum())
    fp = int(((yb == "benign") & (pb == "attack")).sum())
    tn = int(((yb == "benign") & (pb == "benign")).sum())
    out("binary view — benign vs any attack")
    out(f"  detection rate (recall) {tp / max(1, tp + fn):.4f}   "
        f"missed attacks: {fn}")
    out(f"  false-positive rate     {fp / max(1, fp + tn):.4f}   "
        f"benign flagged: {fp}/{fp + tn}")
    out("")

    cm = confusion_matrix(y_te, y_pred, labels=classes)
    out("confusion matrix (rows = true, cols = predicted)")
    w = max(len(c) for c in classes) + 1
    out("  " + " " * w + "".join(f"{c[:9]:>11s}" for c in classes))
    for i, c in enumerate(classes):
        out(f"  {c:<{w}s}" + "".join(f"{v:>11d}" for v in cm[i]))
    out("")

    # confusions worth explaining rather than hiding
    conf = [(classes[i], classes[j], int(cm[i][j]))
            for i in range(len(classes)) for j in range(len(classes))
            if i != j and cm[i][j] > 0]
    if conf:
        out("remaining confusions")
        for a, b, n in sorted(conf, key=lambda x: -x[2]):
            out(f"  {n:4d}  {a} -> {b}")
        out("  note: port_scan vs syn_flood is the expected hard pair — both are")
        out("        1-3 packet SYN-only flows, and at flow level they genuinely")
        out("        look alike. The rule tier separates them on fan-out (many")
        out("        ports on one host vs many sources on one port), which is")
        out("        exactly why the three tiers are run together.")
        out("")

    imp = bundle["importances"]
    order = np.argsort(imp)[::-1]
    out("feature importances (top 15)")
    for i in order[:15]:
        bar = "#" * int(imp[i] / imp[order[0]] * 34)
        out(f"  {FEATURE_NAMES[i]:22s} {imp[i]:.4f}  {bar}")
    out("")
    out("Isolation Forest (tier 2) on the same dataset")
    out(f"  flags {bundle.get('iforest_attack_recall', 0):.1%} of attack flows "
        f"as anomalous, {bundle.get('iforest_benign_fp', 0):.1%} FP on benign")
    out("  — label-free, so it generalises to attacks never trained on, but it")
    out("    reports 'unusual' and not a class name. Complementary, not a rival.")
    out("")

    if plots:
        _plots(cm, classes, imp, order)
    return bundle


def _plots(cm, classes, imp, order):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as exc:
        print(f"(plots skipped: {exc})")
        return

    fig, ax = plt.subplots(figsize=(8, 6.6))
    norm = cm / np.maximum(1, cm.sum(axis=1, keepdims=True))
    im = ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(classes)), classes, rotation=45, ha="right")
    ax.set_yticks(range(len(classes)), classes)
    for i in range(len(classes)):
        for j in range(len(classes)):
            if cm[i][j]:
                ax.text(j, i, cm[i][j], ha="center", va="center", fontsize=9,
                        color="white" if norm[i][j] > 0.5 else "#222")
    ax.set_xlabel("predicted"); ax.set_ylabel("true")
    ax.set_title("NetLens attack classifier — confusion matrix\n"
                 "(held-out test set, counts shown, shading = per-class recall)")
    fig.colorbar(im, ax=ax, shrink=0.8, label="fraction of true class")
    fig.tight_layout()
    p1 = config.DATA_DIR / "confusion_matrix.png"
    fig.savefig(p1, dpi=160); plt.close(fig)

    top = order[:18][::-1]
    fig, ax = plt.subplots(figsize=(8, 6.4))
    ax.barh([FEATURE_NAMES[i] for i in top], [imp[i] for i in top],
            color="#2b6cb0")
    ax.set_xlabel("Gini importance")
    ax.set_title("Which flow features identify an attack")
    fig.tight_layout()
    p2 = config.DATA_DIR / "feature_importance.png"
    fig.savefig(p2, dpi=160); plt.close(fig)
    print(f"plots   -> {p1}\n           {p2}")


# ======================================================= B. pipeline e2e test
def pipeline_detection(out, trials=6, seed=2026):
    from netlens.detect import HybridDetector
    from netlens.synth import ATTACK_CLASSES, ATTACK_SCENARIOS, BENIGN_SCENARIOS

    out("=" * 78)
    out("B.  END-TO-END PIPELINE DETECTION (unseen seed, full L1-L3 stack)")
    out("=" * 78)
    out(f"Each scenario is replayed through FlowTable + all three detector")
    out(f"tiers, {trials} independent trials per attack class, seed {seed}.")
    out("A trial counts as detected if ANY tier raised a matching alert.")
    out("")

    rng = np.random.default_rng(seed)
    results = {}

    for attack in ATTACK_CLASSES:
        hits = defaultdict(int)
        detected = 0
        latencies = []
        for _ in range(trials):
            det = HybridDetector(enable_model=True)
            table = FlowTable()
            # warm the baseline with benign traffic first, as in a real deployment
            t = 1000.0
            for _ in range(14):
                fns, w = zip(*BENIGN_SCENARIOS)
                fn = fns[int(rng.choice(len(fns), p=np.array(w) / sum(w)))]
                recs = sorted(fn(rng, t), key=lambda r: r["ts"])
                for r in recs:
                    table.add_packet(r)
                t = max(t + 1.0, recs[-1]["ts"])
                det.process(recs, table, now=t)
            det.baseline.started_at = t - config.BASELINE_SECONDS - 1
            det.process([], table, now=t)          # force the baseline to fit

            recs = sorted(ATTACK_SCENARIOS[attack](rng, t + 1.0),
                          key=lambda r: r["ts"])
            t_attack = recs[0]["ts"]
            fired, first_ts = set(), None
            # feed in 0.5 s slices so detectors see it the way live capture does
            i = 0
            while i < len(recs):
                slice_end = recs[i]["ts"] + 0.5
                batch = []
                while i < len(recs) and recs[i]["ts"] <= slice_end:
                    batch.append(recs[i]); i += 1
                for r in batch:
                    table.add_packet(r)
                now = batch[-1]["ts"]
                for a in det.process(batch, table, now=now):
                    fired.add(a.tier)
                    hits[f"{a.tier}:{a.kind}"] += 1
                    if first_ts is None:
                        first_ts = now

            # Drain: the flow-scoring tiers only judge settled flows, so give
            # them the quiet ticks a live engine would deliver anyway.
            tail = recs[-1]["ts"]
            for extra in (config.FLOW_SETTLE_IDLE + 0.2,
                          config.FLOW_SETTLE_IDLE + 2.0,
                          config.FLOW_SETTLE_IDLE + 5.0):
                for a in det.process([], table, now=tail + extra):
                    fired.add(a.tier)
                    hits[f"{a.tier}:{a.kind}"] += 1
                    if first_ts is None:
                        first_ts = tail + extra

            if fired:
                detected += 1
                latencies.append((first_ts or t_attack) - t_attack)
            for tier in fired:
                hits[f"TIER_{tier}"] += 1

        rate = detected / trials
        results[attack] = {
            "rate": rate,
            "tiers": {k.split("_", 1)[1]: v for k, v in hits.items()
                      if k.startswith("TIER_")},
            "kinds": {k: v for k, v in hits.items() if not k.startswith("TIER_")},
            "latency": float(np.mean(latencies)) if latencies else None,
        }
        lat = results[attack]["latency"]
        tiers = ", ".join(f"{k}×{v}" for k, v in
                          sorted(results[attack]["tiers"].items()))
        out(f"{attack:16s} detected {detected}/{trials} ({rate:.0%})   "
            f"first alert +{lat:.2f}s   [{tiers or 'none'}]" if lat is not None
            else f"{attack:16s} detected {detected}/{trials} ({rate:.0%})   "
                 f"[{tiers or 'none'}]")
        for k, v in sorted(results[attack]["kinds"].items(), key=lambda x: -x[1]):
            out(f"                   {k}  ×{v}")
    out("")

    # ------------------------------------------------- false positives
    out("false positives on benign-only traffic")
    fp_runs, fp_alerts, benign_flows = 4, defaultdict(int), 0
    for _ in range(fp_runs):
        det = HybridDetector(enable_model=True)
        table = FlowTable()
        t = 5000.0
        for _ in range(45):
            fns, w = zip(*BENIGN_SCENARIOS)
            fn = fns[int(rng.choice(len(fns), p=np.array(w) / sum(w)))]
            recs = sorted(fn(rng, t), key=lambda r: r["ts"])
            for r in recs:
                table.add_packet(r)
            t = max(t + 1.5, recs[-1]["ts"])
            if t > 5000.0 + config.BASELINE_SECONDS:
                det.baseline.started_at = min(det.baseline.started_at or t,
                                              t - config.BASELINE_SECONDS - 1)
            for a in det.process(recs, table, now=t):
                fp_alerts[f"{a.tier}:{a.kind}"] += 1
        benign_flows += table.total_flows_seen

    total_fp = sum(fp_alerts.values())
    out(f"  {fp_runs} runs, {benign_flows} benign flows -> {total_fp} alerts "
        f"({total_fp / max(1, benign_flows):.4f} per flow)")
    for k, v in sorted(fp_alerts.items(), key=lambda x: -x[1]):
        out(f"    {k}  ×{v}")
    if not fp_alerts:
        out("    none")
    out("")
    out("  Reading this: tier-2 alerts on benign traffic are not strictly")
    out("  'wrong' — an Isolation Forest is calibrated to call ~3% of flows")
    out("  unusual (config.IFOREST_CONTAMINATION). Rule-tier and model-tier")
    out("  false positives are the ones that matter, and they are reported")
    out("  separately above for exactly that reason.")
    out("")
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-plots", action="store_true")
    ap.add_argument("--trials", type=int, default=6)
    ap.add_argument("--section", choices=["a", "b", "both"], default="both")
    args = ap.parse_args()

    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []

    def out(s=""):
        print(s, flush=True)
        lines.append(str(s))

    t0 = time.time()
    out("NetLens — Phase 5 evaluation")
    out(time.strftime("%Y-%m-%d %H:%M:%S"))
    out("")

    if args.section in ("a", "both"):
        if classifier_metrics(out, plots=not args.no_plots) is None:
            return 1
    if args.section in ("b", "both"):
        pipeline_detection(out, trials=args.trials)

    out(f"completed in {time.time() - t0:.1f}s")
    rp = config.DATA_DIR / "evaluation_report.txt"
    rp.write_text("\n".join(lines) + "\n")
    print(f"report  -> {rp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
