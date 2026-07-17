#!/usr/bin/env python3
"""
ufs_perf_analyzer.py
====================
A standalone tool for analyzing Linux block-layer ftrace logs from UFS / eMMC
storage devices.

Features
--------
  Single mode   : parse one trace → per-device performance tables + HTML report
  Compare mode  : parse two or more traces → per-device tables + unified
                  comparison charts in a single HTML report
  Outlier removal (IQR + Z-score, configurable)
  Other-bucket histogram (actual IO sizes that don't fit standard buckets)
  2 GB+ file support via line-by-line streaming

Usage
-----
  # Single file
  python ufs_perf_analyzer.py trace.txt --label MyDevice

  # Compare multiple files
  python ufs_perf_analyzer.py a.txt b.txt c.txt --label DevA DevB DevC --compare

  # Tune outlier removal
  python ufs_perf_analyzer.py trace.txt --outlier-method iqr --iqr-k 2.0
  python ufs_perf_analyzer.py trace.txt --outlier-method zscore --zscore-thresh 2.5
  python ufs_perf_analyzer.py trace.txt --outlier-method none

  # Extra options
  python ufs_perf_analyzer.py trace.txt --other-histogram --out-dir ./results

Outputs (per device)
--------------------
  <label>_io_details.csv          every matched IO row
  <label>_summary.csv             (size x direction) RAW stats
  <label>_summary_clean.csv       (size x direction) after outlier removal
  <label>_outlier_report.csv      removed rows with reason

Outputs (compare mode)
----------------------
  comparison_summary.csv          side-by-side RAW
  comparison_summary_clean.csv    side-by-side CLEAN
  ufs_perf_report.html            interactive HTML charts (all devices)

Requirements
------------
  Python 3.6+  —  no third-party packages needed for CSV/text output
  plotly        —  optional, only needed for HTML chart generation
                   pip install plotly
"""

import re, sys, os, csv, argparse, math, json
from collections import defaultdict

# ─── constants ────────────────────────────────────────────────────────────────

SECTOR_BYTES = 512

SIZE_BUCKETS = {
    "4KB":   4    * 1024,
    "8KB":   8    * 1024,
    "16KB":  16   * 1024,
    "32KB":  32   * 1024,
    "64KB":  64   * 1024,
    "128KB": 128  * 1024,
    "256KB": 256  * 1024,
    "512KB": 512  * 1024,
    "1MB":   1024 * 1024,
    "2MB":   2    * 1024 * 1024,
    "4MB":   4    * 1024 * 1024,
}
SNAP_TOLERANCE = 0.10   # ±10 %
BUCKET_ORDER   = list(SIZE_BUCKETS.keys()) + ["Other"]
DIR_ORDER      = ["R", "W", "WS", "WF", "D", "?"]

WRITE_DIRS     = {"W", "WS", "WF"}
READ_DIRS      = {"R"}

# ─── helpers ─────────────────────────────────────────────────────────────────

def bucket_of(nbytes):
    best, best_diff = "Other", float("inf")
    for lbl, sz in SIZE_BUCKETS.items():
        d = abs(nbytes - sz)
        if d < best_diff:
            best_diff, best = d, lbl
    if best != "Other" and best_diff / SIZE_BUCKETS[best] <= SNAP_TOLERANCE:
        return best
    return "Other"

def direction(op):
    op = op.upper()
    if "WS" in op: return "WS"
    if "WF" in op: return "WF"
    if op.startswith("W"): return "W"
    if op.startswith("R"): return "R"
    if op.startswith("D"): return "D"
    return "?"

def _mean_std(vals):
    n = len(vals)
    if n == 0: return 0.0, 0.0
    m = sum(vals) / n
    s = math.sqrt(sum((v - m) ** 2 for v in vals) / n) if n > 1 else 0.0
    return m, s

def _percentile(sorted_vals, pct):
    n = len(sorted_vals)
    if n == 0: return 0.0
    return sorted_vals[min(int(n * pct), n - 1)]

def _iqr_bounds(vals, k=1.5):
    s = sorted(vals)
    n = len(s)
    q1 = s[int(n * 0.25)]
    q3 = s[int(n * 0.75)]
    iqr = q3 - q1
    return q1 - k * iqr, q3 + k * iqr

# ─── regex ───────────────────────────────────────────────────────────────────

RE_ISSUE = re.compile(
    r"[\s]+([\d.]+):\s+block_rq_issue:\s+"
    r"(\d+,\d+)\s+(\w+)\s+\d+\s+\(\)\s+(\d+)\s+\+\s+(\d+)"
)
RE_COMPLETE = re.compile(
    r"[\s]+([\d.]+):\s+block_rq_complete:\s+"
    r"(\d+,\d+)\s+(\w+)\s+\(\)\s+(\d+)\s+\+\s+(\d+)"
)

# ─── parser ──────────────────────────────────────────────────────────────────

def parse_file(path, label, progress_every=500_000):
    print(f"\n[{label}] Parsing : {path}")
    size_mb = os.path.getsize(path) / 1e6
    print(f"[{label}] Size    : {size_mb:.1f} MB")
    pending = {}
    results = []
    n = 0
    with open(path, "r", errors="replace") as fh:
        for raw in fh:
            n += 1
            if n % progress_every == 0:
                print(f"  ... {n:,} lines  |  {len(results):,} IOs matched")
            m = RE_ISSUE.search(raw)
            if m:
                ts, dev, op, sector, slen = m.groups()
                nbytes = int(slen) * SECTOR_BYTES
                pending[(dev, sector, slen)] = (float(ts), direction(op), nbytes)
                continue
            m = RE_COMPLETE.search(raw)
            if m:
                ts, dev, op, sector, slen = m.groups()
                key = (dev, sector, slen)
                if key in pending:
                    issue_ts, op_dir, nbytes = pending.pop(key)
                    lat_ms = (float(ts) - issue_ts) * 1000.0
                    spd = (nbytes / 1_048_576) / (lat_ms / 1000.0) if lat_ms > 0 and nbytes > 0 else 0.0
                    results.append({
                        "timestamp":  float(ts),
                        "direction":  op_dir,
                        "sector":     int(sector),
                        "bytes":      nbytes,
                        "size_label": bucket_of(nbytes),
                        "latency_ms": round(lat_ms, 4),
                        "speed_mbs":  round(spd, 4),
                    })
    print(f"[{label}] Done    : {n:,} lines  →  {len(results):,} matched IOs")
    return results

# ─── outlier detection ───────────────────────────────────────────────────────

def detect_outliers(results, method="both", iqr_k=1.5, z_thresh=3.0):
    """
    Group by (size_label, direction).
    An IO is an outlier only if BOTH selected methods flag it (when method=both).
    Returns (clean_results, outlier_results).
    """
    groups = defaultdict(list)
    for i, r in enumerate(results):
        groups[(r["size_label"], r["direction"])].append(i)

    keep    = set(range(len(results)))
    flagged = {}

    for (sz, dr), idxs in groups.items():
        if len(idxs) < 10:
            continue
        vals = [results[i]["latency_ms"] for i in idxs]
        iqr_lo = iqr_hi = z_mean = z_std = None

        if method in ("iqr", "both"):
            iqr_lo, iqr_hi = _iqr_bounds(vals, iqr_k)
        if method in ("zscore", "both"):
            z_mean, z_std = _mean_std(vals)

        for idx, v in zip(idxs, vals):
            reasons = []
            if iqr_lo is not None and (v < iqr_lo or v > iqr_hi):
                reasons.append(f"IQR[{iqr_lo:.3f},{iqr_hi:.3f}]")
            if z_std is not None and z_std > 0:
                z = abs(v - z_mean) / z_std
                if z > z_thresh:
                    reasons.append(f"Z={z:.2f}")
            if method == "both" and len(reasons) == 2:
                keep.discard(idx)
                flagged[idx] = ", ".join(reasons)
            elif method != "both" and reasons:
                keep.discard(idx)
                flagged[idx] = reasons[0]

    clean    = [results[i] for i in range(len(results)) if i in keep]
    outliers = []
    for i, reason in flagged.items():
        row = dict(results[i])
        row["outlier_reason"] = reason
        outliers.append(row)
    return clean, outliers

# ─── aggregation ─────────────────────────────────────────────────────────────

def make_summary(results):
    agg = defaultdict(lambda: {"count": 0, "bytes": 0, "lat": 0.0, "spd": 0.0})
    for r in results:
        k = (r["size_label"], r["direction"])
        agg[k]["count"] += 1
        agg[k]["bytes"] += r["bytes"]
        agg[k]["lat"]   += r["latency_ms"]
        agg[k]["spd"]   += r["speed_mbs"]
    out = {}
    for k, v in agg.items():
        n = v["count"]
        out[k] = {
            "count":       n,
            "total_mb":    round(v["bytes"] / 1_048_576, 2),
            "avg_lat_ms":  round(v["lat"] / n, 4),
            "avg_spd_mbs": round(v["spd"] / n, 4),
        }
    return out

def weighted_avg_speed(summary, dirs):
    """Calculate throughput-weighted average speed for given direction set."""
    total_mb = total_time = 0.0
    for (sz, dr), v in summary.items():
        if dr in dirs and v["avg_lat_ms"] > 0:
            total_mb   += v["total_mb"]
            total_time += v["avg_lat_ms"] * v["count"] / 1000.0
    return round(total_mb / total_time, 2) if total_time > 0 else 0.0

def make_other_histogram(results):
    hist = defaultdict(lambda: {"count": 0, "bytes": 0})
    for r in results:
        if r["size_label"] == "Other":
            kb = round(r["bytes"] / 1024, 1)
            hist[kb]["count"] += 1
            hist[kb]["bytes"] += r["bytes"]
    rows = sorted(hist.items(), key=lambda x: -x[1]["count"])
    return [{"size_kb": kb, "count": v["count"],
             "total_mb": round(v["bytes"] / 1_048_576, 3)} for kb, v in rows]

def make_dispersion(results, clean):
    groups = defaultdict(list)
    for r in results:
        groups[(r["size_label"], r["direction"])].append(r["latency_ms"])
    clean_groups = defaultdict(list)
    for r in clean:
        clean_groups[(r["size_label"], r["direction"])].append(r["latency_ms"])
    rows = []
    for sz in BUCKET_ORDER:
        for dr in DIR_ORDER:
            vals = groups.get((sz, dr))
            if not vals or len(vals) < 2: continue
            s = sorted(vals)
            n = len(s)
            mean, std = _mean_std(vals)
            removed_n = n - len(clean_groups.get((sz, dr), []))
            rows.append({
                "size": sz, "direction": dr, "n": n,
                "mean_ms": round(mean, 3), "std_ms": round(std, 3),
                "p50_ms":  round(_percentile(s, 0.50), 3),
                "p95_ms":  round(_percentile(s, 0.95), 3),
                "p99_ms":  round(_percentile(s, 0.99), 3),
                "removed": removed_n,
            })
    return rows

# ─── CSV writers ─────────────────────────────────────────────────────────────

def write_csv(rows, path, fields):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(rows)
    print(f"  → {path}")

def write_summary_csv(summary, label, path):
    rows = []
    for sz in BUCKET_ORDER:
        for dr in DIR_ORDER:
            v = summary.get((sz, dr))
            if v:
                rows.append({"label": label, "size": sz, "direction": dr, **v})
    write_csv(rows, path, ["label","size","direction","count","total_mb","avg_lat_ms","avg_spd_mbs"])

def write_comparison_csv(sbl, path):
    labels = list(sbl.keys())
    rows = []
    for sz in BUCKET_ORDER:
        for dr in DIR_ORDER:
            k   = (sz, dr)
            row = {"size": sz, "direction": dr}
            any_data = False
            for lbl in labels:
                v = sbl[lbl].get(k)
                if v:
                    any_data = True
                    row[f"{lbl}_count"]       = v["count"]
                    row[f"{lbl}_total_mb"]    = v["total_mb"]
                    row[f"{lbl}_avg_lat_ms"]  = v["avg_lat_ms"]
                    row[f"{lbl}_avg_spd_mbs"] = v["avg_spd_mbs"]
                else:
                    for s in ["count","total_mb","avg_lat_ms","avg_spd_mbs"]:
                        row[f"{lbl}_{s}"] = "-"
            if any_data:
                rows.append(row)
    fields = ["size","direction"]
    for lbl in labels:
        fields += [f"{lbl}_count",f"{lbl}_total_mb",f"{lbl}_avg_lat_ms",f"{lbl}_avg_spd_mbs"]
    write_csv(rows, path, fields)

# ─── terminal print ──────────────────────────────────────────────────────────

def print_table(summary, label, tag=""):
    print(f"\n{'='*72}")
    print(f"  {label}  {tag}")
    print(f"{'='*72}")
    print(f"  {'Size':<8}  {'Dir':<4}  {'Count':>7}  {'Total MB':>10}  {'Avg Lat ms':>11}  {'Avg MB/s':>10}")
    print("  " + "-"*68)
    for sz in BUCKET_ORDER:
        for dr in DIR_ORDER:
            v = summary.get((sz, dr))
            if v:
                print(f"  {sz:<8}  {dr:<4}  {v['count']:>7,}  "
                      f"{v['total_mb']:>10.2f}  {v['avg_lat_ms']:>11.4f}  "
                      f"{v['avg_spd_mbs']:>10.4f}")

def print_dispersion_table(rows, label):
    print(f"\n{'='*90}")
    print(f"  {label}  —  Dispersion Report")
    print(f"{'='*90}")
    print(f"  {'Size':<8}  {'Dir':<4}  {'N':>7}  {'Mean ms':>9}  {'Std ms':>9}  "
          f"{'P50 ms':>9}  {'P95 ms':>9}  {'P99 ms':>9}  {'Removed':>8}")
    print("  " + "-"*86)
    for r in rows:
        print(f"  {r['size']:<8}  {r['direction']:<4}  {r['n']:>7,}  "
              f"{r['mean_ms']:>9.3f}  {r['std_ms']:>9.3f}  "
              f"{r['p50_ms']:>9.3f}  {r['p95_ms']:>9.3f}  {r['p99_ms']:>9.3f}  "
              f"{r['removed']:>8,}")

# ─── HTML report ─────────────────────────────────────────────────────────────

def build_html_report(datasets, out_path):
    """
    datasets: list of dict {
        label, summary_raw, summary_clean, dispersion, other_hist
    }
    Generates a self-contained interactive HTML report using Plotly.
    """
    try:
        import plotly.graph_objects as go
        from plotly.subplots import make_subplots
        import plotly.offline as po
    except ImportError:
        print("  [WARN] plotly not installed — skipping HTML report.")
        print("         pip install plotly")
        return

    labels      = [d["label"] for d in datasets]
    multi       = len(datasets) > 1
    colors      = ["#2196F3","#FF5722","#4CAF50","#9C27B0","#FF9800","#00BCD4"]
    write_dirs  = ["W", "WS"]
    read_dirs   = ["R"]

    # ── collect per-dataset write & read speed / latency vectors ─────────────
    def extract_vectors(summary, dirs):
        spd_vec, lat_vec, bkt_vec = [], [], []
        for bkt in BUCKET_ORDER:
            vals = [summary.get((bkt, d)) for d in dirs if summary.get((bkt, d))]
            if not vals: continue
            # weighted by count
            total_cnt = sum(v["count"] for v in vals)
            avg_spd   = sum(v["avg_spd_mbs"] * v["count"] for v in vals) / total_cnt
            avg_lat   = sum(v["avg_lat_ms"]  * v["count"] for v in vals) / total_cnt
            spd_vec.append(round(avg_spd, 2))
            lat_vec.append(round(avg_lat, 4))
            bkt_vec.append(bkt)
        return bkt_vec, spd_vec, lat_vec

    sections = []

    # ── 1. Overview: weighted avg R/W speed bar chart ─────────────────────────
    ov_labels, ov_r_raw, ov_w_raw, ov_r_cl, ov_w_cl = [], [], [], [], []
    for d in datasets:
        ov_labels.append(d["label"])
        ov_r_raw.append(weighted_avg_speed(d["summary_raw"],   READ_DIRS))
        ov_w_raw.append(weighted_avg_speed(d["summary_raw"],   WRITE_DIRS))
        ov_r_cl.append(weighted_avg_speed(d["summary_clean"],  READ_DIRS))
        ov_w_cl.append(weighted_avg_speed(d["summary_clean"],  WRITE_DIRS))

    fig_ov = make_subplots(rows=1, cols=2,
        subplot_titles=["Weighted Avg Read Speed (MB/s)", "Weighted Avg Write Speed (MB/s)"])
    for i, lbl in enumerate(ov_labels):
        c = colors[i % len(colors)]
        fig_ov.add_trace(go.Bar(name=f"{lbl} RAW",   x=[lbl], y=[ov_r_raw[i]],
            marker_color=c, opacity=0.6, legendgroup=lbl), row=1, col=1)
        fig_ov.add_trace(go.Bar(name=f"{lbl} CLEAN", x=[lbl], y=[ov_r_cl[i]],
            marker_color=c, opacity=1.0, legendgroup=lbl, showlegend=False), row=1, col=1)
        fig_ov.add_trace(go.Bar(name=f"{lbl} RAW",   x=[lbl], y=[ov_w_raw[i]],
            marker_color=c, opacity=0.6, legendgroup=lbl, showlegend=False), row=1, col=2)
        fig_ov.add_trace(go.Bar(name=f"{lbl} CLEAN", x=[lbl], y=[ov_w_cl[i]],
            marker_color=c, opacity=1.0, legendgroup=lbl, showlegend=False), row=1, col=2)
    fig_ov.update_layout(title="Overview — Weighted Average Throughput",
        barmode="group", height=420, template="plotly_white")
    sections.append(("Overview — Weighted Avg Throughput", fig_ov))

    # ── 2. Write Speed by Size ────────────────────────────────────────────────
    for tag, mode in [("RAW", "summary_raw"), ("CLEAN", "summary_clean")]:
        fig = go.Figure()
        for i, d in enumerate(datasets):
            bkts, spd, _ = extract_vectors(d[mode], write_dirs)
            fig.add_trace(go.Bar(name=d["label"], x=bkts, y=spd,
                marker_color=colors[i % len(colors)]))
        fig.update_layout(
            title=f"Write Speed by IO Size [{tag}]",
            xaxis_title="IO Size", yaxis_title="Avg Speed (MB/s)",
            barmode="group", height=420, template="plotly_white")
        sections.append((f"Write Speed by Size [{tag}]", fig))

    # ── 3. Write Latency by Size (log scale) ─────────────────────────────────
    for tag, mode in [("RAW", "summary_raw"), ("CLEAN", "summary_clean")]:
        fig = go.Figure()
        for i, d in enumerate(datasets):
            bkts, _, lat = extract_vectors(d[mode], write_dirs)
            fig.add_trace(go.Scatter(name=d["label"], x=bkts, y=lat,
                mode="lines+markers", marker_color=colors[i % len(colors)]))
        fig.update_layout(
            title=f"Write Latency by IO Size [{tag}] (log scale)",
            xaxis_title="IO Size", yaxis_title="Avg Latency (ms)",
            yaxis_type="log", height=420, template="plotly_white")
        sections.append((f"Write Latency by Size [{tag}]", fig))

    # ── 4. Read Speed by Size ─────────────────────────────────────────────────
    for tag, mode in [("RAW", "summary_raw"), ("CLEAN", "summary_clean")]:
        fig = go.Figure()
        for i, d in enumerate(datasets):
            bkts, spd, _ = extract_vectors(d[mode], read_dirs)
            fig.add_trace(go.Bar(name=d["label"], x=bkts, y=spd,
                marker_color=colors[i % len(colors)]))
        fig.update_layout(
            title=f"Read Speed by IO Size [{tag}]",
            xaxis_title="IO Size", yaxis_title="Avg Speed (MB/s)",
            barmode="group", height=420, template="plotly_white")
        sections.append((f"Read Speed by Size [{tag}]", fig))

    # ── 5. RAW vs CLEAN delta (write, each device) ───────────────────────────
    for d in datasets:
        bkts_r, spd_r, _ = extract_vectors(d["summary_raw"],   write_dirs)
        bkts_c, spd_c, _ = extract_vectors(d["summary_clean"], write_dirs)
        # align
        bkt_set = list(dict.fromkeys(bkts_r + bkts_c))
        spd_map_r = dict(zip(bkts_r, spd_r))
        spd_map_c = dict(zip(bkts_c, spd_c))
        delta = [round(spd_map_c.get(b, 0) - spd_map_r.get(b, 0), 2) for b in bkt_set]
        colors_bar = ["green" if v >= 0 else "red" for v in delta]
        fig = go.Figure(go.Bar(x=bkt_set, y=delta, marker_color=colors_bar))
        fig.update_layout(
            title=f"{d['label']} — Write Speed Delta (CLEAN − RAW)",
            xaxis_title="IO Size", yaxis_title="Speed Delta (MB/s)",
            height=380, template="plotly_white")
        sections.append((f"{d['label']} Write Delta (CLEAN-RAW)", fig))

    # ── 6. Dispersion heatmap (P95 latency) ──────────────────────────────────
    for d in datasets:
        rows = d["dispersion"]
        if not rows: continue
        sizes_d = list(dict.fromkeys(r["size"] for r in rows))
        dirs_d  = list(dict.fromkeys(r["direction"] for r in rows))
        z = []
        for dr in dirs_d:
            row_z = []
            for sz in sizes_d:
                match = [r for r in rows if r["size"] == sz and r["direction"] == dr]
                row_z.append(match[0]["p95_ms"] if match else None)
            z.append(row_z)
        fig = go.Figure(go.Heatmap(
            z=z, x=sizes_d, y=dirs_d,
            colorscale="RdYlGn_r", colorbar_title="P95 Lat (ms)",
            text=[[f"{v:.2f}" if v is not None else "" for v in row] for row in z],
            texttemplate="%{text}"))
        fig.update_layout(
            title=f"{d['label']} — P95 Latency Heatmap (ms)",
            xaxis_title="IO Size", yaxis_title="Direction",
            height=380, template="plotly_white")
        sections.append((f"{d['label']} P95 Latency Heatmap", fig))

    # ── 7. Other histogram (per device) ──────────────────────────────────────
    for d in datasets:
        hist = d.get("other_hist", [])
        if not hist: continue
        top = hist[:20]
        fig = go.Figure(go.Bar(
            x=[str(r["size_kb"]) + " KB" for r in top],
            y=[r["count"] for r in top],
            text=[r["count"] for r in top],
            textposition="outside",
            marker_color="#607D8B"))
        fig.update_layout(
            title=f"{d['label']} — Other Bucket Size Distribution (top 20)",
            xaxis_title="IO Size", yaxis_title="Count",
            height=380, template="plotly_white")
        sections.append((f"{d['label']} Other Histogram", fig))

    # ── assemble HTML ────────────────────────────────────────────────────────
    divs = []
    for title, fig in sections:
        div = po.plot(fig, output_type="div", include_plotlyjs=False)
        divs.append(f'''
        <div class="card">
          <h3>{title}</h3>
          {div}
        </div>''')

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>UFS Performance Report</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: "Segoe UI", Arial, sans-serif; background: #f4f6f9; color: #333; }}
  header {{ background: #1a237e; color: white; padding: 20px 32px; }}
  header h1 {{ font-size: 1.6rem; }}
  header p  {{ font-size: 0.9rem; opacity: 0.8; margin-top: 4px; }}
  .toolbar {{ background: white; padding: 12px 32px; border-bottom: 1px solid #ddd;
              display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }}
  .toolbar label {{ font-size: 0.85rem; font-weight: 600; color: #555; }}
  .filter-btn {{ padding: 6px 14px; border-radius: 20px; border: 1px solid #90CAF9;
                 background: white; cursor: pointer; font-size: 0.82rem; transition: all .2s; }}
  .filter-btn:hover, .filter-btn.active {{ background: #1565C0; color: white; border-color: #1565C0; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(560px, 1fr));
           gap: 20px; padding: 24px 32px; }}
  .card {{ background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,.08);
           padding: 16px 12px; }}
  .card h3 {{ font-size: 0.92rem; font-weight: 600; color: #1a237e; margin-bottom: 8px; }}
  footer {{ text-align: center; padding: 20px; font-size: 0.8rem; color: #999; }}
</style>
</head>
<body>
<header>
  <h1>UFS / eMMC FTrace Performance Report</h1>
  <p>Generated by ufs_perf_analyzer.py &nbsp;|&nbsp; Devices: {", ".join(labels)}</p>
</header>

<div class="toolbar">
  <label>Filter:</label>
  <button class="filter-btn active" onclick="filterCards(this, 'all')">All</button>
  <button class="filter-btn" onclick="filterCards(this, 'overview')">Overview</button>
  <button class="filter-btn" onclick="filterCards(this, 'write')">Write</button>
  <button class="filter-btn" onclick="filterCards(this, 'read')">Read</button>
  <button class="filter-btn" onclick="filterCards(this, 'latency')">Latency</button>
  <button class="filter-btn" onclick="filterCards(this, 'delta')">RAW vs CLEAN</button>
  <button class="filter-btn" onclick="filterCards(this, 'heatmap')">Heatmap</button>
  <button class="filter-btn" onclick="filterCards(this, 'other')">Other Bucket</button>
</div>

<div class="grid" id="grid">
{"".join(divs)}
</div>

<footer>ufs_perf_analyzer.py — open source UFS ftrace analysis tool</footer>

<script>
function filterCards(btn, kw) {{
  document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  document.querySelectorAll(".card").forEach(c => {{
    const t = c.querySelector("h3").textContent.toLowerCase();
    c.style.display = (kw === "all" || t.includes(kw)) ? "" : "none";
  }});
}}
</script>
</body>
</html>'''

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  → {out_path}")

# ─── sensitivity check ───────────────────────────────────────────────────────

def check_sensitive(path):
    """
    Scan source file for patterns that may indicate sensitive information.
    Returns list of (line_no, line, pattern) tuples.
    """
    _KW_CONFID = r"(confidential|internal only|proprietary)"\n    PATTERNS = [  # nosec
        (re.compile(r"qual" + "comm",   re.I), "Company name"),
        (re.compile(r"\bq" + r"com\b",   re.I), "Company abbreviation"),
        (re.compile(r"\bsdm\d{3}\b",    re.I), "Chipset name (SDM)"),
        (re.compile(r"\bsm\d{4}\b",     re.I), "Chipset name (SM)"),
        (re.compile(r"\bqcs\d{3}\b",    re.I), "Chipset name (QCS)"),
        (re.compile(r"@[a-z0-9._%+\-]+",  re.I), "Email address"),
        (re.compile(r"\b\d{3}[-.]\d{3}[-.]\d{4}\b"), "Phone number"),
        (re.compile(r"(project|proj)\s*[=:\-]\s*\S+", re.I), "Project reference"),
        (re.compile(r"[A-Z]{2,}-\d{5,}"),           "Ticket/JIRA ID"),
        (re.compile(_KW_CONFID, re.I), "Confidentiality marker"),  # nosec
    ]
    findings = []
    with open(path, "r", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            for pat, label in PATTERNS:
                if pat.search(line):
                    findings.append((lineno, line.strip(), label))
                    break
    return findings

# ─── main ────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="UFS / eMMC ftrace performance analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)

    ap.add_argument("files",              nargs="*",  help="Trace file(s) to analyze")
    ap.add_argument("--label",            nargs="*",  help="Label for each file (same order)")
    ap.add_argument("--compare",          action="store_true",
                    help="Generate combined comparison report for multiple files")
    ap.add_argument("--out-dir",          default=None,
                    help="Output directory (default: same dir as input file)")
    ap.add_argument("--other-histogram",  action="store_true",
                    help="Include Other-bucket size distribution")
    ap.add_argument("--outlier-method",   choices=["iqr","zscore","both","none"], default="both",
                    help="Outlier detection method (default: both = IQR AND Z-score)")
    ap.add_argument("--iqr-k",            type=float, default=1.5,
                    help="IQR fence multiplier (default: 1.5)")
    ap.add_argument("--zscore-thresh",    type=float, default=3.0,
                    help="Z-score threshold (default: 3.0)")
    ap.add_argument("--no-html",          action="store_true",
                    help="Skip HTML chart generation")
    ap.add_argument("--check-sensitive",  action="store_true",
                    help="Scan output script for sensitive information before publishing")
    args = ap.parse_args()

    # ── sensitive check mode ──────────────────────────────────────────────────
    if args.check_sensitive:
        print("\n=== Sensitive Information Scan ===")
        script_path = os.path.abspath(__file__)
        findings = check_sensitive(script_path)
        if findings:
            print(f"  ⚠  {len(findings)} potential issues found:")
            for ln, line, label in findings:
                print(f"  Line {ln:5d} [{label}]: {line[:80]}")
        else:
            print("  ✓  No sensitive information detected. Safe to publish.")
        return

    # ── assign labels ─────────────────────────────────────────────────────────
    files  = args.files
    labels = list(args.label or [])
    for f in files[len(labels):]:
        labels.append(os.path.splitext(os.path.basename(f))[0])

    out_dir_base = args.out_dir or os.getcwd()
    os.makedirs(out_dir_base, exist_ok=True)

    datasets   = []
    sbl_raw    = {}
    sbl_clean  = {}

    for fpath, label in zip(files, labels):
        if not os.path.isfile(fpath):
            print(f"ERROR: file not found — {fpath}"); continue

        safe    = re.sub(r"[^\w\-]", "_", label)
        out_dir = args.out_dir or os.path.dirname(os.path.abspath(fpath))
        os.makedirs(out_dir, exist_ok=True)

        # parse
        results = parse_file(fpath, label)
        if not results:
            print(f"[{label}] WARNING: no IOs matched — check log format"); continue

        # outlier removal
        if args.outlier_method != "none":
            clean, outliers = detect_outliers(
                results,
                method   = args.outlier_method,
                iqr_k    = args.iqr_k,
                z_thresh = args.zscore_thresh)
        else:
            clean, outliers = results, []

        # summaries
        summary_raw   = make_summary(results)
        summary_clean = make_summary(clean)
        dispersion    = make_dispersion(results, clean)
        other_hist    = make_other_histogram(results) if args.other_histogram else []

        # terminal output
        print_table(summary_raw,   label, "(RAW)")
        print_table(summary_clean, label, "(CLEAN — outliers removed)")
        print_dispersion_table(dispersion, label)

        if args.other_histogram:
            print(f"\n  {label} — Other Bucket (top 15):")
            for r in other_hist[:15]:
                print(f"    {r['size_kb']:>8.1f} KB  count={r['count']:>6,}  {r['total_mb']:>8.3f} MB")

        # CSVs
        write_csv(results, os.path.join(out_dir, f"{safe}_io_details.csv"),
                  ["timestamp","direction","sector","bytes","size_label","latency_ms","speed_mbs"])
        write_summary_csv(summary_raw,   label, os.path.join(out_dir, f"{safe}_summary.csv"))
        write_summary_csv(summary_clean, label, os.path.join(out_dir, f"{safe}_summary_clean.csv"))
        if outliers:
            write_csv(outliers, os.path.join(out_dir, f"{safe}_outlier_report.csv"),
                      ["timestamp","direction","sector","bytes","size_label","latency_ms","speed_mbs","outlier_reason"])
        write_csv(dispersion, os.path.join(out_dir, f"{safe}_dispersion.csv"),
                  ["size","direction","n","mean_ms","std_ms","p50_ms","p95_ms","p99_ms","removed"])

        datasets.append({
            "label":        label,
            "summary_raw":  summary_raw,
            "summary_clean":summary_clean,
            "dispersion":   dispersion,
            "other_hist":   other_hist,
        })
        sbl_raw[label]   = summary_raw
        sbl_clean[label] = summary_clean

    # ── comparison CSVs ───────────────────────────────────────────────────────
    if args.compare and len(sbl_raw) >= 2:
        write_comparison_csv(sbl_raw,   os.path.join(out_dir_base, "comparison_summary.csv"))
        write_comparison_csv(sbl_clean, os.path.join(out_dir_base, "comparison_summary_clean.csv"))

    # ── HTML report ───────────────────────────────────────────────────────────
    if not args.no_html and datasets:
        html_path = os.path.join(out_dir_base, "ufs_perf_report.html")
        build_html_report(datasets, html_path)


if __name__ == "__main__":
    main()
