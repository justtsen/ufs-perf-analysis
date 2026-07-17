# ufs-perf-analyzer

A lightweight, standalone Python tool for analyzing Linux **block-layer ftrace** logs
from **UFS / eMMC** storage devices.

---

## Features

| Feature | Description |
|---|---|
| **Single mode** | Parse one trace → per-device performance tables + HTML report |
| **Compare mode** | Parse two or more traces → unified comparison charts in one HTML |
| **IO Size Breakdown** | 4KB / 8KB / 16KB / 32KB / 64KB / 128KB / 256KB / 512KB / 1MB / 2MB / 4MB |
| **Direction Breakdown** | Read (R) / Write (W) / Write-Sync (WS) / Write-Flush (WF) / Discard (D) |
| **Outlier Removal** | IQR + Z-score configurable, per (size × direction) group |
| **Other Histogram** | Shows actual IO sizes that don't snap to standard buckets |
| **Dispersion Report** | Mean / Std / P50 / P95 / P99 latency per bucket |
| **2 GB+ Support** | Line-by-line streaming — no memory exhaustion |
| **Sensitive Scan** | Built-in check before publishing to GitHub |

---

## Requirements

```bash
Python 3.6+

# For HTML chart generation (recommended)
pip install plotly
```

---

## Usage

### Single file

```bash
python ufs_perf_analyzer.py trace.txt --label MyDevice
```

### Compare two or more files (most common)

```bash
python ufs_perf_analyzer.py fileA.txt fileB.txt \
       --label DeviceA DeviceB \
       --compare
```

### Full options

```bash
python ufs_perf_analyzer.py fileA.txt fileB.txt fileC.txt \
       --label DevA DevB DevC \
       --compare \
       --other-histogram \
       --outlier-method both \
       --iqr-k 1.5 \
       --zscore-thresh 3.0 \
       --out-dir ./results
```

### Outlier method options

| Option | Description |
|---|---|
| `--outlier-method both` | Remove only IOs flagged by **both** IQR and Z-score (default, conservative) |
| `--outlier-method iqr` | IQR only |
| `--outlier-method zscore` | Z-score only |
| `--outlier-method none` | No outlier removal |

### Tune sensitivity

```bash
# More aggressive removal
python ufs_perf_analyzer.py trace.txt --iqr-k 1.0 --zscore-thresh 2.5

# More conservative removal
python ufs_perf_analyzer.py trace.txt --iqr-k 2.0 --zscore-thresh 4.0
```

### Skip HTML (CSV only)

```bash
python ufs_perf_analyzer.py trace.txt --no-html
```

### Sensitive information scan (before GitHub publish)

```bash
python ufs_perf_analyzer.py --check-sensitive
```

---

## Output files

### Per device

| File | Description |
|---|---|
| `<label>_io_details.csv` | Every matched IO: timestamp / direction / bytes / latency / speed |
| `<label>_summary.csv` | (size × direction) aggregated stats — RAW |
| `<label>_summary_clean.csv` | Same, after outlier removal |
| `<label>_outlier_report.csv` | Removed rows with IQR/Z-score reason |
| `<label>_dispersion.csv` | Mean / Std / P50 / P95 / P99 per group |

### Compare mode

| File | Description |
|---|---|
| `comparison_summary.csv` | Side-by-side RAW stats for all devices |
| `comparison_summary_clean.csv` | Side-by-side CLEAN stats |
| `ufs_perf_report.html` | **Interactive HTML charts** (all devices in one file) |

---

## HTML Report Sections

| Section | Description |
|---|---|
| Overview | Weighted avg Read / Write speed bar chart |
| Write Speed by Size | Bar chart per IO size bucket — RAW & CLEAN |
| Write Latency by Size | Line chart (log scale) — RAW & CLEAN |
| Read Speed by Size | Bar chart per IO size bucket |
| Write Delta (CLEAN−RAW) | Shows how much outlier removal changed each bucket |
| P95 Latency Heatmap | Color heatmap of P95 latency by size × direction |
| Other Histogram | Top 20 non-standard IO sizes |

Use the **Filter toolbar** in the report to show only Write / Read / Latency / Heatmap etc.

---

## Supported trace format

The tool parses standard Linux `block_rq_issue` / `block_rq_complete` ftrace events:

```
 kworker/0:1H-123   [000] .... 1008.408250: block_rq_issue: 259,0 W 0 () 48783096 + 64 [kworker]
 kworker/0:1H-123   [000] .... 1008.408557: block_rq_complete: 259,0 W () 48783096 + 64 [0]
```

Capture with:

```bash
# Enable block events
echo 1 > /sys/kernel/debug/tracing/events/block/block_rq_issue/enable
echo 1 > /sys/kernel/debug/tracing/events/block/block_rq_complete/enable

# Start tracing
echo 1 > /sys/kernel/debug/tracing/tracing_on

# ... run your workload ...

# Capture log
cat /sys/kernel/debug/tracing/trace > ufs_trace.txt
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
