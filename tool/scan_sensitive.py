#!/usr/bin/env python3
"""
scan_sensitive.py — Pre-commit / CI helper
Scans source files for potentially sensitive information before uploading to GitHub.

Usage:
    python tools/scan_sensitive.py --path .
    python tools/scan_sensitive.py --path ./ufs_perf_analyzer.py
    python tools/scan_sensitive.py --path . --exclude .git,__pycache__,*.html,*.csv
"""

import re
import os
import sys
import argparse
import fnmatch

# ── Sensitive keyword fragments (split to avoid self-triggering) ───────────────
_KW_COMPANY_FULL  = "qual" + "comm"
_KW_COMPANY_ABBR  = "q" + "com"
_KW_PATH_PRJ      = "/" + "prj" + "/"
_KW_PATH_ORG      = "/" + _KW_COMPANY_ABBR + "/"
_KW_PATH_UNC      = "//" + "[a-z0-9-]+" + "/" + "prj" + "/"

PATTERNS = [
    # Company identifiers
    (re.compile(_KW_COMPANY_FULL,                    re.I), "Company Keywords"),
    (re.compile(r"\b" + _KW_COMPANY_ABBR + r"\b",   re.I), "Company Keywords"),

    # Chipset model numbers
    (re.compile(r"\bsdm\d{3,4}\b",                  re.I), "Chipset Model (SDM)"),
    (re.compile(r"\bsm\d{4}\b",                     re.I), "Chipset Model (SM)"),
    (re.compile(r"\bqcs\d{3,4}\b",                  re.I), "Chipset Model (QCS)"),
    (re.compile(r"\bqcm\d{3,4}\b",                  re.I), "Chipset Model (QCM)"),
    (re.compile(r"\bmsm\d{4}\b",                    re.I), "Chipset Model (MSM)"),

    # Internal paths
    (re.compile(_KW_PATH_PRJ  + r"\S+",             re.I), "Hardcoded Internal Paths"),
    (re.compile(_KW_PATH_ORG  + r"\S+",             re.I), "Hardcoded Internal Paths"),
    (re.compile(_KW_PATH_UNC  + r"\S+",             re.I), "Hardcoded Internal Paths"),

    # Personal information
    (re.compile(r"[a-z0-9._%+\-]{3,}@[a-z0-9.\-]+\.[a-z]{2,}", re.I), "Email Address"),
    (re.compile(r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b"),               "Phone Number"),

    # Project / ticket references
    (re.compile(r"\b(project|proj)\s*[=:\-]\s*\S+", re.I),         "Project Reference"),
    (re.compile(r"\b[A-Z]{2,10}-\d{5,}\b"),                         "JIRA / Ticket ID"),

    # Confidentiality markers
    (re.compile(r"\b(confidential|internal\s+only|proprietary|trade\s+secret)\b", re.I),
                                                                     "Confidentiality Marker"),

    # Credentials / tokens
    (re.compile(r"(password|passwd|secret|api[_\-]?key|token)\s*=\s*['\"][^'\"]{4,}['\"]", re.I),
                                                                     "Credential / Token"),
    (re.compile(r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"),    "Private Key"),
]

# ── File filters ──────────────────────────────────────────────────────────────
DEFAULT_SKIP_DIRS  = {".git", "__pycache__", ".venv", "venv",
                      "node_modules", ".idea", ".vscode"}
DEFAULT_SKIP_EXTS  = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                      ".zip", ".tar", ".gz", ".bin", ".exe", ".so", ".dll",
                      ".pyc", ".pyo"}
SKIP_FILENAMES     = {"scan_sensitive.py"}   # exclude self from scan

def should_skip(path: str, extra_patterns: list) -> bool:
    name = os.path.basename(path)
    ext  = os.path.splitext(name)[1].lower()
    if name in SKIP_FILENAMES:
        return True
    if ext in DEFAULT_SKIP_EXTS:
        return True
    for pat in extra_patterns:
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(path, pat):
            return True
    return False

def scan_file(filepath: str) -> list:
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                if line.rstrip().endswith("# nosec"):
                    continue
                for pattern, label in PATTERNS:
                    if pattern.search(line):
                        findings.append((lineno, label, line.rstrip()))
                        break
    except (PermissionError, IsADirectoryError):
        pass
    return findings

def scan_path(root: str, extra_skip: list) -> dict:
    results = {}
    root = os.path.abspath(root)
    if os.path.isfile(root):
        paths = [root]
    else:
        paths = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in DEFAULT_SKIP_DIRS]
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                if not should_skip(full, extra_skip):
                    paths.append(full)
    for p in sorted(paths):
        hits = scan_file(p)
        if hits:
            rel = os.path.relpath(p, start=os.path.dirname(root)
                                        if os.path.isfile(root) else root)
            results[rel] = hits
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Scan files for sensitive information before pushing to GitHub."
    )
    parser.add_argument("--path",    required=True, help="File or directory to scan")
    parser.add_argument("--exclude", default="",
                        help="Comma-separated glob patterns to skip (e.g. '*.html,*.csv')")
    args = parser.parse_args()

    extra_skip = [p.strip() for p in args.exclude.split(",") if p.strip()]

    print(f"\n\U0001f50d Scanning: {os.path.abspath(args.path)}")
    print("\u2500" * 50)

    results = scan_path(args.path, extra_skip)

    if not results:
        print("\u2705 No sensitive information found. Safe to upload!\n")
        sys.exit(0)

    total = sum(len(v) for v in results.values())
    print(f"\u26a0\ufe0f  Found {total} potential issue(s):\n")
    for filepath, findings in results.items():
        for lineno, label, line_text in findings:
            print(f"  [{label}] {filepath} line {lineno}: {line_text.strip()[:120]}")
    print(f"\n\u274c Please review above before uploading to GitHub.\n")
    sys.exit(1)

if __name__ == "__main__":
    main()
