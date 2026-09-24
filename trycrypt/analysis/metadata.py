import duckdb
import numpy as np
from datetime import datetime
from ..vault import CryptomatorVault


# Heuristic file-size signatures (bytes)
SIZE_SIGNATURES = [
    ("tiny_config",        0,                     10 * 1024),
    ("small_document",     10 * 1024,             500 * 1024),
    ("image_compressed",   500 * 1024,            10 * 1024 * 1024),
    ("large_image_video",  10 * 1024 * 1024,      100 * 1024 * 1024),
    ("video_archive",      100 * 1024 * 1024,     5 * 1024**3),
    ("huge_archive_iso",   5 * 1024**3,           float("inf")),
]


def analyze_metadata(vault: CryptomatorVault) -> dict:
    """
    Perform metadata leakage analysis using DuckDB + Shannon entropy.
    """
    con = duckdb.connect(":memory:")
    con.execute("""
        CREATE TABLE files(
            path VARCHAR,
            size BIGINT,
            mtime TIMESTAMP,
            ctime TIMESTAMP
        )
    """)

    rows = []
    for f in vault.iter_encrypted_files():
        st = f.stat()
        rows.append((
            str(f),
            st.st_size,
            datetime.fromtimestamp(st.st_mtime),
            datetime.fromtimestamp(st.st_ctime),
        ))

    if not rows:
        return {"error": "no encrypted files found in vault"}

    con.executemany("INSERT INTO files VALUES (?, ?, ?, ?)", rows)

    total_files = con.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    total_bytes = con.execute("SELECT SUM(size) FROM files").fetchone()[0]

    # ---------- Shannon Entropy on log-binned sizes ----------
    sizes = np.array([r[1] for r in rows], dtype=np.float64)
    log_sizes = np.log10(sizes + 1)                    # log-scale: orders of magnitude
    hist, _ = np.histogram(log_sizes, bins="auto")

    p = hist / hist.sum()
    p = p[p > 0]                                       # drop zero-probability bins
    H = float(-np.sum(p * np.log2(p)))                 # Shannon entropy

    max_bins = len(hist)
    H_max = float(np.log2(max_bins)) if max_bins > 1 else 0.0
    H_norm = H / H_max if H_max > 0 else 0.0

    if H_norm < 0.5:
        interp = "CRITICAL — file sizes are highly predictable (heavy metadata leakage)"
    elif H_norm < 0.8:
        interp = "MODERATE — partial metadata leakage"
    else:
        interp = "LOW — file sizes are well distributed"

    # ---------- Statistical Fingerprinting ----------
    fingerprints = {}
    for name, lo, hi in SIZE_SIGNATURES:
        count = con.execute(
            "SELECT COUNT(*) FROM files WHERE size >= ? AND size < ?",
            [lo, hi],
        ).fetchone()[0]
        if count > 0:
            fingerprints[name] = count

    # ---------- Temporal Correlation ----------
    temporal = con.execute("""
        SELECT EXTRACT(hour FROM mtime) AS hour, COUNT(*) AS count
        FROM files
        GROUP BY hour
        ORDER BY count DESC
        LIMIT 5
    """).fetchall()

    return {
        "total_files": int(total_files),
        "total_bytes": int(total_bytes),
        "entropy": {
            "shannon": round(H, 4),
            "max": round(H_max, 4),
            "normalized": round(H_norm, 4),
            "interpretation": interp,
        },
        "fingerprints": fingerprints,
        "temporal_top_hours": [
            {"hour": int(h), "count": int(c)} for h, c in temporal
        ],
    }
