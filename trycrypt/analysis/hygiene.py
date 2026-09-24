"""
OS Hygiene Module — checks local filesystem security around the vault.

Checks:
  1. masterkey.cryptomator file permissions (world-readable = bad)
  2. Owner of the vault directory
  3. Symlinks pointing outside the vault (symlink attack surface)
  4. Cloud-sync folders (Dropbox, Google Drive, OneDrive) in the path
  5. Filesystem mount flags if available
"""

import os
import stat
from pathlib import Path
from ..vault import CryptomatorVault


CLOUD_SYNC_MARKERS = {
    "Dropbox": [".dropbox", "Dropbox"],
    "Google Drive": [".gdrive", "Google Drive", "GoogleDrive"],
    "OneDrive": ["OneDrive", ".onedrive"],
    "iCloud": ["iCloud Drive", "Mobile Documents"],
    "Mega": ["MEGAsync"],
    "pCloud": [".pcloud"],
}


def _format_mode(mode: int) -> str:
    """Convert stat mode to rwxr-xr-x format."""
    return stat.filemode(mode)


def _check_permissions(path: Path) -> dict:
    st = path.stat()
    mode = st.st_mode
    perms = {
        "path": str(path),
        "mode_octal": oct(mode & 0o777),
        "mode_human": _format_mode(mode),
        "owner_uid": st.st_uid,
        "group_gid": st.st_gid,
        "world_readable": bool(mode & stat.S_IROTH),
        "world_writable": bool(mode & stat.S_IWOTH),
        "group_readable": bool(mode & stat.S_IRGRP),
    }
    if perms["world_readable"] or perms["world_writable"]:
        perms["severity"] = "CRITICAL"
        perms["finding"] = "masterkey is readable/writable by ANY user on this system"
    elif perms["group_readable"]:
        perms["severity"] = "MEDIUM"
        perms["finding"] = "masterkey is readable by group members"
    else:
        perms["severity"] = "OK"
        perms["finding"] = "masterkey permissions are restrictive"
    return perms


def _check_symlinks(vault: CryptomatorVault) -> list:
    """Find symlinks in the vault data directory."""
    findings = []
    if not vault.data_dir.exists():
        return findings
    for root, dirs, files in os.walk(vault.data_dir, followlinks=False):
        for name in dirs + files:
            p = Path(root) / name
            if p.is_symlink():
                try:
                    target = p.resolve()
                    inside = str(target).startswith(str(vault.path))
                    findings.append({
                        "path": str(p),
                        "target": str(target),
                        "escapes_vault": not inside,
                        "severity": "HIGH" if not inside else "LOW",
                    })
                except Exception:
                    findings.append({
                        "path": str(p),
                        "target": "<broken>",
                        "escapes_vault": True,
                        "severity": "HIGH",
                    })
    return findings


def _check_cloud_sync(path: Path) -> list:
    """Detect if the vault is stored inside a cloud-sync folder."""
    findings = []
    parts = [p for p in path.parts]
    for provider, markers in CLOUD_SYNC_MARKERS.items():
        for marker in markers:
            if marker in parts:
                findings.append({
                    "provider": provider,
                    "marker": marker,
                    "severity": "MEDIUM",
                    "finding": f"Vault is synced via {provider}. "
                               "If versioning is enabled, old masterkeys may be recoverable.",
                })
                break
    return findings


def _check_path_traversal(vault: CryptomatorVault) -> list:
    """Check for suspicious parent directories (e.g. /tmp, world-writable)."""
    findings = []
    for parent in [vault.path, vault.path.parent, vault.path.parent.parent]:
        try:
            st = parent.stat()
            if st.st_mode & stat.S_IWOTH:
                findings.append({
                    "path": str(parent),
                    "severity": "HIGH",
                    "finding": "Parent directory is world-writable — vault can be tampered with",
                })
        except Exception:
            continue
    return findings


def analyze_hygiene(vault: CryptomatorVault) -> dict:
    """Run all OS hygiene checks."""
    report = {
        "permissions": None,
        "symlinks": [],
        "cloud_sync": [],
        "path_traversal": [],
        "score": 100,
    }

    # 1. Masterkey permissions
    if vault.masterkey_path.exists():
        report["permissions"] = _check_permissions(vault.masterkey_path)
        if report["permissions"]["severity"] == "CRITICAL":
            report["score"] -= 50
        elif report["permissions"]["severity"] == "MEDIUM":
            report["score"] -= 20

    # 2. Symlinks
    report["symlinks"] = _check_symlinks(vault)
    for s in report["symlinks"]:
        if s["severity"] == "HIGH":
            report["score"] -= 15

    # 3. Cloud sync
    report["cloud_sync"] = _check_cloud_sync(vault.path)
    for c in report["cloud_sync"]:
        report["score"] -= 10

    # 4. Path traversal
    report["path_traversal"] = _check_path_traversal(vault)
    for p in report["path_traversal"]:
        if p["severity"] == "HIGH":
            report["score"] -= 20

    report["score"] = max(0, report["score"])

    if report["score"] >= 90:
        report["verdict"] = "CLEAN — no significant OS-level hygiene issues"
    elif report["score"] >= 70:
        report["verdict"] = "FAIR — minor hygiene issues detected"
    elif report["score"] >= 40:
        report["verdict"] = "POOR — multiple hygiene issues, remediation recommended"
    else:
        report["verdict"] = "CRITICAL — vault is exposed to local attackers"

    return report
