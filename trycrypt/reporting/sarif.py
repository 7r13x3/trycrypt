"""
SARIF (Static Analysis Results Interchange Format) 2.1.0 exporter.
Ingestible by GitHub Advanced Security, Splunk, Elastic, and enterprise SIEMs.
Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from datetime import datetime, timezone
from typing import Any


TOOL_NAME = "trycrypt"
TOOL_VERSION = "0.2.0"
TOOL_INFO_URI = "https://github.com/trycrypt/trycrypt"


def _rule(rule_id: str, name: str, description: str, level: str = "warning") -> dict:
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": name},
        "fullDescription": {"text": description},
        "defaultConfiguration": {"level": level},
        "helpUri": TOOL_INFO_URI,
    }


RULES = [
    _rule("TC001", "WeakPassword", "Vault password crackable in under 1 hour.", "error"),
    _rule("TC002", "WeakKDF", "scrypt parameters below recommended N >= 2^17.", "warning"),
    _rule("TC003", "MetadataLeakage", "File-size entropy is low — metadata leaks content type.", "warning"),
    _rule("TC004", "WorldReadableMasterkey", "masterkey.cryptomator is world-readable.", "error"),
    _rule("TC005", "CloudSyncExposure", "Vault resides in a cloud-sync folder with versioning risk.", "warning"),
    _rule("TC006", "SymlinkEscape", "Symlink in vault points outside vault directory.", "error"),
    _rule("TC007", "WorldWritableParent", "Parent directory of vault is world-writable.", "error"),
]


def _result(rule_id: str, message: str, level: str, location: str) -> dict:
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": location},
            }
        }],
    }


def generate_sarif(report: dict) -> dict:
    """Convert a trycrypt audit report into a SARIF 2.1.0 document."""
    results: list[dict] = []

    meta = report.get("metadata") or {}
    if "entropy" in meta:
        norm = meta["entropy"].get("normalized", 1.0)
        if norm < 0.5:
            results.append(_result(
                "TC003",
                f"File-size Shannon entropy is {norm:.2f} — high metadata leakage.",
                "warning",
                "vault/d",
            ))

    pw = report.get("password") or {}
    if "kdf" in pw:
        if pw["kdf"]["N"] < 2**17:
            results.append(_result(
                "TC002",
                f"scrypt N={pw['kdf']['N']} is below recommended minimum (2^17).",
                "warning",
                "vault/masterkey.cryptomator",
            ))
        target = pw.get("target_gpu")
        ttc = pw.get("gpu_estimates", {}).get(target, {}).get("time_to_crack_seconds", float("inf"))
        if ttc < 3600:
            results.append(_result(
                "TC001",
                f"Password crackable in {ttc:.0f}s on {target}.",
                "error",
                "vault/masterkey.cryptomator",
            ))

    hyg = report.get("hygiene") or {}
    perms = hyg.get("permissions")
    if perms and perms.get("world_readable"):
        results.append(_result(
            "TC004",
            f"masterkey permissions {perms['mode_human']} allow world read.",
            "error",
            "vault/masterkey.cryptomator",
        ))
    for c in hyg.get("cloud_sync", []):
        results.append(_result("TC005", c["finding"], "warning", str(c["provider"])))
    for s in hyg.get("symlinks", []):
        if s.get("escapes_vault"):
            results.append(_result(
                "TC006",
                f"Symlink {s['path']} → {s['target']} escapes vault.",
                "error",
                s["path"],
            ))
    for p in hyg.get("path_traversal", []):
        results.append(_result("TC007", p["finding"], "error", p["path"]))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": TOOL_INFO_URI,
                    "rules": RULES,
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
        }],
    }
