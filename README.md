# 🔐 trycrypt

> Offline security auditor for **Cryptomator** vaults.
> Metadata leakage analysis · Password resilience · OS hygiene · SARIF export.

![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

---

## 🎯 What is `trycrypt`?

Cryptomator is excellent at hiding file **contents** and **names** in the cloud.
It is **not** designed to hide:

- File **sizes** (metadata leakage)
- Password **strength** (KDF parameters)
- Local **filesystem** hygiene (permissions, symlinks, cloud sync)

`trycrypt` audits all three vectors against your own vault — the same way an
attacker would — and produces a machine-readable risk report.

---

## 🧠 The Three Pillars

| Module | What it checks | Math |
|--------|----------------|------|
| **Metadata** | File-size distribution, temporal patterns | Shannon entropy `H(X)` on log-binned sizes |
| **Password** | scrypt KDF params, GPU time-to-crack | Attacker cost function `T = |Dict| / Hashrate` |
| **Hygiene**  | `masterkey` permissions, symlinks, cloud sync | Filesystem ACL analysis |

---

## 🚀 Installation

```bash
git clone https://github.com/7r13x3/trycrypt.git
cd trycrypt
pip install -e .
🛠️ Usage
# Full audit (runs all three modules)
trycrypt audit /path/to/vault

# JSON export
trycrypt audit /path/to/vault --output json --export report.json

# SARIF export (GitHub Advanced Security, Splunk, Elastic)
trycrypt sarif /path/to/vault --export report.sarif

# Password resilience only
trycrypt crack /path/to/vault --gpu "RTX 4090"

# OS hygiene only
trycrypt hygiene /path/to/vault
Commands
Command	Description
trycrypt audit <vault>	Run all three modules (metadata + password + hygiene)
trycrypt crack <vault>	Estimate GPU time-to-crack for the vault password
trycrypt hygiene <vault>	Run OS-level hygiene checks only
trycrypt sarif <vault>	Generate a SARIF 2.1.0 report for SIEM integration
📐 Mathematical Model
Shannon Entropy of File Sizes
H(X) = - Σ p_i · log₂(p_i)
Attacker Cost Function (Password)
T_total = |Dictionary| / ((B_gpu · η) / (128 · N · r))
Where:

B_gpu = GPU memory bandwidth (bytes/sec)

η ≈ 0.05 (empirical scrypt efficiency)

N, r = scrypt parameters from masterkey.cryptomator

See docs/MATH.md for the full derivation.
