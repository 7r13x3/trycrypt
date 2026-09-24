<div align="center">

# 🔐 trycrypt

**Offline security auditor for Cryptomator vaults.**

*Metadata leakage · Password resilience · OS hygiene · SARIF export*

[![Python](https://img.shields.io/badge/python-3.11+-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen?style=for-the-badge)](.github/workflows/ci.yml)

</div>

---

## 🎯 What is `trycrypt`?

Cryptomator is excellent at hiding file **contents** and **names** in the cloud. However, it is **not** designed to hide:

- File **sizes** (metadata leakage)
- Password **strength** (KDF parameters)
- Local **filesystem** hygiene (permissions, symlinks, cloud sync)

`trycrypt` audits all three vectors against your own vault — the same way an attacker would — and produces a machine-readable risk report.

---

## 🧠 The Three Pillars

| Module | What it checks | Math |
|:---:|:---|:---|
| **Metadata** | File-size distribution, temporal patterns | Shannon entropy on log-binned sizes |
| **Password** | scrypt KDF params, GPU time-to-crack | Attacker cost function |
| **Hygiene** | `masterkey` permissions, symlinks, cloud sync | Filesystem ACL analysis |

---

## 📐 Mathematical Model

### 1. Shannon Entropy of File Sizes

To quantify metadata leakage, we measure the **Shannon entropy** $H(X)$ of the file-size distribution. Because file sizes span orders of magnitude (KB → GB), we apply $\log_{10}$ binning to preserve resolution:

$$
H(X) = -\sum_{i=1}^{K} p_i \log_2(p_i)
$$

Where $p_i = \frac{n_i}{N}$ is the probability of a file landing in bin $i$. 

The **normalized entropy** is:

$$
H_{\text{norm}} = \frac{H(X)}{H_{\text{max}}} \in [0, 1]
$$

- $H_{\text{norm}} \to 1$ : Sizes uniformly distributed → **low leakage**
- $H_{\text{norm}} \to 0$ : Sizes concentrated → **critical leakage**

### 2. Attacker Cost Function (Password Resilience)

Cryptomator uses `scrypt` with parameters $(N, r, p)$. The memory required per hash is:

$$
M = 128 \cdot N \cdot r \ \text{bytes}
$$

Since `scrypt` is memory-hard, the GPU bottleneck is **memory bandwidth**, not raw compute. The effective hashrate is:

$$
H_{\text{eff}} \approx \frac{B_{\text{gpu}} \cdot \eta}{128 \cdot N \cdot r}
$$

Where:

| Symbol | Description |
|:---:|:---|
| $B_{\text{gpu}}$ | GPU memory bandwidth (bytes/sec) |
| $\eta$ | Empirical scrypt efficiency ($\approx 0.05$) |
| $N, r$ | scrypt parameters from `masterkey.cryptomator` |

The **total time to crack** using a dictionary of size $|D|$ is:

$$
T_{\text{total}} = \frac{|D|}{H_{\text{eff}}} = \frac{|D| \cdot 128 \cdot N \cdot r}{B_{\text{gpu}} \cdot \eta}
$$

> **Example (RTX 4090, Cryptomator defaults):**
> $N = 32768$, $r = 8$, $B_{\text{gpu}} = 1008 \ \text{GB/s}$, $|D| = 14.3\text{M}$ (RockYou)
> 
> $T_{\text{total}} \approx 2.65 \ \text{hours}$ → **CRITICAL**

---

## 🚀 Installation

```bash
git clone https://github.com/7r13x3/trycrypt.git
cd trycrypt
pip install -e .
