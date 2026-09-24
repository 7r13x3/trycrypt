# trycrypt — Mathematical Model

## 1. Shannon Entropy of File Sizes

Given N encrypted files with sizes {s_1, ..., s_N}, we apply log-scale
binning (because file sizes span orders of magnitude) into K bins.

For bin i, probability:
    p_i = n_i / N

Shannon entropy:
    H(X) = - Σ_{i=1}^{K} p_i · log₂(p_i)

Maximum entropy for K bins (uniform distribution):
    H_max = log₂(K)

Normalized entropy:
    H_norm = H(X) / H_max     ∈ [0, 1]

Interpretation:
    H_norm → 1 : sizes uniformly distributed (low leakage)
    H_norm → 0 : sizes concentrated in few bins (HIGH leakage)

## 2. Why Log-Scale Binning?

File sizes follow a log-normal distribution. Linear binning would collapse
99% of files into the first bin. Log₁₀ binning preserves resolution across
scales (KB, MB, GB).

## 3. Fingerprint Heuristics

| Range                | Inferred type        |
|----------------------|----------------------|
| 0 – 10 KB            | tiny config / JSON   |
| 10 KB – 500 KB       | small document       |
| 500 KB – 10 MB       | compressed image     |
| 10 MB – 100 MB       | large image / video  |
| 100 MB – 5 GB        | video / archive      |
| > 5 GB               | ISO / disk image     |

## 4. Password Resilience — Attacker Cost Function

Cryptomator uses scrypt with parameters (N, r, p). 

Memory required per hash:
    M = 128 · N · r   bytes

CPU time per hash:
    T_cpu = (2 · N · r · p) / f_cpu

GPU time-to-crack (memory-bandwidth bound):
    Effective hashrate ≈ (B_gpu · η) / (128 · N · r)

    Where:
      B_gpu = GPU memory bandwidth (bytes/sec)
      η     = efficiency factor (~0.05 for scrypt due to random memory access)

Total time to crack:
    T_total = |Dictionary| / Effective hashrate

For an RTX 4090 (B = 1008 GB/s), with Cryptomator defaults (N=32768, r=8):
    M = 128 · 32768 · 8 = 33.5 MB per hash
    Effective hashrate ≈ (1008e9 · 0.05) / 33.5e6 ≈ 1504 hashes/sec
    T_total ≈ 14,344,391 / 1504 ≈ 9537 seconds ≈ 2.65 hours

## 5. Verdict Thresholds

| Time to crack        | Verdict   |
|----------------------|-----------|
| < 1 hour             | CRITICAL  |
| < 24 hours           | HIGH      |
| < 1 year             | MEDIUM    |
| >= 1 year            | STRONG    |
