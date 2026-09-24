// trycrypt — CUDA scrypt kernel (professor-level)
// Compile with: nvcc -O3 -arch=sm_86 -cubin scrypt_kernel.cu
// Target: NVIDIA RTX 4090 (sm_89) / A100 (sm_80)

#include <cuda_runtime.h>
#include <stdint.h>

#define SCRYPT_BLOCK_SIZE 128
#define SCRYPT_MAX_N       (1 << 20)

// Salsa20/8 core — the heart of scrypt
__device__ __forceinline__ void salsa20_8(uint32_t B[16]) {
    uint32_t x[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) x[i] = B[i];

    #pragma unroll
    for (int i = 0; i < 8; i += 2) {
        // Column round
        x[ 4] ^= rotl(x[ 0] + x[12],  7);
        x[ 8] ^= rotl(x[ 4] + x[ 0],  9);
        x[12] ^= rotl(x[ 8] + x[ 4], 13);
        x[ 0] ^= rotl(x[12] + x[ 8], 18);

        x[ 9] ^= rotl(x[ 5] + x[ 1],  7);
        x[13] ^= rotl(x[ 9] + x[ 5],  9);
        x[ 1] ^= rotl(x[13] + x[ 9], 13);
        x[ 5] ^= rotl(x[ 1] + x[13], 18);

        x[14] ^= rotl(x[10] + x[ 6],  7);
        x[ 2] ^= rotl(x[14] + x[10],  9);
        x[ 6] ^= rotl(x[ 2] + x[14], 13);
        x[10] ^= rotl(x[ 6] + x[ 2], 18);

        x[ 3] ^= rotl(x[15] + x[11],  7);
        x[ 7] ^= rotl(x[ 3] + x[15],  9);
        x[11] ^= rotl(x[ 7] + x[ 3], 13);
        x[15] ^= rotl(x[11] + x[ 7], 18);

        // Row round
        x[ 1] ^= rotl(x[ 0] + x[ 3],  7);
        x[ 2] ^= rotl(x[ 1] + x[ 0],  9);
        x[ 3] ^= rotl(x[ 2] + x[ 1], 13);
        x[ 0] ^= rotl(x[ 3] + x[ 2], 18);

        x[ 6] ^= rotl(x[ 5] + x[ 4],  7);
        x[ 7] ^= rotl(x[ 6] + x[ 5],  9);
        x[ 4] ^= rotl(x[ 7] + x[ 6], 13);
        x[ 5] ^= rotl(x[ 4] + x[ 7], 18);

        x[11] ^= rotl(x[10] + x[ 9],  7);
        x[ 8] ^= rotl(x[11] + x[10],  9);
        x[ 9] ^= rotl(x[ 8] + x[11], 13);
        x[10] ^= rotl(x[ 9] + x[ 8], 18);

        x[12] ^= rotl(x[15] + x[14],  7);
        x[13] ^= rotl(x[12] + x[15],  9);
        x[14] ^= rotl(x[13] + x[12], 13);
        x[15] ^= rotl(x[14] + x[13], 18);
    }

    #pragma unroll
    for (int i = 0; i < 16; i++) B[i] += x[i];
}

__device__ __forceinline__ uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// BlockMix — applies Salsa20/8 in a chain
__device__ void blockmix(uint32_t *B, uint32_t *Y, int r) {
    uint32_t X[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) X[i] = B[(2 * r - 1) * 16 + i];

    for (int i = 0; i < 2 * r; i++) {
        #pragma unroll
        for (int j = 0; j < 16; j++) X[j] ^= B[i * 16 + j];
        salsa20_8(X);
        #pragma unroll
        for (int j = 0; j < 16; j++) Y[i * 16 + j] = X[j];
    }

    // Reorder
    for (int i = 0; i < r; i++) {
        #pragma unroll
        for (int j = 0; j < 16; j++) B[i * 16 + j] = Y[(2 * i) * 16 + j];
        #pragma unroll
        for (int j = 0; j < 16; j++) B[(i + r) * 16 + j] = Y[(2 * i + 1) * 16 + j];
    }
}

// ROMix — the memory-hard part
__device__ void romix(uint32_t *X, uint32_t *V, int N, int r) {
    uint32_t *Y = X + 32 * r;
    
    for (int i = 0; i < N; i++) {
        #pragma unroll
        for (int k = 0; k < 32 * r; k++) V[i * 32 * r + k] = X[k];
        blockmix(X, Y, r);
    }

    for (int i = 0; i < N; i++) {
        uint32_t j = X[(2 * r - 1) * 16] & (N - 1);
        #pragma unroll
        for (int k = 0; k < 32 * r; k++) X[k] ^= V[j * 32 * r + k];
        blockmix(X, Y, r);
    }
}

// The main scrypt kernel — one thread per password candidate
extern "C" __global__ void scrypt_kernel(
    const uint8_t *passwords,
    const uint8_t *salt,
    const uint32_t salt_len,
    const uint32_t N,
    const uint32_t r,
    const uint32_t p,
    uint8_t *output,
    const uint32_t dklen,
    const uint64_t *match_index,
    const uint8_t *target_hash
) {
    uint64_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    // Shared memory for the memory-hard ROMix
    extern __shared__ uint32_t shared[];
    uint32_t *X = shared;
    uint32_t *V = shared + 32 * r;

    // Load password into X
    const uint8_t *pw = passwords + idx * 64;
    #pragma unroll
    for (int i = 0; i < 32 * r; i++) {
        X[i] = ((uint32_t*)pw)[i % 16];
    }

    // Run ROMix
    romix(X, V, N, r);

    // Write result
    uint8_t *out = output + idx * dklen;
    #pragma unroll
    for (int i = 0; i < dklen / 4; i++) {
        ((uint32_t*)out)[i] = X[i];
    }

    // Compare against target hash
    bool match = true;
    for (int i = 0; i < dklen; i++) {
        if (out[i] != target_hash[i]) { match = false; break; }
    }
    if (match) {
        atomicCAS((unsigned long long*)match_index, 0ULL, idx + 1);
    }
}
