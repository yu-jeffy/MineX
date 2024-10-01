// benchmark_sha256.c
// Compile with: gcc -O3 -o benchmark_sha256 benchmark_sha256.c -lcrypto

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

#define MESSAGE_LENGTH 64  // 512 bits

// SHA-256 Constants
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Initial hash values (H0)
static const uint32_t H0[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

// Right rotate function
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

// Optimized SHA-256 function
void optimized_sha256(const uint8_t data[], uint8_t hash[]) {
    // Implement the optimized SHA-256 algorithm here
    // Include optimizations as per your specifications

    uint32_t a, b, c, d, e, f, g, h;
    uint32_t W[64];
    uint32_t S0, S1, ch, temp1, temp2, maj;

    // Initialize working variables with H0
    a = H0[0];
    b = H0[1];
    c = H0[2];
    d = H0[3];
    e = H0[4];
    f = H0[5];
    g = H0[6];
    h = H0[7];

    // Prepare message schedule array W
    // Assuming data is exactly 64 bytes (512 bits)
    for (int i = 0; i < 16; ++i) {
        W[i]  = (uint32_t)data[i * 4] << 24;
        W[i] |= (uint32_t)data[i * 4 + 1] << 16;
        W[i] |= (uint32_t)data[i * 4 + 2] << 8;
        W[i] |= (uint32_t)data[i * 4 + 3];
    }

    // Optimizations can be applied here
    // For example, precomputing W[16] and W[17] if they remain constant
    // Skipping calculations for rounds where W[t] is known or can be optimized

    // Message schedule computation
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = ROTRIGHT(W[i - 15], 7) ^ ROTRIGHT(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = ROTRIGHT(W[i - 2], 17) ^ ROTRIGHT(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    // Compression function main loop
    for (int i = 0; i < 64; ++i) {
        // Early exit optimizations can be applied here (Optimization #2)
        // For rounds 61 and 62

        S1 = ROTRIGHT(e,6) ^ ROTRIGHT(e,11) ^ ROTRIGHT(e,25);
        ch = (e & f) ^ ((~e) & g);
        temp1 = h + S1 + ch + K[i] + W[i];
        S0 = ROTRIGHT(a,2) ^ ROTRIGHT(a,13) ^ ROTRIGHT(a,22);
        maj = (a & b) ^ (a & c) ^ (b & c);
        temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Add the compressed chunk to the current hash value
    a += H0[0];
    b += H0[1];
    c += H0[2];
    d += H0[3];
    e += H0[4];
    f += H0[5];
    g += H0[6];
    h += H0[7];

    // Produce the final hash value (big-endian)
    uint32_t digest[8] = {a, b, c, d, e, f, g, h};
    for (int i = 0; i < 8; ++i) {
        hash[i * 4]     = (digest[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (digest[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (digest[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = digest[i] & 0xFF;
    }
}

// Function to benchmark the custom SHA-256 implementation
double benchmark_custom_sha256(const uint8_t *message, int iterations) {
    uint8_t hash[32];
    clock_t start = clock();

    for (int i = 0; i < iterations; ++i) {
        optimized_sha256(message, hash);
    }

    clock_t end = clock();
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    return time_spent;
}

// Function to benchmark OpenSSL's SHA-256 implementation
double benchmark_openssl_sha256(const uint8_t *message, int iterations) {
    uint8_t hash[32];
    clock_t start = clock();

    for (int i = 0; i < iterations; ++i) {
        SHA256(message, MESSAGE_LENGTH, hash);
    }

    clock_t end = clock();
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    return time_spent;
}

int main() {
    // Test message (64 bytes)
    uint8_t message[MESSAGE_LENGTH];
    memset(message, 'a', MESSAGE_LENGTH);  // Fill with 'a' characters

    int iterations = 100000;

    // Benchmark custom SHA-256
    double custom_time = benchmark_custom_sha256(message, iterations);
    printf("Custom optimized SHA-256 time over %d iterations: %.6f seconds\n", iterations, custom_time);

    // Benchmark OpenSSL's SHA-256
    double openssl_time = benchmark_openssl_sha256(message, iterations);
    printf("OpenSSL SHA-256 time over %d iterations: %.6f seconds\n", iterations, openssl_time);

    // Calculate average time per hash
    printf("Average time per hash (custom): %.2f microseconds\n", (custom_time / iterations) * 1e6);
    printf("Average time per hash (OpenSSL): %.2f microseconds\n", (openssl_time / iterations) * 1e6);

    return 0;
}
