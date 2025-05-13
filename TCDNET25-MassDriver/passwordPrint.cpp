#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <cstring>

// Simulated static data
const uint8_t xmmword_140003170[16] = {
    0x60, 0xE2, 0x53, 0x65, 0xDB, 0x79, 0xDA, 0x7A,
    0xD6, 0xD8, 0x71, 0x44, 0x51, 0x05, 0x56, 0x00
};

char* PASSWORDsub_1400015D8() {
    uint32_t v0 = 1633483301;
    int64_t v1 = -1;
    int64_t v2 = -1;

    uint8_t v7[20] = {0};
    uint8_t v8[20] = {0};

    // Initialize v8 with seed and static data
    *reinterpret_cast<uint32_t*>(v8) = 1633483301;
    memcpy(&v8[4], xmmword_140003170, 16);

    // Compute length of string starting from v8 + 4
    do {
        ++v2;
    } while (v8[v2 + 4] != 0);

    // Allocate memory
    char* Pool2 = (char*)malloc(v2 + 1);
    if (!Pool2) return nullptr;

    int64_t v4 = 0;
    *reinterpret_cast<uint32_t*>(v7) = 1633483301;
    memset(&v7[4], 0, 16);

    int64_t v5 = 15;
    do {
        v7[v4 + 4] = v8[v4 + 4] ^ (v0 & 0xFF);
        ++v4;
        v0 = 48271 * v0 % 0x7FFFFFFF;
        --v5;
    } while (v5);

    // Copy back to v8
    memcpy(&v8[16], &v7[16], 4);
    memcpy(v8, v7, 16);

    // Compute new length
    do {
        ++v1;
    } while (v8[v1 + 4] != 0);

    // Copy to Pool2 and null terminate
    memmove(Pool2, &v8[4], v1 + 1);

    return Pool2;
}

int main() {
    char* result = PASSWORDsub_1400015D8();
    if (result) {
        std::cout << "Decrypted string: " << result << std::endl;
        free(result);
    } else {
        std::cerr << "Memory allocation failed." << std::endl;
    }
    return 0;
}
