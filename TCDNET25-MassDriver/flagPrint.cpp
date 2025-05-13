#include <iostream>
#include <cstdint>
#include <cstring>
#include <cstdlib>

// Rotate right 8-bit
uint8_t ror8(uint8_t value, unsigned int count) {
    return (value >> (count % 8)) | (value << (8 - (count % 8)));
}

// Simulated ExAllocatePool2
uint8_t* AllocatePool(size_t size) {
    return static_cast<uint8_t*>(malloc(size));
}

// Translated DEC_FLAG function
int64_t DEC_FLAG(const uint8_t* input, uint64_t inputLen, const char* key, uint8_t** outputFlag, uint64_t* outLen) {
    if (!input || !key || !outputFlag || !outLen)
        return 0xC000000D;

    char v9 = *key;
    uint64_t v10 = 0;

    if (v9) {
        const char* v11 = key;
        do {
            ++v11;
            v10 = ((v9 + 33 * v10) >> 16) ^ (v9 + 33 * v10);
            v9 = *v11;
        } while (*v11);
    }

    uint8_t* buffer = AllocatePool(inputLen + 1);
    *outputFlag = buffer;

    if (!buffer)
        return 0xC000009A;

    for (uint64_t i = 0; i < inputLen; ++i) {
        uint8_t inputByte = input[i];
        uint8_t keyByte = key[i % 15]; // key length is 15 ("ENGINE_1337_GO")
        uint8_t xorBase = static_cast<uint8_t>(keyByte ^ v10);
        uint8_t rotated = ror8(static_cast<uint8_t>(inputByte - xorBase), 3);

        buffer[i] = static_cast<uint8_t>(
            (7 * i + ((17 * i) ^ (v10 >> (8 * (i & 7)))) + 13) ^ rotated
        );
    }

    buffer[inputLen] = 0; // null-terminate
    *outLen = inputLen;
    return 0;
}

// Helper to convert hex to byte array
void fromHexDwordsToBytes(const uint32_t* dwords, size_t dwordCount, uint8_t* bytesOut) {
    for (size_t i = 0; i < dwordCount; ++i) {
        bytesOut[i * 4 + 0] = (dwords[i] >> 0) & 0xFF;
        bytesOut[i * 4 + 1] = (dwords[i] >> 8) & 0xFF;
        bytesOut[i * 4 + 2] = (dwords[i] >> 16) & 0xFF;
        bytesOut[i * 4 + 3] = (dwords[i] >> 24) & 0xFF;
    }
}

int main() {
    uint32_t v19_dwords[10] = {
        0x46BAFC10, 0xAB91A286, 0x06634417, 0x329C968A, 0x9946AB04,
        0x786009CA, 0x42E0E50C, 0x5D0D1526, 0x4BBE3203, 0xDBAD5D49
    };

    uint8_t inputBytes[40]; // 10 * 4 bytes
    fromHexDwordsToBytes(v19_dwords, 10, inputBytes);

    uint8_t* decrypted = nullptr;
    uint64_t decryptedLen = 0;

    const char* key = "ENGINE_1337_GO";
    uint64_t a2 = 43; // 0x2B

    int64_t status = DEC_FLAG(inputBytes, a2, key, &decrypted, &decryptedLen);

    if (status == 0 && decrypted) {
        std::cout << "Decrypted Flag (" << decryptedLen << " bytes): ";
        for (size_t i = 0; i < decryptedLen; ++i) {
            if (isprint(decrypted[i]))
                std::cout << decrypted[i];
            else
                std::cout << '.';
        }
        std::cout << std::endl;

        free(decrypted);
    } else {
        std::cerr << "Decryption failed with status: 0x" << std::hex << status << std::endl;
    }

    return 0;
}
