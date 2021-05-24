/**
 * 参考:
 * https://en.wikipedia.org/wiki/DES_supplementary_material
 */
#include <iostream>
#include <array>

#define LB32_MASK   0x00000001
#define LB64_MASK   0x0000000000000001
#define L64_MASK    0x00000000ffffffff

enum mode_t {e, d};

std::array<uint64_t, 16> key_generation(uint64_t key);
uint64_t des(uint64_t input, uint64_t key, mode_t mode);