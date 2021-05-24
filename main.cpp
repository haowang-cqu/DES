// https://github.com/iamwhcn
// 2021/5/24
#include "des.h"
#include <iostream>

/**
 * 测试DES
 */
void test() {
    uint64_t input = 0x9474B8E8C73BCA7D;
    uint64_t result = input;
    /*
     * TESTING IMPLEMENTATION OF DES
     * Ronald L. Rivest
     * X0:  9474B8E8C73BCA7D
     * X16: 1B1A2DDB4C642438
     *
     * OUTPUT:
     * E: 8da744e0c94e5e17
     * D: 0cdb25e3ba3c6d79
     * E: 4784c4ba5006081f
     * D: 1cf1fc126f2ef842
     * E: e4be250042098d13
     * D: 7bfc5dc6adb5797c
     * E: 1ab3b4d82082fb28
     * D: c1576a14de707097
     * E: 739b68cd2e26782a
     * D: 2a59f0c464506edb
     * E: a5c39d4251f0a81e
     * D: 7239ac9a6107ddb1
     * E: 070cac8590241233
     * D: 78f87b6e3dfecf61
     * E: 95ec2578c2c433f0
     * D: 1b1a2ddb4c642438  <-- X16
     */
    for (int i = 0; i < 16; i++) {
        if (i % 2 == 0) {
            result = des(result, result, mode_t::e);
            printf ("E: %016llx\n", result);
        } else {
            result = des(result, result, mode_t::d);
            printf ("D: %016llx\n", result);
        }
    }
}

/**
 * 验证弱密钥
 */
void weak_keys() {
    uint64_t weak[] = {
            0x0101010101010101,
            0xFEFEFEFEFEFEFEFE,
            0xE0E0E0E0F1F1F1F1,
            0x1F1F1F1F0E0E0E0E
    };
    uint64_t semi_weak[] = {
            0x011F011F010E010E, 0x1F011F010E010E01,
            0x01E001E001F101F1, 0xE001E001F101F101
    };
    for (auto& k : weak) {
        printf ("弱密钥: %016llx\n", k);
        auto sub_keys = key_generation(k);
        for (auto& sub_key : sub_keys) {
            printf ("  %016llx\n", sub_key);
        }
    }
    for (auto& k : semi_weak) {
        printf ("半弱密钥: %016llx\n", k);
        auto sub_keys = key_generation(k);
        for (auto& sub_key : sub_keys) {
            printf ("  %016llx\n", sub_key);
        }
    }
}

int main() {
    weak_keys();
    return 0;
}
