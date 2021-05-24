// https://github.com/iamwhcn
// 2021/5/24
#include <iostream>
#include "des.h"

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

int main() {
    test();
    return 0;
}
