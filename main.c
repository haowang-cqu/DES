// https://github.com/iamwhcn
// 2021/5/24
#include "des.h"

typedef union {
    char c[8];
    uint64_t l;
} block;

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
            result = des(result, result, e);
            printf("E: %016llx\n", result);
        } else {
            result = des(result, result, d);
            printf("D: %016llx\n", result);
        }
    }
}

/**
 * 验证弱密钥
 */
void weak_keys() {
    uint64_t weak[4] = {
            0x0101010101010101,
            0xFEFEFEFEFEFEFEFE,
            0xE0E0E0E0F1F1F1F1,
            0x1F1F1F1F0E0E0E0E
    };
    uint64_t semi_weak[4] = {
            0x011F011F010E010E, 0x1F011F010E010E01,
            0x01E001E001F101F1, 0xE001E001F101F101
    };
    uint64_t sub_keys[16];
    for (int i = 0; i < 4; i++) {
        printf("弱密钥: %016llx\n", weak[i]);
        key_generation(weak[i], sub_keys);
        for (int j = 0; j < 16; j++) {
            printf("  %016llx\n", sub_keys[j]);
        }
    }
    for (int i = 0; i < 4; i++) {
        printf("半弱密钥: %016llx\n", semi_weak[i]);
        key_generation(semi_weak[i], sub_keys);
        for (int j = 0; j < 16; j++) {
            printf("  %016llx\n", sub_keys[j]);
        }
    }
}

/**
 * 加密16进制数
 */
void en_hex() {
    uint64_t in, key, mode;
    while (1) {
        printf("选择加密(1)解密(2)退出(0): ");
        scanf_s("%lld", &mode);
        if (mode == 0) break;
        printf("  输入一个数(hex): ");
        scanf_s("%llx", &in);
        printf("  输入一个密钥(hex): ");
        scanf_s("%llx", &key);
        if (mode == 1) {
            printf("  加密结果: %08llx\n", des(in, key, e));
        } else {
            printf("  解密结果: %08llx\n", des(in, key, d));
        }
    }
}

/**
 * 长度为8的字节数组转成uint64
 */
inline uint64_t bytes2uint64(const char *bytes) {
    block b = {0};
    for (int i = 0; i < 8; i++) {
        b.c[i] = bytes[i];
    }
    return b.l;
}

/**
 * uint64转成长度为8的字节数组
 */
inline void uint642bytes(uint64_t num, char *bytes) {
    block b = {0};
    b.l = num;
    for (int i = 0; i < 8; i++) {
        bytes[i] = b.c[i];
    }
}

/**
 * 加密文件
 */
void en_file() {
    uint64_t key = 0x1234567812345678;
    FILE *input, *en_out, *de_out;
    input = fopen("D:\\message.txt", "rb");
    en_out = fopen_s("D:\\en_message.txt", "wb");
    de_out = fopen_s("D:\\de_message.txt", "wb");
    if (input == NULL || en_out == NULL || de_out == NULL) {
        printf("fopen() ERROR!\n");
        exit(-1);
    }
    // 获取文件的总字节数
    fseek(input, 0, SEEK_END);
    long length = ftell(input);
    fseek(input, 0, 0);
    // 读取文件(缓冲区的长度加上8字节给padding提供空间)
    char *buffer = malloc(length * sizeof(char) + 8);
    fread(buffer, sizeof(char), length, input);
    fclose(input);
    // ====================加密===================
    // PKCS5Padding
    long padding_bytes = 8 - length % 8;
    for (int i = 0; i < padding_bytes; i++) {
        buffer[length + i] = (char)padding_bytes;
    }
    long total_length = length + padding_bytes;
    for (int i = 0; i < total_length / 8; i++) {
        uint64_t plain = bytes2uint64(buffer + i * 8);
        uint64_t cipher = des(plain, key, e);
        uint642bytes(cipher, buffer + i * 8);
    }
    fwrite(buffer, sizeof(char), total_length, en_out);
    fclose(en_out);
    // ====================解密===================
    for (int i = 0; i < total_length / 8; i++) {
        uint64_t cipher = bytes2uint64(buffer + i * 8);
        uint64_t plain = des(cipher, key, d);
        uint642bytes(plain, buffer + i * 8);
    }
    // 去掉PKCS5Padding
    long true_length = total_length - buffer[total_length - 1];
    fwrite(buffer, sizeof(char), true_length, de_out);
    fclose(de_out);
    free(buffer);
}

int main() {
//    test();
//    weak_keys();
//    en_hex();
    en_file();
    return 0;
}
