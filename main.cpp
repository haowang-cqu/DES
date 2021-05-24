// https://github.com/iamwhcn
// 2021/5/24
#include "des.h"
#include <iostream>
#include <fstream>

using namespace std;

union block {
    char c[8];
    uint64_t l;
};

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
            printf("E: %016llx\n", result);
        } else {
            result = des(result, result, mode_t::d);
            printf("D: %016llx\n", result);
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
    for (auto &k : weak) {
        printf("弱密钥: %016llx\n", k);
        auto sub_keys = key_generation(k);
        for (auto &sub_key : sub_keys) {
            printf("  %016llx\n", sub_key);
        }
    }
    for (auto &k : semi_weak) {
        printf("半弱密钥: %016llx\n", k);
        auto sub_keys = key_generation(k);
        for (auto &sub_key : sub_keys) {
            printf("  %016llx\n", sub_key);
        }
    }
}

/**
 * 加密16进制数
 */
void en_hex() {
    uint64_t in, key, mode;
    while (true) {
        cout << "选择加密(1)解密(2)退出(0): ";
        cin >> mode;
        if (mode == 0) break;
        cout << "  输入一个数(hex): ";
        cin >> hex >> in;
        cout << "  输入一个密钥(hex): ";
        cin >> hex >> key;
        if (mode == 1) {
            cout << "  加密结果: " << hex << des(in, key, mode_t::e) << endl;
        } else {
            cout << "  解密结果: " << hex << des(in, key, mode_t::d) << endl;
        }
    }
}

/**
 * 长度为8的字节数组转成uint64
 */
inline uint64_t bytes2uint64(const char* bytes) {
    block b = {0};
    for (int i = 0; i < 8; i++) {
        b.c[i] = bytes[i];
    }
    return b.l;
}

/**
 * uint64转成长度为8的字节数组
 */
inline void uint642bytes(uint64_t num, char* bytes) {
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
    ifstream in("D:\\message.txt", ifstream::binary);
    ofstream en("D:\\en_message.txt", ofstream::binary);
    ofstream de("D:\\de_message.txt", ofstream::binary);
    // 获取文件的总字节数
    in.seekg(0, fstream::end);
    long long length = in.tellg();
    in.seekg(0, fstream::beg);
    // 读取文件(缓冲区的长度加上8字节给padding提供空间)
    auto *buffer = new char[length + 8];
    in.read(buffer, length);
    in.close();
    // ====================加密===================
    // PKCS5Padding
    char padding_bytes = 8 - length % 8;
    for (int i = 0; i < padding_bytes; i++) {
        buffer[length + i] = padding_bytes;
    }
    auto total_length = length + padding_bytes;
    for (int i = 0; i < total_length / 8; i++) {
        uint64_t plain = bytes2uint64(buffer + i*8);
        uint64_t cipher = des(plain, key, mode_t::e);
        uint642bytes(cipher, buffer + i*8);
    }
    en.write(buffer, total_length);
    en.close();
    // ====================解密===================
    for (int i = 0; i < total_length / 8; i++) {
        uint64_t cipher = bytes2uint64(buffer + i*8);
        uint64_t plain = des(cipher, key, mode_t::d);
        uint642bytes(plain, buffer + i*8);
    }
    // 去掉PKCS5Padding
    auto true_length = total_length - buffer[total_length-1];
    de.write(buffer, true_length);
    de.close();
    delete[] buffer;
}

int main() {
    en_file();
    return 0;
}
