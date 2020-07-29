//
// Created by paradaimu on 7/29/20.
//

#include <string>
#include <iostream>

#include "hmac.h"
#include "mexceptions.h"

using namespace std;

static std::vector<uint8_t> hexToBytes(const std::string hex) {
    std::vector<uint8_t> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

static void test_md5() {
    string s("Hi There");
    vector<uint8_t> data(s.begin(), s.end());
    vector<uint8_t> key = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    vector<uint8_t> exp = hexToBytes("9294727a3638bb1c13f48ef8158bfc9d");
    vector<uint8_t> act;

    shared_ptr<cryptonite::HMAC> hmac = cryptonite::HMAC::init(cryptonite::HASH_TYPE_MD5, key);
    hmac->update(data);
    act = hmac->finale();

    if (act != exp) {
        THROW_EXCEPTION("MD5 1. Not equal.")
    }
}

static void test_hmac_md5_2() {
    string ds("Test Using Larger Than Block-Size Key - Hash Key First");
    vector<uint8_t> key = hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    vector<uint8_t> data(ds.begin(), ds.end());
    vector<uint8_t> exp = hexToBytes("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");
    vector<uint8_t> act;

    act = cryptonite::hmacCore(cryptonite::HASH_TYPE_MD5, key, data);
    if (act != exp) {
        THROW_EXCEPTION("MD5 2. Not equal.")
    }
}

static void test_hmac_sha256() {
    string s("Hi There");
    vector<uint8_t> data(s.begin(), s.end());
    vector<uint8_t> key = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    vector<uint8_t> exp = hexToBytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    vector<uint8_t> act;

    act = cryptonite::hmacCore(cryptonite::HASH_TYPE_SHA2_256, key, data);
    if (act != exp) {
        THROW_EXCEPTION("Sha256_256. Not equal.")
    }
}

int main() {
    for(int i = 0; i < 100; i++) {
        try {
            test_md5();
            test_hmac_md5_2();
            test_hmac_sha256();
        } catch (const exception &e) {
            cout << "Exception: " << e.what() << endl;
        }
    }

    cout << "OK" << endl;
}