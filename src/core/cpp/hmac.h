//
// Created by paradaimu on 7/29/20.
//

#ifndef HMACWRAPER_HMAC_H
#define HMACWRAPER_HMAC_H

#include <inttypes.h>
#include <vector>
#include <memory>

namespace cryptonite {
    typedef enum {
        HASH_TYPE_MD5 = 0,
        HASH_TYPE_SHA1 = 1,
        HASH_TYPE_SHA2_224 = 2,
        HASH_TYPE_SHA2_256 = 3,
        HASH_TYPE_SHA2_384 = 4,
        HASH_TYPE_SHA2_512 = 5,
        HASH_TYPE_GOST_34311 = 6,
    } HashType;

    class HMAC {
    public:
        ~HMAC();

        static std::shared_ptr<HMAC> init(HashType ht, const std::vector<uint8_t> &key);
        void update(const std::vector<uint8_t> &data);
        std::vector<uint8_t> finale();

    private:
        HMAC();
        HMAC(HashType ht);
        void *ctx = NULL;
    };

    std::vector<uint8_t> hmacCore(HashType ht, const std::vector<uint8_t> &key, const std::vector<uint8_t> &data);
}


#endif //HMACWRAPER_HMAC_H
