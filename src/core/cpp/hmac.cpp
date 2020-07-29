//
// Created by paradaimu on 7/29/20.
//

#include <memory>

#include "hmac.h"
#include "mexceptions.h"

#include "cryptonite/c/hmac.h"
#include "cryptonite/c/byte_array.h"
#include "cryptonite/c/cryptonite_errors.h"
#include "cryptonite/c/stacktrace.h"
#include "cryptonite/c/stacktrace.h"
#include "cryptonite/c/macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "hmac.cpp"

using namespace std;

namespace cryptonite {

#define CHECK_CRYPTONITE_ERROR() { \
    if (ret != RET_OK) { \
        THROW_EXCEPTION(errorToString()); \
    } \
}

    static string errorToString() {
        const ErrorCtx *ctx = stacktrace_get_last();
        stringstream ss;
        const ErrorCtx *step = NULL;
        if (ctx) {
            step = ctx;
            do {
                ss << step->file << ":" << (unsigned int)step->line <<", error: " << step->error_code;
                step = step->next;
            } while (step != NULL);
        }
        stacktrace_free_current();

        return ss.str();
    }

    HMAC::HMAC() {}

    HMAC::HMAC(HashType ht) {
        HmacCtx *hctx = NULL;
        int ret(RET_OK);
        switch (ht) {
            case HASH_TYPE_MD5: CHECK_NOT_NULL(hctx = hmac_alloc_md5());
                break;
            case HASH_TYPE_SHA1: CHECK_NOT_NULL(hctx = hmac_alloc_sha1());
                break;
            case HASH_TYPE_SHA2_224: CHECK_NOT_NULL(hctx = hmac_alloc_sha2(SHA2_VARIANT_224));
                break;
            case HASH_TYPE_SHA2_256: CHECK_NOT_NULL(hctx = hmac_alloc_sha2(SHA2_VARIANT_256));
                break;
            case HASH_TYPE_SHA2_384: CHECK_NOT_NULL(hctx = hmac_alloc_sha2(SHA2_VARIANT_384));
                break;
            case HASH_TYPE_SHA2_512: CHECK_NOT_NULL(hctx = hmac_alloc_sha2(SHA2_VARIANT_512));
                break;
            case HASH_TYPE_GOST_34311:
                // sloth
            THROW_EXCEPTION("GOST_34311 not supported")
            default: THROW_EXCEPTION("No such hash type: " << ht);
        }

        cleanup:
        CHECK_CRYPTONITE_ERROR()
        this->ctx = hctx;
    }

    shared_ptr<HMAC> HMAC::init(HashType ht, const std::vector<uint8_t> &key) {
        ByteArray *keyBa = NULL;
        HMAC *ctx = nullptr;;
        int ret(RET_OK);
        HmacCtx* hctx = NULL;

        CHECK_NOT_NULL(ctx = new HMAC(ht));
        CHECK_NOT_NULL(keyBa = ba_alloc_from_uint8(key.data(), key.size()));
        hctx = (HmacCtx*)ctx->ctx;
        DO(hmac_init(hctx, keyBa));

        cleanup:
        ba_free(keyBa);
        if (ret != RET_OK) {
            delete ctx;
            THROW_EXCEPTION(errorToString());
        }

        return std::shared_ptr<HMAC>(ctx);;
    }

    void HMAC::update(const std::vector<uint8_t> &data) {
        ByteArray * dataBa = NULL;
        int ret(RET_OK);
        HmacCtx *ctx = (HmacCtx *) this->ctx;

        CHECK_NOT_NULL(dataBa = ba_alloc_from_uint8(data.data(), data.size()));
        DO(hmac_update(ctx, dataBa));
        cleanup:
        ba_free(dataBa);
        CHECK_CRYPTONITE_ERROR()
    }

    std::vector<uint8_t> HMAC::finale() {
        ByteArray * hashBa = NULL;
        const uint8_t *buf = NULL;
        size_t bufLen = 0;
        std::vector<uint8_t> hash;
        int ret(RET_OK);

        DO(hmac_final((HmacCtx *) this->ctx, &hashBa));

        buf = ba_get_buf(hashBa);
        bufLen = ba_get_len(hashBa);

        hash = std::vector<uint8_t>(buf, buf + bufLen);

        cleanup:
        ba_free(hashBa);
        CHECK_CRYPTONITE_ERROR()

        return hash;
    }

    HMAC::~HMAC() {
        if (this->ctx != NULL) {
            hmac_free((HmacCtx*)this->ctx);
        }
        stacktrace_free_current();
        this->ctx = NULL;
    }

    std::vector<uint8_t> hmacCore(HashType ht, const std::vector<uint8_t> &key, const std::vector<uint8_t> &data) {
        vector<uint8_t> hash;
        shared_ptr<HMAC> ctx = HMAC::init(ht, key);

        DOC(ctx->update(data));
        DOC(hash = ctx->finale());

        return hash;
    }
}