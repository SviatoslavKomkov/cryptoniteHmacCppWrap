//
// Created by paradaimu on 7/29/20.
//

#include <memory>

#include "hmac.h"
#include "mexceptions.h"

#include "cryptonite/c/byte_array.h"
#include "cryptonite/c/cryptonite_errors.h"
#include "cryptonite/c/hmac.h"
#include "cryptonite/c/macros_internal.h"
#include "cryptonite/c/stacktrace.h"

#undef FILE_MARKER
#define FILE_MARKER "hmac.cpp"

namespace cryptonite {

HmacCtx* allocateHmacContext(HashType ht) {
  HmacCtx *hctx = nullptr;

  switch (ht) {
  case HashType::MD5:
    hctx = hmac_alloc_md5();
    break;
  case HashType::SHA1:
    hctx = hmac_alloc_sha1();
    break;
  case HashType::SHA2_224:
    hctx = hmac_alloc_sha2(SHA2_VARIANT_224);
    break;
  case HashType::SHA2_256:
    hctx = hmac_alloc_sha2(SHA2_VARIANT_256);
    break;
  case HashType::SHA2_384:
    hctx = hmac_alloc_sha2(SHA2_VARIANT_384);
    break;
  case HashType::SHA2_512:
    hctx = hmac_alloc_sha2(SHA2_VARIANT_512);
    break;
  case HashType::GOST_34311:
    throw std::runtime_error{"GOST_34311 is  not supported"};
  default:
    std::stringstream error;
    error << "No such hash type: " << static_cast<int>(ht);
    throw std::invalid_argument{error.str()};
  }

  if( hctx == nullptr )
  {
    throw std::bad_alloc{};
  }

  return hctx;
}

Hmac::Hmac(HashType ht, const std::vector<uint8_t>& key) {
  HmacCtx *hctx = allocateHmacContext(ht);

  std::shared_ptr<ByteArray> keyBa{ 
    ba_alloc_from_uint8(key.data(), key.size()), 
    [](auto* data){ 
      ba_free(data); 
    } 
  };

  if (hmac_init(hctx, keyBa.get()) != RET_OK )
  {
    throw std::runtime_error{"failed to inialize hmac"};
  }

  this->ctx = hctx;
}

Hmac::~Hmac() {
  hmac_free((HmacCtx *)this->ctx);
  stacktrace_free_current();
  this->ctx = nullptr;
}

int Hmac::update(const std::vector<uint8_t>& data) {
  std::shared_ptr<ByteArray> dataBa{ 
    ba_alloc_from_uint8(data.data(), data.size()), 
    [](auto* data) { 
      ba_free(data);
    } 
  };

  return hmac_update((HmacCtx *)this->ctx, dataBa.get());
}

std::vector<uint8_t> Hmac::finale() {
  ByteArray* hashBa = nullptr;
  std::shared_ptr<ByteArray> wrapper{ 
    hashBa, 
    [](auto* data) { 
      ba_free(data);
    } 
  };

  if (hmac_final((HmacCtx *)this->ctx, &hashBa) != RET_OK)
  {
    throw std::runtime_error{"failed to finalize hmac"};
  }

  const uint8_t* buffer = ba_get_buf(hashBa);
  const std::size_t length = ba_get_len(hashBa);

  return std::vector<uint8_t>{buffer, buffer + length};
}
} // namespace cryptonite