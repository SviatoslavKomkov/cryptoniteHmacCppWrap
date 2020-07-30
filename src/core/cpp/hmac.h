//
// Created by paradaimu on 7/29/20.
//

#ifndef HMACWRAPER_HMAC_H
#define HMACWRAPER_HMAC_H

#include <inttypes.h>
#include <memory>
#include <vector>

namespace cryptonite {
enum class HashType {
  MD5 = 0,
  SHA1 = 1,
  SHA2_224 = 2,
  SHA2_256 = 3,
  SHA2_384 = 4,
  SHA2_512 = 5,
  GOST_34311 = 6,
};


class Hmac {
public:
  Hmac() = default;
  explicit Hmac(HashType ht, const std::vector<uint8_t>& key);
  explicit Hmac(HashType ht, const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);

  ~Hmac();

  int update(const std::vector<uint8_t>& data);
  std::vector<uint8_t> finale();

private:
  void *ctx = nullptr;
};
} // namespace cryptonite

#endif // HMACWRAPER_HMAC_H
