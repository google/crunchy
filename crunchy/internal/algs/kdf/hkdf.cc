// Copyright 2017 The CrunchyCrypt Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "crunchy/internal/algs/kdf/hkdf.h"

#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/internal/port/port.h"
#include <openssl/digest.h>
#include <openssl/hkdf.h>

namespace crunchy {

namespace {

// This interface defines HKDF derivation utilities following RFC 5869
// implemented using OpenSSL. All public methods are thread-safe.
class HkdfImpl : public Hkdf {
 public:
  // HkdfExpand implements HKDF-Expand from RFC 5869.
  // Derive a pseudo-random number [out_key] of byte length [out_byte_len].
  // [info] stores context information which can be zero-length.
  Status HkdfExpand(absl::string_view info, const size_t out_byte_len,
                    uint8_t* out_key) const override {
    if (out_key == nullptr) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "out_key is nullptr";
    }

    int status = HKDF_expand(
        out_key, out_byte_len, InitHmac(),
        reinterpret_cast<const uint8_t*>(&*prk_.begin()), prk_.length(),
        reinterpret_cast<const uint8_t*>(info.data()), info.length());
    if (status == 1) {
      return OkStatus();
    }
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "HKDF_expand failed: " << GetOpensslErrors();
  }

 protected:
  // HkdfExtract implements HKDF-Extract from RFC 5869.
  // Extract a pseudo-random key [prk_].
  // [in_key] is a non-zero secret input/initial key material.
  // [salt] is an optional non-secret random value.
  Status HkdfExtract(absl::string_view in_key, absl::string_view salt) {
    size_t prk_byte_len = prk_.length();
    int status = HKDF_extract(
        reinterpret_cast<uint8_t*>(&*prk_.begin()), &prk_byte_len, InitHmac(),
        reinterpret_cast<const uint8_t*>(in_key.data()), in_key.length(),
        reinterpret_cast<const uint8_t*>(salt.data()), salt.length());
    if (status == 1) {
      return OkStatus();
    }
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "HKDF_extract failed: " << GetOpensslErrors();
  }

  // Initialize HMAC algorithm.
  virtual const EVP_MD* InitHmac() const = 0;

  std::string prk_;
};

class HkdfSha512 : public HkdfImpl {
 public:
  static StatusOr<std::unique_ptr<Hkdf>> Make(absl::string_view in_key,
                                              absl::string_view salt) {
    const size_t prk_byte_len = 64;
    auto hkdf = absl::make_unique<HkdfSha512>();
    hkdf->prk_.resize(prk_byte_len);
    auto status = hkdf->HkdfExtract(in_key, salt);
    if (!status.ok()) {
      return status;
    }
    CRUNCHY_CHECK_EQ(hkdf->prk_.length(), prk_byte_len);
    return {std::move(hkdf)};
  }

 protected:
  const EVP_MD* InitHmac() const override { return EVP_sha512(); }
};

class HkdfSha256 : public HkdfImpl {
 public:
  static StatusOr<std::unique_ptr<Hkdf>> Make(absl::string_view in_key,
                                              absl::string_view salt) {
    const size_t prk_byte_len = 32;
    auto hkdf = absl::make_unique<HkdfSha256>();
    hkdf->prk_.resize(prk_byte_len);
    auto status = hkdf->HkdfExtract(in_key, salt);
    if (!status.ok()) {
      return status;
    }
    CRUNCHY_CHECK_EQ(hkdf->prk_.length(), prk_byte_len);
    return {std::move(hkdf)};
  }

 protected:
  const EVP_MD* InitHmac() const override { return EVP_sha256(); }
};

}  // namespace

StatusOr<std::unique_ptr<Hkdf>> MakeHkdfSha256(absl::string_view in_key,
                                               absl::string_view salt) {
  return HkdfSha256::Make(in_key, salt);
}

StatusOr<std::unique_ptr<Hkdf>> MakeHkdfSha512(absl::string_view in_key,
                                               absl::string_view salt) {
  return HkdfSha512::Make(in_key, salt);
}

}  // namespace crunchy
