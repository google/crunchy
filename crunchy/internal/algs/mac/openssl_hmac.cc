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

#include "crunchy/internal/algs/mac/openssl_hmac.h"

#include <stdint.h>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/internal/common/string_buffer.h"
#include "crunchy/util/status.h"
#include <openssl/base.h>
#include <openssl/digest.h>
#include <openssl/hmac.h>

namespace crunchy {

namespace {

bool SecureEquals(const char* left, size_t left_length, const char* right,
                  size_t right_length) {
  if (left_length != right_length) {
    return false;
  }
  char result = 0x00;
  for (size_t i = 0; i < left_length; i++) {
    result |= left[i] ^ right[i];
  }
  return result == 0x00;
}

class HmacFactory : public MacFactory {
 public:
  HmacFactory(const EVP_MD* evp_md, size_t key_length, size_t signature_length)
      : evp_md_(evp_md),
        key_length_(key_length),
        signature_length_(signature_length) {}

  size_t GetKeyLength() const override { return key_length_; }
  size_t GetSignatureLength() const override { return signature_length_; }

  StatusOr<std::unique_ptr<MacInterface>> Make(
      absl::string_view key) const override;

  const EVP_MD* evp_md() const { return evp_md_; }

 private:
  const EVP_MD* evp_md_;
  const size_t key_length_;
  const size_t signature_length_;
};

// An interface for computing a cryptographic MAC.
class Hmac : public MacInterface {
 public:
  Hmac(const HmacFactory& factory, absl::string_view key)
      : factory_(factory), key_(key) {}

  // Signs the given std::string and returns the signature.
  StatusOr<std::string> Sign(absl::string_view input) const override;
  Status Verify(absl::string_view input,
                absl::string_view signature) const override;
  size_t GetSignatureLength() const override {
    return factory_.GetSignatureLength();
  }

 private:
  const HmacFactory& factory_;
  std::string key_;

  StatusOr<std::string> Mac(absl::string_view input) const;
};

StatusOr<std::unique_ptr<MacInterface>> HmacFactory::Make(
    absl::string_view key) const {
  if (key.size() != GetKeyLength()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Key length was " << key.size() << " but length "
           << GetKeyLength() << " is required";
  }
  return {absl::make_unique<Hmac>(*this, key)};
}

StatusOr<std::string> Hmac::Mac(absl::string_view input) const {
  StringBuffer result(EVP_MD_size(factory_.evp_md()));
  unsigned int in_out_bytes = EVP_MD_size(factory_.evp_md());

  // Call openssl's HMAC function
  if (HMAC(factory_.evp_md(), key_.data(), key_.length(),
           reinterpret_cast<const uint8_t*>(input.data()), input.size(),
           result.data(), &in_out_bytes) == nullptr) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "HMAC failed: " << GetOpensslErrors();
  }
  result.as_string().resize(in_out_bytes);
  return result.as_string();
}

StatusOr<std::string> Hmac::Sign(absl::string_view input) const {
  auto status_or_mac = Mac(input);
  if (!status_or_mac.ok()) {
    return status_or_mac.status();
  }
  std::string mac = std::move(status_or_mac.ValueOrDie());
  mac.resize(GetSignatureLength());
  return std::move(mac);
}

Status Hmac::Verify(absl::string_view input,
                    absl::string_view signature) const {
  if (signature.size() != GetSignatureLength()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Signature length was " << signature.size() << " expected "
           << GetSignatureLength();
  }
  auto status_or_mac = Mac(input);
  if (!status_or_mac.ok()) {
    return status_or_mac.status();
  }
  std::string mac = std::move(status_or_mac.ValueOrDie());

  if (!SecureEquals(mac.data(), GetSignatureLength(), signature.data(),
                    signature.length())) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).VLog(2)
           << "Mac did not verify";
  }
  return OkStatus();
}

StatusOr<std::unique_ptr<MacFactory>> MakeFactory(const EVP_MD* evp_md,
                                                  size_t key_length,
                                                  size_t signature_length) {
  size_t digest_length = EVP_MD_size(evp_md);
  if (signature_length > digest_length) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Signature length was " << signature_length
           << " bytes but the digest is only " << digest_length << " bytes";
  }
  return {absl::make_unique<HmacFactory>(evp_md, key_length, signature_length)};
}

}  // namespace

const MacFactory& GetHmacSha256HalfDigestFactory() {
  static const size_t digest_length = EVP_MD_size(EVP_sha256());
  static const MacFactory& factory =
      *MakeHmacSha256Factory(digest_length, digest_length / 2)
           .ValueOrDie()
           .release();
  return factory;
}

StatusOr<std::unique_ptr<MacFactory>> MakeHmacSha256Factory(
    size_t key_length, size_t signature_length) {
  return MakeFactory(EVP_sha256(), key_length, signature_length);
}

StatusOr<std::unique_ptr<MacFactory>> MakeHmacSha384Factory(
    size_t key_length, size_t signature_length) {
  return MakeFactory(EVP_sha384(), key_length, signature_length);
}

StatusOr<std::unique_ptr<MacFactory>> MakeHmacSha512Factory(
    size_t key_length, size_t signature_length) {
  return MakeFactory(EVP_sha512(), key_length, signature_length);
}

StatusOr<std::unique_ptr<MacFactory>> MakeHmacSha1Factory(
    size_t key_length, size_t signature_length) {
  return MakeFactory(EVP_sha1(), key_length, signature_length);
}

}  // namespace crunchy
