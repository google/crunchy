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
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/internal/common/string_buffer.h"
#include "crunchy/util/status.h"
#include <openssl/base.h>
#include <openssl/digest.h>
#include <openssl/hmac.h>

namespace crunchy {

namespace {

const EVP_MD* kEvpMd = EVP_sha256();
const size_t kDigestLength = 32;

bool SecureEquals(const char* left, const char* right, size_t length) {
  char result = 0x00;
  for (size_t i = 0; i < length; i++) {
    result |= left[i] ^ right[i];
  }
  return result == 0x00;
}

class HmacSha256Factory : public MacFactory {
 public:
  HmacSha256Factory(size_t key_length, size_t signature_length)
      : key_length_(key_length), signature_length_(signature_length) {}

  size_t GetKeyLength() const override { return key_length_; }
  size_t GetSignatureLength() const override { return signature_length_; }

  StatusOr<std::unique_ptr<MacInterface>> Make(
      absl::string_view key) const override;

 private:
  const size_t key_length_;
  const size_t signature_length_;
};

// An interface for computing a cryptographic MAC.
class HmacSha256 : public MacInterface {
 public:
  HmacSha256(const HmacSha256Factory& factory, absl::string_view key)
      : factory_(factory), key_(key) {}

  // Signs the given std::string and returns the signature.
  StatusOr<std::string> Sign(absl::string_view input) const override;
  Status Verify(absl::string_view input,
                absl::string_view signature) const override;
  size_t GetSignatureLength() const override {
    return factory_.GetSignatureLength();
  }

 private:
  const HmacSha256Factory& factory_;
  std::string key_;

  StatusOr<std::string> Mac(absl::string_view input) const;
};

StatusOr<std::unique_ptr<MacInterface>> HmacSha256Factory::Make(
    absl::string_view key) const {
  if (key.size() != GetKeyLength()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Key length was " << key.size() << " but length "
           << GetKeyLength() << " is required";
  }
  return {absl::make_unique<HmacSha256>(*this, key)};
}

StatusOr<std::string> HmacSha256::Mac(absl::string_view input) const {
  StringBuffer result(kDigestLength);
  unsigned int in_out_bytes = kDigestLength;

  // Call openssl's HMAC function
  if (HMAC(kEvpMd, key_.data(), key_.length(),
           reinterpret_cast<const uint8_t*>(input.data()), input.size(),
           result.data(), &in_out_bytes) == nullptr) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "HMAC failed: " << GetOpensslErrors();
  }
  result.as_string().resize(in_out_bytes);
  return result.as_string();
}

StatusOr<std::string> HmacSha256::Sign(absl::string_view input) const {
  auto status_or_mac = Mac(input);
  if (!status_or_mac.ok()) {
    return status_or_mac.status();
  }
  std::string mac = std::move(status_or_mac.ValueOrDie());
  mac.resize(GetSignatureLength());
  return std::move(mac);
}

Status HmacSha256::Verify(absl::string_view input,
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

  if (!SecureEquals(mac.data(), signature.data(), GetSignatureLength())) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).VLog(2)
           << "Mac did not verify";
  }
  return OkStatus();
}

}  // namespace

const MacFactory& GetHmacSha256Factory() {
  static const MacFactory& factory =
      *new HmacSha256Factory(kDigestLength, kDigestLength / 2);
  return factory;
}

std::unique_ptr<MacFactory> MakeHmacSha256FactoryForTest(
    size_t key_length, size_t signature_length) {
  return absl::make_unique<HmacSha256Factory>(key_length, signature_length);
}

}  // namespace crunchy
