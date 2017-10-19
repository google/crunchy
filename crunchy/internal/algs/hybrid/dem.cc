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

#include "crunchy/internal/algs/hybrid/dem.h"

#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "crunchy/internal/algs/crypt/aes_gcm.h"
#include "crunchy/internal/algs/crypt/crypter_interface.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

const size_t kNonceLength = 12;
const size_t kTagLength = 16;

class DemImpl : public Dem {
 public:
  explicit DemImpl(std::unique_ptr<CrypterInterface> crypter)
      : crypter_(std::move(crypter)) {}

  StatusOr<std::string> Encrypt(absl::string_view plaintext) const override {
    std::string nonce = RandString(crypter_->nonce_length());
    auto status_or_ciphertext =
        crypter_->Encrypt(nonce, "" /* aad */, plaintext);
    if (!status_or_ciphertext.ok()) {
      return status_or_ciphertext.status();
    }
    std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
    return absl::StrCat(nonce, ciphertext);
  }
  StatusOr<std::string> Decrypt(absl::string_view ciphertext) const override {
    if (ciphertext.length() < crypter_->nonce_length()) {
      return FailedPreconditionErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "ciphertext is not large enough to hold a nonce, at least "
             << crypter_->nonce_length() << " expected " << ciphertext.length()
             << " given";
    }
    absl::string_view nonce = ciphertext.substr(0, crypter_->nonce_length());
    absl::string_view inner_ciphertext =
        absl::ClippedSubstr(ciphertext, crypter_->nonce_length());
    return crypter_->Decrypt(nonce, "" /* aad */, inner_ciphertext);
  }

 private:
  std::unique_ptr<CrypterInterface> crypter_;
};

class DemFactoryImpl : public DemFactory {
 public:
  explicit DemFactoryImpl(const CrypterFactory& crypter_factory)
      : crypter_factory_(crypter_factory) {}

  size_t GetKeyLength() const override {
    return crypter_factory_.GetKeyLength();
  }
  size_t GetMaxCiphertextLength(size_t plaintext_length) const override {
    return plaintext_length + crypter_factory_.GetNonceLength() +
           crypter_factory_.GetTagLength();
  }
  size_t GetMaxPlaintextLength(size_t ciphertext_length) const override {
    if (ciphertext_length <
        crypter_factory_.GetNonceLength() + crypter_factory_.GetTagLength()) {
      return 0;
    }
    return ciphertext_length - crypter_factory_.GetNonceLength() -
           crypter_factory_.GetTagLength();
  }
  StatusOr<std::unique_ptr<Dem>> MakeDem(absl::string_view key) const override {
    auto status_or_crypter = crypter_factory_.Make(key);
    if (!status_or_crypter.ok()) {
      return status_or_crypter.status();
    }
    return {
        absl::make_unique<DemImpl>(std::move(status_or_crypter.ValueOrDie()))};
  }

 private:
  const CrypterFactory& crypter_factory_;
};

}  // namespace

const DemFactory& GetAes128GcmDemFactory() {
  static const DemFactory& factory = *new DemFactoryImpl(GetAes128GcmFactory());
  return factory;
}

const DemFactory& GetAes256GcmDemFactory() {
  static const DemFactory& factory = *new DemFactoryImpl(GetAes256GcmFactory());
  return factory;
}

}  // namespace crunchy
