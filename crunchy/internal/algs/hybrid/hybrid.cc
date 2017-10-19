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

#include "crunchy/internal/algs/hybrid/hybrid.h"

#include <stddef.h>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "crunchy/internal/algs/hybrid/dem.h"
#include "crunchy/internal/algs/hybrid/kem.h"
#include "crunchy/internal/algs/hybrid/openssl_kem.h"
#include "crunchy/internal/algs/hybrid/x25519_kem.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

const char kInfo[] = "GOOGLE_KEYMASTER";

class HybridCrypterFactoryImpl : public HybridCrypterFactory {
 public:
  HybridCrypterFactoryImpl(const DemFactory& dem_factory,
                           const KemFactory& kem_factory,
                           absl::string_view info)
      : dem_factory_(dem_factory), kem_factory_(kem_factory), info_(info) {}
  Status NewKeypair(std::string* public_key, std::string* private_key) const override;

  StatusOr<std::unique_ptr<HybridEncrypterInterface>> MakeHybridEncrypter(
      absl::string_view public_key) const override;
  StatusOr<std::unique_ptr<HybridDecrypterInterface>> MakeHybridDecrypter(
      absl::string_view private_key) const override;
  size_t GetMaxCiphertextLength(size_t plaintext_length) const override {
    return dem_factory_.GetMaxCiphertextLength(plaintext_length) +
           kem_factory_.KemPublicTokenSerializedSize();
  }
  size_t GetMaxPlaintextLength(size_t ciphertext_length) const override {
    size_t dem_length = dem_factory_.GetMaxPlaintextLength(ciphertext_length);
    if (dem_length < kem_factory_.KemPublicTokenSerializedSize()) {
      return 0;
    }
    return dem_length - kem_factory_.KemPublicTokenSerializedSize();
  }

  const DemFactory& dem_factory() const { return dem_factory_; }
  const KemFactory& kem_factory() const { return kem_factory_; }
  const std::string& info() const { return info_; }

 private:
  const DemFactory& dem_factory_;
  const KemFactory& kem_factory_;
  const std::string info_;
};

// An encryption interface generated from the recipient's public key.
class HybridEncrypterImpl : public HybridEncrypterInterface {
 public:
  HybridEncrypterImpl(std::unique_ptr<Dem> dem, absl::string_view token)
      : dem_(std::move(dem)), token_(token) {}
  StatusOr<std::string> Encrypt(absl::string_view plaintext) const override;

 private:
  std::unique_ptr<Dem> dem_;
  std::string token_;
};

// A decryption interface generated from the recipient's private key.
class HybridDecrypterImpl : public HybridDecrypterInterface {
 public:
  HybridDecrypterImpl(const HybridCrypterFactoryImpl& factory,
                      std::unique_ptr<KemPrivateKey> kem_private_key)
      : factory_(factory), kem_private_key_(std::move(kem_private_key)) {}
  StatusOr<std::string> Decrypt(absl::string_view ciphertext) const override;

 private:
  const HybridCrypterFactoryImpl& factory_;
  std::unique_ptr<KemPrivateKey> kem_private_key_;
};

Status HybridCrypterFactoryImpl::NewKeypair(std::string* public_key,
                                            std::string* private_key) const {
  if (public_key == nullptr) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "public_key is null";
  }
  if (private_key == nullptr) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "private_key is null";
  }
  std::unique_ptr<KemPublicKey> kem_public_key;
  std::unique_ptr<KemPrivateKey> kem_private_key;
  Status status = kem_factory_.NewKeypair(&kem_public_key, &kem_private_key);
  if (!status.ok()) {
    return status;
  }
  *public_key = kem_public_key->Serialize();
  *private_key = kem_private_key->Serialize();
  return OkStatus();
}

StatusOr<std::unique_ptr<HybridEncrypterInterface>>
HybridCrypterFactoryImpl::MakeHybridEncrypter(
    absl::string_view public_key) const {
  auto status_or_kem_public_key =
      kem_factory_.DeserializeKemPublicKey(public_key);
  if (!status_or_kem_public_key.ok()) {
    return status_or_kem_public_key.status();
  }
  std::unique_ptr<KemPublicKey> kem_public_key =
      std::move(status_or_kem_public_key.ValueOrDie());

  std::string dem_key;
  std::string token;
  Status status = kem_public_key->NewKeyAndToken(dem_factory_.GetKeyLength(),
                                                 info_, &dem_key, &token);
  if (!status.ok()) {
    return status;
  }
  auto status_or_dem = dem_factory_.MakeDem(dem_key);
  if (!status_or_dem.ok()) {
    return status_or_dem.status();
  }
  std::unique_ptr<Dem> dem = std::move(status_or_dem.ValueOrDie());

  return {absl::make_unique<HybridEncrypterImpl>(std::move(dem), token)};
}
StatusOr<std::unique_ptr<HybridDecrypterInterface>>
HybridCrypterFactoryImpl::MakeHybridDecrypter(
    absl::string_view private_key) const {
  auto status_or_kem_private_key =
      kem_factory_.DeserializeKemPrivateKey(private_key);
  if (!status_or_kem_private_key.ok()) {
    return status_or_kem_private_key.status();
  }
  std::unique_ptr<KemPrivateKey> kem_private_key =
      std::move(status_or_kem_private_key.ValueOrDie());

  return {absl::make_unique<HybridDecrypterImpl>(*this,
                                                 std::move(kem_private_key))};
}

StatusOr<std::string> HybridEncrypterImpl::Encrypt(
    absl::string_view plaintext) const {
  auto status_or_ciphertext = dem_->Encrypt(plaintext);
  if (!status_or_ciphertext.ok()) {
    return status_or_ciphertext.status();
  }
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  return absl::StrCat(token_, ciphertext);
}
StatusOr<std::string> HybridDecrypterImpl::Decrypt(
    absl::string_view ciphertext) const {
  size_t token_size = factory_.kem_factory().KemPublicTokenSerializedSize();
  if (ciphertext.length() < token_size) {
    return FailedPreconditionErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "ciphertext is not large enough to hold a token, at least "
           << token_size << " expected " << ciphertext.length() << " given";
  }
  absl::string_view token = ciphertext.substr(0, token_size);

  auto status_or_key = kem_private_key_->DeriveKeyFromToken(
      token, factory_.dem_factory().GetKeyLength(), factory_.info());
  if (!status_or_key.ok()) {
    return status_or_key.status();
  }
  std::string key = std::move(status_or_key.ValueOrDie());
  auto status_or_dem = factory_.dem_factory().MakeDem(key);
  if (!status_or_dem.ok()) {
    return status_or_dem.status();
  }
  std::unique_ptr<Dem> dem = std::move(status_or_dem.ValueOrDie());
  auto status_or_plaintext =
      dem->Decrypt(absl::ClippedSubstr(ciphertext, token_size));
  if (!status_or_plaintext.ok()) {
    return status_or_plaintext.status();
  }
  std::string plaintext = std::move(status_or_plaintext.ValueOrDie());

  return std::move(plaintext);
}

// Returns a HybridCrypterFactory based on a DemFactory and a KemFactory.
// info is a domain-specific parameter to obtain key separation,
std::unique_ptr<HybridCrypterFactory> NewHybridCrypterFactory(
    const DemFactory& dem_factory, const KemFactory& kem_factory,
    absl::string_view info) {
  return absl::make_unique<HybridCrypterFactoryImpl>(dem_factory, kem_factory,
                                                     info);
}

}  // namespace

const HybridCrypterFactory& GetP256Aes128GcmFactory() {
  static const HybridCrypterFactory& factory =
      *NewHybridCrypterFactory(GetAes128GcmDemFactory(), GetP256KemFactory(),
                               kInfo)
           .release();
  return factory;
}
const HybridCrypterFactory& GetP256Aes256GcmFactory() {
  static const HybridCrypterFactory& factory =
      *NewHybridCrypterFactory(GetAes256GcmDemFactory(), GetP256KemFactory(),
                               kInfo)
           .release();
  return factory;
}
const HybridCrypterFactory& GetP521Aes256GcmFactory() {
  static const HybridCrypterFactory& factory =
      *NewHybridCrypterFactory(GetAes256GcmDemFactory(), GetP521KemFactory(),
                               kInfo)
           .release();
  return factory;
}
const HybridCrypterFactory& GetX25519Aes256GcmFactory() {
  static const HybridCrypterFactory& factory =
      *NewHybridCrypterFactory(GetAes256GcmDemFactory(), GetX25519KemFactory(),
                               kInfo)
           .release();
  return factory;
}

}  // namespace crunchy
