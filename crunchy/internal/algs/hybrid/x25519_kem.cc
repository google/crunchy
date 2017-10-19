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

#include "crunchy/internal/algs/hybrid/x25519_kem.h"

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/kdf/hkdf.h"
#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/internal/algs/openssl/openssl_unique_ptr.h"
#include "crunchy/internal/common/string_buffer.h"
#include "crunchy/util/status.h"
#include <openssl/curve25519.h>

namespace crunchy {
namespace {

typedef StatusOr<std::unique_ptr<Hkdf>>(HkdfFactory)(absl::string_view in_key,
                                                     absl::string_view salt);

class X25519KemFactory;

class X25519KemPublicKey : public KemPublicKey {
 public:
  X25519KemPublicKey(const X25519KemFactory& factory, const std::string& point)
      : factory_(factory), point_(point) {}

  Status NewKeyAndToken(size_t num_bytes, absl::string_view info, std::string* key,
                        std::string* token) const override;
  std::string Serialize() const override { return point_; }

 private:
  const X25519KemFactory& factory_;
  const std::string point_;
};

class X25519KemPrivateKey : public KemPrivateKey {
 public:
  X25519KemPrivateKey(const X25519KemFactory& factory, const std::string& key)
      : factory_(factory), key_(key) {}

  // Can be used to derive the same key bytes given by KemPublicKey::NewToken.
  StatusOr<std::string> DeriveKeyFromToken(absl::string_view token, size_t num_bytes,
                                      absl::string_view info) const override;
  std::string Serialize() const override { return key_; }

 private:
  const X25519KemFactory& factory_;
  const std::string key_;
};

class X25519KemFactory : public KemFactory {
 public:
  explicit X25519KemFactory(HkdfFactory* hkdf_factory)
      : hkdf_factory_(hkdf_factory) {}

  // Creates a public/private keypair
  Status NewKeypair(
      std::unique_ptr<KemPublicKey>* public_key,
      std::unique_ptr<KemPrivateKey>* private_key) const override {
    if (public_key == nullptr) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "public_key is null";
    }
    if (private_key == nullptr) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "private_key is null";
    }

    uint8_t out_public_value[X25519_PUBLIC_VALUE_LEN];
    uint8_t out_private_key[X25519_PRIVATE_KEY_LEN];
    X25519_keypair(out_public_value, out_private_key);

    *public_key = absl::make_unique<X25519KemPublicKey>(
        *this, std::string(reinterpret_cast<char*>(out_public_value),
                      X25519_PUBLIC_VALUE_LEN));

    *private_key = absl::make_unique<X25519KemPrivateKey>(
        *this, std::string(reinterpret_cast<char*>(out_private_key),
                      X25519_PRIVATE_KEY_LEN));

    return OkStatus();
  }

  // Deserialize functions.
  StatusOr<std::unique_ptr<KemPublicKey>> DeserializeKemPublicKey(
      absl::string_view serialized) const override {
    if (serialized.length() != KemPublicKeySerializedSize()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Length of serialized public key [" << serialized.length()
             << "] does not match expected size ["
             << KemPublicKeySerializedSize() << "] for curve25519";
    }

    return {absl::make_unique<X25519KemPublicKey>(*this, std::string(serialized))};
  }

  StatusOr<std::unique_ptr<KemPrivateKey>> DeserializeKemPrivateKey(
      absl::string_view serialized) const override {
    if (serialized.length() != KemPrivateKeySerializedSize()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Length of serialized private key [" << serialized.length()
             << "] does not match expected size ["
             << KemPrivateKeySerializedSize() << "] for curve25519";
    }

    return {absl::make_unique<X25519KemPrivateKey>(*this, std::string(serialized))};
  }

  // The size of serialized keys and tokens.
  size_t KemPublicTokenSerializedSize() const override {
    return X25519_PUBLIC_VALUE_LEN;
  };
  size_t KemPublicKeySerializedSize() const override {
    return X25519_PUBLIC_VALUE_LEN;
  };
  size_t KemPrivateKeySerializedSize() const override {
    return X25519_PRIVATE_KEY_LEN;
  };

  StatusOr<std::string> ComputeDhAndHkdf(absl::string_view private_key,
                                    absl::string_view public_key,
                                    absl::string_view public_token,
                                    absl::string_view info,
                                    size_t num_bytes) const {
    uint8_t out_shared_key[X25519_SHARED_KEY_LEN];
    if (X25519(out_shared_key,
               reinterpret_cast<const uint8_t*>(private_key.data()),
               reinterpret_cast<const uint8_t*>(public_key.data())) != 1) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Boringssl internal error computing DH result: "
             << GetOpensslErrors();
    }

    auto status_or_hkdf = CreateHkdf(
        StrCat(public_token,
               absl::string_view(reinterpret_cast<char*>(out_shared_key),
                                 X25519_SHARED_KEY_LEN)),
        "" /* salt */);
    if (!status_or_hkdf.ok()) {
      return status_or_hkdf.status();
    }

    std::unique_ptr<Hkdf> hkdf = std::move(status_or_hkdf.ValueOrDie());
    StringBuffer out_bytes(num_bytes);
    Status status = hkdf->HkdfExpand(info, num_bytes, out_bytes.data());
    if (!status.ok()) {
      return status;
    }
    return out_bytes.as_string();
  }

  StatusOr<std::unique_ptr<Hkdf>> CreateHkdf(absl::string_view in_key,
                                             absl::string_view salt) const {
    return hkdf_factory_(in_key, salt);
  }

 private:
  HkdfFactory* const hkdf_factory_;
};

Status X25519KemPublicKey::NewKeyAndToken(size_t num_bytes,
                                          absl::string_view info, std::string* key,
                                          std::string* token) const {
  if (key == nullptr) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo() << "key is null";
  }
  if (token == nullptr) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "token is null";
  }

  std::unique_ptr<KemPublicKey> public_key;
  std::unique_ptr<KemPrivateKey> private_key;
  auto status = factory_.NewKeypair(&public_key, &private_key);
  if (!status.ok()) {
    return status;
  }

  *token = public_key->Serialize();

  auto status_or_bytes = factory_.ComputeDhAndHkdf(
      private_key->Serialize(), point_, *token, info, num_bytes);
  if (!status_or_bytes.ok()) {
    return status_or_bytes.status();
  }

  *key = std::move(status_or_bytes.ValueOrDie());

  return OkStatus();
}

StatusOr<std::string> X25519KemPrivateKey::DeriveKeyFromToken(
    absl::string_view token, size_t num_bytes, absl::string_view info) const {
  if (token.length() != factory_.KemPublicTokenSerializedSize()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Length of serialized public token ["
           << factory_.KemPublicTokenSerializedSize()
           << "] does not match expected size [" << token.length()
           << "] for curve25519";
  }

  return factory_.ComputeDhAndHkdf(key_, token, token, info, num_bytes);
}

}  // namespace

const KemFactory& GetX25519KemFactory() {
  static const KemFactory& factory = *new X25519KemFactory(MakeHkdfSha256);
  return factory;
}

}  // namespace crunchy
