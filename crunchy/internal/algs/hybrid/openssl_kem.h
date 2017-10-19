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

#ifndef CRUNCHY_ALGS_HYBRID_OPENSSL_KEM_H_
#define CRUNCHY_ALGS_HYBRID_OPENSSL_KEM_H_

#include <stddef.h>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/hybrid/kem.h"
#include "crunchy/internal/algs/kdf/hkdf.h"
#include "crunchy/internal/algs/openssl/openssl_unique_ptr.h"
#include "crunchy/util/status.h"
#include <openssl/base.h>
#include <openssl/ec.h>

namespace crunchy {

typedef StatusOr<std::unique_ptr<Hkdf>>(HkdfFactory)(absl::string_view in_key,
                                                     absl::string_view salt);

class OpensslKemFactory : public KemFactory {
 public:
  OpensslKemFactory(int curve_nid, HkdfFactory* hkdf_factory);

  // Creates a public/private keypair
  Status NewKeypair(std::unique_ptr<KemPublicKey>* public_key,
                    std::unique_ptr<KemPrivateKey>* private_key) const override;

  // Deserialize functions.
  StatusOr<std::unique_ptr<KemPublicKey>> DeserializeKemPublicKey(
      absl::string_view serialized) const override;
  StatusOr<std::unique_ptr<KemPrivateKey>> DeserializeKemPrivateKey(
      absl::string_view serialized) const override;

  // The size of serialized keys and tokens.
  size_t KemPublicTokenSerializedSize() const override;
  size_t KemPublicKeySerializedSize() const override;
  size_t KemPrivateKeySerializedSize() const override;

  StatusOr<std::string> ComputeDhAndHkdf(const EC_KEY* private_key,
                                    const EC_POINT* public_key,
                                    absl::string_view public_token,
                                    absl::string_view info,
                                    size_t num_bytes) const;
  StatusOr<std::string> SerializePoint(const EC_POINT* point) const;
  StatusOr<openssl_unique_ptr<EC_POINT>> DeserializePoint(
      absl::string_view serialized_point) const;
  StatusOr<std::string> SerializePrivateKey(const EC_KEY* key) const;
  StatusOr<openssl_unique_ptr<EC_KEY>> DeserializePrivateKey(
      absl::string_view serialized) const;

  StatusOr<std::unique_ptr<Hkdf>> CreateHkdf(absl::string_view in_key,
                                             absl::string_view salt) const {
    return hkdf_factory_(in_key, salt);
  }

  const EC_GROUP* group() const { return group_; }
  int curve_nid() const { return curve_nid_; }

 private:
  const int curve_nid_;
  const EC_GROUP* group_;
  const int field_byte_length_;
  HkdfFactory* hkdf_factory_;
};

class OpensslKemPublicKey : public KemPublicKey {
 public:
  OpensslKemPublicKey(const OpensslKemFactory& factory,
                      openssl_unique_ptr<EC_POINT> point,
                      const std::string& serialized_point)
      : factory_(factory),
        point_(std::move(point)),
        serialized_point_(serialized_point) {}

  Status NewKeyAndToken(size_t num_bytes, absl::string_view info, std::string* key,
                        std::string* token) const override;
  std::string Serialize() const override { return serialized_point_; }

 private:
  const OpensslKemFactory& factory_;
  openssl_unique_ptr<EC_POINT> point_;
  const std::string serialized_point_;
};

class OpensslKemPrivateKey : public KemPrivateKey {
 public:
  OpensslKemPrivateKey(const OpensslKemFactory& factory,
                       openssl_unique_ptr<EC_KEY> key,
                       const std::string& serialized_key)
      : factory_(factory),
        key_(std::move(key)),
        serialized_key_(serialized_key) {}

  // Can be used to derive the same key bytes given by KemPublicKey::NewToken.
  StatusOr<std::string> DeriveKeyFromToken(absl::string_view token, size_t num_bytes,
                                      absl::string_view info) const override;
  std::string Serialize() const override { return serialized_key_; }

 private:
  const OpensslKemFactory& factory_;
  openssl_unique_ptr<EC_KEY> key_;
  const std::string serialized_key_;
};

const KemFactory& GetP256KemFactory();
const KemFactory& GetP521KemFactory();

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_HYBRID_OPENSSL_KEM_H_
