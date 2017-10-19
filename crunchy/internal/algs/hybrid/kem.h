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

#ifndef CRUNCHY_ALGS_HYBRID_KEM_H_
#define CRUNCHY_ALGS_HYBRID_KEM_H_

#include <stddef.h>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/util/status.h"

namespace crunchy {

// The recipient's public key
class KemPublicKey {
 public:
  virtual ~KemPublicKey() = default;

  // Creates a KemPublicToken and the specified number of key bytes.
  // KemPrivateKey::Derive can be used to generate the same key bytes, given the
  // returned token.
  virtual Status NewKeyAndToken(size_t num_bytes, absl::string_view info,
                                std::string* key, std::string* token) const = 0;
  virtual std::string Serialize() const = 0;
};

// The recipient's private key
class KemPrivateKey {
 public:
  virtual ~KemPrivateKey() = default;

  // Can be used to derive the same key bytes given by KemPublicKey::NewToken.
  virtual StatusOr<std::string> DeriveKeyFromToken(absl::string_view token,
                                              size_t num_bytes,
                                              absl::string_view info) const = 0;
  virtual std::string Serialize() const = 0;
};

// A factory capable of generating and parsing kem keys/tokens of a particular
// type.
class KemFactory {
 public:
  virtual ~KemFactory() = default;

  // Creates a public/private keypair
  virtual Status NewKeypair(
      std::unique_ptr<KemPublicKey>* public_key,
      std::unique_ptr<KemPrivateKey>* private_key) const = 0;

  // Deserialize functions.
  virtual StatusOr<std::unique_ptr<KemPublicKey>> DeserializeKemPublicKey(
      absl::string_view serialized) const = 0;
  virtual StatusOr<std::unique_ptr<KemPrivateKey>> DeserializeKemPrivateKey(
      absl::string_view serialized) const = 0;

  // The size of serialized keys and tokens.
  virtual size_t KemPublicTokenSerializedSize() const = 0;
  virtual size_t KemPublicKeySerializedSize() const = 0;
  virtual size_t KemPrivateKeySerializedSize() const = 0;
};

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_HYBRID_KEM_H_
