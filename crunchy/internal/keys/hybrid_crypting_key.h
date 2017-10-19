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

#ifndef CRUNCHY_INTERNAL_KEYS_HYBRID_CRYPTING_KEY_H_
#define CRUNCHY_INTERNAL_KEYS_HYBRID_CRYPTING_KEY_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/hybrid/hybrid.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/util/status.h"

namespace crunchy {

class HybridEncryptingKey {
 public:
  virtual ~HybridEncryptingKey() = default;

  virtual StatusOr<std::string> Encrypt(absl::string_view plaintext) const = 0;
};

class HybridDecryptingKey {
 public:
  virtual ~HybridDecryptingKey() = default;

  virtual StatusOr<std::string> Decrypt(absl::string_view ciphertext) const = 0;
};

class HybridCryptingKeyFactory {
 public:
  virtual ~HybridCryptingKeyFactory() = default;

  virtual StatusOr<KeyData> CreateRandomPrivateKeyData() const = 0;
  virtual StatusOr<KeyData> CreatePublicKeyData(
      const KeyData& key_data) const = 0;
  virtual StatusOr<std::unique_ptr<HybridEncryptingKey>>
  MakeHybridEncryptingKey(const KeyData& key_data) const = 0;
  virtual StatusOr<std::unique_ptr<HybridDecryptingKey>>
  MakeHybridDecryptingKey(const KeyData& key_data) const = 0;
};

std::unique_ptr<HybridCryptingKeyFactory> MakeFactory(
    const HybridCrypterFactory& crypter_factory);

}  // namespace crunchy

#endif  // CRUNCHY_INTERNAL_KEYS_HYBRID_CRYPTING_KEY_H_
