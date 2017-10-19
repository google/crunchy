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

#ifndef CRUNCHY_ALGS_HYBRID_HYBRID_H_
#define CRUNCHY_ALGS_HYBRID_HYBRID_H_

#include <stddef.h>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/util/status.h"

namespace crunchy {

// An encryption interface generated from the recipient's public key.
class HybridEncrypterInterface {
 public:
  virtual ~HybridEncrypterInterface() = default;
  virtual StatusOr<std::string> Encrypt(absl::string_view plaintext) const = 0;
};

// A decryption interface generated from the recipient's private key.
class HybridDecrypterInterface {
 public:
  virtual ~HybridDecrypterInterface() = default;
  virtual StatusOr<std::string> Decrypt(absl::string_view ciphertext) const = 0;
};

// A factory capable to generating Hybrid cryption keys and
// APIs capable to hybrid encryption/decryption.
class HybridCrypterFactory {
 public:
  virtual ~HybridCrypterFactory() = default;
  virtual Status NewKeypair(std::string* public_key, std::string* private_key) const = 0;

  virtual StatusOr<std::unique_ptr<HybridEncrypterInterface>>
  MakeHybridEncrypter(absl::string_view public_key) const = 0;
  virtual StatusOr<std::unique_ptr<HybridDecrypterInterface>>
  MakeHybridDecrypter(absl::string_view private_key) const = 0;
  virtual size_t GetMaxCiphertextLength(size_t plaintext_length) const = 0;
  virtual size_t GetMaxPlaintextLength(size_t ciphertext_length) const = 0;
};

const HybridCrypterFactory& GetP256Aes128GcmFactory();
const HybridCrypterFactory& GetP256Aes256GcmFactory();
const HybridCrypterFactory& GetP521Aes256GcmFactory();
const HybridCrypterFactory& GetX25519Aes256GcmFactory();

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_HYBRID_HYBRID_H_
