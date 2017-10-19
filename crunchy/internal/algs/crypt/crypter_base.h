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

#ifndef CRUNCHY_ALGS_CRYPT_CRYPTER_BASE_H_
#define CRUNCHY_ALGS_CRYPT_CRYPTER_BASE_H_

#include <stddef.h>
#include <stdint.h>
#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/crypt/crypter_interface.h"
#include "crunchy/util/status.h"

namespace crunchy {

// A class that implements common functions of CrypterInterface such as
// max length of plaintext or ciphertext_and_tag, input sanity check, and
// encrypt and decrypt functions for absl::string_view.
class CrypterBase : public CrypterInterface {
 public:
  Status Encrypt(const uint8_t* nonce, size_t nonce_length, const uint8_t* aad,
                 size_t aad_length, const uint8_t* plaintext,
                 size_t plaintext_length, uint8_t* ciphertext_and_tag,
                 size_t ciphertext_and_tag_length,
                 size_t* bytes_written) override = 0;

  StatusOr<std::string> Encrypt(absl::string_view nonce, absl::string_view aad,
                           absl::string_view plaintext) override;

  Status Decrypt(const uint8_t* nonce, size_t nonce_length, const uint8_t* aad,
                 size_t aad_length, const uint8_t* ciphertext_and_tag,
                 size_t ciphertext_and_tag_length, uint8_t* plaintext,
                 size_t plaintext_length, size_t* bytes_written) override = 0;

  StatusOr<std::string> Decrypt(absl::string_view nonce, absl::string_view aad,
                           absl::string_view ciphertext_and_tag) override;

  size_t max_ciphertext_and_tag_length(size_t plaintext_length) const override {
    return plaintext_length + this->tag_length();
  }

  size_t max_plaintext_length(size_t ciphertext_and_tag_length) const override {
    if (ciphertext_and_tag_length < this->tag_length()) {
      return 0;
    }
    return ciphertext_and_tag_length - this->tag_length();
  }

 protected:
  CrypterBase() = default;

  // Santiy check on inputs to the encryption and decryption functions
  Status CheckEncryptInput(const uint8_t* nonce, size_t nonce_length,
                           const uint8_t* aad, size_t aad_length,
                           const uint8_t* plaintext, size_t plaintext_length,
                           const uint8_t* ciphertext_and_tag,
                           size_t ciphertext_and_tag_length,
                           const size_t* bytes_written) const;

  Status CheckDecryptInput(const uint8_t* nonce, size_t nonce_length,
                           const uint8_t* aad, size_t aad_length,
                           const uint8_t* plaintext, size_t plaintext_length,
                           const uint8_t* ciphertext_and_tag,
                           size_t ciphertext_and_tag_length,
                           const size_t* bytes_written) const;
};

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_CRYPT_CRYPTER_BASE_H_
