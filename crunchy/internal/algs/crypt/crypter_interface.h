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

#ifndef CRUNCHY_ALGS_CRYPT_CRYPTER_INTERFACE_H_
#define CRUNCHY_ALGS_CRYPT_CRYPTER_INTERFACE_H_

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/util/status.h"

namespace crunchy {

// An interface for AEAD encryption schemes such as AES-GCM. All methods are
// thread-safe.
class CrypterInterface {
 public:
  virtual ~CrypterInterface() = default;

  // Encryption function which takes in pointers to data containing nonce, aad
  // (unencrypted associated authenticated data), and plaintext, along with
  // their lengths. Produces ciphertext and tag values, along with number of
  // bytes written. Returns OK when encryption completes successfully.
  // Otherwise, returns an error status. plaintext and ciphertext buffers must
  // either not overlap or their pointers must be equal. ciphertext must have
  // length at least max_ciphertext_length(plaintext_length) bytes.
  // If aad is null, aad_length must be 0. If any of plaintext, ciphertext, or
  // ciphertext_bytes_written is null, plaintext_length must be zero.
  virtual Status Encrypt(const uint8_t* nonce, size_t nonce_length,
                         const uint8_t* aad, size_t aad_length,
                         const uint8_t* plaintext, size_t plaintext_length,
                         uint8_t* ciphertext_and_tag,
                         size_t ciphertext_and_tag_length,
                         size_t* bytes_written) = 0;
  virtual StatusOr<std::string> Encrypt(absl::string_view nonce,
                                   absl::string_view aad,
                                   absl::string_view plaintext) = 0;

  // Decryption function which takes in pointers to data containing nonce, aad
  // (unencrypted associated authenticated data), and ciphertext+tag, along with
  // their lengths. Produces decrypted plaintext and returns OK when decryption
  // completes successfully. Otherwise, returns an error status. The plaintext
  // buffer may be zeroed if decryption fails. plaintext and ciphertext buffers
  // must either not overlap or their pointers must be equal. plaintext must
  // have length at least max_plaintext_length(ciphertext_length) bytes.
  // If aad is null, aad_length must be 0. If any of plaintext, ciphertext, or
  // ciphertext_bytes_written is null, ciphertext_length must be zero.
  virtual Status Decrypt(const uint8_t* nonce, size_t nonce_length,
                         const uint8_t* aad, size_t aad_length,
                         const uint8_t* ciphertext_and_tag,
                         size_t ciphertext_and_tag_length, uint8_t* plaintext,
                         size_t plaintext_length, size_t* bytes_written) = 0;
  virtual StatusOr<std::string> Decrypt(absl::string_view nonce,
                                   absl::string_view aad,
                                   absl::string_view ciphertext_and_tag) = 0;

  // Returns the size of the ciphertext array that must be passed to the Encrypt
  // function. The actual size of the ciphertext written may be smaller.
  virtual size_t max_ciphertext_and_tag_length(
      size_t plaintext_length) const = 0;

  // Returns the size of the plaintext array that must be passed to the Decrypt
  // function. The actual size of the plaintext written may be smaller.
  virtual size_t max_plaintext_length(
      size_t ciphertext_and_tag_length) const = 0;

  // The size of nonce array that must be passed to the Encrypt/Decrypt
  // functions.
  virtual size_t nonce_length() const = 0;

  // The size of tag array that must be passed to the Encrypt/Decrypt functions.
  virtual size_t tag_length() const = 0;

 protected:
  CrypterInterface() = default;
};

class CrypterFactory {
 public:
  virtual ~CrypterFactory() = default;

  virtual size_t GetKeyLength() const = 0;
  virtual size_t GetNonceLength() const = 0;
  virtual size_t GetTagLength() const = 0;

  virtual StatusOr<std::unique_ptr<CrypterInterface>> Make(
      absl::string_view key) const = 0;
};

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_CRYPT_CRYPTER_INTERFACE_H_
