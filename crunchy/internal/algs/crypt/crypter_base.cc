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

#include "crunchy/internal/algs/crypt/crypter_base.h"

#include "absl/strings/str_cat.h"

namespace crunchy {

StatusOr<std::string> CrypterBase::Encrypt(absl::string_view nonce,
                                      absl::string_view aad,
                                      absl::string_view plaintext) {
  std::string ciphertext_and_tag;
  ciphertext_and_tag.resize(max_ciphertext_and_tag_length(plaintext.length()));
  size_t bytes_written = 0;
  auto status = this->Encrypt(
      reinterpret_cast<const uint8_t*>(nonce.data()), nonce.length(),
      reinterpret_cast<const uint8_t*>(aad.data()), aad.length(),
      reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.length(),
      reinterpret_cast<uint8_t*>(&*ciphertext_and_tag.begin()),
      ciphertext_and_tag.length(), &bytes_written);
  if (!status.ok()) {
    return status;
  }
  ciphertext_and_tag.resize(bytes_written);
  return ciphertext_and_tag;
}

StatusOr<std::string> CrypterBase::Decrypt(absl::string_view nonce,
                                      absl::string_view aad,
                                      absl::string_view ciphertext_and_tag) {
  std::string plaintext;
  plaintext.resize(max_plaintext_length(ciphertext_and_tag.length()));
  size_t bytes_written = 0;
  auto status = this->Decrypt(
      reinterpret_cast<const uint8_t*>(nonce.data()), nonce.length(),
      reinterpret_cast<const uint8_t*>(aad.data()), aad.length(),
      reinterpret_cast<const uint8_t*>(ciphertext_and_tag.data()),
      ciphertext_and_tag.length(),
      reinterpret_cast<uint8_t*>(&*plaintext.begin()), plaintext.length(),
      &bytes_written);
  if (!status.ok()) {
    return status;
  }
  plaintext.resize(bytes_written);
  return plaintext;
}

Status CrypterBase::CheckEncryptInput(const uint8_t* nonce, size_t nonce_length,
                                      const uint8_t* aad, size_t aad_length,
                                      const uint8_t* plaintext,
                                      size_t plaintext_length,
                                      const uint8_t* ciphertext_and_tag,
                                      size_t ciphertext_and_tag_length,
                                      const size_t* bytes_written) const {
  if (nullptr == nonce) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Nonce buffer is null.";
  }
  if (this->nonce_length() != nonce_length) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Nonce buffer has the wrong length, " << nonce_length
           << " given, " << this->nonce_length() << " expected.";
  }
  if (aad_length > 0 && nullptr == aad) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Non-zero aad length but aad buffer is null.";
  }
  if (plaintext_length > 0 && nullptr == plaintext) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Non-zero plaintext length but plaintext buffer is null.";
  }
  if (nullptr == ciphertext_and_tag || nullptr == bytes_written) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "ciphertext_and_tag or bytes_written is null.";
  }
  if (ciphertext_and_tag_length <
      this->max_ciphertext_and_tag_length(plaintext_length)) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "ciphertext_and_tag_length is smaller than "
              "max_ciphertext_and_tag_length(plaintext_length).";
  }
  return OkStatus();
}

Status CrypterBase::CheckDecryptInput(const uint8_t* nonce, size_t nonce_length,
                                      const uint8_t* aad, size_t aad_length,
                                      const uint8_t* plaintext,
                                      size_t plaintext_length,
                                      const uint8_t* ciphertext_and_tag,
                                      size_t ciphertext_and_tag_length,
                                      const size_t* bytes_written) const {
  if (nullptr == nonce) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Nonce buffer is null.";
  }
  if (this->nonce_length() != nonce_length) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Nonce buffer has the wrong length.";
  }
  if (aad_length > 0 && nullptr == aad) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Non-zero aad length but aad buffer is null.";
  }
  if (nullptr == ciphertext_and_tag) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "ciphertext_and_tag is null.";
  }
  if (ciphertext_and_tag_length < this->tag_length()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "ciphertext_and_tag_length is smaller than tag_length().";
  }
  if (ciphertext_and_tag_length > this->tag_length() &&
      (nullptr == plaintext || nullptr == bytes_written)) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "ciphertext_and_tag_length is larger than tag_length(), but "
              "either plaintext or bytes_written is null.";
  }
  if (plaintext_length <
      this->max_plaintext_length(ciphertext_and_tag_length)) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "plaintext_length is less than "
              "max_plaintext_length(ciphertext_and_tag_length).";
  }
  return OkStatus();
}

}  // namespace crunchy
