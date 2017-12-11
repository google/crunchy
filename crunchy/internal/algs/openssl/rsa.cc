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

#include "crunchy/internal/algs/openssl/rsa.h"
#include <openssl/pem.h>

namespace crunchy {

StatusOr<std::string> SerializePrivateKey(const RSA* rsa) {
  uint8_t* serialized_private_key = nullptr;
  size_t serialized_private_key_length;
  if (RSA_private_key_to_bytes(&serialized_private_key,
                               &serialized_private_key_length, rsa) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error serializing private key: "
           << GetOpensslErrors();
  }
  std::string result(reinterpret_cast<char*>(serialized_private_key),
                serialized_private_key_length);
  OPENSSL_free(serialized_private_key);
  return result;
}

StatusOr<openssl_unique_ptr<RSA>> DeserializePrivateKey(
    absl::string_view serialized_private_key) {
  openssl_unique_ptr<RSA> rsa(RSA_private_key_from_bytes(
      reinterpret_cast<const uint8_t*>(serialized_private_key.data()),
      serialized_private_key.size()));
  if (rsa == nullptr) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error parsing private key: "
           << GetOpensslErrors();
  }
  return std::move(rsa);
}

StatusOr<std::string> SerializePublicKey(const RSA* rsa) {
  uint8_t* serialized_public_key = nullptr;
  size_t serialized_public_key_length;
  if (RSA_public_key_to_bytes(&serialized_public_key,
                              &serialized_public_key_length, rsa) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error serializing public key: "
           << GetOpensslErrors();
  }
  std::string result(reinterpret_cast<char*>(serialized_public_key),
                serialized_public_key_length);
  OPENSSL_free(serialized_public_key);
  return result;
}

StatusOr<openssl_unique_ptr<RSA>> DeserializePublicKey(
    absl::string_view serialized_public_key) {
  openssl_unique_ptr<RSA> rsa(RSA_public_key_from_bytes(
      reinterpret_cast<const uint8_t*>(serialized_public_key.data()),
      serialized_public_key.size()));
  if (rsa == nullptr) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error parsing public key: "
           << GetOpensslErrors();
  }
  return std::move(rsa);
}

StatusOr<std::string> DeserializeDerPublicKeyAsPemPublicKey(
    absl::string_view der_public_key) {
  auto bio = openssl_make_unique<BIO>(BIO_s_mem());

  openssl_unique_ptr<RSA> rsa(RSA_public_key_from_bytes(
      reinterpret_cast<const uint8_t*>(der_public_key.data()),
      der_public_key.size()));
  if (rsa == nullptr) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "RSA generate key error." << GetOpensslErrors();
  }
  if (PEM_write_bio_RSAPublicKey(bio.get(), rsa.get()) <= 0) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Save to public key file error." << GetOpensslErrors();
  }

  const uint8_t* pem = nullptr;
  size_t pem_length = 0;
  if (!BIO_mem_contents(bio.get(), &pem, &pem_length) || !pem) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error getting pem: " << GetOpensslErrors();
  }

  return {std::string(reinterpret_cast<const char*>(pem), pem_length)};
}

StatusOr<std::string> DeserializePemPublicKeyAsDerPublicKey(
    absl::string_view pem_public_key) {
  std::string pem(pem_public_key);
  openssl_unique_ptr<BIO> bio(BIO_new_mem_buf(&pem[0], pem.length()));
  openssl_unique_ptr<RSA> rsa(
      PEM_read_bio_RSAPublicKey(bio.get(), nullptr, nullptr, nullptr));
  if (rsa == nullptr) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error converting PEM to RSA: "
           << GetOpensslErrors();
  }

  return SerializePublicKey(rsa.get());
}

}  // namespace crunchy
