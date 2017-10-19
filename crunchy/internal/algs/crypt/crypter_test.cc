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

#include <string.h>
#include <cstdint>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/crypt/crypter_test.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/common/file.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/test_factory.h"
#include "crunchy/internal/port/port.h"
#include "crunchy/util/status.h"

using absl::make_unique;
using testing::HasSubstr;
using testing::_;
using testing::crunchy_status::StatusIs;

namespace crunchy {

std::unique_ptr<uint8_t[]> RandomArray(size_t length) {
  auto result = make_unique<uint8_t[]>(length);
  RandBytes(result.get(), length);
  return result;
}

std::unique_ptr<uint8_t[]> Copy(uint8_t* source, size_t source_len) {
  auto dest = make_unique<uint8_t[]>(source_len);
  memcpy(dest.get(), source, source_len);
  return dest;
}

std::unique_ptr<uint8_t[]> CopyAndAlterRandomByte(const uint8_t* source,
                                                  size_t source_len) {
  auto dest = make_unique<uint8_t[]>(source_len);
  memcpy(dest.get(), source, source_len);
  dest[BiasRandInt(source_len)]++;
  return dest;
}

std::string CopyAndAlterRandomByte(const std::string& source) {
  auto dest = CopyAndAlterRandomByte(
      reinterpret_cast<const uint8_t*>(source.data()), source.length());
  return std::string(reinterpret_cast<char*>(dest.get()), source.length());
}

std::string ToHex(const uint8_t* hex, size_t length) {
  return absl::BytesToHexString(
      absl::string_view(reinterpret_cast<const char*>(hex), length));
}

void RandomEncryptDecrypt(const CrypterFactory& factory, size_t aad_length,
                          size_t message_length, bool corrupt_tag) {
  auto status_or_crypter = factory.Make(RandString(factory.GetKeyLength()));
  CRUNCHY_EXPECT_OK(status_or_crypter.status());
  std::unique_ptr<CrypterInterface> crypter =
      std::move(status_or_crypter.ValueOrDie());

  SCOPED_TRACE(absl::StrCat("aad_length=", aad_length,
                            " message_length=", message_length,
                            " nonce_length=", crypter->nonce_length(),
                            " tag_length=", crypter->tag_length()));
  size_t nonce_length = crypter->nonce_length();
  std::unique_ptr<uint8_t[]> nonce = RandomArray(nonce_length);
  std::unique_ptr<uint8_t[]> aad = RandomArray(aad_length);
  std::unique_ptr<uint8_t[]> message = RandomArray(message_length);

  // Test encryption
  size_t ciphertext_and_tag_length =
      crypter->max_ciphertext_and_tag_length(message_length);
  auto ciphertext_and_tag = make_unique<uint8_t[]>(ciphertext_and_tag_length);
  size_t ciphertext_bytes_written = 0;
  EXPECT_EQ(message_length + crypter->tag_length(), ciphertext_and_tag_length);
  CRUNCHY_EXPECT_OK(
      crypter->Encrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                       message.get(), message_length, ciphertext_and_tag.get(),
                       ciphertext_and_tag_length, &ciphertext_bytes_written));
  EXPECT_EQ(ciphertext_bytes_written, ciphertext_and_tag_length);

  // Test decryption
  size_t plaintext_length =
      crypter->max_plaintext_length(ciphertext_and_tag_length);
  auto plaintext = make_unique<uint8_t[]>(plaintext_length);
  size_t plaintext_bytes_written = 0;
  CRUNCHY_EXPECT_OK(crypter->Decrypt(
      nonce.get(), nonce_length, aad.get(), aad_length,
      ciphertext_and_tag.get(), ciphertext_and_tag_length, plaintext.get(),
      plaintext_length, &plaintext_bytes_written));
  EXPECT_EQ(message_length, plaintext_bytes_written);

  EXPECT_EQ(ToHex(message.get(), message_length),
            ToHex(plaintext.get(), plaintext_bytes_written));

  // The returned plaintext will be zeroed if there was an authentication
  // error.
  auto zero_message = make_unique<uint8_t[]>(plaintext_length);
  memset(zero_message.get(), 0x00, plaintext_length);

  if (corrupt_tag) {
    // Corrupt nonce
    if (nonce_length > 0) {
      plaintext_bytes_written = 0;
      auto corrupt_nonce = CopyAndAlterRandomByte(nonce.get(), nonce_length);
      EXPECT_FALSE(crypter
                       ->Decrypt(corrupt_nonce.get(), nonce_length, aad.get(),
                                 aad_length, ciphertext_and_tag.get(),
                                 ciphertext_and_tag_length, plaintext.get(),
                                 plaintext_length, &plaintext_bytes_written)
                       .ok());
      EXPECT_EQ(0, plaintext_bytes_written);

      EXPECT_EQ(ToHex(zero_message.get(), plaintext_length),
                ToHex(plaintext.get(), plaintext_length));
    }

    // Corrupt ciphertext_and_tag
    plaintext_bytes_written = 0;
    auto corrupt_ciphertext_and_tag = CopyAndAlterRandomByte(
        ciphertext_and_tag.get(), ciphertext_and_tag_length);
    EXPECT_FALSE(
        crypter->Decrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                         corrupt_ciphertext_and_tag.get(),
                         ciphertext_and_tag_length, plaintext.get(),
                         plaintext_length, &plaintext_bytes_written).ok());
    EXPECT_EQ(0, plaintext_bytes_written);

    EXPECT_EQ(ToHex(zero_message.get(), plaintext_length),
              ToHex(plaintext.get(), plaintext_length));

    // Corrupt start of ciphertext_and_tag
    plaintext_bytes_written = 0;
    corrupt_ciphertext_and_tag =
        Copy(ciphertext_and_tag.get(), ciphertext_and_tag_length);
    corrupt_ciphertext_and_tag[0]++;
    EXPECT_FALSE(
        crypter->Decrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                         corrupt_ciphertext_and_tag.get(),
                         ciphertext_and_tag_length, plaintext.get(),
                         plaintext_length, &plaintext_bytes_written).ok());
    EXPECT_EQ(0, plaintext_bytes_written);

    // Corrupt end of ciphertext_and_tag
    plaintext_bytes_written = 0;
    corrupt_ciphertext_and_tag =
        Copy(ciphertext_and_tag.get(), ciphertext_and_tag_length);
    corrupt_ciphertext_and_tag[ciphertext_and_tag_length - 1]++;
    EXPECT_FALSE(
        crypter->Decrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                         corrupt_ciphertext_and_tag.get(),
                         ciphertext_and_tag_length, plaintext.get(),
                         plaintext_length, &plaintext_bytes_written).ok());
    EXPECT_EQ(0, plaintext_bytes_written);

    EXPECT_EQ(ToHex(zero_message.get(), plaintext_bytes_written),
              ToHex(plaintext.get(), plaintext_bytes_written));
  }
}

void RandomEncryptDecryptTest(const CrypterFactory& factory,
                              size_t min_message_length, bool corrupt_tag) {
  size_t aad_length = BiasRandInt(1024);
  size_t message_length = BiasRandInt(1024) + min_message_length;
  RandomEncryptDecrypt(factory, aad_length, message_length, corrupt_tag);
  RandomEncryptDecrypt(factory, 0, message_length, corrupt_tag);
  RandomEncryptDecrypt(factory, aad_length, min_message_length, corrupt_tag);
}

void EncryptionFailureTest(const CrypterFactory& factory,
                           bool allow_empty_messages) {
  auto status_or_crypter = factory.Make(RandString(factory.GetKeyLength()));
  CRUNCHY_EXPECT_OK(status_or_crypter.status());
  std::unique_ptr<CrypterInterface> crypter =
      std::move(status_or_crypter.ValueOrDie());

  size_t aad_length = 1024;
  size_t message_length = 1024;
  size_t nonce_length = crypter->nonce_length();
  std::unique_ptr<uint8_t[]> nonce = RandomArray(nonce_length);
  std::unique_ptr<uint8_t[]> aad = RandomArray(aad_length);
  std::unique_ptr<uint8_t[]> message = RandomArray(message_length);

  size_t ciphertext_and_tag_length =
      crypter->max_ciphertext_and_tag_length(message_length);
  auto ciphertext_and_tag = make_unique<uint8_t[]>(ciphertext_and_tag_length);
  size_t ciphertext_bytes_written = 0;

  // Null nonce.
  EXPECT_THAT(
      crypter->Encrypt(nullptr, nonce_length, aad.get(), aad_length,
                       message.get(), message_length, ciphertext_and_tag.get(),
                       ciphertext_and_tag_length, &ciphertext_bytes_written),
      StatusIs(INVALID_ARGUMENT, HasSubstr("Nonce buffer is null.")));

  // Big nonce.
  EXPECT_THAT(
      crypter->Encrypt(nonce.get(), nonce_length + 1, aad.get(), aad_length,
                       message.get(), message_length, ciphertext_and_tag.get(),
                       ciphertext_and_tag_length, &ciphertext_bytes_written),
      StatusIs(INVALID_ARGUMENT,
               HasSubstr("Nonce buffer has the wrong length.")));

  // Small nonce.
  EXPECT_THAT(
      crypter->Encrypt(nonce.get(), nonce_length - 1, aad.get(), aad_length,
                       message.get(), message_length, ciphertext_and_tag.get(),
                       ciphertext_and_tag_length, &ciphertext_bytes_written),
      StatusIs(INVALID_ARGUMENT,
               HasSubstr("Nonce buffer has the wrong length.")));

  // Null aad.
  EXPECT_THAT(
      crypter->Encrypt(nonce.get(), nonce_length, nullptr, aad_length,
                       message.get(), message_length, ciphertext_and_tag.get(),
                       ciphertext_and_tag_length, &ciphertext_bytes_written),
      StatusIs(INVALID_ARGUMENT,
               HasSubstr("Non-zero aad length but aad buffer is null.")));

  // Null aad with zero length.
  CRUNCHY_EXPECT_OK(
      crypter->Encrypt(nonce.get(), nonce_length, nullptr, 0, message.get(),
                       message_length, ciphertext_and_tag.get(),
                       ciphertext_and_tag_length, &ciphertext_bytes_written));

  // Null plaintext.
  EXPECT_THAT(
      crypter->Encrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                       nullptr, message_length, ciphertext_and_tag.get(),
                       ciphertext_and_tag_length, &ciphertext_bytes_written),
      StatusIs(INVALID_ARGUMENT,
               HasSubstr(
                   "Non-zero plaintext length but plaintext buffer is null.")));

  // Null ciphertext.
  EXPECT_THAT(
      crypter->Encrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                       message.get(), message_length, nullptr,
                       ciphertext_and_tag_length, &ciphertext_bytes_written),
      StatusIs(INVALID_ARGUMENT,
               HasSubstr("ciphertext_and_tag or bytes_written is null.")));

  // Short ciphertext.
  EXPECT_THAT(
      crypter->Encrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                       message.get(), message_length, ciphertext_and_tag.get(),
                       ciphertext_and_tag_length - 1,
                       &ciphertext_bytes_written),
      StatusIs(INVALID_ARGUMENT,
               HasSubstr("ciphertext_and_tag_length is smaller than "
                         "max_ciphertext_and_tag_length(plaintext_length).")));

  // Null ciphertext_bytes_written.
  EXPECT_THAT(
      crypter->Encrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                       message.get(), message_length, ciphertext_and_tag.get(),
                       ciphertext_and_tag_length, nullptr),
      StatusIs(INVALID_ARGUMENT,
               HasSubstr("ciphertext_and_tag or bytes_written is null.")));

  // Null plaintext/ciphertext encrypt with zero length.
  if (allow_empty_messages) {
    // Some modes (e.g. AES-HEH) don't support empty messages.
    CRUNCHY_EXPECT_OK(
        crypter->Encrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                         nullptr, 0, ciphertext_and_tag.get(),
                         ciphertext_and_tag_length, &ciphertext_bytes_written));
  } else {
    EXPECT_FALSE(crypter
                     ->Encrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                               nullptr, 0, ciphertext_and_tag.get(),
                               ciphertext_and_tag_length,
                               &ciphertext_bytes_written)
                     .ok());
  }

  // Success.
  CRUNCHY_EXPECT_OK(
      crypter->Encrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                       message.get(), message_length, ciphertext_and_tag.get(),
                       ciphertext_and_tag_length, &ciphertext_bytes_written));
}

void DecryptionFailureTest(const CrypterFactory& factory) {
  auto status_or_crypter = factory.Make(RandString(factory.GetKeyLength()));
  CRUNCHY_EXPECT_OK(status_or_crypter.status());
  std::unique_ptr<CrypterInterface> crypter =
      std::move(status_or_crypter.ValueOrDie());

  size_t aad_length = 1024;
  size_t message_length = 1024;
  size_t nonce_length = crypter->nonce_length();
  std::unique_ptr<uint8_t[]> nonce = RandomArray(nonce_length);
  std::unique_ptr<uint8_t[]> aad = RandomArray(aad_length);
  std::unique_ptr<uint8_t[]> message = RandomArray(message_length);

  // Test encryption
  size_t ciphertext_and_tag_length =
      crypter->max_ciphertext_and_tag_length(message_length);
  auto ciphertext_and_tag = make_unique<uint8_t[]>(ciphertext_and_tag_length);
  size_t ciphertext_bytes_written = 0;
  CRUNCHY_EXPECT_OK(
      crypter->Encrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                       message.get(), message_length, ciphertext_and_tag.get(),
                       ciphertext_and_tag_length, &ciphertext_bytes_written));
  EXPECT_EQ(ciphertext_bytes_written, ciphertext_and_tag_length);

  size_t plaintext_length =
      crypter->max_plaintext_length(ciphertext_and_tag_length);
  auto plaintext = make_unique<uint8_t[]>(plaintext_length);
  size_t plaintext_bytes_written = 0;

  // Null nonce.
  EXPECT_THAT(crypter->Decrypt(nullptr, nonce_length, aad.get(), aad_length,
                               ciphertext_and_tag.get(),
                               ciphertext_and_tag_length, plaintext.get(),
                               plaintext_length, &plaintext_bytes_written),
              StatusIs(INVALID_ARGUMENT, HasSubstr("Nonce buffer is null.")));

  // Big nonce.
  EXPECT_THAT(crypter->Decrypt(nonce.get(), nonce_length + 1, aad.get(),
                               aad_length, ciphertext_and_tag.get(),
                               ciphertext_and_tag_length, plaintext.get(),
                               plaintext_length, &plaintext_bytes_written),
              StatusIs(INVALID_ARGUMENT,
                       HasSubstr("Nonce buffer has the wrong length.")));

  // Small nonce.
  EXPECT_THAT(crypter->Decrypt(nonce.get(), nonce_length - 1, aad.get(),
                               aad_length, ciphertext_and_tag.get(),
                               ciphertext_and_tag_length, plaintext.get(),
                               plaintext_length, &plaintext_bytes_written),
              StatusIs(INVALID_ARGUMENT,
                       HasSubstr("Nonce buffer has the wrong length.")));

  // Null aad.
  EXPECT_THAT(
      crypter->Decrypt(nonce.get(), nonce_length, nullptr, aad_length,
                       ciphertext_and_tag.get(), ciphertext_and_tag_length,
                       plaintext.get(), plaintext_length,
                       &plaintext_bytes_written),
      StatusIs(INVALID_ARGUMENT,
               HasSubstr("Non-zero aad length but aad buffer is null.")));

  // Null aad with zero length.
  CRUNCHY_EXPECT_OK(
      crypter->Encrypt(nonce.get(), nonce_length, nullptr, 0, message.get(),
                       message_length, ciphertext_and_tag.get(),
                       ciphertext_and_tag_length, &ciphertext_bytes_written));
  CRUNCHY_EXPECT_OK(crypter->Decrypt(
      nonce.get(), nonce_length, nullptr, 0, ciphertext_and_tag.get(),
      ciphertext_and_tag_length, plaintext.get(), plaintext_length,
      &plaintext_bytes_written));

  // Small ciphertext.
  if (crypter->tag_length() > 0) {
    EXPECT_THAT(
        crypter->Decrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                         ciphertext_and_tag.get(), crypter->tag_length() - 1,
                         plaintext.get(), plaintext_length,
                         &plaintext_bytes_written),
        StatusIs(
            INVALID_ARGUMENT,
            HasSubstr("ciphertext_and_tag_length is smaller than tag_length")));
  }

  // Null ciphertext.
  EXPECT_THAT(
      crypter->Decrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                       nullptr, ciphertext_and_tag_length, plaintext.get(),
                       plaintext_length, &plaintext_bytes_written),
      StatusIs(INVALID_ARGUMENT, HasSubstr("ciphertext_and_tag is null.")));

  // Null plaintext.
  EXPECT_THAT(
      crypter->Decrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                       ciphertext_and_tag.get(), ciphertext_and_tag_length,
                       nullptr, plaintext_length, &plaintext_bytes_written),
      StatusIs(INVALID_ARGUMENT,
               HasSubstr("ciphertext_and_tag_length is larger than "
                         "tag_length(), but either "
                         "plaintext or bytes_written is null.")));

  // Short plaintext
  EXPECT_THAT(
      crypter->Decrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                       ciphertext_and_tag.get(), ciphertext_and_tag_length,
                       plaintext.get(), plaintext_length - 1,
                       &plaintext_bytes_written),
      StatusIs(INVALID_ARGUMENT,
               HasSubstr("plaintext_length is less than "
                         "max_plaintext_length(ciphertext_and_tag_length).")));

  // Null plaintext_bytes_written.
  EXPECT_THAT(
      crypter->Decrypt(nonce.get(), nonce_length, aad.get(), aad_length,
                       ciphertext_and_tag.get(), ciphertext_and_tag_length,
                       plaintext.get(), plaintext_length, nullptr),
      StatusIs(INVALID_ARGUMENT,
               HasSubstr("ciphertext_and_tag_length is larger than "
                         "tag_length(), but either "
                         "plaintext or bytes_written is null.")));

  // Null aad with zero length.
  CRUNCHY_EXPECT_OK(
      crypter->Encrypt(nonce.get(), nonce_length, nullptr, 0, message.get(),
                       message_length, ciphertext_and_tag.get(),
                       ciphertext_and_tag_length, &ciphertext_bytes_written));
  CRUNCHY_EXPECT_OK(crypter->Decrypt(
      nonce.get(), nonce_length, nullptr, 0, ciphertext_and_tag.get(),
      ciphertext_and_tag_length, plaintext.get(), plaintext_length,
      &plaintext_bytes_written));
}

void RandomEncryptDecryptString(const CrypterFactory& factory,
                                size_t aad_length, size_t message_length,
                                bool corrupt_tag) {
  auto status_or_crypter = factory.Make(RandString(factory.GetKeyLength()));
  CRUNCHY_EXPECT_OK(status_or_crypter.status());
  std::unique_ptr<CrypterInterface> crypter =
      std::move(status_or_crypter.ValueOrDie());

  SCOPED_TRACE(absl::StrCat("aad_length=", aad_length,
                            " message_length=", message_length,
                            " nonce_length=", crypter->nonce_length(),
                            " tag_length=", crypter->tag_length()));
  size_t nonce_length = crypter->nonce_length();
  std::string nonce = RandString(nonce_length);
  std::string aad = RandString(aad_length);
  std::string message = RandString(message_length);

  // Test encryption
  auto status_or_ciphertext_and_tag = crypter->Encrypt(nonce, aad, message);
  CRUNCHY_EXPECT_OK(status_or_ciphertext_and_tag.status());
  std::string ciphertext_and_tag = status_or_ciphertext_and_tag.ValueOrDie();
  EXPECT_EQ(crypter->max_ciphertext_and_tag_length(message_length),
            ciphertext_and_tag.length());

  // Test decryption
  auto status_or_plaintext = crypter->Decrypt(nonce, aad, ciphertext_and_tag);
  CRUNCHY_EXPECT_OK(status_or_plaintext.status());
  std::string plaintext = status_or_plaintext.ValueOrDie();
  EXPECT_EQ(absl::BytesToHexString(message), absl::BytesToHexString(plaintext));

  if (corrupt_tag) {
    // Corrupt nonce
    if (nonce_length > 0) {
      auto corrupt_nonce = CopyAndAlterRandomByte(nonce);
      EXPECT_FALSE(
          crypter->Decrypt(corrupt_nonce, aad, ciphertext_and_tag).ok());
    }

    // Corrupt ciphertext_and_tag
    auto corrupt_ciphertext_and_tag =
        CopyAndAlterRandomByte(ciphertext_and_tag);
    EXPECT_FALSE(
        crypter->Decrypt(nonce, aad, corrupt_ciphertext_and_tag).ok());
  }
}

void RandomEncryptDecryptStringTest(const CrypterFactory& factory,
                                    size_t min_message_length,
                                    bool corrupt_tag) {
  size_t aad_length = BiasRandInt(1024);
  size_t message_length = BiasRandInt(1024) + min_message_length;
  RandomEncryptDecryptString(factory, aad_length, message_length, corrupt_tag);
  RandomEncryptDecryptString(factory, 0, message_length, corrupt_tag);
  RandomEncryptDecryptString(factory, aad_length, min_message_length,
                             corrupt_tag);
}

void EncryptionFailureStringTest(const CrypterFactory& factory) {
  auto status_or_crypter = factory.Make(RandString(factory.GetKeyLength()));
  CRUNCHY_EXPECT_OK(status_or_crypter.status());
  std::unique_ptr<CrypterInterface> crypter =
      std::move(status_or_crypter.ValueOrDie());

  size_t aad_length = 1024;
  size_t message_length = 1024;
  size_t nonce_length = crypter->nonce_length();
  std::string nonce = RandString(nonce_length);
  std::string aad = RandString(aad_length);
  std::string message = RandString(message_length);

  size_t ciphertext_and_tag_length =
      crypter->max_ciphertext_and_tag_length(message_length);
  auto ciphertext_and_tag = make_unique<uint8_t[]>(ciphertext_and_tag_length);

  // Empty nonce.
  if (crypter->nonce_length() > 0) {
    EXPECT_THAT(crypter->Encrypt("", aad, message),
                StatusIs(INVALID_ARGUMENT,
                         HasSubstr("Nonce buffer has the wrong length.")));
  }

  // Success.
  CRUNCHY_EXPECT_OK(crypter->Encrypt(nonce, aad, message).status());
}

void DecryptionFailureStringTest(CrypterInterface* crypter) {
  CRUNCHY_CHECK(crypter);
  size_t aad_length = 1024;
  size_t message_length = 1024;
  size_t nonce_length = crypter->nonce_length();
  std::string nonce = RandString(nonce_length);
  std::string aad = RandString(aad_length);
  std::string message = RandString(message_length);

  // Test encryption
  auto status_or_ciphertext_and_tag = crypter->Encrypt(nonce, aad, message);
  CRUNCHY_EXPECT_OK(status_or_ciphertext_and_tag.status());
  std::string ciphertext_and_tag = status_or_ciphertext_and_tag.ValueOrDie();
  EXPECT_EQ(crypter->max_ciphertext_and_tag_length(message_length),
            ciphertext_and_tag.length());

  // Empty nonce.
  if (crypter->nonce_length() > 0) {
    EXPECT_THAT(crypter->Decrypt("", aad, ciphertext_and_tag),
                StatusIs(INVALID_ARGUMENT,
                         HasSubstr("Nonce buffer has the wrong length.")));
  }

  // Empty ciphertext.
  if (crypter->tag_length() > 0) {
    EXPECT_THAT(
        crypter->Decrypt(nonce, aad, ""),
        StatusIs(
            INVALID_ARGUMENT,
            HasSubstr("ciphertext_and_tag_length is smaller than tag_length")));
  }
}

void VerifyTestVector(const CrypterFactory& factory,
                      const CrypterInterfaceTestVector& test_vector) {
  auto status_or_crypter = factory.Make(test_vector.key());
  CRUNCHY_EXPECT_OK(status_or_crypter.status());
  std::unique_ptr<CrypterInterface> crypter =
      std::move(status_or_crypter.ValueOrDie());

  // Test the std::string-based encryption interface.
  auto status_or_ciphertext_and_tag = crypter->Encrypt(
      test_vector.nonce(), test_vector.aad(), test_vector.plaintext());
  CRUNCHY_EXPECT_OK(status_or_ciphertext_and_tag.status());
  std::string ciphertext_and_tag = status_or_ciphertext_and_tag.ValueOrDie();
  EXPECT_EQ(absl::BytesToHexString(test_vector.ciphertext_and_tag()),
            absl::BytesToHexString(ciphertext_and_tag));

  // Test the byte-based encryption interface.
  size_t ciphertext_and_tag_length =
      crypter->max_ciphertext_and_tag_length(test_vector.plaintext().length());
  auto ciphertext_and_tag_bytes =
      make_unique<uint8_t[]>(ciphertext_and_tag_length);
  size_t ciphertext_bytes_written = 0;
  CRUNCHY_EXPECT_OK(crypter->Encrypt(
      reinterpret_cast<const uint8_t*>(test_vector.nonce().data()),
      test_vector.nonce().length(),
      reinterpret_cast<const uint8_t*>(test_vector.aad().data()),
      test_vector.aad().length(),
      reinterpret_cast<const uint8_t*>(test_vector.plaintext().data()),
      test_vector.plaintext().length(), ciphertext_and_tag_bytes.get(),
      ciphertext_and_tag_length, &ciphertext_bytes_written));
  EXPECT_EQ(ciphertext_bytes_written, ciphertext_and_tag_length);
  EXPECT_EQ(absl::BytesToHexString(test_vector.ciphertext_and_tag()),
            ToHex(ciphertext_and_tag_bytes.get(), ciphertext_and_tag_length));

  // Test the std::string-based decryption interface.
  auto status_or_plaintext = crypter->Decrypt(
      test_vector.nonce(), test_vector.aad(), test_vector.ciphertext_and_tag());
  CRUNCHY_EXPECT_OK(status_or_plaintext.status());
  std::string plaintext = status_or_plaintext.ValueOrDie();
  EXPECT_EQ(absl::BytesToHexString(test_vector.plaintext()),
            absl::BytesToHexString(plaintext));

  // Test the byte-based decryption interface.
  size_t plaintext_length =
      crypter->max_plaintext_length(ciphertext_and_tag_length);
  auto plaintext_bytes = make_unique<uint8_t[]>(plaintext_length);
  size_t plaintext_bytes_written = 0;
  CRUNCHY_EXPECT_OK(crypter->Decrypt(
      reinterpret_cast<const uint8_t*>(test_vector.nonce().data()),
      test_vector.nonce().length(),
      reinterpret_cast<const uint8_t*>(test_vector.aad().data()),
      test_vector.aad().length(),
      reinterpret_cast<const uint8_t*>(test_vector.ciphertext_and_tag().data()),
      test_vector.ciphertext_and_tag().length(), plaintext_bytes.get(),
      plaintext_length, &plaintext_bytes_written));
  EXPECT_EQ(absl::BytesToHexString(test_vector.plaintext()),
            ToHex(plaintext_bytes.get(), plaintext_bytes_written));
}

CrypterInterfaceTestVector GenerateTestVector(const CrypterFactory& factory) {
  std::string key = RandString(factory.GetKeyLength());

  auto status_or_crypter = factory.Make(key);
  CRUNCHY_EXPECT_OK(status_or_crypter.status());
  std::unique_ptr<CrypterInterface> crypter =
      std::move(status_or_crypter.ValueOrDie());

  size_t aad_magnatude = BiasRandInt(10);
  size_t aad_length = BiasRandInt(1 << aad_magnatude);
  size_t plaintext_magnatude = BiasRandInt(10);
  size_t plaintext_length = BiasRandInt(1 << plaintext_magnatude);

  std::string nonce = RandString(crypter->nonce_length());
  std::string aad = RandString(aad_length);
  std::string plaintext = RandString(plaintext_length);

  auto status_or_ciphertext = crypter->Encrypt(nonce, aad, plaintext);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());

  CrypterInterfaceTestVector test_vector;
  test_vector.set_key(key);
  test_vector.set_nonce(nonce);
  test_vector.set_aad(aad);
  test_vector.set_plaintext(plaintext);
  test_vector.set_ciphertext_and_tag(ciphertext);

  VerifyTestVector(factory, test_vector);
  return test_vector;
}

}  // namespace crunchy
