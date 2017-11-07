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

#include "crunchy/internal/bindings/crypto.h"

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "crunchy/internal/common/file.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/string_buffer.h"
#include "crunchy/internal/keyset/aead_crypting_key_registry.h"
#include "crunchy/internal/keyset/testdata/factory_test_vectors.pb.h"
#include "crunchy/internal/port/port.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/util/status.h"

namespace crunchy {
namespace {

using testing::StartsWith;

TEST(CrypterTest, UnparsableKeyset) {
  ccr_error error;
  ccr_error_init(&error);

  static const uint8_t malformed_keyset[] = "banana";
  ccr_crypter* c_crypter = ccr_crypter_new_from_serialized_keyset(
      malformed_keyset, sizeof(malformed_keyset), &error);
  EXPECT_EQ(c_crypter, nullptr);
  EXPECT_THAT(error.message, StartsWith("Couldn't parse keyset"));
  ccr_error_cleanup(&error);
}

TEST(CrypterTest, NullKeyset) {
  ccr_error error;
  ccr_error_init(&error);

  ccr_crypter* c_crypter =
      ccr_crypter_new_from_serialized_keyset(nullptr, 42, &error);
  EXPECT_EQ(c_crypter, nullptr);
  EXPECT_THAT(error.message, StartsWith("keyset_bytes is null"));
  ccr_error_cleanup(&error);
}

void VerifyTestVector(const CrypterFactoryTestVector& test_vector) {
  ccr_error error;

  std::string serialized_keyset = test_vector.keyset().SerializeAsString();

  ccr_error_init(&error);
  ccr_crypter* c_crypter = ccr_crypter_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  // Encrypt/Decrypt the test vector's plaintext
  StringBuffer ciphertext(ccr_crypter_max_ciphertext_length(
      c_crypter, test_vector.plaintext().length()));
  ASSERT_NE(ciphertext.length(), 0);

  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_crypter_encrypt(
          c_crypter,
          reinterpret_cast<const uint8_t*>(test_vector.plaintext().data()),
          test_vector.plaintext().length(),
          reinterpret_cast<const uint8_t*>(test_vector.aad().data()),
          test_vector.aad().length(), ciphertext.data(), ciphertext.length(),
          ciphertext.mutable_limit(), &error),
      1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer decrypted(
      ccr_crypter_max_plaintext_length(c_crypter, ciphertext.length()));

  ccr_error_init(&error);
  EXPECT_EQ(ccr_crypter_decrypt(
                c_crypter, ciphertext.data(), ciphertext.length(),
                reinterpret_cast<const uint8_t*>(test_vector.aad().data()),
                test_vector.aad().length(), decrypted.data(),
                decrypted.length(), decrypted.mutable_limit(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  EXPECT_EQ(test_vector.plaintext(), decrypted.as_string_view());

  // Decrypt the test vector's ciphertext
  decrypted = StringBuffer(ccr_crypter_max_plaintext_length(
      c_crypter, test_vector.ciphertext().length()));

  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_crypter_decrypt(
          c_crypter,
          reinterpret_cast<const uint8_t*>(test_vector.ciphertext().data()),
          test_vector.ciphertext().length(),
          reinterpret_cast<const uint8_t*>(test_vector.aad().data()),
          test_vector.aad().length(), decrypted.data(), decrypted.length(),
          decrypted.mutable_limit(), &error),
      1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  EXPECT_EQ(test_vector.plaintext(), decrypted.as_string_view());
  ccr_crypter_free(c_crypter);
}

const CrypterFactoryTestVectors& GetCrypterFactoryTestVectors() {
  static const CrypterFactoryTestVectors& test_vectors = []() {
    CrypterFactoryTestVectors test_vectors;
    std::string serialized_test_vectors;
    CRUNCHY_CHECK_OK(
        GetFile("crunchy/internal/keyset/testdata/"
                "crypter_factory_test_vectors.proto.bin",
                &serialized_test_vectors));
    CRUNCHY_CHECK(test_vectors.ParseFromString(serialized_test_vectors));
    return test_vectors;
  }();
  return test_vectors;
}

std::string GetSerializedCrypterKeyset() {
  std::string serialized_keyset = GetCrypterFactoryTestVectors()
                                 .test_vector(0)
                                 .keyset()
                                 .SerializeAsString();
  return serialized_keyset;
}

TEST(CrypterTest, TestVectors) {
  const CrypterFactoryTestVectors& test_vectors =
      GetCrypterFactoryTestVectors();
  for (const CrypterFactoryTestVector& test_vector :
       test_vectors.test_vector()) {
    VerifyTestVector(test_vector);
  }
}

TEST(CrypterTest, EncryptDecryptNull) {
  ccr_error error;

  std::string serialized_keyset = GetSerializedCrypterKeyset();

  ccr_error_init(&error);
  ccr_crypter* c_crypter = ccr_crypter_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer plaintext("banana");
  StringBuffer aad("apple");
  StringBuffer ciphertext(
      ccr_crypter_max_ciphertext_length(c_crypter, plaintext.length()));
  ASSERT_NE(ciphertext.length(), 0);

  // Null self with encrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_crypter_encrypt(nullptr, plaintext.data(), plaintext.length(),
                                aad.data(), aad.length(), ciphertext.data(),
                                ciphertext.length(), ciphertext.mutable_limit(),
                                &error),
            0);
  EXPECT_THAT(error.message, StartsWith("ccr_crypter_encrypt: self is null"));
  ccr_error_cleanup(&error);

  // Null plaintext with encrypt
  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_crypter_encrypt(c_crypter, nullptr, plaintext.length(), aad.data(),
                          aad.length(), ciphertext.data(), ciphertext.length(),
                          ciphertext.mutable_limit(), &error),
      0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_crypter_encrypt: plaintext buffer is null"));
  ccr_error_cleanup(&error);

  // Null aad with encrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_crypter_encrypt(c_crypter, plaintext.data(), plaintext.length(),
                                nullptr, aad.length(), ciphertext.data(),
                                ciphertext.length(), ciphertext.mutable_limit(),
                                &error),
            0);
  EXPECT_THAT(
      error.message,
      StartsWith("ccr_crypter_encrypt: associated_data buffer is null"));
  ccr_error_cleanup(&error);

  // Null ciphertext with encrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_crypter_encrypt(c_crypter, plaintext.data(), plaintext.length(),
                                aad.data(), aad.length(), nullptr,
                                ciphertext.length(), ciphertext.mutable_limit(),
                                &error),
            0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_crypter_encrypt: ciphertext buffer is null"));
  ccr_error_cleanup(&error);

  // Null bytes_written with encrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_crypter_encrypt(c_crypter, plaintext.data(), plaintext.length(),
                                aad.data(), aad.length(), ciphertext.data(),
                                ciphertext.length(), nullptr, &error),
            0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_crypter_encrypt: bytes_written is null"));
  ccr_error_cleanup(&error);

  // Successful encrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_crypter_encrypt(c_crypter, plaintext.data(), plaintext.length(),
                                aad.data(), aad.length(), ciphertext.data(),
                                ciphertext.length(), ciphertext.mutable_limit(),
                                &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer decrypted(
      ccr_crypter_max_plaintext_length(c_crypter, ciphertext.length()));

  // Null self with decrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_crypter_decrypt(nullptr, ciphertext.data(), ciphertext.length(),
                                aad.data(), aad.length(), decrypted.data(),
                                decrypted.length(), decrypted.mutable_limit(),
                                &error),
            0);
  EXPECT_THAT(error.message, StartsWith("ccr_crypter_decrypt: self is null"));
  ccr_error_cleanup(&error);

  // Null ciphertext with decrypt
  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_crypter_decrypt(c_crypter, nullptr, ciphertext.length(), aad.data(),
                          aad.length(), decrypted.data(), decrypted.length(),
                          decrypted.mutable_limit(), &error),
      0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_crypter_decrypt: ciphertext buffer is null"));
  ccr_error_cleanup(&error);

  // Null aad with decrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_crypter_decrypt(c_crypter, ciphertext.data(),
                                ciphertext.length(), nullptr, aad.length(),
                                decrypted.data(), decrypted.length(),
                                decrypted.mutable_limit(), &error),
            0);
  EXPECT_THAT(
      error.message,
      StartsWith("ccr_crypter_decrypt: associated_data buffer is null"));
  ccr_error_cleanup(&error);

  // Null plaintext with decrypt
  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_crypter_decrypt(c_crypter, ciphertext.data(), ciphertext.length(),
                          aad.data(), aad.length(), nullptr, decrypted.length(),
                          decrypted.mutable_limit(), &error),
      0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_crypter_decrypt: plaintext buffer is null"));
  ccr_error_cleanup(&error);

  // Null bytes_written with decrypt
  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_crypter_decrypt(c_crypter, ciphertext.data(), ciphertext.length(),
                          aad.data(), aad.length(), decrypted.data(),
                          decrypted.length(), nullptr, &error),
      0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_crypter_decrypt: bytes_written is null"));
  ccr_error_cleanup(&error);

  // Successful decrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_crypter_decrypt(c_crypter, ciphertext.data(),
                                ciphertext.length(), aad.data(), aad.length(),
                                decrypted.data(), decrypted.length(),
                                decrypted.mutable_limit(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  EXPECT_EQ(plaintext.as_string_view(), decrypted.as_string_view());
  ccr_crypter_free(c_crypter);
}

TEST(CrypterTest, EncryptOutputBufferTooSmall) {
  ccr_error error;

  std::string serialized_keyset = GetSerializedCrypterKeyset();

  ccr_error_init(&error);
  ccr_crypter* c_crypter = ccr_crypter_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer plaintext("banana");
  StringBuffer aad("apple");
  StringBuffer ciphertext(
      ccr_crypter_max_ciphertext_length(c_crypter, plaintext.length()));
  ASSERT_NE(ciphertext.length(), 0);
  ccr_error_init(&error);
  EXPECT_EQ(ccr_crypter_encrypt(c_crypter, plaintext.data(), plaintext.length(),
                                aad.data(), aad.length(), ciphertext.data(),
                                ciphertext.length(), ciphertext.mutable_limit(),
                                &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  ccr_error_init(&error);
  EXPECT_EQ(ccr_crypter_encrypt(c_crypter, plaintext.data(), plaintext.length(),
                                aad.data(), aad.length(), ciphertext.data(),
                                ciphertext.length() / 2,
                                ciphertext.mutable_limit(), &error),
            0);

  EXPECT_THAT(error.message, StartsWith("ciphertext buffer is too short"));
  ccr_error_cleanup(&error);
  ccr_crypter_free(c_crypter);
}

TEST(CrypterTest, DecryptOutputBufferTooSmall) {
  ccr_error error;

  std::string serialized_keyset = GetSerializedCrypterKeyset();

  ccr_error_init(&error);
  ccr_crypter* c_crypter = ccr_crypter_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer plaintext("banana");
  StringBuffer aad("apple");
  StringBuffer ciphertext(
      ccr_crypter_max_ciphertext_length(c_crypter, plaintext.length()));
  ASSERT_NE(ciphertext.length(), 0);
  ccr_error_init(&error);
  EXPECT_EQ(ccr_crypter_encrypt(c_crypter, plaintext.data(), plaintext.length(),
                                aad.data(), aad.length(), ciphertext.data(),
                                ciphertext.length(), ciphertext.mutable_limit(),
                                &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer decrypted(
      ccr_crypter_max_plaintext_length(c_crypter, ciphertext.length()));
  ccr_error_init(&error);
  EXPECT_EQ(ccr_crypter_decrypt(c_crypter, ciphertext.data(),
                                ciphertext.length(), aad.data(), aad.length(),
                                decrypted.data(), decrypted.length(),
                                decrypted.mutable_limit(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  EXPECT_EQ(plaintext.as_string_view(), decrypted.as_string_view());

  ciphertext.data()[ciphertext.length() - 1] ^= 0x01;
  decrypted = StringBuffer(
      ccr_crypter_max_plaintext_length(c_crypter, ciphertext.length()));
  ccr_error_init(&error);
  EXPECT_EQ(ccr_crypter_decrypt(c_crypter, ciphertext.data(),
                                ciphertext.length(), aad.data(), aad.length(),
                                decrypted.data(), decrypted.length(),
                                decrypted.mutable_limit(), &error),
            0);
  EXPECT_NE(error.message, nullptr);
  ccr_error_cleanup(&error);
  ccr_error_init(&error);
  ciphertext.data()[ciphertext.length() - 1] ^= 0x01;

  decrypted = StringBuffer(
      ccr_crypter_max_plaintext_length(c_crypter, ciphertext.length()));
  EXPECT_EQ(ccr_crypter_decrypt(c_crypter, ciphertext.data(),
                                ciphertext.length(), aad.data(), aad.length(),
                                decrypted.data(), plaintext.length() / 2,
                                decrypted.mutable_limit(), &error),
            0);
  EXPECT_THAT(error.message, StartsWith("plaintext buffer is too short"));
  ccr_error_cleanup(&error);
  ccr_crypter_free(c_crypter);
}

TEST(MacTest, UnparsableKeyset) {
  ccr_error error;
  ccr_error_init(&error);

  static const uint8_t malformed_keyset[] = "banana";
  ccr_macer* c_mac = ccr_macer_new_from_serialized_keyset(
      malformed_keyset, sizeof(malformed_keyset), &error);
  EXPECT_EQ(c_mac, nullptr);
  EXPECT_THAT(error.message, StartsWith("Couldn't parse keyset"));
  ccr_error_cleanup(&error);
}

TEST(MacTest, NullKeyset) {
  ccr_error error;
  ccr_error_init(&error);

  ccr_macer* c_mac = ccr_macer_new_from_serialized_keyset(nullptr, 42, &error);
  EXPECT_EQ(c_mac, nullptr);
  EXPECT_THAT(error.message, StartsWith("keyset_bytes is null"));
  ccr_error_cleanup(&error);
}

void VerifyTestVector(const MacerFactoryTestVector& test_vector) {
  ccr_error error;

  std::string serialized_keyset = test_vector.keyset().SerializeAsString();

  ccr_error_init(&error);
  ccr_macer* c_mac = ccr_macer_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  // Sign/verify the test vector's message
  {
    const std::string& message = test_vector.message();
    StringBuffer signature(ccr_macer_max_signature_length(c_mac));

    ccr_error_init(&error);
    EXPECT_EQ(
        ccr_macer_sign(c_mac, reinterpret_cast<const uint8_t*>(message.data()),
                       message.length(), signature.data(), signature.length(),
                       signature.mutable_limit(), &error),
        1);
    EXPECT_EQ(error.message, nullptr) << error.message;
    ccr_error_cleanup(&error);

    ccr_error_init(&error);
    EXPECT_EQ(ccr_macer_verify(c_mac,
                               reinterpret_cast<const uint8_t*>(message.data()),
                               message.length(), signature.data(),
                               signature.length(), &error),
              1);
    EXPECT_EQ(error.message, nullptr) << error.message;
    ccr_error_cleanup(&error);
  }

  // Verify the test vector's signature
  {
    const std::string& message = test_vector.message();
    const std::string& signature = test_vector.signature();

    ccr_error_init(&error);
    EXPECT_EQ(ccr_macer_verify(
                  c_mac, reinterpret_cast<const uint8_t*>(message.data()),
                  message.length(),
                  reinterpret_cast<const uint8_t*>(signature.data()),
                  signature.length(), &error),
              1);
    EXPECT_EQ(error.message, nullptr) << error.message;
    ccr_error_cleanup(&error);
  }
  ccr_macer_free(c_mac);
}

const MacerFactoryTestVectors& GetMacerFactoryTestVectors() {
  static const MacerFactoryTestVectors& test_vectors = []() {
    MacerFactoryTestVectors test_vectors;
    std::string serialized_test_vectors;
    CRUNCHY_CHECK_OK(
        GetFile("crunchy/internal/keyset/testdata/"
                "macer_factory_test_vectors.proto.bin",
                &serialized_test_vectors));
    CRUNCHY_CHECK(test_vectors.ParseFromString(serialized_test_vectors));
    return test_vectors;
  }();
  return test_vectors;
}

std::string GetSerializedMacerKeyset() {
  std::string serialized_keyset =
      GetMacerFactoryTestVectors().test_vector(0).keyset().SerializeAsString();
  return serialized_keyset;
}

TEST(MacerTest, TestVectors) {
  const MacerFactoryTestVectors& test_vectors = GetMacerFactoryTestVectors();
  for (const MacerFactoryTestVector& test_vector : test_vectors.test_vector()) {
    VerifyTestVector(test_vector);
  }
}

TEST(MacTest, SignVerifyNull) {
  ccr_error error;

  std::string serialized_keyset = GetSerializedMacerKeyset();

  ccr_error_init(&error);
  ccr_macer* c_mac = ccr_macer_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer message("banana");
  StringBuffer signature(ccr_macer_max_signature_length(c_mac));

  // Null self with sign
  ccr_error_init(&error);
  EXPECT_EQ(ccr_macer_sign(nullptr, message.data(), message.length(),
                           signature.data(), signature.length(),
                           signature.mutable_limit(), &error),
            0);
  EXPECT_THAT(error.message, StartsWith("ccr_macer_sign: self is null"));
  ccr_error_cleanup(&error);

  // Null message buffer with sign
  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_macer_sign(c_mac, nullptr, message.length(), signature.data(),
                     signature.length(), signature.mutable_limit(), &error),
      0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_macer_sign: message buffer is null"));
  ccr_error_cleanup(&error);

  // Null signature buffer with sign
  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_macer_sign(c_mac, message.data(), message.length(), nullptr,
                     signature.length(), signature.mutable_limit(), &error),
      0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_macer_sign: signature buffer is null"));
  ccr_error_cleanup(&error);

  // Null bytes_written with sign
  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_macer_sign(c_mac, message.data(), message.length(), signature.data(),
                     signature.length(), nullptr, &error),
      0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_macer_sign: bytes_written is null"));
  ccr_error_cleanup(&error);

  // Successful sign
  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_macer_sign(c_mac, message.data(), message.length(), signature.data(),
                     signature.length(), signature.mutable_limit(), &error),
      1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  // Null self with verify
  ccr_error_init(&error);
  EXPECT_EQ(ccr_macer_verify(nullptr, message.data(), message.length(),
                             signature.data(), signature.length(), &error),
            0);
  EXPECT_THAT(error.message, StartsWith("ccr_macer_verify: self is null"));
  ccr_error_cleanup(&error);

  // Null message buffer with verify
  ccr_error_init(&error);
  EXPECT_EQ(ccr_macer_verify(c_mac, nullptr, message.length(), signature.data(),
                             signature.length(), &error),
            0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_macer_verify: message buffer is null"));
  ccr_error_cleanup(&error);

  // Null signature buffer with verify
  ccr_error_init(&error);
  EXPECT_EQ(ccr_macer_verify(c_mac, message.data(), message.length(), nullptr,
                             signature.length(), &error),
            0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_macer_verify: signature buffer is null"));
  ccr_error_cleanup(&error);

  // Successful verify
  ccr_error_init(&error);
  EXPECT_EQ(ccr_macer_verify(c_mac, message.data(), message.length(),
                             signature.data(), signature.length(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_macer_free(c_mac);
}

TEST(MacTest, SignVerifyBadSignature) {
  ccr_error error;

  std::string serialized_keyset = GetSerializedMacerKeyset();

  ccr_error_init(&error);
  ccr_macer* c_mac = ccr_macer_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer message("banana");
  StringBuffer signature(ccr_macer_max_signature_length(c_mac));
  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_macer_sign(c_mac, message.data(), message.length(), signature.data(),
                     signature.length(), signature.mutable_limit(), &error),
      1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_error_init(&error);

  EXPECT_EQ(ccr_macer_verify(c_mac, message.data(), message.length(),
                             signature.data(), signature.length(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_error_init(&error);

  signature.data()[signature.length() - 1] ^= 0x01;
  EXPECT_EQ(ccr_macer_verify(c_mac, message.data(), message.length(),
                             signature.data(), signature.length(), &error),
            0);
  EXPECT_NE(error.message, nullptr);
  ccr_error_cleanup(&error);
  ccr_error_init(&error);
  signature.data()[signature.length() - 1] ^= 0x01;

  message.data()[0] ^= 0x01;
  EXPECT_EQ(ccr_macer_verify(c_mac, message.data(), message.length(),
                             signature.data(), signature.length(), &error),
            0);
  EXPECT_NE(error.message, nullptr);
  ccr_error_cleanup(&error);
  message.data()[0] ^= 0x01;
  ccr_macer_free(c_mac);
}

TEST(MacTest, SignVerifySignatureBufferTooSmall) {
  ccr_error error;

  std::string serialized_keyset = GetSerializedMacerKeyset();

  ccr_error_init(&error);
  ccr_macer* c_mac = ccr_macer_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer message("banana");
  StringBuffer signature(ccr_macer_max_signature_length(c_mac));
  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_macer_sign(c_mac, message.data(), message.length(), signature.data(),
                     signature.length(), signature.mutable_limit(), &error),
      1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_error_init(&error);

  EXPECT_EQ(ccr_macer_verify(c_mac, message.data(), message.length(),
                             signature.data(), signature.length(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_error_init(&error);

  EXPECT_EQ(
      ccr_macer_sign(c_mac, message.data(), message.length(), signature.data(),
                     1, signature.mutable_limit(), &error),
      0);
  EXPECT_THAT(error.message, StartsWith("signature buffer is too short"));
  ccr_error_cleanup(&error);
  ccr_macer_free(c_mac);
}

TEST(SignerTest, UnparsableKeyset) {
  ccr_error error;
  ccr_error_init(&error);

  static const uint8_t malformed_keyset[] = "banana";
  ccr_signer* c_signer = ccr_signer_new_from_serialized_keyset(
      malformed_keyset, sizeof(malformed_keyset), &error);
  EXPECT_EQ(c_signer, nullptr);
  EXPECT_THAT(error.message, StartsWith("Couldn't parse keyset"));
  ccr_error_cleanup(&error);

  ccr_error_init(&error);
  ccr_verifier* c_verifier = ccr_verifier_new_from_serialized_keyset(
      malformed_keyset, sizeof(malformed_keyset), &error);
  EXPECT_EQ(c_verifier, nullptr);
  EXPECT_THAT(error.message, StartsWith("Couldn't parse keyset"));
  ccr_error_cleanup(&error);
}

TEST(SignerTest, NullKeyset) {
  ccr_error error;

  ccr_error_init(&error);
  ccr_signer* c_signer =
      ccr_signer_new_from_serialized_keyset(nullptr, 42, &error);
  EXPECT_EQ(c_signer, nullptr);
  EXPECT_THAT(error.message, StartsWith("keyset_bytes is null"));
  ccr_error_cleanup(&error);

  ccr_error_init(&error);
  ccr_verifier* c_verifier =
      ccr_verifier_new_from_serialized_keyset(nullptr, 42, &error);
  EXPECT_EQ(c_verifier, nullptr);
  EXPECT_THAT(error.message, StartsWith("keyset_bytes is null"));
  ccr_error_cleanup(&error);
}

void VerifyTestVector(const SignerFactoryTestVector& test_vector) {
  ccr_error error;

  std::string serialized_keyset = test_vector.private_keyset().SerializeAsString();

  ccr_error_init(&error);
  ccr_signer* c_signer = ccr_signer_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  serialized_keyset = test_vector.public_keyset().SerializeAsString();

  ccr_error_init(&error);
  ccr_verifier* c_verifier = ccr_verifier_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  // Sign/verify the test vector's message
  {
    const std::string& message = test_vector.message();
    StringBuffer signature(ccr_signer_max_signature_length(c_signer));

    ccr_error_init(&error);
    EXPECT_EQ(ccr_signer_sign(
                  c_signer, reinterpret_cast<const uint8_t*>(message.data()),
                  message.length(), signature.data(), signature.length(),
                  signature.mutable_limit(), &error),
              1);
    EXPECT_EQ(error.message, nullptr) << error.message;
    ccr_error_cleanup(&error);

    ccr_error_init(&error);
    EXPECT_EQ(
        ccr_verifier_verify(
            c_verifier, reinterpret_cast<const uint8_t*>(message.data()),
            message.length(), signature.data(), signature.length(), &error),
        1);
    EXPECT_EQ(error.message, nullptr) << error.message;
    ccr_error_cleanup(&error);
  }

  // Verify the test vector's signature
  {
    const std::string& message = test_vector.message();
    const std::string& signature = test_vector.signature();

    ccr_error_init(&error);
    EXPECT_EQ(ccr_verifier_verify(
                  c_verifier, reinterpret_cast<const uint8_t*>(message.data()),
                  message.length(),
                  reinterpret_cast<const uint8_t*>(signature.data()),
                  signature.length(), &error),
              1);
    EXPECT_EQ(error.message, nullptr) << error.message;
    ccr_error_cleanup(&error);
  }
  ccr_signer_free(c_signer);
  ccr_verifier_free(c_verifier);
}

const SignerFactoryTestVectors& GetSignerFactoryTestVectors() {
  static const SignerFactoryTestVectors& test_vectors = []() {
    SignerFactoryTestVectors test_vectors;
    std::string serialized_test_vectors;
    CRUNCHY_CHECK_OK(
        GetFile("crunchy/internal/keyset/testdata/"
                "signer_factory_test_vectors.proto.bin",
                &serialized_test_vectors));
    CRUNCHY_CHECK(test_vectors.ParseFromString(serialized_test_vectors));
    return test_vectors;
  }();
  return test_vectors;
}

std::string GetSerializedSignerKeyset() {
  std::string serialized_keyset = GetSignerFactoryTestVectors()
                                 .test_vector(0)
                                 .private_keyset()
                                 .SerializeAsString();
  return serialized_keyset;
}

std::string GetSerializedVerifiererKeyset() {
  std::string serialized_keyset = GetSignerFactoryTestVectors()
                                 .test_vector(0)
                                 .public_keyset()
                                 .SerializeAsString();
  return serialized_keyset;
}

TEST(SignerTest, TestVectors) {
  const SignerFactoryTestVectors& test_vectors = GetSignerFactoryTestVectors();
  for (const SignerFactoryTestVector& test_vector :
       test_vectors.test_vector()) {
    VerifyTestVector(test_vector);
  }
}

TEST(SignerTest, SignVerifyNull) {
  ccr_error error;

  std::string serialized_keyset = GetSerializedSignerKeyset();

  ccr_error_init(&error);
  ccr_signer* c_signer = ccr_signer_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  serialized_keyset = GetSerializedVerifiererKeyset();

  ccr_error_init(&error);
  ccr_verifier* c_verifier = ccr_verifier_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer message("banana");
  StringBuffer signature(ccr_signer_max_signature_length(c_signer));

  // Null self with sign
  ccr_error_init(&error);
  EXPECT_EQ(ccr_signer_sign(nullptr, message.data(), message.length(),
                            signature.data(), signature.length(),
                            signature.mutable_limit(), &error),
            0);
  EXPECT_THAT(error.message, StartsWith("ccr_signer_sign: self is null"));
  ccr_error_cleanup(&error);

  // Null message buffer with sign
  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_signer_sign(c_signer, nullptr, message.length(), signature.data(),
                      signature.length(), signature.mutable_limit(), &error),
      0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_signer_sign: message buffer is null"));
  ccr_error_cleanup(&error);

  // Null signature buffer with sign
  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_signer_sign(c_signer, message.data(), message.length(), nullptr,
                      signature.length(), signature.mutable_limit(), &error),
      0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_signer_sign: signature buffer is null"));
  ccr_error_cleanup(&error);

  // Null bytes_written with sign
  ccr_error_init(&error);
  EXPECT_EQ(
      ccr_signer_sign(c_signer, message.data(), message.length(),
                      signature.data(), signature.length(), nullptr, &error),
      0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_signer_sign: bytes_written is null"));
  ccr_error_cleanup(&error);

  // Successful sign
  ccr_error_init(&error);
  EXPECT_EQ(ccr_signer_sign(c_signer, message.data(), message.length(),
                            signature.data(), signature.length(),
                            signature.mutable_limit(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  // Null self with verify
  ccr_error_init(&error);
  EXPECT_EQ(ccr_verifier_verify(nullptr, message.data(), message.length(),
                                signature.data(), signature.length(), &error),
            0);
  EXPECT_THAT(error.message, StartsWith("ccr_verifier_verify: self is null"));
  ccr_error_cleanup(&error);

  // Null message buffer with verify
  ccr_error_init(&error);
  EXPECT_EQ(ccr_verifier_verify(c_verifier, nullptr, message.length(),
                                signature.data(), signature.length(), &error),
            0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_verifier_verify: message buffer is null"));
  ccr_error_cleanup(&error);

  // Null signature buffer with verify
  ccr_error_init(&error);
  EXPECT_EQ(ccr_verifier_verify(c_verifier, message.data(), message.length(),
                                nullptr, signature.length(), &error),
            0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_verifier_verify: signature buffer is null"));
  ccr_error_cleanup(&error);

  // Sucessful verify
  ccr_error_init(&error);
  EXPECT_EQ(ccr_verifier_verify(c_verifier, message.data(), message.length(),
                                signature.data(), signature.length(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_signer_free(c_signer);
  ccr_verifier_free(c_verifier);
}

TEST(SignerTest, SignVerifyBadSignature) {
  ccr_error error;

  std::string serialized_keyset = GetSerializedSignerKeyset();

  ccr_error_init(&error);
  ccr_signer* c_signer = ccr_signer_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  serialized_keyset = GetSerializedVerifiererKeyset();

  ccr_error_init(&error);
  ccr_verifier* c_verifier = ccr_verifier_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer message("banana");
  StringBuffer signature(ccr_signer_max_signature_length(c_signer));
  ccr_error_init(&error);
  EXPECT_EQ(ccr_signer_sign(c_signer, message.data(), message.length(),
                            signature.data(), signature.length(),
                            signature.mutable_limit(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_error_init(&error);

  EXPECT_EQ(ccr_verifier_verify(c_verifier, message.data(), message.length(),
                                signature.data(), signature.length(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_error_init(&error);

  signature.data()[signature.length() - 1] ^= 0x01;
  EXPECT_EQ(ccr_verifier_verify(c_verifier, message.data(), message.length(),
                                signature.data(), signature.length(), &error),
            0);
  EXPECT_NE(error.message, nullptr);
  ccr_error_cleanup(&error);
  ccr_error_init(&error);
  signature.data()[signature.length() - 1] ^= 0x01;

  message.data()[0] ^= 0x01;
  EXPECT_EQ(ccr_verifier_verify(c_verifier, message.data(), message.length(),
                                signature.data(), signature.length(), &error),
            0);
  EXPECT_NE(error.message, nullptr);
  ccr_error_cleanup(&error);
  message.data()[0] ^= 0x01;
  ccr_signer_free(c_signer);
  ccr_verifier_free(c_verifier);
}

TEST(SignerTest, SignVerifySignatureBufferTooSmall) {
  ccr_error error;

  std::string serialized_keyset = GetSerializedSignerKeyset();

  ccr_error_init(&error);
  ccr_signer* c_signer = ccr_signer_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  serialized_keyset = GetSerializedVerifiererKeyset();

  ccr_error_init(&error);
  ccr_verifier* c_verifier = ccr_verifier_new_from_serialized_keyset(
      reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
      serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer message("banana");
  StringBuffer signature(ccr_signer_max_signature_length(c_signer));
  ccr_error_init(&error);
  EXPECT_EQ(ccr_signer_sign(c_signer, message.data(), message.length(),
                            signature.data(), signature.length(),
                            signature.mutable_limit(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_error_init(&error);

  EXPECT_EQ(ccr_verifier_verify(c_verifier, message.data(), message.length(),
                                signature.data(), signature.length(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_error_init(&error);

  EXPECT_EQ(
      ccr_signer_sign(c_signer, message.data(), message.length(),
                      signature.data(), 1, signature.mutable_limit(), &error),
      0);
  EXPECT_THAT(error.message, StartsWith("signature buffer is too short"));
  ccr_error_cleanup(&error);
  ccr_signer_free(c_signer);
  ccr_verifier_free(c_verifier);
}

TEST(HybridTest, UnparsableKeyset) {
  ccr_error error;
  ccr_error_init(&error);

  static const uint8_t malformed_keyset[] = "banana";
  ccr_hybrid_encrypter* c_hybrid_encrypter =
      ccr_hybrid_encrypter_new_from_serialized_keyset(
          malformed_keyset, sizeof(malformed_keyset), &error);
  EXPECT_EQ(c_hybrid_encrypter, nullptr);
  EXPECT_THAT(error.message, StartsWith("Couldn't parse keyset"));
  ccr_error_cleanup(&error);

  ccr_error_init(&error);
  ccr_hybrid_decrypter* c_hybrid_decrypter =
      ccr_hybrid_decrypter_new_from_serialized_keyset(
          malformed_keyset, sizeof(malformed_keyset), &error);
  EXPECT_EQ(c_hybrid_decrypter, nullptr);
  EXPECT_THAT(error.message, StartsWith("Couldn't parse keyset"));
  ccr_error_cleanup(&error);
}

TEST(HybridTest, NullKeyset) {
  ccr_error error;

  ccr_error_init(&error);
  ccr_hybrid_encrypter* c_hybrid_encrypter =
      ccr_hybrid_encrypter_new_from_serialized_keyset(nullptr, 42, &error);
  EXPECT_EQ(c_hybrid_encrypter, nullptr);
  EXPECT_THAT(error.message, StartsWith("keyset_bytes is null"));
  ccr_error_cleanup(&error);

  ccr_error_init(&error);
  ccr_hybrid_decrypter* c_hybrid_decrypter =
      ccr_hybrid_decrypter_new_from_serialized_keyset(nullptr, 42, &error);
  EXPECT_EQ(c_hybrid_decrypter, nullptr);
  EXPECT_THAT(error.message, StartsWith("keyset_bytes is null"));
  ccr_error_cleanup(&error);
}

void VerifyTestVector(const HybridCrypterFactoryTestVector& test_vector) {
  ccr_error error;

  std::string serialized_keyset = test_vector.public_keyset().SerializeAsString();

  ccr_error_init(&error);
  ccr_hybrid_encrypter* c_hybrid_encrypter =
      ccr_hybrid_encrypter_new_from_serialized_keyset(
          reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
          serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  serialized_keyset = test_vector.private_keyset().SerializeAsString();

  ccr_error_init(&error);
  ccr_hybrid_decrypter* c_hybrid_decrypter =
      ccr_hybrid_decrypter_new_from_serialized_keyset(
          reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
          serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  // Encrypt/decrypt the test vector's plaintext
  {
    const std::string& plaintext = test_vector.plaintext();
    StringBuffer ciphertext(ccr_hybrid_encrypter_max_ciphertext_length(
        c_hybrid_encrypter, plaintext.length()));
    ASSERT_NE(ciphertext.length(), 0);
    EXPECT_EQ(ccr_hybrid_encrypter_encrypt(
                  c_hybrid_encrypter,
                  reinterpret_cast<const uint8_t*>(plaintext.data()),
                  plaintext.length(), ciphertext.data(), ciphertext.length(),
                  ciphertext.mutable_limit(), &error),
              1);
    EXPECT_EQ(error.message, nullptr) << error.message;
    ccr_error_cleanup(&error);
    ccr_error_init(&error);

    StringBuffer decrypted(ccr_hybrid_decrypter_max_plaintext_length(
        c_hybrid_decrypter, ciphertext.length()));

    EXPECT_EQ(ccr_hybrid_decrypter_decrypt(
                  c_hybrid_decrypter, ciphertext.data(), ciphertext.length(),
                  decrypted.data(), decrypted.length(),
                  decrypted.mutable_limit(), &error),
              1);
    EXPECT_EQ(error.message, nullptr) << error.message;
    ccr_error_cleanup(&error);
    EXPECT_EQ(plaintext, decrypted.as_string_view());
  }

  // Decrypt the test vector's ciphertext
  {
    const std::string& plaintext = test_vector.plaintext();
    const std::string& ciphertext = test_vector.ciphertext();

    StringBuffer decrypted(ccr_hybrid_decrypter_max_plaintext_length(
        c_hybrid_decrypter, ciphertext.length()));

    EXPECT_EQ(ccr_hybrid_decrypter_decrypt(
                  c_hybrid_decrypter,
                  reinterpret_cast<const uint8_t*>(ciphertext.data()),
                  ciphertext.length(), decrypted.data(), decrypted.length(),
                  decrypted.mutable_limit(), &error),
              1);
    EXPECT_EQ(error.message, nullptr) << error.message;
    ccr_error_cleanup(&error);
    EXPECT_EQ(plaintext, decrypted.as_string_view());
  }
  ccr_hybrid_decrypter_free(c_hybrid_decrypter);
  ccr_hybrid_encrypter_free(c_hybrid_encrypter);
}

const HybridCrypterFactoryTestVectors& GetHybridCrypterFactoryTestVectors() {
  static const HybridCrypterFactoryTestVectors& test_vectors = []() {
    HybridCrypterFactoryTestVectors test_vectors;
    std::string serialized_test_vectors;
    CRUNCHY_CHECK_OK(
        GetFile("crunchy/internal/keyset/testdata/"
                "hybrid_crypter_factory_test_vectors.proto.bin",
                &serialized_test_vectors));
    CRUNCHY_CHECK(test_vectors.ParseFromString(serialized_test_vectors));
    return test_vectors;
  }();
  return test_vectors;
}

std::string GetSerializedHybridEncryptererKeyset() {
  std::string serialized_keyset = GetHybridCrypterFactoryTestVectors()
                                 .test_vector(0)
                                 .public_keyset()
                                 .SerializeAsString();
  return serialized_keyset;
}

std::string GetSerializedHybridDecrypterKeyset() {
  std::string serialized_keyset = GetHybridCrypterFactoryTestVectors()
                                 .test_vector(0)
                                 .private_keyset()
                                 .SerializeAsString();
  return serialized_keyset;
}

TEST(HybridCrypterTest, TestVectors) {
  const HybridCrypterFactoryTestVectors& test_vectors =
      GetHybridCrypterFactoryTestVectors();
  for (const HybridCrypterFactoryTestVector& test_vector :
       test_vectors.test_vector()) {
    VerifyTestVector(test_vector);
  }
}

TEST(HybridTest, EncryptDecryptNull) {
  ccr_error error;

  std::string serialized_keyset = GetSerializedHybridEncryptererKeyset();

  ccr_error_init(&error);
  ccr_hybrid_encrypter* c_hybrid_encrypter =
      ccr_hybrid_encrypter_new_from_serialized_keyset(
          reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
          serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  serialized_keyset = GetSerializedHybridDecrypterKeyset();

  ccr_error_init(&error);
  ccr_hybrid_decrypter* c_hybrid_decrypter =
      ccr_hybrid_decrypter_new_from_serialized_keyset(
          reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
          serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer plaintext("banana");
  StringBuffer ciphertext(ccr_hybrid_encrypter_max_ciphertext_length(
      c_hybrid_encrypter, plaintext.length()));
  ASSERT_NE(ciphertext.length(), 0);

  // Null self with encrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_hybrid_encrypter_encrypt(nullptr, plaintext.data(),
                                         plaintext.length(), ciphertext.data(),
                                         ciphertext.length(),
                                         ciphertext.mutable_limit(), &error),
            0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_hybrid_encrypter_encrypt: self is null"));
  ccr_error_cleanup(&error);

  // Null plaintext with encrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_hybrid_encrypter_encrypt(c_hybrid_encrypter, nullptr,
                                         plaintext.length(), ciphertext.data(),
                                         ciphertext.length(),
                                         ciphertext.mutable_limit(), &error),
            0);
  EXPECT_THAT(
      error.message,
      StartsWith("ccr_hybrid_encrypter_encrypt: plaintext buffer is null"));
  ccr_error_cleanup(&error);

  // Null ciphertext with encrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_hybrid_encrypter_encrypt(c_hybrid_encrypter, plaintext.data(),
                                         plaintext.length(), nullptr,
                                         ciphertext.length(),
                                         ciphertext.mutable_limit(), &error),
            0);
  EXPECT_THAT(
      error.message,
      StartsWith("ccr_hybrid_encrypter_encrypt: ciphertext buffer is null"));
  ccr_error_cleanup(&error);

  // Null bytes_written with encrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_hybrid_encrypter_encrypt(c_hybrid_encrypter, plaintext.data(),
                                         plaintext.length(), ciphertext.data(),
                                         ciphertext.length(), nullptr, &error),
            0);
  EXPECT_THAT(
      error.message,
      StartsWith("ccr_hybrid_encrypter_encrypt: bytes_written is null"));
  ccr_error_cleanup(&error);

  // Successful encrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_hybrid_encrypter_encrypt(c_hybrid_encrypter, plaintext.data(),
                                         plaintext.length(), ciphertext.data(),
                                         ciphertext.length(),
                                         ciphertext.mutable_limit(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer decrypted(ccr_hybrid_decrypter_max_plaintext_length(
      c_hybrid_decrypter, ciphertext.length()));

  // Null self with decrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_hybrid_decrypter_decrypt(nullptr, ciphertext.data(),
                                         ciphertext.length(), decrypted.data(),
                                         decrypted.length(),
                                         decrypted.mutable_limit(), &error),
            0);
  EXPECT_THAT(error.message,
              StartsWith("ccr_hybrid_decrypter_decrypt: self is null"));
  ccr_error_cleanup(&error);

  // Null ciphertext with decrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_hybrid_decrypter_decrypt(c_hybrid_decrypter, nullptr,
                                         ciphertext.length(), decrypted.data(),
                                         decrypted.length(),
                                         decrypted.mutable_limit(), &error),
            0);
  EXPECT_THAT(
      error.message,
      StartsWith("ccr_hybrid_decrypter_decrypt: ciphertext buffer is null"));
  ccr_error_cleanup(&error);

  // Null plaintext with decrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_hybrid_decrypter_decrypt(
                c_hybrid_decrypter, ciphertext.data(), ciphertext.length(),
                nullptr, decrypted.length(), decrypted.mutable_limit(), &error),
            0);
  EXPECT_THAT(
      error.message,
      StartsWith("ccr_hybrid_decrypter_decrypt: plaintext buffer is null"));
  ccr_error_cleanup(&error);

  // Null bytes_written with decrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_hybrid_decrypter_decrypt(c_hybrid_decrypter, ciphertext.data(),
                                         ciphertext.length(), decrypted.data(),
                                         decrypted.length(), nullptr, &error),
            0);
  EXPECT_THAT(
      error.message,
      StartsWith("ccr_hybrid_decrypter_decrypt: bytes_written is null"));
  ccr_error_cleanup(&error);

  // Successful decrypt
  ccr_error_init(&error);
  EXPECT_EQ(ccr_hybrid_decrypter_decrypt(c_hybrid_decrypter, ciphertext.data(),
                                         ciphertext.length(), decrypted.data(),
                                         decrypted.length(),
                                         decrypted.mutable_limit(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  EXPECT_EQ(plaintext.as_string_view(), decrypted.as_string_view());
  ccr_hybrid_decrypter_free(c_hybrid_decrypter);
  ccr_hybrid_encrypter_free(c_hybrid_encrypter);
}

TEST(HybridTest, EncryptOutputBufferTooSmall) {
  ccr_error error;

  std::string serialized_keyset = GetSerializedHybridEncryptererKeyset();

  ccr_error_init(&error);
  ccr_hybrid_encrypter* c_hybrid_encrypter =
      ccr_hybrid_encrypter_new_from_serialized_keyset(
          reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
          serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer plaintext("banana");
  StringBuffer ciphertext(ccr_hybrid_encrypter_max_ciphertext_length(
      c_hybrid_encrypter, plaintext.length()));
  ASSERT_NE(ciphertext.length(), 0);
  ccr_error_init(&error);
  EXPECT_EQ(ccr_hybrid_encrypter_encrypt(c_hybrid_encrypter, plaintext.data(),
                                         plaintext.length(), ciphertext.data(),
                                         ciphertext.length(),
                                         ciphertext.mutable_limit(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_error_init(&error);

  EXPECT_EQ(ccr_hybrid_encrypter_encrypt(c_hybrid_encrypter, plaintext.data(),
                                         plaintext.length(), ciphertext.data(),
                                         ciphertext.length() / 2,
                                         ciphertext.mutable_limit(), &error),
            0);

  EXPECT_THAT(error.message, StartsWith("ciphertext buffer is too short"));
  ccr_error_cleanup(&error);
  ccr_hybrid_encrypter_free(c_hybrid_encrypter);
}

TEST(HybridTest, DecryptBitFlip) {
  ccr_error error;

  std::string serialized_keyset = GetSerializedHybridEncryptererKeyset();

  ccr_error_init(&error);
  ccr_hybrid_encrypter* c_hybrid_encrypter =
      ccr_hybrid_encrypter_new_from_serialized_keyset(
          reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
          serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  serialized_keyset = GetSerializedHybridDecrypterKeyset();

  ccr_error_init(&error);
  ccr_hybrid_decrypter* c_hybrid_decrypter =
      ccr_hybrid_decrypter_new_from_serialized_keyset(
          reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
          serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer plaintext("banana");
  StringBuffer ciphertext(ccr_hybrid_encrypter_max_ciphertext_length(
      c_hybrid_encrypter, plaintext.length()));
  ASSERT_NE(ciphertext.length(), 0);
  EXPECT_EQ(ccr_hybrid_encrypter_encrypt(c_hybrid_encrypter, plaintext.data(),
                                         plaintext.length(), ciphertext.data(),
                                         ciphertext.length(),
                                         ciphertext.mutable_limit(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_error_init(&error);

  StringBuffer decrypted(ccr_hybrid_decrypter_max_plaintext_length(
      c_hybrid_decrypter, ciphertext.length()));
  EXPECT_EQ(ccr_hybrid_decrypter_decrypt(c_hybrid_decrypter, ciphertext.data(),
                                         ciphertext.length(), decrypted.data(),
                                         decrypted.length(),
                                         decrypted.mutable_limit(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_error_init(&error);
  EXPECT_EQ(plaintext.as_string_view(), decrypted.as_string_view());

  ciphertext.data()[ciphertext.length() - 1] ^= 0x01;
  decrypted = StringBuffer(ccr_hybrid_decrypter_max_plaintext_length(
      c_hybrid_decrypter, ciphertext.length()));
  EXPECT_EQ(ccr_hybrid_decrypter_decrypt(c_hybrid_decrypter, ciphertext.data(),
                                         ciphertext.length(), decrypted.data(),
                                         decrypted.length(),
                                         decrypted.mutable_limit(), &error),
            0);
  EXPECT_THAT(error.message, StartsWith("AEAD open failed"));
  ccr_error_cleanup(&error);
  ciphertext.data()[ciphertext.length() - 1] ^= 0x01;
  ccr_hybrid_encrypter_free(c_hybrid_encrypter);
  ccr_hybrid_decrypter_free(c_hybrid_decrypter);
}

TEST(HybridTest, DecryptOutputBufferTooSmall) {
  ccr_error error;

  std::string serialized_keyset = GetSerializedHybridEncryptererKeyset();

  ccr_error_init(&error);
  ccr_hybrid_encrypter* c_hybrid_encrypter =
      ccr_hybrid_encrypter_new_from_serialized_keyset(
          reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
          serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  serialized_keyset = GetSerializedHybridDecrypterKeyset();

  ccr_error_init(&error);
  ccr_hybrid_decrypter* c_hybrid_decrypter =
      ccr_hybrid_decrypter_new_from_serialized_keyset(
          reinterpret_cast<const uint8_t*>(serialized_keyset.data()),
          serialized_keyset.size(), &error);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);

  StringBuffer plaintext("banana");
  StringBuffer ciphertext(ccr_hybrid_encrypter_max_ciphertext_length(
      c_hybrid_encrypter, plaintext.length()));
  ASSERT_NE(ciphertext.length(), 0);
  ccr_error_init(&error);
  EXPECT_EQ(ccr_hybrid_encrypter_encrypt(c_hybrid_encrypter, plaintext.data(),
                                         plaintext.length(), ciphertext.data(),
                                         ciphertext.length(),
                                         ciphertext.mutable_limit(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_error_init(&error);

  StringBuffer decrypted(ccr_hybrid_decrypter_max_plaintext_length(
      c_hybrid_decrypter, ciphertext.length()));
  EXPECT_EQ(ccr_hybrid_decrypter_decrypt(c_hybrid_decrypter, ciphertext.data(),
                                         ciphertext.length(), decrypted.data(),
                                         decrypted.length(),
                                         decrypted.mutable_limit(), &error),
            1);
  EXPECT_EQ(error.message, nullptr) << error.message;
  ccr_error_cleanup(&error);
  ccr_error_init(&error);
  EXPECT_EQ(plaintext.as_string_view(), decrypted.as_string_view());

  decrypted = StringBuffer(ccr_hybrid_decrypter_max_plaintext_length(
      c_hybrid_decrypter, ciphertext.length()));
  EXPECT_EQ(ccr_hybrid_decrypter_decrypt(c_hybrid_decrypter, ciphertext.data(),
                                         ciphertext.length(), decrypted.data(),
                                         plaintext.length() / 2,
                                         decrypted.mutable_limit(), &error),
            0);
  EXPECT_THAT(error.message, StartsWith("plaintext buffer is too short"));
  ccr_error_cleanup(&error);
  ccr_hybrid_encrypter_free(c_hybrid_encrypter);
  ccr_hybrid_decrypter_free(c_hybrid_decrypter);
}

}  // namespace
}  // namespace crunchy
