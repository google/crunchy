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

#ifndef CRUNCHY_ALGS_CRYPT_CRYPTER_TEST_H_
#define CRUNCHY_ALGS_CRYPT_CRYPTER_TEST_H_

// This file contains shared functionalities used for testing.
// The actual tests are in the mode-specific _test files.

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <string>
#include <utility>

#include <gmock/gmock.h>
#include "crunchy/internal/algs/crypt/crypter_interface.h"
#include "crunchy/internal/algs/crypt/testdata/crypter_test_vectors.pb.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/common/init.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/util/status.h"

namespace crunchy {

// Get an array of random bytes.
std::unique_ptr<uint8_t[]> RandomArray(size_t length);

// Copy source and return.
std::unique_ptr<uint8_t[]> Copy(uint8_t* source, size_t source_len);

// Copy source and flip one byte randomly
std::unique_ptr<uint8_t[]> CopyAndAlterRandomByte(const uint8_t* source,
                                                  size_t source_len);

// Copy std::string and flip one byte randomly.
std::string CopyAndAlterRandomByte(const std::string& source);

// Output to Heximal std::string.
std::string ToHex(const uint8_t* hex, size_t length);

// Test random encryption and decryption.
void RandomEncryptDecryptTest(const CrypterFactory& factory,
                              size_t min_message_length, bool corrupt_tag);

inline void RandomEncryptDecryptTest(const CrypterFactory& factory) {
  return RandomEncryptDecryptTest(factory, 0 /* min_message_length */,
                                  true /* corrupt_tag */);
}

// Test encryption failure
void EncryptionFailureTest(const CrypterFactory& factory,
                           bool allow_empty_messages);
inline void EncryptionFailureTest(const CrypterFactory& factory) {
  EncryptionFailureTest(factory, true /* allow_empty_messages */);
}

// Test decryption failure.
void DecryptionFailureTest(const CrypterFactory& factory);

// Test random encryption and decrytion on std::string input.
void RandomEncryptDecryptStringTest(const CrypterFactory& factory,
                                    size_t min_message_length,
                                    bool corrupt_tag);
inline void RandomEncryptDecryptStringTest(const CrypterFactory& factory) {
  return RandomEncryptDecryptStringTest(factory, 0 /* min_message_length */,
                                        true /* corrupt_tag */);
}

// Test encryption failure on std::string input.
void EncryptionFailureStringTest(const CrypterFactory& factory);

// Test decryption failure on std::string input.
void DecryptionFailureStringTest(CrypterInterface* crypter);
inline void DecryptionFailureStringTest(const CrypterFactory& factory) {
  auto status_or_crypter = factory.Make(RandString(factory.GetKeyLength()));
  CRUNCHY_EXPECT_OK(status_or_crypter.status());
  std::unique_ptr<CrypterInterface> crypter =
      std::move(status_or_crypter.ValueOrDie());
  DecryptionFailureStringTest(crypter.get());
}

void VerifyTestVector(const CrypterFactory& factory,
                      const CrypterInterfaceTestVector& test_vector);

// Create a random test vector given a crypter instance
CrypterInterfaceTestVector GenerateTestVector(const CrypterFactory& factory);

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_CRYPT_CRYPTER_TEST_H_
