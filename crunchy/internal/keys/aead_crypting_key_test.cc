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

#include "crunchy/internal/keys/aead_crypting_key.h"

#include <stddef.h>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include "crunchy/internal/algs/crypt/openssl_aead.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/common/init.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/test_factory.h"
#include "crunchy/internal/keys/aead_crypting_key_test_vectors.pb.h"
#include "crunchy/internal/port/port.h"

namespace crunchy {

namespace {

std::vector<FactoryInfo<AeadCryptingKeyFactory>>* FactoryInfoVector() {
  auto factories = new std::vector<FactoryInfo<AeadCryptingKeyFactory>>();
  static const AeadCryptingKeyFactory& aes_128_gcm_factory =
      *MakeFactory(GetAes128GcmFactory()).release();
  factories->push_back(
      {"aes_128_gcm", aes_128_gcm_factory,
       "crunchy/internal/keys/testdata/aes_128_gcm.proto.bin"});
  static const AeadCryptingKeyFactory& aes_256_gcm_factory =
      *MakeFactory(GetAes256GcmFactory()).release();
  factories->push_back(
      {"aes_256_gcm", aes_256_gcm_factory,
       "crunchy/internal/keys/testdata/aes_256_gcm.proto.bin"});
  return factories;
}

using AeadCryptingKeyTest =
    FactoryParamTest<AeadCryptingKeyFactory, FactoryInfoVector>;

TEST_P(AeadCryptingKeyTest, EncryptDecrypt) {
  KeyData key_data = factory().CreateRandomKeyData();

  std::string plaintext = "banana";
  std::string aad = "apple";
  auto status_or_key = factory().MakeKey(key_data);
  CRUNCHY_EXPECT_OK(status_or_key.status());
  std::unique_ptr<AeadCryptingKey> key = std::move(status_or_key.ValueOrDie());
  auto status_or_ciphertext = key->Encrypt(plaintext, aad);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  auto status_or_decrypted = key->Decrypt(ciphertext, aad);
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  EXPECT_EQ(plaintext, decrypted);
}

TEST_P(AeadCryptingKeyTest, EncryptDecryptRecreate) {
  KeyData key_data = factory().CreateRandomKeyData();

  std::string plaintext = "banana";
  std::string aad = "apple";
  auto status_or_key = factory().MakeKey(key_data);
  CRUNCHY_EXPECT_OK(status_or_key.status());
  std::unique_ptr<AeadCryptingKey> key = std::move(status_or_key.ValueOrDie());
  auto status_or_ciphertext = key->Encrypt(plaintext, aad);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  auto status_or_decrypted = key->Decrypt(ciphertext, aad);
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  EXPECT_EQ(plaintext, decrypted);

  // Make sure we can decrypt using another deserialized key
  status_or_key = factory().MakeKey(key_data);
  CRUNCHY_EXPECT_OK(status_or_key.status());
  key = std::move(status_or_key.ValueOrDie());
  status_or_decrypted = key->Decrypt(ciphertext, aad);
  decrypted = std::move(status_or_decrypted.ValueOrDie());
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  EXPECT_EQ(plaintext, decrypted);
}

TEST_P(AeadCryptingKeyTest, EncryptNonDeterministic) {
  KeyData key_data = factory().CreateRandomKeyData();

  std::string plaintext = "banana";
  std::string aad = "apple";
  auto status_or_key = factory().MakeKey(key_data);
  CRUNCHY_EXPECT_OK(status_or_key.status());
  std::unique_ptr<AeadCryptingKey> key = std::move(status_or_key.ValueOrDie());
  auto status_or_ciphertext = key->Encrypt(plaintext, aad);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());

  status_or_ciphertext = key->Encrypt(plaintext, aad);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string another_ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  EXPECT_NE(ciphertext, another_ciphertext);
}

TEST_P(AeadCryptingKeyTest, EncryptDecryptErrors) {
  KeyData key_data = factory().CreateRandomKeyData();

  std::string plaintext = "banana";
  std::string aad = "apple";
  auto status_or_key = factory().MakeKey(key_data);
  CRUNCHY_EXPECT_OK(status_or_key.status());
  std::unique_ptr<AeadCryptingKey> key = std::move(status_or_key.ValueOrDie());
  auto status_or_ciphertext = key->Encrypt(plaintext, aad);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  auto status_or_decrypted = key->Decrypt(ciphertext, aad);
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  EXPECT_EQ(plaintext, decrypted);

  // Decrypt without aad
  EXPECT_FALSE(key->Decrypt(ciphertext, "").ok());

  // Corrupt ciphertext start
  ciphertext[0] ^= 0x01;
  EXPECT_FALSE(key->Decrypt(ciphertext, "").ok());
  ciphertext[0] ^= 0x01;

  // Corrupt ciphertext middle
  ciphertext[ciphertext.length() / 2] ^= 0x01;
  EXPECT_FALSE(key->Decrypt(ciphertext, "").ok());
  ciphertext[ciphertext.length() / 2] ^= 0x01;

  // Corrupt ciphertext end
  ciphertext[ciphertext.length() - 1] ^= 0x01;
  EXPECT_FALSE(key->Decrypt(ciphertext, "").ok());
  ciphertext[ciphertext.length() - 1] ^= 0x01;

  // Corrupt aad
  ciphertext[0] ^= 0x01;
  EXPECT_FALSE(key->Decrypt(ciphertext, "").ok());
  ciphertext[0] ^= 0x01;

  // Ciphertext empty
  EXPECT_FALSE(key->Decrypt("", aad).ok());

  // Ciphertext too short
  status_or_ciphertext = key->Encrypt("", aad);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  EXPECT_FALSE(key->Decrypt(absl::ClippedSubstr(absl::string_view(ciphertext),
                                                ciphertext.length() - 1),
                            aad)
                   .ok());
}

TEST_P(AeadCryptingKeyTest, BadKeyData) {
  KeyData key_data = factory().CreateRandomKeyData();

  // Missing private_key
  key_data.clear_private_key();
  EXPECT_FALSE(factory().MakeKey(key_data).ok());

  // Malformed private_key (one would hope)
  key_data.set_private_key("corn");
  EXPECT_FALSE(factory().MakeKey(key_data).ok());
}

void VerifyTestVector(const AeadCryptingKeyFactory& factory,
                      const AeadCryptingKeyTestVector& test_vector) {
  auto status_or_crypting_key = factory.MakeKey(test_vector.key_data());
  CRUNCHY_EXPECT_OK(status_or_crypting_key.status());
  std::unique_ptr<AeadCryptingKey> crypting_key =
      std::move(status_or_crypting_key.ValueOrDie());

  // Decrypt the ciphertext in the test vector
  auto status_or_decrypted =
      crypting_key->Decrypt(test_vector.ciphertext(), test_vector.aad());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  EXPECT_EQ(test_vector.plaintext(), decrypted);

  // Encrypt/decrypt the plaintext/aad in the test vector.
  auto status_or_ciphertext =
      crypting_key->Encrypt(test_vector.plaintext(), test_vector.aad());
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  status_or_decrypted = crypting_key->Decrypt(ciphertext, test_vector.aad());
  decrypted = std::move(status_or_decrypted.ValueOrDie());
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  EXPECT_EQ(test_vector.plaintext(), decrypted);
}

TEST_P(AeadCryptingKeyTest, TestVectors) {
  if (test_data_path().empty()) {
    CRUNCHY_LOG(ERROR) << name() << " has an empty test_data_path, skipping";
    return;
  }
  auto test_vectors = GetTestVectors<AeadCryptingKeyTestVectors>();
  for (const auto& test_vector : test_vectors.test_vector()) {
    VerifyTestVector(factory(), test_vector);
  }
}

INSTANTIATE_TEST_CASE_P(, AeadCryptingKeyTest,
                        ::testing::ValuesIn(AeadCryptingKeyTest::factories()),
                        AeadCryptingKeyTest::GetNameFromParam);

AeadCryptingKeyTestVector GenerateTestVector(
    const AeadCryptingKeyFactory& factory) {
  KeyData key_data = factory.CreateRandomKeyData();

  auto status_or_crypting_key = factory.MakeKey(key_data);
  CRUNCHY_EXPECT_OK(status_or_crypting_key.status());
  std::unique_ptr<AeadCryptingKey> crypting_key =
      std::move(status_or_crypting_key.ValueOrDie());

  size_t aad_magnatude = BiasRandInt(10);
  size_t aad_length = BiasRandInt(1 << aad_magnatude);
  size_t plaintext_magnatude = BiasRandInt(10);
  size_t plaintext_length = BiasRandInt(1 << plaintext_magnatude);

  AeadCryptingKeyTestVector test_vector;
  *test_vector.mutable_key_data() = key_data;
  test_vector.set_plaintext(RandString(plaintext_length));
  test_vector.set_aad(RandString(aad_length));

  auto status_or_ciphertext =
      crypting_key->Encrypt(test_vector.plaintext(), test_vector.aad());
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  test_vector.set_ciphertext(status_or_ciphertext.ValueOrDie());

  VerifyTestVector(factory, test_vector);
  return test_vector;
}

}  // namespace

}  // namespace crunchy

int main(int argc, char** argv) {
  crunchy::InitCrunchyTest(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
