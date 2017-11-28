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

#include "crunchy/internal/keys/hybrid_crypting_key.h"

#include <stddef.h>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include "crunchy/internal/algs/hybrid/hybrid.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/common/init.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/test_factory.h"
#include "crunchy/internal/keys/hybrid_crypting_key_test_vectors.pb.h"

namespace crunchy {

namespace {

std::vector<FactoryInfo<HybridCryptingKeyFactory>>* FactoryInfoVector() {
  auto factories = new std::vector<FactoryInfo<HybridCryptingKeyFactory>>();
  static const HybridCryptingKeyFactory& x25519_aes_256_gcm_factory =
      *MakeFactory(GetX25519Aes256GcmFactory()).release();
  factories->push_back({"x25519_aes_256_gcm", x25519_aes_256_gcm_factory,
                        "crunchy/internal/keys/testdata/"
                        "x25519_aes_256_gcm.proto.bin"});
  return factories;
}

using HybridCryptingKeyTest =
    FactoryParamTest<HybridCryptingKeyFactory, FactoryInfoVector>;

TEST_P(HybridCryptingKeyTest, EncryptDecrypt) {
  auto status_or_private_key_data = factory().CreateRandomPrivateKeyData();
  CRUNCHY_EXPECT_OK(status_or_private_key_data.status());
  KeyData private_key_data = status_or_private_key_data.ValueOrDie();

  auto status_or_public_key_data =
      factory().CreatePublicKeyData(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key_data.status());
  KeyData public_key_data = status_or_public_key_data.ValueOrDie();

  auto status_or_public_key =
      factory().MakeHybridEncryptingKey(public_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key.status());
  std::unique_ptr<HybridEncryptingKey> public_key =
      std::move(status_or_public_key.ValueOrDie());

  auto status_or_private_key =
      factory().MakeHybridDecryptingKey(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_private_key.status());
  std::unique_ptr<HybridDecryptingKey> private_key =
      std::move(status_or_private_key.ValueOrDie());

  std::string plaintext = "banana";
  auto status_or_ciphertext = public_key->Encrypt(plaintext);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  auto status_or_decrypted = private_key->Decrypt(ciphertext);
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  EXPECT_EQ(plaintext, decrypted);
}

TEST_P(HybridCryptingKeyTest, EncryptDecryptRecreate) {
  auto status_or_private_key_data = factory().CreateRandomPrivateKeyData();
  CRUNCHY_EXPECT_OK(status_or_private_key_data.status());
  KeyData private_key_data = status_or_private_key_data.ValueOrDie();

  auto status_or_public_key_data =
      factory().CreatePublicKeyData(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key_data.status());
  KeyData public_key_data = status_or_public_key_data.ValueOrDie();

  auto status_or_public_key =
      factory().MakeHybridEncryptingKey(public_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key.status());
  std::unique_ptr<HybridEncryptingKey> public_key =
      std::move(status_or_public_key.ValueOrDie());

  auto status_or_private_key =
      factory().MakeHybridDecryptingKey(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_private_key.status());
  std::unique_ptr<HybridDecryptingKey> private_key =
      std::move(status_or_private_key.ValueOrDie());

  std::string plaintext = "banana";
  auto status_or_ciphertext = public_key->Encrypt(plaintext);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  auto status_or_decrypted = private_key->Decrypt(ciphertext);
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  EXPECT_EQ(plaintext, decrypted);

  // Make sure we can decrypt using another deserialized key
  status_or_private_key = factory().MakeHybridDecryptingKey(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_private_key.status());
  private_key = std::move(status_or_private_key.ValueOrDie());
  status_or_decrypted = private_key->Decrypt(ciphertext);
  decrypted = std::move(status_or_decrypted.ValueOrDie());
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  EXPECT_EQ(plaintext, decrypted);
}

TEST_P(HybridCryptingKeyTest, EncryptNonDeterministic) {
  auto status_or_private_key_data = factory().CreateRandomPrivateKeyData();
  CRUNCHY_EXPECT_OK(status_or_private_key_data.status());
  KeyData private_key_data = status_or_private_key_data.ValueOrDie();

  auto status_or_public_key_data =
      factory().CreatePublicKeyData(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key_data.status());
  KeyData public_key_data = status_or_public_key_data.ValueOrDie();

  auto status_or_public_key =
      factory().MakeHybridEncryptingKey(public_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key.status());
  std::unique_ptr<HybridEncryptingKey> public_key =
      std::move(status_or_public_key.ValueOrDie());

  auto status_or_private_key =
      factory().MakeHybridDecryptingKey(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_private_key.status());
  std::unique_ptr<HybridDecryptingKey> private_key =
      std::move(status_or_private_key.ValueOrDie());

  std::string plaintext = "banana";
  auto status_or_ciphertext = public_key->Encrypt(plaintext);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());

  status_or_ciphertext = public_key->Encrypt(plaintext);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string another_ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  EXPECT_NE(ciphertext, another_ciphertext);
}

TEST_P(HybridCryptingKeyTest, EncryptDecryptErrors) {
  auto status_or_private_key_data = factory().CreateRandomPrivateKeyData();
  CRUNCHY_EXPECT_OK(status_or_private_key_data.status());
  KeyData private_key_data = status_or_private_key_data.ValueOrDie();

  auto status_or_public_key_data =
      factory().CreatePublicKeyData(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key_data.status());
  KeyData public_key_data = status_or_public_key_data.ValueOrDie();

  auto status_or_public_key =
      factory().MakeHybridEncryptingKey(public_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key.status());
  std::unique_ptr<HybridEncryptingKey> public_key =
      std::move(status_or_public_key.ValueOrDie());

  auto status_or_private_key =
      factory().MakeHybridDecryptingKey(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_private_key.status());
  std::unique_ptr<HybridDecryptingKey> private_key =
      std::move(status_or_private_key.ValueOrDie());

  std::string plaintext = "banana";
  auto status_or_ciphertext = public_key->Encrypt(plaintext);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  auto status_or_decrypted = private_key->Decrypt(ciphertext);
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  EXPECT_EQ(plaintext, decrypted);

  // Corrupt ciphertext start
  ciphertext[0] ^= 0x01;
  EXPECT_FALSE(private_key->Decrypt(ciphertext).ok());
  ciphertext[0] ^= 0x01;

  // Corrupt ciphertext middle
  ciphertext[ciphertext.length() / 2] ^= 0x01;
  EXPECT_FALSE(private_key->Decrypt(ciphertext).ok());
  ciphertext[ciphertext.length() / 2] ^= 0x01;

  // Corrupt ciphertext end
  ciphertext[ciphertext.length() - 1] ^= 0x01;
  EXPECT_FALSE(private_key->Decrypt(ciphertext).ok());
  ciphertext[ciphertext.length() - 1] ^= 0x01;

  // Corrupt aad
  ciphertext[0] ^= 0x01;
  EXPECT_FALSE(private_key->Decrypt(ciphertext).ok());
  ciphertext[0] ^= 0x01;

  // Ciphertext empty
  EXPECT_FALSE(private_key->Decrypt("").ok());

  // Ciphertext too short
  status_or_ciphertext = public_key->Encrypt("");
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  EXPECT_FALSE(private_key
                   ->Decrypt(absl::ClippedSubstr(absl::string_view(ciphertext),
                                                 ciphertext.length() - 1))
                   .ok());
}

TEST_P(HybridCryptingKeyTest, BadKeyData) {
  auto status_or_private_key_data = factory().CreateRandomPrivateKeyData();
  CRUNCHY_EXPECT_OK(status_or_private_key_data.status());
  KeyData private_key_data = status_or_private_key_data.ValueOrDie();

  auto status_or_public_key_data =
      factory().CreatePublicKeyData(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key_data.status());
  KeyData public_key_data = status_or_public_key_data.ValueOrDie();

  // MakeHybridDecrypter with missing private_key
  KeyData bad_key_data = private_key_data;
  bad_key_data.clear_private_key();
  EXPECT_FALSE(factory().MakeHybridDecryptingKey(bad_key_data).ok());

  // MakeHybridEncrypter with missing public_key
  bad_key_data = public_key_data;
  bad_key_data.clear_public_key();
  EXPECT_FALSE(factory().MakeHybridEncryptingKey(bad_key_data).ok());

  // MakeHybridEncrypter with private_key
  EXPECT_FALSE(factory().MakeHybridEncryptingKey(private_key_data).ok());

  // CreatePublicKeyData with no public_key
  bad_key_data = private_key_data;
  bad_key_data.clear_public_key();
  EXPECT_FALSE(factory().CreatePublicKeyData(bad_key_data).ok());

  // MakeHybridDecrypter with corrupt private_key
  bad_key_data = private_key_data;
  bad_key_data.set_private_key("corn");
  EXPECT_FALSE(factory().MakeHybridDecryptingKey(bad_key_data).ok());

  // MakeHybridEncrypter with corrupt public_key
  bad_key_data = public_key_data;
  bad_key_data.set_public_key("corn");
  EXPECT_FALSE(factory().MakeHybridEncryptingKey(bad_key_data).ok());
}

void VerifyTestVector(const HybridCryptingKeyFactory& factory,
                      const HybridCryptingKeyTestVector& test_vector) {
  auto status_or_public_key =
      factory.MakeHybridEncryptingKey(test_vector.public_key_data());
  CRUNCHY_EXPECT_OK(status_or_public_key.status());
  std::unique_ptr<HybridEncryptingKey> public_key =
      std::move(status_or_public_key.ValueOrDie());

  auto status_or_private_key =
      factory.MakeHybridDecryptingKey(test_vector.private_key_data());
  CRUNCHY_EXPECT_OK(status_or_private_key.status());
  std::unique_ptr<HybridDecryptingKey> private_key =
      std::move(status_or_private_key.ValueOrDie());

  // Decrypt the ciphertext in the test vector
  auto status_or_decrypted = private_key->Decrypt(test_vector.ciphertext());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  EXPECT_EQ(test_vector.plaintext(), decrypted);

  // Encrypt/decrypt the plaintext in the test vector.
  auto status_or_ciphertext = public_key->Encrypt(test_vector.plaintext());
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  status_or_decrypted = private_key->Decrypt(ciphertext);
  decrypted = std::move(status_or_decrypted.ValueOrDie());
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  EXPECT_EQ(test_vector.plaintext(), decrypted);
}

TEST_P(HybridCryptingKeyTest, TestVectors) {
  auto test_vectors = GetTestVectors<HybridCryptingKeyTestVectors>();
  for (const auto& test_vector : test_vectors->test_vector()) {
    VerifyTestVector(factory(), test_vector);
  }
}

INSTANTIATE_TEST_CASE_P(, HybridCryptingKeyTest,
                        ::testing::ValuesIn(HybridCryptingKeyTest::factories()),
                        HybridCryptingKeyTest::GetNameFromParam);

HybridCryptingKeyTestVector GenerateTestVector(
    const HybridCryptingKeyFactory& factory) {
  auto status_or_private_key_data = factory.CreateRandomPrivateKeyData();
  CRUNCHY_EXPECT_OK(status_or_private_key_data.status());
  KeyData private_key_data = status_or_private_key_data.ValueOrDie();
  auto status_or_public_key_data =
      factory.CreatePublicKeyData(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key_data.status());
  KeyData public_key_data = status_or_public_key_data.ValueOrDie();

  auto status_or_public_key = factory.MakeHybridEncryptingKey(public_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key.status());
  std::unique_ptr<HybridEncryptingKey> public_key =
      std::move(status_or_public_key.ValueOrDie());

  auto status_or_private_key =
      factory.MakeHybridDecryptingKey(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_private_key.status());
  std::unique_ptr<HybridDecryptingKey> private_key =
      std::move(status_or_private_key.ValueOrDie());

  size_t plaintext_magnatude = BiasRandInt(10);
  size_t plaintext_length = BiasRandInt(1 << plaintext_magnatude);

  HybridCryptingKeyTestVector test_vector;
  *test_vector.mutable_public_key_data() = public_key_data;
  *test_vector.mutable_private_key_data() = private_key_data;
  test_vector.set_plaintext(RandString(plaintext_length));

  auto status_or_ciphertext = public_key->Encrypt(test_vector.plaintext());
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
