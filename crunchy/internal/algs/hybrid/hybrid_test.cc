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

#include "crunchy/internal/algs/hybrid/hybrid.h"

#include <stddef.h>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "crunchy/internal/algs/hybrid/testdata/hybrid_test_vectors.pb.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/common/init.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/test_factory.h"
#include "crunchy/internal/port/port.h"

namespace crunchy {

namespace {

using testing::HasSubstr;
using testing::crunchy_status::StatusIs;

const size_t kTestVectorMaxPlaintextSize = 42;

std::vector<FactoryInfo<HybridCrypterFactory>>* FactoryInfoVector() {
  auto factories = new std::vector<FactoryInfo<HybridCrypterFactory>>();
  factories->push_back(
      {"P256_AES_128_GCM", GetP256Aes128GcmFactory(),
       "crunchy/internal/algs/hybrid/testdata/p256_aes_128_gcm.proto.bin"});
  factories->push_back(
      {"P256_AES_256_GCM", GetP256Aes256GcmFactory(),
       "crunchy/internal/algs/hybrid/testdata/p256_aes_256_gcm.proto.bin"});
  factories->push_back(
      {"P521_AES_256_GCM", GetP521Aes256GcmFactory(),
       "crunchy/internal/algs/hybrid/testdata/p521_aes_256_gcm.proto.bin"});
  factories->push_back({"X25519_AES_256_GCM", GetX25519Aes256GcmFactory(),
                        "crunchy/internal/algs/hybrid/testdata/"
                        "x25519_aes_256_gcm.proto.bin"});
  return factories;
}

using HybridCrypterTest =
    FactoryParamTest<HybridCrypterFactory, FactoryInfoVector>;

void EncryptDecryptTest(const HybridEncrypterInterface& encrypter,
                        const HybridDecrypterInterface& decrypter,
                        absl::string_view plaintext) {
  auto status_or_ciphertext = encrypter.Encrypt(plaintext);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());

  auto status_or_decrypted = decrypter.Decrypt(ciphertext);
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());

  EXPECT_EQ(plaintext, decrypted);
}

TEST_P(HybridCrypterTest, EncryptDecryptTest) {
  std::string public_key;
  std::string private_key;
  CRUNCHY_EXPECT_OK(factory().NewKeypair(&public_key, &private_key));
  EXPECT_NE(public_key, "");
  EXPECT_NE(private_key, "");

  auto status_or_encrypter = factory().MakeHybridEncrypter(public_key);
  CRUNCHY_EXPECT_OK(status_or_encrypter.status());
  std::unique_ptr<HybridEncrypterInterface> encrypter =
      std::move(status_or_encrypter.ValueOrDie());
  EXPECT_NE(encrypter, nullptr);

  auto status_or_decrypter = factory().MakeHybridDecrypter(private_key);
  CRUNCHY_EXPECT_OK(status_or_decrypter.status());
  std::unique_ptr<HybridDecrypterInterface> decrypter =
      std::move(status_or_decrypter.ValueOrDie());

  EncryptDecryptTest(*encrypter, *decrypter, RandString(42));
  EncryptDecryptTest(*encrypter, *decrypter, "");
  EncryptDecryptTest(*encrypter, *decrypter, RandString(16 * 1024));
}

TEST_P(HybridCrypterTest, NullInputsTest) {
  std::string public_key;
  std::string private_key;
  EXPECT_FALSE(factory().NewKeypair(nullptr, &private_key).ok());
  EXPECT_FALSE(factory().NewKeypair(&public_key, nullptr).ok());
}

TEST_P(HybridCrypterTest, BadPublicKey) {
  std::string public_key;

  auto status_or_encrypter = factory().MakeHybridEncrypter(public_key);
  EXPECT_FALSE(status_or_encrypter.ok());
}

TEST_P(HybridCrypterTest, BadPrivateKey) {
  std::string private_key;

  auto status_or_decrypter = factory().MakeHybridDecrypter(private_key);
  EXPECT_FALSE(status_or_decrypter.ok());
}

TEST_P(HybridCrypterTest, SmallCiphertextTest) {
  std::string public_key;
  std::string private_key;
  CRUNCHY_EXPECT_OK(factory().NewKeypair(&public_key, &private_key));
  EXPECT_NE(public_key, "");
  EXPECT_NE(private_key, "");

  auto status_or_encrypter = factory().MakeHybridEncrypter(public_key);
  CRUNCHY_EXPECT_OK(status_or_encrypter.status());
  std::unique_ptr<HybridEncrypterInterface> encrypter =
      std::move(status_or_encrypter.ValueOrDie());
  EXPECT_NE(encrypter, nullptr);

  std::string plaintext = RandString(42);
  auto status_or_ciphertext = encrypter->Encrypt(plaintext);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());

  auto status_or_decrypter = factory().MakeHybridDecrypter(private_key);
  CRUNCHY_EXPECT_OK(status_or_decrypter.status());
  std::unique_ptr<HybridDecrypterInterface> decrypter =
      std::move(status_or_decrypter.ValueOrDie());

  auto status_or_decrypted = decrypter->Decrypt(ciphertext.substr(0, 1));
  EXPECT_THAT(status_or_decrypted.status(),
              StatusIs(FAILED_PRECONDITION,
                       HasSubstr("ciphertext is not large enough")));

  status_or_decrypted = decrypter->Decrypt(ciphertext.substr(1));
  EXPECT_FALSE(status_or_decrypted.ok());
}

TEST_P(HybridCrypterTest, CorruptCiphertextTest) {
  std::string public_key;
  std::string private_key;
  CRUNCHY_EXPECT_OK(factory().NewKeypair(&public_key, &private_key));
  EXPECT_NE(public_key, "");
  EXPECT_NE(private_key, "");

  auto status_or_encrypter = factory().MakeHybridEncrypter(public_key);
  CRUNCHY_EXPECT_OK(status_or_encrypter.status());
  std::unique_ptr<HybridEncrypterInterface> encrypter =
      std::move(status_or_encrypter.ValueOrDie());
  EXPECT_NE(encrypter, nullptr);

  std::string plaintext = RandString(42);
  auto status_or_ciphertext = encrypter->Encrypt(plaintext);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());

  auto status_or_decrypter = factory().MakeHybridDecrypter(private_key);
  CRUNCHY_EXPECT_OK(status_or_decrypter.status());
  std::unique_ptr<HybridDecrypterInterface> decrypter =
      std::move(status_or_decrypter.ValueOrDie());

  ciphertext[0] ^= 0x01;
  auto status_or_decrypted = decrypter->Decrypt(ciphertext);
  EXPECT_FALSE(status_or_decrypted.ok());
  ciphertext[0] ^= 0x01;

  ciphertext[ciphertext.length() - 1] ^= 0x01;
  status_or_decrypted = decrypter->Decrypt(ciphertext);
  EXPECT_FALSE(status_or_decrypted.ok());
  ciphertext[ciphertext.length() - 1] ^= 0x01;
}

TEST(P256Test, BadPublicKey) {
  const HybridCrypterFactory& factory = GetP256Aes128GcmFactory();

  std::string public_key = absl::HexStringToBytes(
      "b120de4aa36492795346e8de6c2c8646ae06aaea279fa775b3ab0715f6ce51b0"
      "9f1b7eece20d7b5ed8ec685fa3f071d83727027092a8411385c34dde5708b2b6");

  CRUNCHY_EXPECT_OK(factory.MakeHybridEncrypter(public_key));

  public_key[0] ^= 0x01;
  EXPECT_FALSE(factory.MakeHybridEncrypter(public_key).ok());
  public_key[0] ^= 0x01;
}

TEST(P521Test, BadPublicKey) {
  const HybridCrypterFactory& factory = GetP521Aes256GcmFactory();

  std::string public_key = absl::HexStringToBytes(
      "01EBB34DD75721ABF8ADC9DBED17889CBB9765D90A7C60F2CEF007BB0F2B26E14881FD"
      "4442E689D61CB2DD046EE30E3FFD20F9A45BBDF6413D583A2DBF59924FD35C"
      "00F6B632D194C0388E22D8437E558C552AE195ADFD153F92D74908351B2F8C4EDA94ED"
      "B0916D1B53C020B5EECAED1A5FC38A233E4830587BB2EE3489B3B42A5A86A4");

  CRUNCHY_EXPECT_OK(factory.MakeHybridEncrypter(public_key));

  public_key[0] ^= 0x01;
  EXPECT_FALSE(factory.MakeHybridEncrypter(public_key).ok());
  public_key[0] ^= 0x01;
}

void VerifyTestVector(const HybridCrypterFactory& factory,
                      const HybridCrypterTestVector& test_vector) {
  auto status_or_encrypter =
      factory.MakeHybridEncrypter(test_vector.public_key());
  CRUNCHY_EXPECT_OK(status_or_encrypter.status());
  std::unique_ptr<HybridEncrypterInterface> encrypter =
      std::move(status_or_encrypter.ValueOrDie());
  EXPECT_NE(encrypter, nullptr);

  auto status_or_decrypter =
      factory.MakeHybridDecrypter(test_vector.private_key());
  CRUNCHY_EXPECT_OK(status_or_decrypter.status());
  std::unique_ptr<HybridDecrypterInterface> decrypter =
      std::move(status_or_decrypter.ValueOrDie());

  // Decrypt the test_vector ciphertext
  auto status_or_decrypted = decrypter->Decrypt(test_vector.ciphertext());
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());

  EXPECT_EQ(test_vector.plaintext(), decrypted);

  // Encrypt/decrypt the test_vector plaintext.
  auto status_or_ciphertext = encrypter->Encrypt(test_vector.plaintext());
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());

  status_or_decrypted = decrypter->Decrypt(ciphertext);
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  decrypted = std::move(status_or_decrypted.ValueOrDie());

  EXPECT_EQ(test_vector.plaintext(), decrypted);
}

TEST_P(HybridCrypterTest, TestVectors) {
  if (test_data_path().empty()) {
    CRUNCHY_LOG(ERROR) << name() << " has an empty test_data_path, skipping";
    return;
  }
  auto test_vectors = GetTestVectors<HybridCrypterTestVectors>();
  for (const auto& test_vector : test_vectors.test_vector()) {
    VerifyTestVector(factory(), test_vector);
  }
}

INSTANTIATE_TEST_CASE_P(, HybridCrypterTest,
                        ::testing::ValuesIn(HybridCrypterTest::factories()),
                        HybridCrypterTest::GetNameFromParam);

HybridCrypterTestVector GenerateTestVector(
    const HybridCrypterFactory& factory) {
  HybridCrypterTestVector test_vector;
  CRUNCHY_EXPECT_OK(factory.NewKeypair(test_vector.mutable_public_key(),
                                       test_vector.mutable_private_key()));
  size_t plaintext_size = BiasRandInt(kTestVectorMaxPlaintextSize);

  auto status_or_encrypter =
      factory.MakeHybridEncrypter(test_vector.public_key());
  CRUNCHY_EXPECT_OK(status_or_encrypter.status());
  std::unique_ptr<HybridEncrypterInterface> encrypter =
      std::move(status_or_encrypter.ValueOrDie());
  EXPECT_NE(encrypter, nullptr);

  test_vector.set_plaintext(RandString(plaintext_size));

  auto status_or_ciphertext = encrypter->Encrypt(test_vector.plaintext());
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
