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

#include "crunchy/internal/keys/signing_key.h"

#include <stddef.h>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/algs/sign/ed25519.h"
#include "crunchy/internal/algs/sign/p256_ecdsa.h"
#include "crunchy/internal/common/init.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/test_factory.h"
#include "crunchy/internal/keys/signing_key_test_vectors.pb.h"

namespace crunchy {

namespace {

std::vector<FactoryInfo<SigningKeyFactory>>* FactoryInfoVector() {
  auto factories = new std::vector<FactoryInfo<SigningKeyFactory>>();
  static const SigningKeyFactory& ed25519_factory =
      *MakeFactory(GetEd25519Factory()).release();
  factories->push_back(
      {"ed25519", ed25519_factory,
       "crunchy/internal/keys/testdata/ed25519.proto.bin"});
  static const SigningKeyFactory& p256_factory =
      *MakeFactory(GetP256EcdsaAsn1Factory()).release();
  factories->push_back(
      {"p256", p256_factory,
       "crunchy/internal/keys/testdata/p256.proto.bin"});
  return factories;
}

using SigningKeyTest = FactoryParamTest<SigningKeyFactory, FactoryInfoVector>;

TEST_P(SigningKeyTest, SignVerify) {
  auto status_or_private_key_data = factory().CreateRandomPrivateKeyData();
  CRUNCHY_EXPECT_OK(status_or_private_key_data.status());
  KeyData private_key_data = status_or_private_key_data.ValueOrDie();

  auto status_or_public_key_data =
      factory().CreatePublicKeyData(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key_data.status());
  KeyData public_key_data = status_or_public_key_data.ValueOrDie();

  std::string message = "banana";
  auto status_or_private_key = factory().MakeSigningKey(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_private_key.status());
  std::unique_ptr<SigningKey> private_key =
      std::move(status_or_private_key.ValueOrDie());

  auto status_or_public_key = factory().MakeVerifyingKey(public_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key.status());
  std::unique_ptr<VerifyingKey> public_key =
      std::move(status_or_public_key.ValueOrDie());

  auto status_or_signature = private_key->Sign(message);
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());

  CRUNCHY_EXPECT_OK(public_key->Verify(message, signature));
}

TEST_P(SigningKeyTest, SignVerifyErrors) {
  auto status_or_private_key_data = factory().CreateRandomPrivateKeyData();
  CRUNCHY_EXPECT_OK(status_or_private_key_data.status());
  KeyData private_key_data = status_or_private_key_data.ValueOrDie();

  auto status_or_public_key_data =
      factory().CreatePublicKeyData(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key_data.status());
  KeyData public_key_data = status_or_public_key_data.ValueOrDie();

  std::string message = "banana";
  auto status_or_private_key = factory().MakeSigningKey(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_private_key.status());
  std::unique_ptr<SigningKey> private_key =
      std::move(status_or_private_key.ValueOrDie());

  auto status_or_public_key = factory().MakeVerifyingKey(public_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key.status());
  std::unique_ptr<VerifyingKey> public_key =
      std::move(status_or_public_key.ValueOrDie());

  auto status_or_signature = private_key->Sign(message);
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());

  CRUNCHY_EXPECT_OK(public_key->Verify(message, signature));

  // Corrupt signature start
  signature[0] ^= 0x01;
  EXPECT_FALSE(public_key->Verify(message, signature).ok());
  signature[0] ^= 0x01;

  // Corrupt ciphertext middle
  signature[signature.length() / 2] ^= 0x01;
  EXPECT_FALSE(public_key->Verify(message, signature).ok());
  signature[signature.length() / 2] ^= 0x01;

  // Corrupt signature end
  signature[signature.length() - 1] ^= 0x01;
  EXPECT_FALSE(public_key->Verify(message, signature).ok());
  signature[signature.length() - 1] ^= 0x01;

  // Corrupt message
  message[0] ^= 0x01;
  EXPECT_FALSE(public_key->Verify(message, signature).ok());
  message[0] ^= 0x01;

  // Signature too short
  EXPECT_FALSE(
      public_key
          ->Verify(message, absl::ClippedSubstr(absl::string_view(signature),
                                                signature.length() - 1))
          .ok());
}

TEST_P(SigningKeyTest, BadKeyData) {
  auto status_or_private_key_data = factory().CreateRandomPrivateKeyData();
  CRUNCHY_EXPECT_OK(status_or_private_key_data.status());
  KeyData private_key_data = status_or_private_key_data.ValueOrDie();
  CRUNCHY_EXPECT_OK(factory().MakeSigningKey(private_key_data).status());

  auto status_or_public_key_data =
      factory().CreatePublicKeyData(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key_data.status());
  KeyData public_key_data = status_or_public_key_data.ValueOrDie();
  CRUNCHY_EXPECT_OK(factory().MakeVerifyingKey(public_key_data).status());

  // MakeSigner with missing private_key
  KeyData bad_key_data = private_key_data;
  bad_key_data.clear_private_key();
  EXPECT_FALSE(factory().MakeSigningKey(bad_key_data).ok());

  // MakeVerifier with missing public_key
  bad_key_data = public_key_data;
  bad_key_data.clear_public_key();
  EXPECT_FALSE(factory().MakeVerifyingKey(bad_key_data).ok());

  // MakeVerifier with private_key
  EXPECT_FALSE(factory().MakeVerifyingKey(private_key_data).ok());

  // CreatePublicKeyData with no public_key
  bad_key_data = private_key_data;
  bad_key_data.clear_public_key();
  EXPECT_FALSE(factory().CreatePublicKeyData(bad_key_data).ok());

  // MakeSigner with corrupt private_key
  bad_key_data = private_key_data;
  bad_key_data.set_private_key("corn");
  EXPECT_FALSE(factory().MakeSigningKey(bad_key_data).ok());

  // MakeVerifier with corrupt public_key
  bad_key_data = public_key_data;
  bad_key_data.set_public_key("corn");
  EXPECT_FALSE(factory().MakeVerifyingKey(bad_key_data).ok());
}

void VerifyTestVector(const SigningKeyFactory& factory,
                      const SigningKeyTestVector& test_vector) {
  // Create a signer and verifier from the test_vector
  auto status_or_private_key =
      factory.MakeSigningKey(test_vector.private_key_data());
  CRUNCHY_EXPECT_OK(status_or_private_key.status());
  std::unique_ptr<SigningKey> private_key =
      std::move(status_or_private_key.ValueOrDie());
  auto status_or_public_key =
      factory.MakeVerifyingKey(test_vector.public_key_data());
  CRUNCHY_EXPECT_OK(status_or_public_key.status());
  std::unique_ptr<VerifyingKey> public_key =
      std::move(status_or_public_key.ValueOrDie());

  // Verify the test vector
  CRUNCHY_EXPECT_OK(
      public_key->Verify(test_vector.message(), test_vector.signature()));

  // Sign and verify the message
  auto status_or_signature = private_key->Sign(test_vector.message());
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());
  CRUNCHY_EXPECT_OK(public_key->Verify(test_vector.message(), signature));

  // Create a verifier from the private key and verify with the result
  auto status_or_public_key_data =
      factory.CreatePublicKeyData(test_vector.private_key_data());
  CRUNCHY_EXPECT_OK(status_or_public_key_data.status());
  KeyData public_key_data = status_or_public_key_data.ValueOrDie();
  status_or_public_key = factory.MakeVerifyingKey(public_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key.status());
  public_key = std::move(status_or_public_key.ValueOrDie());
  CRUNCHY_EXPECT_OK(
      public_key->Verify(test_vector.message(), test_vector.signature()));
}

TEST_P(SigningKeyTest, TestVectors) {
  auto test_vectors = GetTestVectors<SigningKeyTestVectors>();
  for (const auto& test_vector : test_vectors->test_vector()) {
    VerifyTestVector(factory(), test_vector);
  }
}

INSTANTIATE_TEST_CASE_P(, SigningKeyTest,
                        ::testing::ValuesIn(SigningKeyTest::factories()),
                        SigningKeyTest::GetNameFromParam);

SigningKeyTestVector GenerateTestVector(const SigningKeyFactory& factory) {
  auto status_or_private_key_data = factory.CreateRandomPrivateKeyData();
  CRUNCHY_EXPECT_OK(status_or_private_key_data.status());
  KeyData private_key_data = status_or_private_key_data.ValueOrDie();

  auto status_or_public_key_data =
      factory.CreatePublicKeyData(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key_data.status());
  KeyData public_key_data = status_or_public_key_data.ValueOrDie();

  size_t message_magnatude = BiasRandInt(10);
  size_t message_length = BiasRandInt(1 << message_magnatude);
  std::string message = RandString(message_length);

  auto status_or_private_key = factory.MakeSigningKey(private_key_data);
  CRUNCHY_EXPECT_OK(status_or_private_key.status());
  std::unique_ptr<SigningKey> private_key =
      std::move(status_or_private_key.ValueOrDie());

  auto status_or_public_key = factory.MakeVerifyingKey(public_key_data);
  CRUNCHY_EXPECT_OK(status_or_public_key.status());
  std::unique_ptr<VerifyingKey> public_key =
      std::move(status_or_public_key.ValueOrDie());

  auto status_or_signature = private_key->Sign(message);
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());

  SigningKeyTestVector test_vector;
  *test_vector.mutable_private_key_data() = private_key_data;
  *test_vector.mutable_public_key_data() = public_key_data;
  test_vector.set_message(message);
  test_vector.set_signature(signature);

  VerifyTestVector(factory, test_vector);
  return test_vector;
}

}  // namespace

}  // namespace crunchy

int main(int argc, char** argv) {
  crunchy::InitCrunchyTest(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
