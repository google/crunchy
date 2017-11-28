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

#include "crunchy/internal/keyset/signer_factory.h"

#include <stddef.h>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/common/file.h"
#include "crunchy/internal/common/init.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/test_factory.h"
#include "crunchy/internal/keys/key_util.h"
#include "crunchy/internal/keyset/keyset_util.h"
#include "crunchy/internal/keyset/testdata/factory_test_vectors.pb.h"
#include "crunchy/key_management/algorithms.h"
#include "crunchy/key_management/crunchy_factory.h"
#include "crunchy/key_management/internal/advanced_keyset_manager.h"
#include "crunchy/key_management/key_handle.h"
#include "crunchy/key_management/keyset_handle.h"
#include "crunchy/key_management/keyset_manager.h"

namespace crunchy {

namespace {

const char kKeyUri[] = "p256-ecdsa";

std::shared_ptr<KeysetHandle> GetDefaultKeysetHandle() {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);
  auto status_or_key_handle =
      keyset_manager->GenerateAndAddNewKey(GetP256EcdsaKeyType());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteToPrimary(key_handle));
  return keyset_handle;
}

TEST(KeysetFactoryTest, BadKeyset) {
  // empty keyset
  {
    auto keyset_handle = std::make_shared<KeysetHandle>();
    ASSERT_FALSE(MakeCrunchySigner(keyset_handle).ok());
    ASSERT_FALSE(MakeCrunchyVerifier(keyset_handle).ok());
  }

  // bad primary id
  {
    auto private_keyset_handle = std::make_shared<KeysetHandle>();
    auto keyset_manager =
        ::absl::make_unique<KeysetManager>(private_keyset_handle);
    CRUNCHY_EXPECT_OK(
        keyset_manager->GenerateAndAddNewKey(GetP256EcdsaKeyType()));
    auto status_or_public_keyset_handle =
        private_keyset_handle->CloneAsPublicOnly();
    CRUNCHY_EXPECT_OK(status_or_public_keyset_handle.status());
    auto public_keyset_handle = status_or_public_keyset_handle.ValueOrDie();
    ASSERT_FALSE(MakeCrunchySigner(public_keyset_handle).ok());

    // Verifier doesn't mind
    CRUNCHY_ASSERT_OK(MakeCrunchyVerifier(public_keyset_handle).status());
  }

  // Using a private key for a verifier
  {
    std::shared_ptr<KeysetHandle> private_keyset_handle =
        GetDefaultKeysetHandle();
    ASSERT_FALSE(MakeCrunchyVerifier(private_keyset_handle).ok());
  }
}

TEST(KeysetFactoryTest, SignVerify) {
  std::shared_ptr<KeysetHandle> private_keyset_handle =
      GetDefaultKeysetHandle();
  auto status_or_signer = MakeCrunchySigner(private_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_signer.status());
  std::unique_ptr<CrunchySigner> signer =
      std::move(status_or_signer.ValueOrDie());

  auto status_or_public_keyset_handle =
      private_keyset_handle->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_public_keyset_handle);
  auto public_keyset_handle = status_or_public_keyset_handle.ValueOrDie();
  auto status_or_verifier = MakeCrunchyVerifier(public_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_verifier.status());
  std::unique_ptr<CrunchyVerifier> verifier =
      std::move(status_or_verifier.ValueOrDie());

  std::string message = "banana";

  auto status_or_signature = signer->Sign(message);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());
  CRUNCHY_ASSERT_OK(verifier->Verify(message, signature));
}

TEST(KeysetFactoryTest, SignVerifyErrors) {
  std::shared_ptr<KeysetHandle> private_keyset_handle =
      GetDefaultKeysetHandle();
  auto status_or_signer = MakeCrunchySigner(private_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_signer.status());
  std::unique_ptr<CrunchySigner> signer =
      std::move(status_or_signer.ValueOrDie());

  auto status_or_public_keyset_handle =
      private_keyset_handle->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_public_keyset_handle);
  auto public_keyset_handle = status_or_public_keyset_handle.ValueOrDie();
  auto status_or_verifier = MakeCrunchyVerifier(public_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_verifier.status());
  std::unique_ptr<CrunchyVerifier> verifier =
      std::move(status_or_verifier.ValueOrDie());

  std::string message = "banana";

  auto status_or_signature = signer->Sign(message);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());
  CRUNCHY_ASSERT_OK(verifier->Verify(message, signature));

  // Corrupt start
  signature[0] ^= 0x01;
  ASSERT_FALSE(verifier->Verify(message, signature).ok());
  signature[0] ^= 0x01;

  // Corrupt middle
  signature[signature.length() / 2] ^= 0x01;
  ASSERT_FALSE(verifier->Verify(message, signature).ok());
  signature[signature.length() / 2] ^= 0x01;

  // Corrupt end
  signature[signature.length() - 1] ^= 0x01;
  ASSERT_FALSE(verifier->Verify(message, signature).ok());
  signature[signature.length() - 1] ^= 0x01;

  // No key found
  std::shared_ptr<KeysetHandle> another_private_keyset_handle =
      GetDefaultKeysetHandle();
  auto status_or_another_public_keyset_handle =
      another_private_keyset_handle->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_another_public_keyset_handle);
  auto another_public_keyset_handle =
      status_or_another_public_keyset_handle.ValueOrDie();
  auto status_or_another_verifier =
      MakeCrunchyVerifier(another_public_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_another_verifier.status());
  std::unique_ptr<CrunchyVerifier> another_verifier =
      std::move(status_or_another_verifier.ValueOrDie());
  ASSERT_FALSE(another_verifier->Verify(message, signature).ok());
}

TEST(KeysetFactoryTest, TwoKey) {
  // Get two random keysets and create a signature for each one.
  std::string message1 = "banana";
  std::string message2 = "plantain";

  std::shared_ptr<KeysetHandle> private_keyset_handle1 =
      GetDefaultKeysetHandle();
  auto status_or_signer1 = MakeCrunchySigner(private_keyset_handle1);
  CRUNCHY_ASSERT_OK(status_or_signer1.status());
  std::unique_ptr<CrunchySigner> signer1 =
      std::move(status_or_signer1.ValueOrDie());
  auto status_or_signature = signer1->Sign(message1);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string signature1 = std::move(status_or_signature.ValueOrDie());

  std::shared_ptr<KeysetHandle> private_keyset_handle2 =
      GetDefaultKeysetHandle();
  auto status_or_signer2 = MakeCrunchySigner(private_keyset_handle2);
  CRUNCHY_ASSERT_OK(status_or_signer2.status());
  std::unique_ptr<CrunchySigner> signer2 =
      std::move(status_or_signer2.ValueOrDie());
  status_or_signature = signer2->Sign(message2);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string signature2 = std::move(status_or_signature.ValueOrDie());

  // Make sure we can verify both signatures using a combined private_keyset.
  std::shared_ptr<KeysetHandle> combined_private_keyset_handle =
      std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<AdvancedKeysetManager>(
      combined_private_keyset_handle);
  EXPECT_EQ(1, private_keyset_handle1->key_handles().size());
  for (const auto& key_handle : private_keyset_handle1->key_handles()) {
    CRUNCHY_ASSERT_OK(keyset_manager->AddKey(key_handle));
    CRUNCHY_ASSERT_OK(keyset_manager->PromoteToPrimary(key_handle));
  }
  EXPECT_EQ(1, private_keyset_handle2->key_handles().size());
  for (const auto& key_handle : private_keyset_handle2->key_handles()) {
    CRUNCHY_ASSERT_OK(keyset_manager->AddKey(key_handle));
    CRUNCHY_ASSERT_OK(keyset_manager->PromoteToPrimary(key_handle));
  }
  auto status_or_combined_public_keyset_handle =
      combined_private_keyset_handle->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_combined_public_keyset_handle);
  auto status_or_verifier =
      MakeCrunchyVerifier(status_or_combined_public_keyset_handle.ValueOrDie());
  CRUNCHY_ASSERT_OK(status_or_verifier.status());
  std::unique_ptr<CrunchyVerifier> combined_verifier =
      std::move(status_or_verifier.ValueOrDie());

  CRUNCHY_ASSERT_OK(combined_verifier->Verify(message1, signature1));
  CRUNCHY_ASSERT_OK(combined_verifier->Verify(message2, signature2));

  // Sign using the combined private_keyset, which should use key2
  auto status_or_signer = MakeCrunchySigner(combined_private_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_signer.status());
  std::unique_ptr<CrunchySigner> combined_signer =
      std::move(status_or_signer.ValueOrDie());
  status_or_signature = combined_signer->Sign(message1);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());

  // Verify using verifier1, should fail
  auto status_or_public_keyset_handle1 =
      private_keyset_handle1->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_public_keyset_handle1);
  status_or_verifier =
      MakeCrunchyVerifier(status_or_public_keyset_handle1.ValueOrDie());
  CRUNCHY_ASSERT_OK(status_or_verifier.status());
  std::unique_ptr<CrunchyVerifier> verifier1 =
      std::move(status_or_verifier.ValueOrDie());
  ASSERT_FALSE(verifier1->Verify(message1, signature).ok());

  // Verify using verifier2, should succeed
  auto status_or_public_keyset_handle2 =
      private_keyset_handle2->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_public_keyset_handle2);
  status_or_verifier =
      MakeCrunchyVerifier(status_or_public_keyset_handle2.ValueOrDie());
  CRUNCHY_ASSERT_OK(status_or_verifier.status());
  std::unique_ptr<CrunchyVerifier> verifier2 =
      std::move(status_or_verifier.ValueOrDie());
  CRUNCHY_ASSERT_OK(verifier2->Verify(message1, signature));
}

TEST(KeysetFactoryTest, Prefix) {
  // Create prefix signer
  std::shared_ptr<KeysetHandle> private_prefix_keyset_handle =
      GetDefaultKeysetHandle();
  auto status_or_prefix_signer =
      MakeCrunchySigner(private_prefix_keyset_handle);
  CRUNCHY_EXPECT_OK(status_or_prefix_signer.status());
  auto prefix_signer = std::move(status_or_prefix_signer.ValueOrDie());
  EXPECT_EQ(1, private_prefix_keyset_handle->key_handles().size());
  const std::string prefix =
      private_prefix_keyset_handle->key_handles().at(0)->metadata().prefix();

  // Create prefix verifier
  auto status_or_public_prefix_handle =
      private_prefix_keyset_handle->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_public_prefix_handle);
  auto status_or_prefix_verifier =
      MakeCrunchyVerifier(status_or_public_prefix_handle.ValueOrDie());
  CRUNCHY_EXPECT_OK(status_or_prefix_verifier);
  auto prefix_verifier = std::move(status_or_prefix_verifier.ValueOrDie());

  // Create nonprefix signer
  auto status_or_private_nonprefix_keyset_handle =
      KeysetUtil::MakeCopy(private_prefix_keyset_handle);
  CRUNCHY_EXPECT_OK(status_or_private_nonprefix_keyset_handle);
  auto private_nonprefix_keyset_handle =
      status_or_private_nonprefix_keyset_handle.ValueOrDie();
  EXPECT_EQ(1, private_nonprefix_keyset_handle->key_handles().size());
  KeyMetadata* key_metadata = KeyUtil::GetKeyMetadata(
      private_nonprefix_keyset_handle->key_handles().at(0));
  key_metadata->clear_prefix();
  auto status_or_nonprefix_signer =
      MakeCrunchySigner(private_nonprefix_keyset_handle);
  CRUNCHY_EXPECT_OK(status_or_nonprefix_signer);
  auto nonprefix_signer = std::move(status_or_nonprefix_signer.ValueOrDie());

  // Create nonprefix verifier
  auto status_or_nonprefix_keyset_handle =
      private_nonprefix_keyset_handle->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_nonprefix_keyset_handle);
  auto status_or_nonprefix_verifier =
      MakeCrunchyVerifier(status_or_nonprefix_keyset_handle.ValueOrDie());
  CRUNCHY_EXPECT_OK(status_or_nonprefix_verifier);
  auto nonprefix_verifier =
      std::move(status_or_nonprefix_verifier.ValueOrDie());

  std::string message = "banana";

  // Create a pair of signatures
  auto status_or_signature = prefix_signer->Sign(message);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string prefix_signature = std::move(status_or_signature.ValueOrDie());
  status_or_signature = nonprefix_signer->Sign(message);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());

  // Prove that the prefix is independent of the rest of the signature
  CRUNCHY_ASSERT_OK(nonprefix_verifier->Verify(
      message, prefix_signature.substr(prefix.size())));
  CRUNCHY_ASSERT_OK(
      prefix_verifier->Verify(message, absl::StrCat(prefix, signature)));
}

TEST(KeysetFactoryTest, StringFactory) {
  std::shared_ptr<KeysetHandle> private_keyset_handle =
      GetDefaultKeysetHandle();
  auto status_or_public_keyset_handle =
      private_keyset_handle->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_public_keyset_handle);
  auto public_keyset_handle = status_or_public_keyset_handle.ValueOrDie();

  Keyset private_keyset =
      KeysetUtil::KeysetHandleAsProto(private_keyset_handle);
  Keyset public_keyset = KeysetUtil::KeysetHandleAsProto(public_keyset_handle);

  CRUNCHY_EXPECT_OK(
      MakeCrunchySigner(private_keyset.SerializeAsString()).status());
  CRUNCHY_EXPECT_OK(
      MakeCrunchyVerifier(public_keyset.SerializeAsString()).status());

  std::string malformed_keyset = "apple";
  EXPECT_FALSE(MakeCrunchySigner(malformed_keyset).ok());
  EXPECT_FALSE(MakeCrunchyVerifier(malformed_keyset).ok());
}

const char kTestDataPath[] =
    "crunchy/internal/keyset/testdata/"
    "signer_factory_test_vectors.proto.bin";

void VerifyTestVector(const SigningKeyRegistry& registry,
                      const SignerFactoryTestVector& test_vector) {
  auto status_or_verifier =
      MakeCrunchyVerifier(registry, test_vector.public_keyset());
  CRUNCHY_ASSERT_OK(status_or_verifier.status());
  std::unique_ptr<CrunchyVerifier> verifier =
      std::move(status_or_verifier.ValueOrDie());

  CRUNCHY_EXPECT_OK(
      verifier->Verify(test_vector.message(), test_vector.signature()));
}

TEST(KeysetFactoryTest, TestVectors) {
  const SigningKeyRegistry& registry = GetSigningKeyRegistry();
  SignerFactoryTestVectors test_vectors;

  std::string serialized_test_vectors;
  CRUNCHY_EXPECT_OK(GetFile(kTestDataPath, &serialized_test_vectors))
      << "Couldn't load test vectors, try passing --gen_test_vectors=yes";
  EXPECT_TRUE(test_vectors.ParseFromString(serialized_test_vectors));
  for (const SignerFactoryTestVector& test_vector :
       test_vectors.test_vector()) {
    VerifyTestVector(registry, test_vector);
  }
}

}  // namespace

}  // namespace crunchy

int main(int argc, char** argv) {
  crunchy::InitCrunchyTest(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
