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

#include "crunchy/internal/keyset/macer_factory.h"

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
#include "crunchy/key_management/crunchy_factory.h"
#include "crunchy/key_management/internal/advanced_keyset_manager.h"
#include "crunchy/key_management/key_handle.h"
#include "crunchy/key_management/keyset_handle.h"
#include "crunchy/key_management/keyset_manager.h"

namespace crunchy {

namespace {

const char kKeyUri[] = "hmac-sha256-halfdigest";

std::shared_ptr<KeysetHandle> GetDefaultKeysetHandle() {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);
  auto status_or_key_handle = keyset_manager->GenerateAndAddNewKey(kKeyUri);
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteToPrimary(key_handle));
  return keyset_handle;
}

TEST(KeysetFactoryTest, BadKeyset) {
  // empty keyset
  {
    auto keyset_handle = std::make_shared<KeysetHandle>();
    ASSERT_FALSE(MakeCrunchyMacer(keyset_handle).ok());
  }

  // bad primary id
  {
    auto keyset_handle = std::make_shared<KeysetHandle>();
    auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);
    CRUNCHY_EXPECT_OK(keyset_manager->GenerateAndAddNewKey(kKeyUri));
    ASSERT_FALSE(MakeCrunchyMacer(keyset_handle).ok());
  }
}

TEST(KeysetFactoryTest, SignVerify) {
  auto keyset_handle = GetDefaultKeysetHandle();
  auto status_or_macer = MakeCrunchyMacer(keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_macer.status());
  std::unique_ptr<CrunchyMacer> macer = std::move(status_or_macer.ValueOrDie());

  std::string message = "banana";

  auto status_or_signature = macer->Sign(message);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());
  CRUNCHY_ASSERT_OK(macer->Verify(message, signature));
}

TEST(KeysetFactoryTest, SignVerifyErrors) {
  auto keyset_handle = GetDefaultKeysetHandle();
  auto status_or_macer = MakeCrunchyMacer(keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_macer.status());
  std::unique_ptr<CrunchyMacer> macer = std::move(status_or_macer.ValueOrDie());

  std::string message = "banana";

  auto status_or_signature = macer->Sign(message);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());
  CRUNCHY_ASSERT_OK(macer->Verify(message, signature));

  // Corrupt start
  signature[0] ^= 0x01;
  ASSERT_FALSE(macer->Verify(message, signature).ok());
  signature[0] ^= 0x01;

  // Corrupt middle
  signature[signature.length() / 2] ^= 0x01;
  ASSERT_FALSE(macer->Verify(message, signature).ok());
  signature[signature.length() / 2] ^= 0x01;

  // Corrupt end
  signature[signature.length() - 1] ^= 0x01;
  ASSERT_FALSE(macer->Verify(message, signature).ok());
  signature[signature.length() - 1] ^= 0x01;

  // No key found
  auto another_keyset_handle = GetDefaultKeysetHandle();
  auto status_or_another_macer = MakeCrunchyMacer(another_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_another_macer.status());
  std::unique_ptr<CrunchyMacer> another_macer =
      std::move(status_or_another_macer.ValueOrDie());
  ASSERT_FALSE(another_macer->Verify(message, signature).ok());
}

TEST(KeysetFactoryTest, TwoKey) {
  // Get two random keysets and create a signature for each one.
  std::string message1 = "banana";
  std::string message2 = "plantain";
  std::string aad = "apple";

  auto keyset_handle1 = GetDefaultKeysetHandle();
  auto status_or_macer1 = MakeCrunchyMacer(keyset_handle1);
  CRUNCHY_ASSERT_OK(status_or_macer1.status());
  std::unique_ptr<CrunchyMacer> macer1 =
      std::move(status_or_macer1.ValueOrDie());
  auto status_or_signature = macer1->Sign(message1);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string signature1 = std::move(status_or_signature.ValueOrDie());

  auto keyset_handle2 = GetDefaultKeysetHandle();
  auto status_or_macer2 = MakeCrunchyMacer(keyset_handle2);
  CRUNCHY_ASSERT_OK(status_or_macer2.status());
  std::unique_ptr<CrunchyMacer> macer2 =
      std::move(status_or_macer2.ValueOrDie());
  status_or_signature = macer2->Sign(message2);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string signature2 = std::move(status_or_signature.ValueOrDie());

  // Make sure we can verify both signatures using a combined keyset.
  auto combined_keyset_handle = std::make_shared<KeysetHandle>();
  auto combined_keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(combined_keyset_handle);
  for (const auto& key_handle : keyset_handle1->key_handles()) {
    CRUNCHY_EXPECT_OK(combined_keyset_manager->AddKey(key_handle));
    CRUNCHY_EXPECT_OK(combined_keyset_manager->PromoteToPrimary(key_handle));
  }
  for (const auto& key_handle : keyset_handle2->key_handles()) {
    CRUNCHY_EXPECT_OK(combined_keyset_manager->AddKey(key_handle));
    CRUNCHY_EXPECT_OK(combined_keyset_manager->PromoteToPrimary(key_handle));
  }
  auto status_or_combined_macer = MakeCrunchyMacer(combined_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_combined_macer.status());
  std::unique_ptr<CrunchyMacer> combined_macer =
      std::move(status_or_combined_macer.ValueOrDie());

  CRUNCHY_ASSERT_OK(combined_macer->Verify(message1, signature1));
  CRUNCHY_ASSERT_OK(combined_macer->Verify(message2, signature2));

  // Sign using the combined keyset, which should use key2
  status_or_signature = combined_macer->Sign(message1);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());

  // Decrypt using macer1 (failure) and macer2 (success)
  ASSERT_FALSE(macer1->Verify(message1, signature).ok());
  CRUNCHY_ASSERT_OK(macer2->Verify(message1, signature));
}

TEST(KeysetFactoryTest, Prefix) {
  auto prefix_keyset_handle = GetDefaultKeysetHandle();
  EXPECT_EQ(1, prefix_keyset_handle->key_handles().size());
  const std::string prefix =
      prefix_keyset_handle->key_handles().at(0)->metadata().prefix();

  // Create keyset with the same key but remove the prefix
  auto nonprefix_keyset_handle = std::make_shared<KeysetHandle>();
  auto nonprefix_keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(nonprefix_keyset_handle);
  for (const auto& key_handle : prefix_keyset_handle->key_handles()) {
    auto status_or_cloned_key_handle = KeyUtil::MakeCopy(key_handle);
    CRUNCHY_EXPECT_OK(status_or_cloned_key_handle);
    auto cloned_key_handle = status_or_cloned_key_handle.ValueOrDie();
    KeyMetadata* key_metadata = KeyUtil::GetKeyMetadata(cloned_key_handle);
    key_metadata->clear_prefix();
    CRUNCHY_EXPECT_OK(nonprefix_keyset_manager->AddKey(cloned_key_handle));
    CRUNCHY_EXPECT_OK(
        nonprefix_keyset_manager->PromoteToPrimary(cloned_key_handle));
  }

  auto status_or_macer = MakeCrunchyMacer(prefix_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_macer.status());
  std::unique_ptr<CrunchyMacer> prefix_macer =
      std::move(status_or_macer.ValueOrDie());
  status_or_macer = MakeCrunchyMacer(nonprefix_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_macer.status());
  std::unique_ptr<CrunchyMacer> macer = std::move(status_or_macer.ValueOrDie());

  std::string message = "banana";

  // Create a pair of signatures
  auto status_or_signature = prefix_macer->Sign(message);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string prefix_signature = std::move(status_or_signature.ValueOrDie());
  status_or_signature = macer->Sign(message);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());

  // Prove that the prefix is independent of the rest of the signature
  CRUNCHY_ASSERT_OK(
      macer->Verify(message, prefix_signature.substr(prefix.size())));
  CRUNCHY_ASSERT_OK(
      prefix_macer->Verify(message, absl::StrCat(prefix, signature)));
}

TEST(KeysetFactoryTest, StringFactory) {
  auto keyset_handle = GetDefaultKeysetHandle();
  Keyset keyset = KeysetUtil::KeysetHandleAsProto(keyset_handle);
  CRUNCHY_EXPECT_OK(MakeCrunchyMacer(keyset.SerializeAsString()).status());

  std::string malformed_keyset = "apple";
  EXPECT_FALSE(MakeCrunchyMacer(malformed_keyset).ok());
}

const char kTestDataPath[] =
    "crunchy/internal/keyset/testdata/"
    "macer_factory_test_vectors.proto.bin";

void VerifyTestVector(const MacingKeyRegistry& registry,
                      const MacerFactoryTestVector& test_vector) {
  auto status_or_macer = MakeCrunchyMacer(registry, test_vector.keyset());
  CRUNCHY_ASSERT_OK(status_or_macer.status());
  std::unique_ptr<CrunchyMacer> macer = std::move(status_or_macer.ValueOrDie());

  CRUNCHY_EXPECT_OK(
      macer->Verify(test_vector.message(), test_vector.signature()));
}

TEST(KeysetFactoryTest, TestVectors) {
  const MacingKeyRegistry& registry = GetMacingKeyRegistry();
  MacerFactoryTestVectors test_vectors;

  std::string serialized_test_vectors;
  CRUNCHY_EXPECT_OK(GetFile(kTestDataPath, &serialized_test_vectors))
      << "Couldn't load test vectors, try passing --gen_test_vectors=yes";
  EXPECT_TRUE(test_vectors.ParseFromString(serialized_test_vectors));
  for (const MacerFactoryTestVector& test_vector : test_vectors.test_vector()) {
    VerifyTestVector(registry, test_vector);
  }
}

}  // namespace

}  // namespace crunchy

int main(int argc, char** argv) {
  crunchy::InitCrunchyTest(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
