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

#include "crunchy/key_management/keyset_manager.h"

#include <stdint.h>
#include <string>

#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/crunchy_crypter.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/keys/key_util.h"
#include "crunchy/internal/port/port.h"
#include "crunchy/key_management/algorithms.h"
#include "crunchy/key_management/internal/advanced_keyset_manager.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

class KeysetManagerTest : public ::testing::TestWithParam<const KeyType*> {
 protected:
  const KeyType& type() { return *GetParam(); }
};

TEST_P(KeysetManagerTest, GenerateAndAddNewKeyAsPrimary) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);

  auto status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteToPrimary(key_handle));

  EXPECT_EQ(1, keyset_manager->KeyHandles().size());
  EXPECT_EQ(type().crunchy_label(),
            key_handle->metadata().type().crunchy_label());
  EXPECT_EQ(key_handle, keyset_manager->PrimaryKey());
}

TEST_P(KeysetManagerTest, GenerateOneAndPromoteNextToPrimary) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);

  auto status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = keyset_manager->PromoteNextToPrimary().ValueOrDie();

  EXPECT_EQ(1, keyset_manager->KeyHandles().size());
  EXPECT_EQ(key_handle, keyset_manager->PrimaryKey());
}

TEST_P(KeysetManagerTest, GenerateTwoAndPromoteNextToPrimary) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);

  auto status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteToPrimary(key_handle));
  status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  key_handle = status_or_key_handle.ValueOrDie();
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteNextToPrimary());

  EXPECT_EQ(2, keyset_manager->KeyHandles().size());
  EXPECT_EQ(key_handle, keyset_manager->PrimaryKey());
}

TEST_P(KeysetManagerTest, EmptyKeysetPromoteNextToPrimaryError) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);
  EXPECT_EQ(FailedPreconditionError(
                "Keyset is empty. Can't promote next key to primary."),
            keyset_manager->PromoteNextToPrimary());
}

TEST_P(KeysetManagerTest, NewestKeyAlreadyPrimaryPromoteNextToPrimaryError) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);

  auto status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteNextToPrimary());

  EXPECT_EQ(FailedPreconditionError("Newest key is already the primary key. "
                                    "Can't promote next key to primary."),
            keyset_manager->PromoteNextToPrimary());
}

TEST_P(KeysetManagerTest, GarbageCollectKeysSuccess) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);

  auto status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  KeyMetadata* key_metadata = KeyUtil::GetKeyMetadata(key_handle);
  key_metadata->set_status(KeyStatus::DELETED);
  EXPECT_EQ(1, keyset_handle->key_handles().size());
  CRUNCHY_EXPECT_OK(keyset_manager->GarbageCollectKeys());
  EXPECT_EQ(0, keyset_handle->key_handles().size());
}

TEST_P(KeysetManagerTest, GarbageCollectKeysWithMultipleSuccess) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);

  auto status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle_to_keep = status_or_key_handle.ValueOrDie();

  status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle_to_delete = status_or_key_handle.ValueOrDie();
  KeyMetadata* key_metadata = KeyUtil::GetKeyMetadata(key_handle_to_delete);
  key_metadata->set_status(KeyStatus::DELETED);

  std::vector<std::shared_ptr<KeyHandle>> deleted_keys =
      keyset_manager->GarbageCollectKeys().ValueOrDie();

  std::vector<std::shared_ptr<KeyHandle>> expected_deleted_keys = {
      key_handle_to_delete};
  EXPECT_EQ(expected_deleted_keys, deleted_keys);

  std::vector<std::shared_ptr<KeyHandle>> expected_keys_to_keep = {
      key_handle_to_keep};
  EXPECT_EQ(expected_keys_to_keep, keyset_handle->key_handles());
}

TEST_P(KeysetManagerTest, GarbageCollectKeysPrimaryKeyError) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);

  auto status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteToPrimary(key_handle));
  KeyMetadata* key_metadata = KeyUtil::GetKeyMetadata(key_handle);
  key_metadata->set_status(KeyStatus::DELETED);
  EXPECT_EQ(FailedPreconditionError(
                "Primary key has DELETED status. Refusing to delete."),
            keyset_manager->GarbageCollectKeys());
}

TEST_P(KeysetManagerTest, GarbageCollectKeysEmptyKeyset) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);
  std::vector<std::shared_ptr<KeyHandle>> deleted_keys =
      keyset_manager->GarbageCollectKeys().ValueOrDie();
  EXPECT_EQ(0, deleted_keys.size());
}

TEST_P(KeysetManagerTest, DeleteOldestKeySuccess) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);

  auto status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle_to_delete = status_or_key_handle.ValueOrDie();

  status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle_to_keep = status_or_key_handle.ValueOrDie();

  std::shared_ptr<KeyHandle> deleted_key =
      keyset_manager->DeleteOldestKey().ValueOrDie();

  EXPECT_EQ(deleted_key, key_handle_to_delete);

  std::vector<std::shared_ptr<KeyHandle>> expected_keys_to_keep = {
      key_handle_to_keep};
  EXPECT_EQ(expected_keys_to_keep, keyset_handle->key_handles());
}

TEST_P(KeysetManagerTest, DeleteOldestKeyEmptyKeyset) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);
  EXPECT_EQ(
      FailedPreconditionError("Keyset is empty. Can't delete oldest key."),
      keyset_manager->DeleteOldestKey().status());
}

TEST_P(KeysetManagerTest, DeleteOldestKeyOldestKeyIsPrimaryError) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);

  auto status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteToPrimary(key_handle));
  EXPECT_EQ(FailedPreconditionError(
                "Oldest key is primary key. Can't delete oldest key."),
            keyset_manager->DeleteOldestKey().status());
}

TEST_P(KeysetManagerTest, GenerateAndAddNewKeyIncrementalTwoBytePrefix) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);

  const int kNumKeys = 100;
  for (uint16_t i = 0; i < kNumKeys; ++i) {
    auto status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
    CRUNCHY_EXPECT_OK(status_or_key_handle.status());
    auto key_handle = status_or_key_handle.ValueOrDie();
    const uint16_t generated_prefix =
        BigEndianLoad16(key_handle->metadata().prefix().data());
    EXPECT_EQ(i, generated_prefix);
  }
}

TEST_P(KeysetManagerTest,
       GenerateAndAddNewKeyIncrementalTwoBytePrefixChooseNext) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);

  const int kNumKeys = 100;
  for (uint16_t i = 0; i < kNumKeys; ++i) {
    auto status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
    CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  }

  // Delete random key.
  const int key_index_to_delete = 43;
  auto advanced_keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(keyset_handle);
  auto key_handle_to_delete =
      keyset_handle->key_handles().at(key_index_to_delete);
  CRUNCHY_EXPECT_OK(advanced_keyset_manager->RemoveKey(key_handle_to_delete));
  CRUNCHY_EXPECT_OK(keyset_manager->GarbageCollectKeys());

  // Ensure deleted key has index kNumKeys.
  auto status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  const uint16_t generated_prefix =
      BigEndianLoad16(key_handle->metadata().prefix().data());
  EXPECT_EQ(kNumKeys, generated_prefix);
}

TEST_P(KeysetManagerTest, GenerateAndAddNewKeyIncrementalTwoBytePrefixFromOne) {
  auto keyset_handle = std::make_shared<KeysetHandle>();

  // Create a key with prefix "\x00\x01" and add it to the keyset.
  auto advanced_keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(keyset_handle);
  auto status_or_key_handle =
      advanced_keyset_manager->CreateNewKey(type(), std::string("\x00\x01", 2));
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());

  // Expect the next key to be "\x00\x02"
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);
  status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  const std::string expected_prefix = std::string("\x00\x02", 2);
  EXPECT_EQ(expected_prefix, key_handle->metadata().prefix());
}

TEST_P(KeysetManagerTest, GenerateAndAddNewKeyIncrementalTwoBytePrefixFromMax) {
  auto keyset_handle = std::make_shared<KeysetHandle>();

  // Create a key with prefix "\xFF\xFF" and add it to the keyset.
  auto advanced_keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(keyset_handle);
  auto status_or_key_handle =
      advanced_keyset_manager->CreateNewKey(type(), "\xFF\xFF");
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());

  // Expect the next key to be "\x00\x00"
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);
  status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  const std::string expected_prefix = std::string("\x00\x00", 2);
  EXPECT_EQ(expected_prefix, key_handle->metadata().prefix());
}

TEST_P(KeysetManagerTest,
       GenerateAndAddNewKeyIncrementalTwoBytePrefixFromBigCollision) {
  auto keyset_handle = std::make_shared<KeysetHandle>();

  // Create a keys with prefixs "\x00\x00" and "\x00\x01xy" and add them to the
  // keyset.
  auto advanced_keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(keyset_handle);
  auto status_or_key_handle =
      advanced_keyset_manager->CreateNewKey(type(), std::string("\x00\x00", 2));
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  status_or_key_handle =
      advanced_keyset_manager->CreateNewKey(type(), std::string("\x00\x01xy", 4));
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());

  // Expect the next key to be "\x00\x02"
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);
  status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  const std::string expected_prefix = std::string("\x00\x02", 2);
  EXPECT_EQ(expected_prefix, key_handle->metadata().prefix());
}

TEST_P(KeysetManagerTest,
       GenerateAndAddNewKeyIncrementalTwoBytePrefixFromSmallCollision) {
  auto keyset_handle = std::make_shared<KeysetHandle>();

  // Create a keys with prefixs "\x00\xFF" and "\x01" and add them to the
  // keyset.
  auto advanced_keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(keyset_handle);
  auto status_or_key_handle =
      advanced_keyset_manager->CreateNewKey(type(), std::string("\x00\xFF", 2));
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  status_or_key_handle = advanced_keyset_manager->CreateNewKey(type(), "\x01");
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());

  // Expect the next key to be "\x01\x01"
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);
  status_or_key_handle = keyset_manager->GenerateAndAddNewKey(type());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  const std::string expected_prefix = std::string("\x02\x00", 2);
  EXPECT_EQ(expected_prefix, key_handle->metadata().prefix());
}

INSTANTIATE_TEST_CASE_P(CrypterKeysetManagerTest, KeysetManagerTest,
                        ::testing::Values(&GetAes128GcmKeyType(),
                                          &GetX25519Aes256GcmKeyType(),
                                          &GetHmacSha256HalfDigest(),
                                          &GetP256EcdsaKeyType()));

}  // namespace

}  // namespace crunchy
