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

#include "crunchy/key_management/internal/advanced_keyset_manager.h"

#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/key_management/algorithms.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/key_management/keyset_enums.pb.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

const char kDefaultPrefix[] = "keymasterciphertext";

class AdvancedKeysetManagerTest
    : public ::testing::TestWithParam<const KeyType*> {
 protected:
  const KeyType& type() { return *GetParam(); }
};

TEST_P(AdvancedKeysetManagerTest, AddKeySuccess) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(keyset_handle);

  CRUNCHY_EXPECT_OK(keyset_manager->CreateNewKey(type(), kDefaultPrefix));

  const std::vector<std::shared_ptr<KeyHandle>>& key_handles =
      keyset_manager->KeyHandles();
  EXPECT_EQ(1, key_handles.size());

  KeyMetadata metadata = key_handles.at(0)->metadata();

  EXPECT_EQ(CURRENT, metadata.status());
  EXPECT_EQ(kDefaultPrefix, metadata.prefix());

  EXPECT_THAT(type().SerializeAsString(), metadata.type().SerializeAsString());
}

TEST_P(AdvancedKeysetManagerTest, SetKeyStatusSuccess) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(keyset_handle);

  CRUNCHY_EXPECT_OK(keyset_manager->CreateNewKey(type(), kDefaultPrefix));

  const std::vector<std::shared_ptr<KeyHandle>>& key_handles =
      keyset_manager->KeyHandles();
  CRUNCHY_EXPECT_OK(keyset_manager->SetKeyStatus(key_handles.at(0), RETIRED));

  KeyMetadata metadata = key_handles.at(0)->metadata();
  EXPECT_EQ(RETIRED, metadata.status());
}

TEST_P(AdvancedKeysetManagerTest, SetKeyStatusUnknownStatusFailure) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(keyset_handle);

  CRUNCHY_EXPECT_OK(keyset_manager->CreateNewKey(type(), kDefaultPrefix));

  const std::vector<std::shared_ptr<KeyHandle>>& key_handles =
      keyset_manager->KeyHandles();
  Status set_key_status =
      keyset_manager->SetKeyStatus(key_handles.at(0), UNKNOWN_STATE);

  EXPECT_EQ(NotFoundError("key_status is UNKNOWN_STATE"), set_key_status);
}

TEST_P(AdvancedKeysetManagerTest, RemoveKeySuccess) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(keyset_handle);

  CRUNCHY_EXPECT_OK(keyset_manager->CreateNewKey(type(), kDefaultPrefix));

  const std::vector<std::shared_ptr<KeyHandle>>& key_handles =
      keyset_manager->KeyHandles();
  EXPECT_EQ(1, key_handles.size());

  CRUNCHY_EXPECT_OK(keyset_manager->RemoveKey(key_handles.at(0)));
  EXPECT_EQ(0, key_handles.size());
}

TEST_P(AdvancedKeysetManagerTest, RemoveKeyBadHandleFailure) {
  auto keyset_handle1 = std::make_shared<KeysetHandle>();
  auto keyset_manager1 =
      ::absl::make_unique<AdvancedKeysetManager>(keyset_handle1);
  auto keyset_handle2 = std::make_shared<KeysetHandle>();
  auto keyset_manager2 =
      ::absl::make_unique<AdvancedKeysetManager>(keyset_handle2);

  CRUNCHY_EXPECT_OK(keyset_manager1->CreateNewKey(type(), kDefaultPrefix));
  CRUNCHY_EXPECT_OK(keyset_manager2->CreateNewKey(type(), kDefaultPrefix));

  const std::vector<std::shared_ptr<KeyHandle>>& key_handles1 =
      keyset_manager1->KeyHandles();
  EXPECT_EQ(1, key_handles1.size());

  const std::vector<std::shared_ptr<KeyHandle>>& key_handles2 =
      keyset_manager2->KeyHandles();
  EXPECT_EQ(1, key_handles2.size());

  Status remove_key_status = keyset_manager1->RemoveKey(key_handles2.at(0));
  EXPECT_EQ(NotFoundError("couldn't find KeyHandle"), remove_key_status);
  EXPECT_EQ(1, key_handles1.size());
}

TEST_P(AdvancedKeysetManagerTest, PromoteToPrimarySuccess) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(keyset_handle);

  CRUNCHY_EXPECT_OK(keyset_manager->CreateNewKey(type(), kDefaultPrefix));

  const std::vector<std::shared_ptr<KeyHandle>>& key_handles =
      keyset_manager->KeyHandles();
  EXPECT_EQ(-1, keyset_handle->primary_key_id());
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteToPrimary(key_handles.at(0)));
  EXPECT_EQ(0, keyset_handle->primary_key_id());
}

TEST_P(AdvancedKeysetManagerTest, PromoteToPrimaryBadHandleFailure) {
  auto keyset_handle1 = std::make_shared<KeysetHandle>();
  auto keyset_manager1 =
      ::absl::make_unique<AdvancedKeysetManager>(keyset_handle1);
  auto keyset_handle2 = std::make_shared<KeysetHandle>();
  auto keyset_manager2 =
      ::absl::make_unique<AdvancedKeysetManager>(keyset_handle2);

  CRUNCHY_EXPECT_OK(keyset_manager1->CreateNewKey(type(), kDefaultPrefix));
  CRUNCHY_EXPECT_OK(keyset_manager2->CreateNewKey(type(), kDefaultPrefix));

  const std::vector<std::shared_ptr<KeyHandle>>& key_handles1 =
      keyset_manager1->KeyHandles();
  EXPECT_EQ(1, key_handles1.size());

  const std::vector<std::shared_ptr<KeyHandle>>& key_handles2 =
      keyset_manager2->KeyHandles();
  EXPECT_EQ(1, key_handles2.size());

  Status promote_status = keyset_manager1->PromoteToPrimary(key_handles2.at(0));
  EXPECT_EQ(NotFoundError("couldn't find KeyHandle"), promote_status);
}

INSTANTIATE_TEST_CASE_P(
    AllKeyTypesAdvancedKeysetManagerTest, AdvancedKeysetManagerTest,
    ::testing::Values(&GetAes128GcmKeyType(), &GetX25519Aes256GcmKeyType(),
                      &GetHmacSha256HalfDigest(), &GetP256EcdsaKeyType()));

}  // namespace

}  // namespace crunchy
