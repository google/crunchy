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

#include "crunchy/internal/keys/key_util.h"

#include <gtest/gtest.h>
#include "crunchy/key_management/internal/advanced_keyset_manager.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/key_management/keyset_enums.pb.h"

namespace crunchy {

namespace {

std::shared_ptr<KeyHandle> GetDefaultKeyHandle(const std::string& public_key_data,
                                               const std::string& private_key_data) {
  Key key;
  *key.mutable_metadata()->mutable_type()->mutable_google_key_type_label() =
      "some_key_type";
  key.mutable_metadata()->set_status(CURRENT);
  *key.mutable_metadata()->mutable_prefix() = "the_keys_prefix";
  *key.mutable_data()->mutable_public_key() = public_key_data;
  *key.mutable_data()->mutable_private_key() = private_key_data;

  return std::make_shared<KeyHandle>(std::make_shared<Key>(key));
}

TEST(KeyUtilTest, SimpleMakeCopySuccess) {
  auto key_handle = GetDefaultKeyHandle("public_key_data", "private_key_data");
  auto key_handle_copy = KeyUtil::MakeCopy(key_handle).ValueOrDie();

  auto key = KeyUtil::KeyHandleAsProto(key_handle);
  auto key_copy = KeyUtil::KeyHandleAsProto(key_handle_copy);

  EXPECT_EQ(key.SerializeAsString(), key_copy.SerializeAsString());
}

TEST(KeyUtilTest, MakeCopyMissingKeyData) {
  auto key_handle = GetDefaultKeyHandle("", "");
  EXPECT_FALSE(KeyUtil::MakeCopy(key_handle).ok());
}

}  //  namespace

}  //  namespace crunchy
