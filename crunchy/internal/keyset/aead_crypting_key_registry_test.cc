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

#include "crunchy/internal/keyset/aead_crypting_key_registry.h"

#include <utility>

#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "crunchy/internal/algs/crypt/openssl_aead.h"
#include "crunchy/internal/common/status_matchers.h"

namespace crunchy {

namespace {

TEST(AeadCryptingKeyRegistryTest, MakeKey) {
  const AeadCryptingKeyRegistry& registry = GetAeadCryptingKeyRegistry();
  std::string key_label = "aes-128-gcm";
  auto status_or_key_data = registry.CreateRandomKeyData(key_label);
  CRUNCHY_ASSERT_OK(status_or_key_data.status());
  KeyData key_data = status_or_key_data.ValueOrDie();
  auto status_or_key = registry.MakeKey(key_label, key_data);
  CRUNCHY_ASSERT_OK(status_or_key.status());
  std::unique_ptr<AeadCryptingKey> crypting_key =
      std::move(status_or_key.ValueOrDie());
}

TEST(AeadCryptingKeyRegistryTest, UnregisteredLabel) {
  const AeadCryptingKeyRegistry& registry = GetAeadCryptingKeyRegistry();
  std::string key_label = "aes-128-gcm";
  std::string bad_key_label = "tripple-des";
  ASSERT_FALSE(registry.CreateRandomKeyData(bad_key_label).ok());
  auto status_or_key_data = registry.CreateRandomKeyData(key_label);
  CRUNCHY_ASSERT_OK(status_or_key_data.status());
  KeyData key_data = status_or_key_data.ValueOrDie();
  ASSERT_FALSE(registry.MakeKey(bad_key_label, key_data).ok());
}

TEST(AeadCryptingKeyRegistryTest, DoubleRegister) {
  auto registry = absl::make_unique<AeadCryptingKeyRegistry>();
  CRUNCHY_ASSERT_OK(
      registry->Register("aes-128-gcm", MakeFactory(GetAes128GcmFactory())));
  ASSERT_FALSE(
      registry->Register("aes-128-gcm", MakeFactory(GetAes128GcmFactory()))
          .ok());
}

}  // namespace

}  // namespace crunchy
