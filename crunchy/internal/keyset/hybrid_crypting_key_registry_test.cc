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

#include "crunchy/internal/keyset/hybrid_crypting_key_registry.h"

#include <utility>

#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "crunchy/internal/algs/hybrid/hybrid.h"
#include "crunchy/internal/common/status_matchers.h"

namespace crunchy {

namespace {

TEST(HybridCryptingKeyRegistryTest, MakeKey) {
  const HybridCryptingKeyRegistry& registry = GetHybridCryptingKeyRegistry();

  std::string key_label = "x25519-aes-256-gcm";
  auto status_or_decrypting_key_data =
      registry.CreateRandomPrivateKeyData(key_label);
  CRUNCHY_ASSERT_OK(status_or_decrypting_key_data.status());
  KeyData decrypting_key_data = status_or_decrypting_key_data.ValueOrDie();
  auto status_or_verifying_key_data =
      registry.CreatePublicKeyData(key_label, decrypting_key_data);
  CRUNCHY_ASSERT_OK(status_or_verifying_key_data.status());
  KeyData verifying_key_data = status_or_verifying_key_data.ValueOrDie();

  auto status_or_decrypting_key =
      registry.MakeHybridDecryptingKey(key_label, decrypting_key_data);
  CRUNCHY_ASSERT_OK(status_or_decrypting_key.status());
  std::unique_ptr<HybridDecryptingKey> decrypting_key =
      std::move(status_or_decrypting_key.ValueOrDie());

  auto status_or_verifying_key =
      registry.MakeHybridEncryptingKey(key_label, verifying_key_data);
  CRUNCHY_ASSERT_OK(status_or_verifying_key.status());
  std::unique_ptr<HybridEncryptingKey> verifying_key =
      std::move(status_or_verifying_key.ValueOrDie());
}

TEST(HybridCryptingKeyRegistryTest, UnregisteredLabel) {
  const HybridCryptingKeyRegistry& registry = GetHybridCryptingKeyRegistry();

  std::string key_label = "x25519-aes-256-gcm";
  std::string bad_key_label = "rsa-512-oaep";
  ASSERT_FALSE(registry.CreateRandomPrivateKeyData(bad_key_label).ok());
  auto status_or_signing_key_data =
      registry.CreateRandomPrivateKeyData(key_label);
  CRUNCHY_ASSERT_OK(status_or_signing_key_data.status());
  KeyData signing_key_data = status_or_signing_key_data.ValueOrDie();
  ASSERT_FALSE(
      registry.MakeHybridDecryptingKey(bad_key_label, signing_key_data).ok());

  ASSERT_FALSE(
      registry.CreatePublicKeyData(bad_key_label, signing_key_data).ok());
  auto status_or_verifying_key_data =
      registry.CreatePublicKeyData(key_label, signing_key_data);
  CRUNCHY_ASSERT_OK(status_or_verifying_key_data.status());
  KeyData verifying_key_data = status_or_verifying_key_data.ValueOrDie();
  ASSERT_FALSE(
      registry.MakeHybridEncryptingKey(bad_key_label, verifying_key_data).ok());
}

TEST(HybridCryptingKeyRegistryTest, DoubleRegister) {
  auto registry = absl::make_unique<HybridCryptingKeyRegistry>();
  CRUNCHY_ASSERT_OK(registry->Register(
      "x25519-aes-256-gcm", MakeFactory(GetX25519Aes256GcmFactory())));
  ASSERT_FALSE(registry
                   ->Register("x25519-aes-256-gcm",
                              MakeFactory(GetX25519Aes256GcmFactory()))
                   .ok());
}

}  // namespace

}  // namespace crunchy
