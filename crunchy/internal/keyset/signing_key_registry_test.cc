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

#include "crunchy/internal/keyset/signing_key_registry.h"

#include <utility>

#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "crunchy/internal/algs/sign/p256_ecdsa.h"
#include "crunchy/internal/common/status_matchers.h"

namespace crunchy {

namespace {

TEST(SigningKeyRegistryTest, MakeSigningKey) {
  const SigningKeyRegistry& registry = GetSigningKeyRegistry();
  std::string key_label = "p256-ecdsa";
  auto status_or_signing_key_data =
      registry.CreateRandomPrivateKeyData(key_label);
  CRUNCHY_ASSERT_OK(status_or_signing_key_data.status());
  KeyData signing_key_data = status_or_signing_key_data.ValueOrDie();
  auto status_or_verifying_key_data =
      registry.CreatePublicKeyData(key_label, signing_key_data);
  CRUNCHY_ASSERT_OK(status_or_verifying_key_data.status());
  KeyData verifying_key_data = status_or_verifying_key_data.ValueOrDie();

  auto status_or_signing_key =
      registry.MakeSigningKey(key_label, signing_key_data);
  CRUNCHY_ASSERT_OK(status_or_signing_key.status());
  std::unique_ptr<SigningKey> signing_key =
      std::move(status_or_signing_key.ValueOrDie());

  auto status_or_verifying_key =
      registry.MakeVerifyingKey(key_label, verifying_key_data);
  CRUNCHY_ASSERT_OK(status_or_verifying_key.status());
  std::unique_ptr<VerifyingKey> verifying_key =
      std::move(status_or_verifying_key.ValueOrDie());
}

TEST(SigningKeyRegistryTest, UnregisteredLabel) {
  const SigningKeyRegistry& registry = GetSigningKeyRegistry();
  std::string key_label = "p256-ecdsa";
  std::string bad_key_label = "ff-dsa-512";
  ASSERT_FALSE(registry.CreateRandomPrivateKeyData(bad_key_label).ok());
  auto status_or_signing_key_data =
      registry.CreateRandomPrivateKeyData(key_label);
  CRUNCHY_ASSERT_OK(status_or_signing_key_data.status());
  KeyData signing_key_data = status_or_signing_key_data.ValueOrDie();
  ASSERT_FALSE(registry.MakeSigningKey(bad_key_label, signing_key_data).ok());

  ASSERT_FALSE(
      registry.CreatePublicKeyData(bad_key_label, signing_key_data).ok());
  auto status_or_verifying_key_data =
      registry.CreatePublicKeyData(key_label, signing_key_data);
  CRUNCHY_ASSERT_OK(status_or_verifying_key_data.status());
  KeyData verifying_key_data = status_or_verifying_key_data.ValueOrDie();
  ASSERT_FALSE(
      registry.MakeVerifyingKey(bad_key_label, verifying_key_data).ok());
}

TEST(SigningKeyRegistryTest, DoubleRegister) {
  auto registry = absl::make_unique<SigningKeyRegistry>();
  CRUNCHY_ASSERT_OK(
      registry->Register("p256-ecdsa", MakeFactory(GetP256EcdsaAsn1Factory())));
  ASSERT_FALSE(
      registry->Register("p256-ecdsa", MakeFactory(GetP256EcdsaAsn1Factory()))
          .ok());
}

}  // namespace

}  // namespace crunchy
