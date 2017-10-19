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

#include <type_traits>
#include <utility>

#include "absl/memory/memory.h"
#include "crunchy/internal/algs/sign/ed25519.h"
#include "crunchy/internal/algs/sign/p256_ecdsa.h"
#include "crunchy/internal/algs/sign/rsa.h"
#include "crunchy/internal/port/port.h"

namespace crunchy {

StatusOr<std::unique_ptr<SigningKey>> SigningKeyRegistry::MakeSigningKey(
    absl::string_view key_label, const KeyData& key_data) const {
  auto factory = factory_map_.find(std::string(key_label));
  if (factory == factory_map_.end()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "key_label " << key_label << " not found";
  }
  return (*factory).second->MakeSigningKey(key_data);
}

StatusOr<std::unique_ptr<VerifyingKey>> SigningKeyRegistry::MakeVerifyingKey(
    absl::string_view key_label, const KeyData& key_data) const {
  auto factory = factory_map_.find(std::string(key_label));
  if (factory == factory_map_.end()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "key_label " << key_label << " not found";
  }
  return (*factory).second->MakeVerifyingKey(key_data);
}

StatusOr<KeyData> SigningKeyRegistry::CreateRandomPrivateKeyData(
    absl::string_view key_label) const {
  auto factory = factory_map_.find(std::string(key_label));
  if (factory == factory_map_.end()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "key_label " << key_label << " not found";
  }
  return (*factory).second->CreateRandomPrivateKeyData();
}

StatusOr<KeyData> SigningKeyRegistry::CreatePublicKeyData(
    absl::string_view key_label, const KeyData& private_key) const {
  auto factory = factory_map_.find(std::string(key_label));
  if (factory == factory_map_.end()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "key_label " << key_label << " not found";
  }
  return (*factory).second->CreatePublicKeyData(private_key);
}

Status SigningKeyRegistry::Register(
    absl::string_view key_label,
    std::unique_ptr<SigningKeyFactory> key_factory) {
  auto result =
      factory_map_.insert(std::pair<std::string, std::unique_ptr<SigningKeyFactory>>(
          std::string(key_label), std::move(key_factory)));
  if (result.second == false) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << key_label << " is already registered";
  }
  return OkStatus();
}

namespace {

std::unique_ptr<SigningKeyRegistry> MakeRegistry() {
  auto registry = absl::make_unique<SigningKeyRegistry>();
  CRUNCHY_CHECK_EQ(
      registry->Register("p256-ecdsa", MakeFactory(GetP256EcdsaAsn1Factory())),
      OkStatus());
  CRUNCHY_CHECK_EQ(registry->Register("p256-ecdsa-jwt",
                                      MakeFactory(GetP256EcdsaJwtFactory())),
                   OkStatus());
  CRUNCHY_CHECK_EQ(
      registry->Register("ed25519", MakeFactory(GetEd25519Factory())),
      OkStatus());
  CRUNCHY_CHECK_EQ(registry->Register("rsa-2048-pkcs1",
                                      MakeFactory(GetRsa2048PkcsFactory())),
                   OkStatus());
  CRUNCHY_CHECK_EQ(
      registry->Register("rsa-2048-pss", MakeFactory(GetRsa2048PssFactory())),
      OkStatus());
  return registry;
}

}  // namespace

const SigningKeyRegistry& GetSigningKeyRegistry() {
  static const SigningKeyRegistry& registry = *MakeRegistry().release();
  return registry;
}

}  // namespace crunchy
