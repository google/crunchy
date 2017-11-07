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

#include "absl/memory/memory.h"
#include "crunchy/internal/algs/hybrid/hybrid.h"
#include "crunchy/internal/port/port.h"

namespace crunchy {

StatusOr<std::unique_ptr<HybridEncryptingKey>>
HybridCryptingKeyRegistry::MakeHybridEncryptingKey(
    absl::string_view key_label, const KeyData& key_data) const {
  auto factory = factory_map_.find(std::string(key_label));
  if (factory == factory_map_.end()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "key_label " << key_label << " not found";
  }
  return (*factory).second->MakeHybridEncryptingKey(key_data);
}

StatusOr<std::unique_ptr<HybridDecryptingKey>>
HybridCryptingKeyRegistry::MakeHybridDecryptingKey(
    absl::string_view key_label, const KeyData& key_data) const {
  auto factory = factory_map_.find(std::string(key_label));
  if (factory == factory_map_.end()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "key_label " << key_label << " not found";
  }
  return (*factory).second->MakeHybridDecryptingKey(key_data);
}

StatusOr<KeyData> HybridCryptingKeyRegistry::CreateRandomPrivateKeyData(
    absl::string_view key_label) const {
  auto factory = factory_map_.find(std::string(key_label));
  if (factory == factory_map_.end()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "key_label " << key_label << " not found";
  }
  return (*factory).second->CreateRandomPrivateKeyData();
}

StatusOr<KeyData> HybridCryptingKeyRegistry::CreatePublicKeyData(
    absl::string_view key_label, const KeyData& private_key) const {
  auto factory = factory_map_.find(std::string(key_label));
  if (factory == factory_map_.end()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "key_label " << key_label << " not found";
  }
  return (*factory).second->CreatePublicKeyData(private_key);
}

Status HybridCryptingKeyRegistry::Register(
    absl::string_view key_label,
    std::unique_ptr<HybridCryptingKeyFactory> key_factory) {
  auto result = factory_map_.insert(
      std::pair<std::string, std::unique_ptr<HybridCryptingKeyFactory>>(
          std::string(key_label), std::move(key_factory)));
  if (result.second == false) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << key_label << " is already registered";
  }
  return OkStatus();
}

namespace {

std::unique_ptr<HybridCryptingKeyRegistry> MakeRegistry() {
  auto registry = absl::make_unique<HybridCryptingKeyRegistry>();
  CRUNCHY_CHECK_EQ(registry->Register("p256-aes-128-gcm",
                                      MakeFactory(GetP256Aes128GcmFactory())),
                   OkStatus());
  CRUNCHY_CHECK_EQ(registry->Register("p256-aes-256-gcm",
                                      MakeFactory(GetP256Aes256GcmFactory())),
                   OkStatus());
  CRUNCHY_CHECK_EQ(registry->Register("x25519-aes-256-gcm",
                                      MakeFactory(GetX25519Aes256GcmFactory())),
                   OkStatus());
  return registry;
}

}  // namespace

const HybridCryptingKeyRegistry& GetHybridCryptingKeyRegistry() {
  static const HybridCryptingKeyRegistry& registry = *MakeRegistry().release();
  return registry;
}

}  // namespace crunchy
