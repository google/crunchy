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

#include "absl/memory/memory.h"
#include "crunchy/internal/algs/crypt/aes_eax.h"
#include "crunchy/internal/algs/crypt/openssl_aead.h"
#include "crunchy/internal/port/port.h"

namespace crunchy {

StatusOr<std::unique_ptr<AeadCryptingKey>> AeadCryptingKeyRegistry::MakeKey(
    absl::string_view key_label, const KeyData& key_data) const {
  auto factory = factory_map_.find(std::string(key_label));
  if (factory == factory_map_.end()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "key_label " << key_label << " not found";
  }
  return (*factory).second->MakeKey(key_data);
}

StatusOr<KeyData> AeadCryptingKeyRegistry::CreateRandomKeyData(
    absl::string_view key_label) const {
  auto factory = factory_map_.find(std::string(key_label));
  if (factory == factory_map_.end()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "key_label " << key_label << " not found";
  }
  return (*factory).second->CreateRandomKeyData();
}

Status AeadCryptingKeyRegistry::Register(
    absl::string_view key_label,
    std::unique_ptr<AeadCryptingKeyFactory> key_factory) {
  auto result = factory_map_.insert(
      std::pair<std::string, std::unique_ptr<AeadCryptingKeyFactory>>(
          std::string(key_label), std::move(key_factory)));
  if (result.second == false) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << key_label << " is already registered";
  }
  return OkStatus();
}

namespace {

std::unique_ptr<AeadCryptingKeyRegistry> MakeRegistry() {
  auto registry = absl::make_unique<AeadCryptingKeyRegistry>();
  CRUNCHY_CHECK_EQ(
      registry->Register("aes-128-gcm", MakeFactory(GetAes128GcmFactory())),
      OkStatus());
  CRUNCHY_CHECK_EQ(
      registry->Register("aes-256-gcm", MakeFactory(GetAes256GcmFactory())),
      OkStatus());
  CRUNCHY_CHECK_EQ(
      registry->Register("aes-128-eax", MakeFactory(GetAes128EaxFactory())),
      OkStatus());
  CRUNCHY_CHECK_EQ(
      registry->Register("aes-256-eax", MakeFactory(GetAes256EaxFactory())),
      OkStatus());
  return registry;
}

}  // namespace

const AeadCryptingKeyRegistry& GetAeadCryptingKeyRegistry() {
  static const AeadCryptingKeyRegistry& registry = *MakeRegistry().release();
  return registry;
}

}  // namespace crunchy
