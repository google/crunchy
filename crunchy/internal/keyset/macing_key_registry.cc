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

#include "crunchy/internal/keyset/macing_key_registry.h"

#include <utility>

#include "absl/memory/memory.h"
#include "crunchy/internal/algs/mac/openssl_hmac.h"
#include "crunchy/internal/port/port.h"

namespace crunchy {

StatusOr<std::unique_ptr<MacingKey>> MacingKeyRegistry::MakeKey(
    absl::string_view key_label, const KeyData& key_data) const {
  auto factory = factory_map_.find(std::string(key_label));
  if (factory == factory_map_.end()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "key_label " << key_label << " not found";
  }
  return (*factory).second->MakeKey(key_data);
}

StatusOr<KeyData> MacingKeyRegistry::CreateRandomKeyData(
    absl::string_view key_label) const {
  auto factory = factory_map_.find(std::string(key_label));
  if (factory == factory_map_.end()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "key_label " << key_label << " not found";
  }
  return (*factory).second->CreateRandomKeyData();
}

Status MacingKeyRegistry::Register(
    absl::string_view key_label,
    std::unique_ptr<MacingKeyFactory> key_factory) {
  auto result =
      factory_map_.insert(std::pair<std::string, std::unique_ptr<MacingKeyFactory>>(
          std::string(key_label), std::move(key_factory)));
  if (result.second == false) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << key_label << " is already registered";
  }
  return OkStatus();
}

namespace {

std::unique_ptr<MacingKeyRegistry> MakeRegistry() {
  auto registry = absl::make_unique<MacingKeyRegistry>();
  CRUNCHY_CHECK_EQ(
      registry->Register("hmac-sha256-halfdigest",
                         MakeFactory(GetHmacSha256HalfDigestFactory())),
      OkStatus());
  return registry;
}

}  // namespace

const MacingKeyRegistry& GetMacingKeyRegistry() {
  static const MacingKeyRegistry& registry = *MakeRegistry().release();
  return registry;
}

}  // namespace crunchy
