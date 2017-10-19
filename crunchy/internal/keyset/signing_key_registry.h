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

#ifndef CRUNCHY_INTERNAL_KEYSET_SIGNING_KEY_REGISTRY_H_
#define CRUNCHY_INTERNAL_KEYSET_SIGNING_KEY_REGISTRY_H_

#include <map>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/internal/keys/signing_key.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/util/status.h"

namespace crunchy {

class SigningKeyRegistry {
 public:
  SigningKeyRegistry() = default;

  SigningKeyRegistry(const SigningKeyRegistry&) = delete;
  SigningKeyRegistry operator=(const SigningKeyRegistry&) = delete;

  StatusOr<std::unique_ptr<VerifyingKey>> MakeVerifyingKey(
      absl::string_view key_label, const KeyData& key_data) const;

  StatusOr<std::unique_ptr<SigningKey>> MakeSigningKey(
      absl::string_view key_label, const KeyData& key_data) const;

  StatusOr<KeyData> CreateRandomPrivateKeyData(
      absl::string_view key_label) const;
  StatusOr<KeyData> CreatePublicKeyData(absl::string_view key_label,
                                        const KeyData& private_key) const;

  Status Register(absl::string_view key_label,
                  std::unique_ptr<SigningKeyFactory> key_factory);

 private:
  std::map<std::string, std::unique_ptr<SigningKeyFactory>> factory_map_;
};

const SigningKeyRegistry& GetSigningKeyRegistry();

}  // namespace crunchy

#endif  // CRUNCHY_INTERNAL_KEYSET_SIGNING_KEY_REGISTRY_H_
