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

#include "crunchy/internal/keys/macing_key.h"

#include <utility>

#include "absl/memory/memory.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/port/port.h"

namespace crunchy {

namespace {

class MacingKeyImpl : public MacingKey {
 public:
  explicit MacingKeyImpl(std::unique_ptr<MacInterface> macer)
      : macer_(std::move(macer)) {}
  StatusOr<std::string> Sign(absl::string_view message) const override {
    return macer_->Sign(message);
  }
  Status Verify(absl::string_view message,
                absl::string_view signature) const override {
    return macer_->Verify(message, signature);
  }

 private:
  std::unique_ptr<MacInterface> macer_;
};

class MacingKeyFactoryImpl : public MacingKeyFactory {
 public:
  explicit MacingKeyFactoryImpl(const MacFactory& factory)
      : factory_(factory) {}

  KeyData CreateRandomKeyData() const override {
    KeyData key_data;
    key_data.set_private_key(RandString(factory_.GetKeyLength()));
    return key_data;
  }

  StatusOr<std::unique_ptr<MacingKey>> MakeKey(
      const KeyData& key_data) const override {
    if (key_data.private_key().empty()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "key_data.private_key() is empty";
    }
    auto status_or_crypter = factory_.Make(key_data.private_key());
    if (!status_or_crypter.ok()) {
      return status_or_crypter.status();
    }
    return {absl::make_unique<MacingKeyImpl>(
        std::move(status_or_crypter.ValueOrDie()))};
  }

 private:
  const MacFactory& factory_;
};

}  // namespace

std::unique_ptr<MacingKeyFactory> MakeFactory(const MacFactory& factory) {
  return {absl::make_unique<MacingKeyFactoryImpl>(factory)};
}

}  // namespace crunchy
