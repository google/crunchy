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

#include "crunchy/key_management/keyset_manager.h"

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <unordered_set>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/port/port.h"
#include "crunchy/key_management/internal/advanced_keyset_manager.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/key_management/keyset_enums.pb.h"

namespace crunchy {

const int kCrunchyDefaultKeyPrefixLength = 2;

namespace {

void IncrementTwoBytePrefixWithRollover(char* prefix) {
  const uint16_t prefix_as_int = BigEndianLoad16(prefix);
  BigEndianStore16(prefix, prefix_as_int + 1);
}

}  // namespace

KeysetManager::KeysetManager(std::shared_ptr<KeysetHandle> keyset_handle)
    : keyset_handle_(CRUNCHY_CHECK_NOTNULL(keyset_handle)),
      advanced_keyset_manager_(::absl::make_unique<AdvancedKeysetManager>(
          std::move(keyset_handle))) {}

KeysetManager::~KeysetManager() {}

StatusOr<std::shared_ptr<KeyHandle>> KeysetManager::GenerateAndAddNewKey(
    const KeyType& type) {
  uint16_t max_prefix = 0;
  std::unordered_set<std::string> existing_prefixes;
  for (const auto& key_handle : keyset_handle_->key_handles()) {
    std::string tmp_prefix = key_handle->metadata().prefix();

    // Look at the existing prefix, if it's not length
    // kCrunchyDefaultKeyPrefixLength, then modify such that it is. There's no
    // strict requirements here. However, we want to avoid having prefixes be
    // prefixes of one another as it has performance implications.
    if (tmp_prefix.size() < kCrunchyDefaultKeyPrefixLength) {
      absl::StrAppend(
          &tmp_prefix,
          std::string(kCrunchyDefaultKeyPrefixLength - tmp_prefix.size(), '\xFF'));

    } else if (tmp_prefix.size() > kCrunchyDefaultKeyPrefixLength) {
      tmp_prefix = tmp_prefix.substr(0, kCrunchyDefaultKeyPrefixLength);
    }

    existing_prefixes.insert(tmp_prefix);

    const uint16_t current_prefix = BigEndianLoad16(tmp_prefix.data());
    if (current_prefix > max_prefix) {
      max_prefix = current_prefix;
    }
  }

  char prefix[kCrunchyDefaultKeyPrefixLength];
  if (existing_prefixes.empty()) {
    BigEndianStore16(prefix, 0);
  } else {
    BigEndianStore16(prefix, max_prefix + 1);
  }

  // Unfortunately, it might be the case that max_prefix + 1 is used.
  // This is when we have a keyset that has prefixes {..., 0xFFFF, 0x0000, ...}.
  // So, attempt to find an unused prefix.
  while (existing_prefixes.find(prefix) != existing_prefixes.end()) {
    IncrementTwoBytePrefixWithRollover(prefix);
    if (BigEndianLoad16(prefix) == max_prefix) {
      // We've exhausted all possible prefixes.
      return InternalError(
          "All prefixes exhausted. Unable to add new key to keyset.");
    }
  }

  StatusOr<std::shared_ptr<KeyHandle>> status_or_key_handle =
      advanced_keyset_manager_->CreateNewKey(
          type, std::string(prefix, kCrunchyDefaultKeyPrefixLength));
  if (!status_or_key_handle.ok()) {
    return status_or_key_handle.status();
  }

  return status_or_key_handle.ValueOrDie();
}

const std::vector<std::shared_ptr<KeyHandle>>& KeysetManager::KeyHandles()
    const {
  return advanced_keyset_manager_->KeyHandles();
}

std::shared_ptr<KeyHandle> KeysetManager::PrimaryKey() {
  return advanced_keyset_manager_->KeyHandles().at(
      keyset_handle_->primary_key_id());
}

StatusOr<std::shared_ptr<KeyHandle>> KeysetManager::PromoteNextToPrimary() {
  if (keyset_handle_->key_handles().empty()) {
    return FailedPreconditionError(
        "Keyset is empty. Can't promote next key to primary.");
  }

  if (keyset_handle_->primary_key_id() >= 0 &&
      static_cast<size_t>(keyset_handle_->primary_key_id()) ==
          (keyset_handle_->key_handles().size() - 1)) {
    return FailedPreconditionError(
        "Newest key is already the primary key. Can't promote next key to "
        "primary.");
  }

  int new_primary_key_id;
  if (keyset_handle_->primary_key_id() == -1) {
    new_primary_key_id = 0;
  } else {
    new_primary_key_id = keyset_handle_->primary_key_id() + 1;
  }

  const std::shared_ptr<KeyHandle> key_handle =
      keyset_handle_->key_handles().at(new_primary_key_id);
  const Status promote_status =
      advanced_keyset_manager_->PromoteToPrimary(key_handle);
  if (!promote_status.ok()) {
    return promote_status;
  }

  return key_handle;
}

Status KeysetManager::PromoteToPrimary(
    const std::shared_ptr<KeyHandle>& key_handle) {
  return advanced_keyset_manager_->PromoteToPrimary(key_handle);
}

StatusOr<std::shared_ptr<KeyHandle>> KeysetManager::DeleteOldestKey() {
  if (keyset_handle_->key_handles().empty()) {
    return FailedPreconditionError("Keyset is empty. Can't delete oldest key.");
  }

  const std::shared_ptr<KeyHandle> oldest_key =
      keyset_handle_->key_handles().at(0);
  if (keyset_handle_->PrimaryKey() == oldest_key) {
    return FailedPreconditionError(
        "Oldest key is primary key. Can't delete oldest key.");
  }

  Status remove_key_status = advanced_keyset_manager_->RemoveKey(oldest_key);
  if (!remove_key_status.ok()) {
    return remove_key_status;
  }

  return oldest_key;
}

StatusOr<std::vector<std::shared_ptr<KeyHandle>>>
KeysetManager::GarbageCollectKeys() {
  std::vector<std::shared_ptr<KeyHandle>> keys_to_delete;
  for (const std::shared_ptr<KeyHandle>& key_handle :
       keyset_handle_->key_handles()) {
    if (key_handle->metadata().status() == KeyStatus::DELETED) {
      if (key_handle == keyset_handle_->PrimaryKey()) {
        return FailedPreconditionError(
            "Primary key has DELETED status. Refusing to delete.");
      }
      keys_to_delete.push_back(key_handle);
    }
  }
  for (const auto& key_handle : keys_to_delete) {
    Status status = advanced_keyset_manager_->RemoveKey(key_handle);
    if (!status.ok()) {
      return status;
    }
  }
  return keys_to_delete;
}

}  // namespace crunchy
