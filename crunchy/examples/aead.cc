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

#include <memory>
#include <string>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "crunchy/crunchy_crypter.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/key_management/algorithms.h"
#include "crunchy/key_management/crunchy_factory.h"
#include "crunchy/key_management/key_handle.h"
#include "crunchy/key_management/keyset_handle.h"
#include "crunchy/key_management/keyset_manager.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

Status Aes128GcmEncryptionExample() {
  // Create the keyset.
  std::shared_ptr<KeysetHandle> keyset_handle =
      std::make_shared<KeysetHandle>();
  std::unique_ptr<KeysetManager> keyset_manager =
      ::absl::make_unique<KeysetManager>(keyset_handle);

  // Add a key to keyset, keeping a reference to the new key.
  StatusOr<std::shared_ptr<KeyHandle>> status_or_key_handle =
      keyset_manager->GenerateAndAddNewKey(GetAes128GcmKeyType());
  if (!status_or_key_handle.ok()) {
    return status_or_key_handle.status();
  }
  std::shared_ptr<KeyHandle> key_handle = status_or_key_handle.ValueOrDie();

  // Make the newly created key the primary, it will be used for Encryption.
  Status status = keyset_manager->PromoteToPrimary(key_handle);
  if (!status.ok()) {
    return status;
  }

  // Create a CrunchyCrypter from our keyset.
  StatusOr<std::unique_ptr<CrunchyCrypter>> status_or_crypter =
      MakeCrunchyCrypter(keyset_handle);
  if (!status_or_crypter.ok()) {
    return status_or_crypter.status();
  }
  std::unique_ptr<CrunchyCrypter> crypter =
      std::move(status_or_crypter).ValueOrDie();

  // Encrypt plaintext with our Crypter.
  const std::string plaintext = "banana";
  const std::string aad = "apple";
  StatusOr<std::string> status_or_ciphertext = crypter->Encrypt(plaintext, aad);
  if (!status_or_ciphertext.ok()) {
    return status_or_ciphertext.status();
  }
  std::string ciphertext = status_or_ciphertext.ValueOrDie();

  // Recover the plaintext.
  StatusOr<std::string> status_or_decrypted = crypter->Decrypt(ciphertext, aad);
  if (!status_or_decrypted.ok()) {
    return status_or_decrypted.status();
  }
  std::string decrypted = status_or_decrypted.ValueOrDie();
  if (plaintext != decrypted) {
    return InternalError("plaintext != decrypted");
  }

  return OkStatus();
}

}  // namespace

}  // namespace crunchy

TEST(Aes128GcmEncryptionExample, Run) {
  CRUNCHY_EXPECT_OK(crunchy::Aes128GcmEncryptionExample());
}
