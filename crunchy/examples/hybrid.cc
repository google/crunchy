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
#include "crunchy/crunchy_hybrid_crypter.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/key_management/algorithms.h"
#include "crunchy/key_management/crunchy_factory.h"
#include "crunchy/key_management/key_handle.h"
#include "crunchy/key_management/keyset_handle.h"
#include "crunchy/key_management/keyset_manager.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

Status X25519Aes256GcmHybridExample() {
  // Create the keyset.
  std::shared_ptr<KeysetHandle> private_keyset_handle =
      std::make_shared<KeysetHandle>();
  std::unique_ptr<KeysetManager> keyset_manager =
      ::absl::make_unique<KeysetManager>(private_keyset_handle);

  // Add a key to keyset, keeping a reference to the new key.
  StatusOr<std::shared_ptr<KeyHandle>> status_or_key_handle =
      keyset_manager->GenerateAndAddNewKey(GetX25519Aes256GcmKeyType());
  if (!status_or_key_handle.ok()) {
    return status_or_key_handle.status();
  }
  std::shared_ptr<KeyHandle> key_handle = status_or_key_handle.ValueOrDie();

  // Make the newly created key the primary, it will be used for Encryption.
  Status status = keyset_manager->PromoteToPrimary(key_handle);
  if (!status.ok()) {
    return status;
  }

  // Create a CrunchyHybridEncrypter from our keyset.
  StatusOr<std::shared_ptr<KeysetHandle>> status_or_public_keyset_handle =
      private_keyset_handle->CloneAsPublicOnly();
  if (!status_or_public_keyset_handle.ok()) {
    return status_or_public_keyset_handle.status();
  }
  std::shared_ptr<KeysetHandle> public_keyset_handle =
      std::move(status_or_public_keyset_handle).ValueOrDie();

  StatusOr<std::unique_ptr<CrunchyHybridEncrypter>> status_or_encrypter =
      MakeCrunchyHybridEncrypter(public_keyset_handle);
  if (!status_or_encrypter.ok()) {
    return status_or_encrypter.status();
  }
  std::unique_ptr<CrunchyHybridEncrypter> encrypter =
      std::move(status_or_encrypter).ValueOrDie();

  // Create a CrunchyHybridDecrypter from our keyset.
  StatusOr<std::unique_ptr<CrunchyHybridDecrypter>> status_or_decrypter =
      MakeCrunchyHybridDecrypter(private_keyset_handle);
  if (!status_or_decrypter.ok()) {
    return status_or_decrypter.status();
  }
  std::unique_ptr<CrunchyHybridDecrypter> decrypter =
      std::move(status_or_decrypter).ValueOrDie();

  // Encrypt plaintext with our Crypter.
  const std::string plaintext = "banana";
  StatusOr<std::string> status_or_ciphertext = encrypter->Encrypt(plaintext);
  if (!status_or_ciphertext.ok()) {
    return status_or_ciphertext.status();
  }
  std::string ciphertext = status_or_ciphertext.ValueOrDie();

  // Recover the plaintext.
  StatusOr<std::string> status_or_decrypted = decrypter->Decrypt(ciphertext);
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

TEST(X25519Aes256GcmHybridExample, Run) {
  CRUNCHY_EXPECT_OK(crunchy::X25519Aes256GcmHybridExample());
}
