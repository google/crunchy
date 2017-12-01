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

#include "crunchy/internal/keyset/hybrid_crypter_factory.h"

#include <stddef.h>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/common/file.h"
#include "crunchy/internal/common/init.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/test_factory.h"
#include "crunchy/internal/keys/key_util.h"
#include "crunchy/internal/keyset/keyset_util.h"
#include "crunchy/internal/keyset/testdata/factory_test_vectors.pb.h"
#include "crunchy/key_management/algorithms.h"
#include "crunchy/key_management/crunchy_factory.h"
#include "crunchy/key_management/internal/advanced_keyset_manager.h"
#include "crunchy/key_management/keyset_handle.h"
#include "crunchy/key_management/keyset_manager.h"

namespace crunchy {

namespace {

std::shared_ptr<KeysetHandle> GetDefaultKeysetHandle() {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);
  auto status_or_key_handle =
      keyset_manager->GenerateAndAddNewKey(GetX25519Aes256GcmKeyType());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteToPrimary(key_handle));
  return keyset_handle;
}

TEST(KeysetFactoryTest, BadKeyset) {
  // empty keyset
  {
    auto keyset_handle = std::make_shared<KeysetHandle>();
    ASSERT_FALSE(MakeCrunchyHybridDecrypter(keyset_handle).ok());
    ASSERT_FALSE(MakeCrunchyHybridEncrypter(keyset_handle).ok());
  }

  // bad primary id
  {
    auto private_keyset_handle = std::make_shared<KeysetHandle>();
    auto keyset_manager =
        ::absl::make_unique<KeysetManager>(private_keyset_handle);
    CRUNCHY_EXPECT_OK(
        keyset_manager->GenerateAndAddNewKey(GetX25519Aes256GcmKeyType()));
    auto status_or_public_keyset_handle =
        private_keyset_handle->CloneAsPublicOnly();
    CRUNCHY_EXPECT_OK(status_or_public_keyset_handle.status());
    auto public_keyset_handle = status_or_public_keyset_handle.ValueOrDie();
    ASSERT_FALSE(MakeCrunchyHybridEncrypter(public_keyset_handle).ok());

    // HybridDecrypter doesn't mind
    CRUNCHY_ASSERT_OK(
        MakeCrunchyHybridDecrypter(private_keyset_handle).status());
  }

  // Using a private key for an encrypter
  {
    std::shared_ptr<KeysetHandle> private_keyset_handle =
        GetDefaultKeysetHandle();
    ASSERT_FALSE(MakeCrunchyHybridEncrypter(private_keyset_handle).ok());
  }
}

TEST(KeysetFactoryTest, EncryptDecrypt) {
  std::shared_ptr<KeysetHandle> private_keyset_handle =
      GetDefaultKeysetHandle();
  auto status_or_decrypter = MakeCrunchyHybridDecrypter(private_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_decrypter.status());
  std::unique_ptr<CrunchyHybridDecrypter> decrypter =
      std::move(status_or_decrypter.ValueOrDie());

  auto status_or_public_keyset_handle =
      private_keyset_handle->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_public_keyset_handle.status());
  auto public_keyset_handle = status_or_public_keyset_handle.ValueOrDie();
  auto status_or_encrypter = MakeCrunchyHybridEncrypter(public_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_encrypter.status());
  std::unique_ptr<CrunchyHybridEncrypter> encrypter =
      std::move(status_or_encrypter.ValueOrDie());

  std::string plaintext = "banana";

  auto status_or_ciphertext = encrypter->Encrypt(plaintext);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  auto status_or_decrypted = decrypter->Decrypt(ciphertext);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext, decrypted);
}

TEST(KeysetFactoryTest, EncryptDecryptErrors) {
  std::shared_ptr<KeysetHandle> private_keyset_handle =
      GetDefaultKeysetHandle();
  auto status_or_decrypter = MakeCrunchyHybridDecrypter(private_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_decrypter.status());
  std::unique_ptr<CrunchyHybridDecrypter> decrypter =
      std::move(status_or_decrypter.ValueOrDie());

  auto status_or_public_keyset_handle =
      private_keyset_handle->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_public_keyset_handle.status());
  auto public_keyset_handle = status_or_public_keyset_handle.ValueOrDie();
  auto status_or_encrypter = MakeCrunchyHybridEncrypter(public_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_encrypter.status());
  std::unique_ptr<CrunchyHybridEncrypter> encrypter =
      std::move(status_or_encrypter.ValueOrDie());

  std::string plaintext = "banana";

  auto status_or_ciphertext = encrypter->Encrypt(plaintext);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  auto status_or_decrypted = decrypter->Decrypt(ciphertext);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext, decrypted);

  // Corrupt start
  ciphertext[0] ^= 0x01;
  ASSERT_FALSE(decrypter->Decrypt(ciphertext).ok());
  ciphertext[0] ^= 0x01;

  // Corrupt middle
  ciphertext[ciphertext.length() / 2] ^= 0x01;
  ASSERT_FALSE(decrypter->Decrypt(ciphertext).ok());
  ciphertext[ciphertext.length() / 2] ^= 0x01;

  // Corrupt end
  ciphertext[ciphertext.length() - 1] ^= 0x01;
  ASSERT_FALSE(decrypter->Decrypt(ciphertext).ok());
  ciphertext[ciphertext.length() - 1] ^= 0x01;

  // No key found
  std::shared_ptr<KeysetHandle> another_private_keyset_handle =
      GetDefaultKeysetHandle();
  status_or_decrypter =
      MakeCrunchyHybridDecrypter(another_private_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_encrypter.status());
  std::unique_ptr<CrunchyHybridDecrypter> another_decrypter =
      std::move(status_or_decrypter.ValueOrDie());
  ASSERT_FALSE(another_decrypter->Decrypt(ciphertext).ok());
}

TEST(KeysetFactoryTest, TwoKey) {
  std::string plaintext1 = "banana";
  std::string plaintext2 = "plantain";

  std::shared_ptr<KeysetHandle> private_keyset_handle1 =
      GetDefaultKeysetHandle();
  auto status_or_decrypter = MakeCrunchyHybridDecrypter(private_keyset_handle1);
  CRUNCHY_ASSERT_OK(status_or_decrypter.status());
  std::unique_ptr<CrunchyHybridDecrypter> decrypter1 =
      std::move(status_or_decrypter.ValueOrDie());

  auto status_or_public_keyset_handle1 =
      private_keyset_handle1->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_public_keyset_handle1.status());
  auto public_keyset_handle1 = status_or_public_keyset_handle1.ValueOrDie();
  auto status_or_encrypter = MakeCrunchyHybridEncrypter(public_keyset_handle1);
  CRUNCHY_ASSERT_OK(status_or_encrypter.status());
  std::unique_ptr<CrunchyHybridEncrypter> encrypter1 =
      std::move(status_or_encrypter.ValueOrDie());

  auto status_or_ciphertext = encrypter1->Encrypt(plaintext1);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string ciphertext1 = std::move(status_or_ciphertext.ValueOrDie());

  std::shared_ptr<KeysetHandle> private_keyset_handle2 =
      GetDefaultKeysetHandle();
  status_or_decrypter = MakeCrunchyHybridDecrypter(private_keyset_handle2);
  CRUNCHY_ASSERT_OK(status_or_decrypter.status());
  std::unique_ptr<CrunchyHybridDecrypter> decrypter2 =
      std::move(status_or_decrypter.ValueOrDie());

  auto status_or_public_keyset_handle2 =
      private_keyset_handle2->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_public_keyset_handle2.status());
  auto public_keyset_handle2 = status_or_public_keyset_handle2.ValueOrDie();
  status_or_encrypter = MakeCrunchyHybridEncrypter(public_keyset_handle2);
  CRUNCHY_ASSERT_OK(status_or_encrypter.status());
  std::unique_ptr<CrunchyHybridEncrypter> encrypter2 =
      std::move(status_or_encrypter.ValueOrDie());

  status_or_ciphertext = encrypter2->Encrypt(plaintext2);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string ciphertext2 = std::move(status_or_ciphertext.ValueOrDie());

  // Make sure we can decrypt both ciphertexts using a combined keyset.
  std::shared_ptr<KeysetHandle> combined_private_keyset_handle =
      std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<AdvancedKeysetManager>(
      combined_private_keyset_handle);
  EXPECT_EQ(1, private_keyset_handle1->key_handles().size());
  for (const auto& key_handle : private_keyset_handle1->key_handles()) {
    CRUNCHY_ASSERT_OK(keyset_manager->AddKey(key_handle));
    CRUNCHY_ASSERT_OK(keyset_manager->PromoteToPrimary(key_handle));
  }
  EXPECT_EQ(1, private_keyset_handle2->key_handles().size());
  for (const auto& key_handle : private_keyset_handle2->key_handles()) {
    CRUNCHY_ASSERT_OK(keyset_manager->AddKey(key_handle));
    CRUNCHY_ASSERT_OK(keyset_manager->PromoteToPrimary(key_handle));
  }
  status_or_decrypter =
      MakeCrunchyHybridDecrypter(combined_private_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_decrypter.status());
  std::unique_ptr<CrunchyHybridDecrypter> combined_decrypter =
      std::move(status_or_decrypter.ValueOrDie());

  auto status_or_decrypted = combined_decrypter->Decrypt(ciphertext1);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext1, decrypted);

  status_or_decrypted = combined_decrypter->Decrypt(ciphertext2);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext2, decrypted);

  // Encrypt using the combined keyset, which should use key2

  auto status_or_combined_public_keyset_handle =
      combined_private_keyset_handle->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_combined_public_keyset_handle.status());
  auto combined_public_keyset_handle =
      status_or_combined_public_keyset_handle.ValueOrDie();
  status_or_encrypter =
      MakeCrunchyHybridEncrypter(combined_public_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_encrypter.status());
  std::unique_ptr<CrunchyHybridEncrypter> combined_encrypter =
      std::move(status_or_encrypter.ValueOrDie());
  status_or_ciphertext = combined_encrypter->Encrypt(plaintext1);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());

  // Decrypt using crypter1 (failure) and crypter2 (success)
  ASSERT_FALSE(decrypter1->Decrypt(ciphertext).ok());

  status_or_decrypted = decrypter2->Decrypt(ciphertext);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext1, decrypted);
}

TEST(KeysetFactoryTest, Prefix) {
  // Create two keysets with identitical keys, but one is missing a prefix.
  size_t prefix_length = 42;
  const std::string prefix = RandString(prefix_length);
  auto private_prefix_keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(private_prefix_keyset_handle);
  auto status_or_key_handle =
      keyset_manager->CreateNewKey(GetX25519Aes256GcmKeyType(), prefix);
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteToPrimary(key_handle));
  auto status_or_private_nonprefix_keyset_handle =
      KeysetUtil::MakeCopy(private_prefix_keyset_handle);
  CRUNCHY_EXPECT_OK(status_or_private_nonprefix_keyset_handle.status());
  auto private_nonprefix_keyset_handle =
      status_or_private_nonprefix_keyset_handle.ValueOrDie();
  KeyMetadata* key_metadata = KeyUtil::GetKeyMetadata(
      private_nonprefix_keyset_handle->key_handles().at(0));
  key_metadata->clear_prefix();

  auto status_or_decrypter =
      MakeCrunchyHybridDecrypter(private_prefix_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_decrypter.status());
  std::unique_ptr<CrunchyHybridDecrypter> prefix_decrypter =
      std::move(status_or_decrypter.ValueOrDie());
  status_or_decrypter =
      MakeCrunchyHybridDecrypter(private_nonprefix_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_decrypter.status());
  std::unique_ptr<CrunchyHybridDecrypter> decrypter =
      std::move(status_or_decrypter.ValueOrDie());

  auto status_or_public_prefix_keyset_handle =
      private_prefix_keyset_handle->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_public_prefix_keyset_handle.status());
  auto public_prefix_keyset_handle =
      status_or_public_prefix_keyset_handle.ValueOrDie();
  auto status_or_encrypter =
      MakeCrunchyHybridEncrypter(public_prefix_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_encrypter.status());
  std::unique_ptr<CrunchyHybridEncrypter> prefix_encrypter =
      std::move(status_or_encrypter.ValueOrDie());
  auto status_or_public_nonprefix_keyset_handle =
      private_nonprefix_keyset_handle->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_public_nonprefix_keyset_handle.status());
  auto public_nonprefix_keyset_handle =
      status_or_public_nonprefix_keyset_handle.ValueOrDie();
  status_or_encrypter =
      MakeCrunchyHybridEncrypter(public_nonprefix_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_encrypter.status());
  std::unique_ptr<CrunchyHybridEncrypter> encrypter =
      std::move(status_or_encrypter.ValueOrDie());

  std::string plaintext = "banana";

  // Create a pair of ciphertexts, their lengths should differ by prefix_length
  auto status_or_ciphertext = prefix_encrypter->Encrypt(plaintext);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string prefix_ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  status_or_ciphertext = encrypter->Encrypt(plaintext);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  EXPECT_EQ(ciphertext.length() + prefix_length, prefix_ciphertext.length());

  // Prove that the prefix is independent of the rest of the ciphertext
  auto status_or_decrypted =
      decrypter->Decrypt(prefix_ciphertext.substr(prefix_length));
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext, decrypted);
  status_or_decrypted =
      prefix_decrypter->Decrypt(absl::StrCat(prefix, ciphertext));
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext, decrypted);
}

TEST(KeysetFactoryTest, StringFactorySuccess) {
  std::shared_ptr<KeysetHandle> private_keyset_handle =
      GetDefaultKeysetHandle();
  auto status_or_public_keyset_handle =
      private_keyset_handle->CloneAsPublicOnly();
  CRUNCHY_EXPECT_OK(status_or_public_keyset_handle.status());
  auto public_keyset_handle = status_or_public_keyset_handle.ValueOrDie();

  Keyset private_keyset =
      KeysetUtil::KeysetHandleAsProto(private_keyset_handle);
  Keyset public_keyset = KeysetUtil::KeysetHandleAsProto(public_keyset_handle);

  CRUNCHY_EXPECT_OK(
      MakeCrunchyHybridEncrypter(public_keyset.SerializeAsString()).status());
  CRUNCHY_EXPECT_OK(
      MakeCrunchyHybridDecrypter(private_keyset.SerializeAsString()).status());
}

TEST(KeysetFactoryTest, StringFactoryMalformed) {
  std::string malformed_keyset = "apple";
  EXPECT_FALSE(MakeCrunchyHybridEncrypter(malformed_keyset).ok());
  EXPECT_FALSE(MakeCrunchyHybridDecrypter(malformed_keyset).ok());
}

const char kTestDataPath[] =
    "crunchy/internal/keyset/testdata/"
    "hybrid_crypter_factory_test_vectors.proto.bin";

void VerifyTestVector(const HybridCryptingKeyRegistry& registry,
                      const HybridCrypterFactoryTestVector& test_vector) {
  auto status_or_decrypter =
      MakeCrunchyHybridDecrypter(registry, test_vector.private_keyset());
  CRUNCHY_ASSERT_OK(status_or_decrypter.status());
  std::unique_ptr<CrunchyHybridDecrypter> decrypter =
      std::move(status_or_decrypter.ValueOrDie());

  auto status_or_decrypted = decrypter->Decrypt(test_vector.ciphertext());
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(test_vector.plaintext(), decrypted);
}

TEST(KeysetFactoryTest, TestVectors) {
  const HybridCryptingKeyRegistry& registry = GetHybridCryptingKeyRegistry();

  auto status_or_test_vectors =
      GetProtoFromFile<HybridCrypterFactoryTestVectors>(kTestDataPath);
  CRUNCHY_EXPECT_OK(status_or_test_vectors.status())
      << "Couldn't load test vectors, try passing --gen_test_vectors=yes";
  HybridCrypterFactoryTestVectors test_vectors =
      std::move(status_or_test_vectors).ValueOrDie();

  for (const HybridCrypterFactoryTestVector& test_vector :
       test_vectors.test_vector()) {
    VerifyTestVector(registry, test_vector);
  }
}

}  // namespace

}  // namespace crunchy

int main(int argc, char** argv) {
  crunchy::InitCrunchyTest(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
