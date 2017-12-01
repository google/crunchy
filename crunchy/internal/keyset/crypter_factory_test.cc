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

#include "crunchy/internal/keyset/crypter_factory.h"

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
#include "crunchy/key_management/key_handle.h"
#include "crunchy/key_management/keyset_manager.h"

namespace crunchy {

namespace {

std::shared_ptr<KeysetHandle> GetDefaultKeysetHandle() {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);
  auto status_or_key_handle =
      keyset_manager->GenerateAndAddNewKey(GetAes128GcmKeyType());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteToPrimary(key_handle));
  return keyset_handle;
}

TEST(KeysetFactoryTest, BadKeyset) {
  auto keyset_handle = std::make_shared<KeysetHandle>();

  // empty keyset
  { ASSERT_FALSE(MakeCrunchyCrypter(keyset_handle).ok()); }
}

TEST(KeysetFactoryTest, EncryptDecrypt) {
  auto keyset_handle = GetDefaultKeysetHandle();
  auto status_or_crypter = MakeCrunchyCrypter(keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_crypter.status());
  std::unique_ptr<CrunchyCrypter> crypter =
      std::move(status_or_crypter.ValueOrDie());
  std::string plaintext = "banana";
  std::string aad = "apple";

  auto status_or_ciphertext = crypter->Encrypt(plaintext, aad);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  auto status_or_decrypted = crypter->Decrypt(ciphertext, aad);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext, decrypted);
}

TEST(KeysetFactoryTest, EncryptDecryptNoAad) {
  auto keyset_handle = GetDefaultKeysetHandle();
  auto status_or_crypter = MakeCrunchyCrypter(keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_crypter.status());
  std::unique_ptr<CrunchyCrypter> crypter =
      std::move(status_or_crypter.ValueOrDie());
  std::string plaintext = "banana";
  std::string empty_aad = "";

  // Encrypt with empty aad, decrypt without aad
  auto status_or_ciphertext = crypter->Encrypt(plaintext, empty_aad);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  auto status_or_decrypted = crypter->Decrypt(ciphertext, empty_aad);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext, decrypted);

  status_or_decrypted = crypter->Decrypt(ciphertext);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext, decrypted);

  // Encrypt with no aad, decrypt with empty aad
  status_or_ciphertext = crypter->Encrypt(plaintext);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  status_or_decrypted = crypter->Decrypt(ciphertext);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext, decrypted);

  status_or_decrypted = crypter->Decrypt(ciphertext, empty_aad);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext, decrypted);
}

TEST(KeysetFactoryTest, EncryptDecryptErrors) {
  auto keyset_handle = GetDefaultKeysetHandle();
  auto status_or_crypter = MakeCrunchyCrypter(keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_crypter.status());
  std::unique_ptr<CrunchyCrypter> crypter =
      std::move(status_or_crypter.ValueOrDie());
  std::string plaintext = "banana";
  std::string aad = "banana";

  auto status_or_ciphertext = crypter->Encrypt(plaintext, aad);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  auto status_or_decrypted = crypter->Decrypt(ciphertext, aad);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext, decrypted);

  // No aad
  ASSERT_FALSE(crypter->Decrypt(ciphertext, "").ok());

  // Corrupt start
  ciphertext[0] ^= 0x01;
  ASSERT_FALSE(crypter->Decrypt(ciphertext, aad).ok());
  ciphertext[0] ^= 0x01;

  // Corrupt middle
  ciphertext[ciphertext.length() / 2] ^= 0x01;
  ASSERT_FALSE(crypter->Decrypt(ciphertext, aad).ok());
  ciphertext[ciphertext.length() / 2] ^= 0x01;

  // Corrupt end
  ciphertext[ciphertext.length() - 1] ^= 0x01;
  ASSERT_FALSE(crypter->Decrypt(ciphertext, aad).ok());
  ciphertext[ciphertext.length() - 1] ^= 0x01;

  // No key found
  auto another_keyset_handle = GetDefaultKeysetHandle();
  status_or_crypter = MakeCrunchyCrypter(another_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_crypter.status());
  std::unique_ptr<CrunchyCrypter> another_crypter =
      std::move(status_or_crypter.ValueOrDie());
  ASSERT_FALSE(another_crypter->Decrypt(ciphertext, aad).ok());
}

TEST(KeysetFactoryTest, TwoKey) {
  std::string plaintext1 = "banana";
  std::string plaintext2 = "plantain";
  std::string aad = "apple";

  auto keyset_handle1 = GetDefaultKeysetHandle();
  auto status_or_crypter = MakeCrunchyCrypter(keyset_handle1);
  CRUNCHY_ASSERT_OK(status_or_crypter.status());
  std::unique_ptr<CrunchyCrypter> crypter1 =
      std::move(status_or_crypter.ValueOrDie());
  auto status_or_ciphertext = crypter1->Encrypt(plaintext1, aad);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string ciphertext1 = std::move(status_or_ciphertext.ValueOrDie());

  auto keyset_handle2 = GetDefaultKeysetHandle();
  status_or_crypter = MakeCrunchyCrypter(keyset_handle2);
  CRUNCHY_ASSERT_OK(status_or_crypter.status());
  std::unique_ptr<CrunchyCrypter> crypter2 =
      std::move(status_or_crypter.ValueOrDie());
  status_or_ciphertext = crypter2->Encrypt(plaintext2, aad);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string ciphertext2 = std::move(status_or_ciphertext.ValueOrDie());

  // Make sure we can verify both ciphertexts using a combined keyset.
  std::shared_ptr<KeyHandle> key_handle1 = keyset_handle1->key_handles().at(0);
  std::shared_ptr<KeyHandle> key_handle2 = keyset_handle2->key_handles().at(0);
  auto combined_keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(combined_keyset_handle);
  CRUNCHY_ASSERT_OK(keyset_manager->AddKey(key_handle1));
  CRUNCHY_ASSERT_OK(keyset_manager->AddKey(key_handle2));
  CRUNCHY_ASSERT_OK(keyset_manager->PromoteToPrimary(key_handle2));
  status_or_crypter = MakeCrunchyCrypter(combined_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_crypter.status());
  std::unique_ptr<CrunchyCrypter> combined_crypter =
      std::move(status_or_crypter.ValueOrDie());

  auto status_or_decrypted = combined_crypter->Decrypt(ciphertext1, aad);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext1, decrypted);

  status_or_decrypted = combined_crypter->Decrypt(ciphertext2, aad);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext2, decrypted);

  // Encrypt using the combined keyset, which should use key2
  status_or_ciphertext = combined_crypter->Encrypt(plaintext1, aad);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());

  // Decrypt using crypter1 (failure) and crypter2 (success)
  ASSERT_FALSE(crypter1->Decrypt(ciphertext, aad).ok());

  status_or_decrypted = crypter2->Decrypt(ciphertext, aad);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext1, decrypted);
}

TEST(KeysetFactoryTest, Prefix) {
  size_t prefix_length = 42;
  auto prefix_keyset_handle = std::make_shared<KeysetHandle>();
  auto prefix_keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(prefix_keyset_handle);
  auto status_or_key_handle = prefix_keyset_manager->CreateNewKey(
      GetAes128GcmKeyType(), RandString(prefix_length));
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto prefix_key_handle = status_or_key_handle.ValueOrDie();
  CRUNCHY_EXPECT_OK(prefix_keyset_manager->PromoteToPrimary(prefix_key_handle));
  absl::string_view prefix = prefix_key_handle->metadata().prefix();

  auto nonprefix_keyset_handle = std::make_shared<KeysetHandle>();
  auto status_or_noprefix_key_handle = KeyUtil::MakeCopy(prefix_key_handle);
  CRUNCHY_EXPECT_OK(status_or_noprefix_key_handle.status());
  auto noprefix_key_handle = status_or_noprefix_key_handle.ValueOrDie();
  KeyMetadata* key_metadata = KeyUtil::GetKeyMetadata(noprefix_key_handle);
  key_metadata->clear_prefix();
  auto nonprefix_keyset_manager =
      ::absl::make_unique<AdvancedKeysetManager>(nonprefix_keyset_handle);
  CRUNCHY_ASSERT_OK(nonprefix_keyset_manager->AddKey(noprefix_key_handle));
  CRUNCHY_ASSERT_OK(
      nonprefix_keyset_manager->PromoteToPrimary(noprefix_key_handle));

  auto status_or_crypter = MakeCrunchyCrypter(prefix_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_crypter.status());
  std::unique_ptr<CrunchyCrypter> prefix_crypter =
      std::move(status_or_crypter.ValueOrDie());
  status_or_crypter = MakeCrunchyCrypter(nonprefix_keyset_handle);
  CRUNCHY_ASSERT_OK(status_or_crypter.status());
  std::unique_ptr<CrunchyCrypter> crypter =
      std::move(status_or_crypter.ValueOrDie());

  std::string plaintext = "banana";
  std::string aad = "apple";

  // Create a pair of ciphertexts, their lengths should differ by prefix_length
  auto status_or_ciphertext = prefix_crypter->Encrypt(plaintext, aad);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string prefix_ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  status_or_ciphertext = crypter->Encrypt(plaintext, aad);
  CRUNCHY_ASSERT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());
  EXPECT_EQ(ciphertext.length() + prefix_length, prefix_ciphertext.length());

  // Prove that the prefix is independent of the rest of the ciphertext
  auto status_or_decrypted =
      crypter->Decrypt(prefix_ciphertext.substr(prefix_length), aad);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext, decrypted);
  status_or_decrypted =
      prefix_crypter->Decrypt(StrCat(prefix, ciphertext), aad);
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(plaintext, decrypted);
}

TEST(KeysetFactoryTest, StringFactory) {
  auto keyset_handle = GetDefaultKeysetHandle();
  Keyset keyset = KeysetUtil::KeysetHandleAsProto(keyset_handle);
  CRUNCHY_EXPECT_OK(MakeCrunchyCrypter(keyset.SerializeAsString()).status());

  std::string malformed_keyset = "apple";
  EXPECT_FALSE(MakeCrunchyCrypter(malformed_keyset).ok());
}

const char kTestDataPath[] =
    "crunchy/internal/keyset/testdata/"
    "crypter_factory_test_vectors.proto.bin";

void VerifyTestVector(const AeadCryptingKeyRegistry& registry,
                      const CrypterFactoryTestVector& test_vector) {
  auto status_or_crypter = MakeCrunchyCrypter(registry, test_vector.keyset());
  CRUNCHY_ASSERT_OK(status_or_crypter.status());
  std::unique_ptr<CrunchyCrypter> crypter =
      std::move(status_or_crypter.ValueOrDie());

  auto status_or_decrypted =
      crypter->Decrypt(test_vector.ciphertext(), test_vector.aad());
  CRUNCHY_ASSERT_OK(status_or_decrypted.status());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());
  ASSERT_EQ(test_vector.plaintext(), decrypted);
}

TEST(KeysetFactoryTest, TestVectors) {
  const AeadCryptingKeyRegistry& registry = GetAeadCryptingKeyRegistry();

  auto status_or_test_vectors =
      GetProtoFromFile<CrypterFactoryTestVectors>(kTestDataPath);
  CRUNCHY_EXPECT_OK(status_or_test_vectors.status())
      << "Couldn't load test vectors, try passing --gen_test_vectors=yes";
  CrypterFactoryTestVectors test_vectors =
      std::move(status_or_test_vectors).ValueOrDie();

  for (const CrypterFactoryTestVector& test_vector :
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
