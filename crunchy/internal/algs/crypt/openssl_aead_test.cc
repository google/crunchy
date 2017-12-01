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

#include "crunchy/internal/algs/crypt/openssl_aead.h"

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/crypt/crypter_interface.h"
#include "crunchy/internal/algs/crypt/crypter_test.h"
#include "crunchy/internal/algs/crypt/testdata/crypter_test_vectors.pb.h"
#include "crunchy/internal/common/init.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/test_factory.h"
#include "crunchy/internal/port/port.h"

namespace crunchy {

namespace {

std::vector<FactoryInfo<CrypterFactory>>* FactoryInfoVector() {
  auto factories = new std::vector<FactoryInfo<CrypterFactory>>();
  factories->push_back(
      {"Aes128Gcm", GetAes128GcmFactory(),
       "crunchy/internal/algs/crypt/testdata/aes_128_gcm.proto.bin"});
  factories->push_back(
      {"Aes256Gcm", GetAes256GcmFactory(),
       "crunchy/internal/algs/crypt/testdata/aes_256_gcm.proto.bin"});
  factories->push_back(
      {"ChaCha20Poly1305", GetChaCha20Poly1305Factory(),
       "crunchy/internal/algs/crypt/testdata/chacha20_poly1305.proto.bin"});
  factories->push_back(
      {"Aes128GcmSiv", GetAes128GcmSivFactory(),
       "crunchy/internal/algs/crypt/testdata/aes_128_gcm_siv.proto.bin"});
  factories->push_back(
      {"Aes256GcmSiv", GetAes256GcmSivFactory(),
       "crunchy/internal/algs/crypt/testdata/aes_256_gcm_siv.proto.bin"});
  return factories;
}

using CrypterTest = FactoryParamTest<CrypterFactory, FactoryInfoVector>;

TEST_P(CrypterTest, RandomEncryptDecryptTests) {
  RandomEncryptDecryptTest(factory());
}

TEST_P(CrypterTest, EncryptionFailureTests) {
  EncryptionFailureTest(factory());
}

TEST_P(CrypterTest, DecryptionFailureTests) {
  DecryptionFailureTest(factory());
}

TEST_P(CrypterTest, RandomEncryptDecryptStringTests) {
  RandomEncryptDecryptStringTest(factory());
}

TEST_P(CrypterTest, EncryptionFailureStringTests) {
  EncryptionFailureStringTest(factory());
}

TEST_P(CrypterTest, DecryptionFailureStringTests) {
  DecryptionFailureStringTest(factory());
}

TEST_P(CrypterTest, TestVectors) {
  if (test_data_path().empty()) {
    CRUNCHY_LOG(ERROR) << name() << " has an empty test_data_path, skipping";
    return;
  }
  auto test_vectors = GetTestVectors<CrypterInterfaceTestVectors>();
  for (const auto& test_vector : test_vectors.vector()) {
    VerifyTestVector(factory(), test_vector);
  }
}

INSTANTIATE_TEST_CASE_P(, CrypterTest,
                        ::testing::ValuesIn(CrypterTest::factories()),
                        CrypterTest::GetNameFromParam);

void VerifyGcmTestVector(const CrypterInterfaceTestVector& test_vector) {
  if (test_vector.key().length() == GetAes128GcmFactory().GetKeyLength()) {
    VerifyTestVector(GetAes128GcmFactory(), test_vector);
  } else if (test_vector.key().length() ==
             GetAes256GcmFactory().GetKeyLength()) {
    VerifyTestVector(GetAes256GcmFactory(), test_vector);
  } else {
    CRUNCHY_LOG(FATAL) << "test vector had key of length "
                       << test_vector.key().length() << " which is unsupported";
  }
}

// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
TEST(AesGcm, GcmPaper) {
  CrypterInterfaceTestVector test_vector;

  test_vector.set_key(
      absl::HexStringToBytes("00000000000000000000000000000000"));
  test_vector.set_nonce(absl::HexStringToBytes("000000000000000000000000"));
  test_vector.set_aad("");
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("58e2fccefa7e3061367f1d57a4e7455a"));
  VerifyGcmTestVector(test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("00000000000000000000000000000000"));
  test_vector.set_nonce(absl::HexStringToBytes("000000000000000000000000"));
  test_vector.set_aad("");
  test_vector.set_plaintext(
      absl::HexStringToBytes("00000000000000000000000000000000"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("0388dace60b6a392f328c2b971b2fe78"
                             "ab6e47d42cec13bdf53a67b21257bddf"));
  VerifyGcmTestVector(test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("feffe9928665731c6d6a8f9467308308"));
  test_vector.set_nonce(absl::HexStringToBytes("cafebabefacedbaddecaf888"));
  test_vector.set_aad("");
  test_vector.set_plaintext(
      absl::HexStringToBytes("d9313225f88406e5a55909c5aff5269a"
                             "86a7a9531534f7da2e4c303d8a318a72"
                             "1c3c0c95956809532fcf0e2449a6b525"
                             "b16aedf5aa0de657ba637b391aafd255"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("42831ec2217774244b7221b784d0d49c"
                             "e3aa212f2c02a4e035c17e2329aca12e"
                             "21d514b25466931c7d8f6a5aac84aa05"
                             "1ba30b396a0aac973d58e091473f5985"
                             "4d5c2af327cd64a62cf35abd2ba6fab4"));
  VerifyGcmTestVector(test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("feffe9928665731c6d6a8f9467308308"));
  test_vector.set_nonce(absl::HexStringToBytes("cafebabefacedbaddecaf888"));
  test_vector.set_aad(
      absl::HexStringToBytes("feedfacedeadbeeffeedfacedeadbeef"
                             "abaddad2"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("d9313225f88406e5a55909c5aff5269a"
                             "86a7a9531534f7da2e4c303d8a318a72"
                             "1c3c0c95956809532fcf0e2449a6b525"
                             "b16aedf5aa0de657ba637b39"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("42831ec2217774244b7221b784d0d49c"
                             "e3aa212f2c02a4e035c17e2329aca12e"
                             "21d514b25466931c7d8f6a5aac84aa05"
                             "1ba30b396a0aac973d58e091"
                             "5bc94fbc3221a5db94fae95ae7121a47"));
  VerifyGcmTestVector(test_vector);
}

// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
TEST(AesGcm, OddSizes) {
  CrypterInterfaceTestVector test_vector;

  // 2.1.1 54-byte auth
  test_vector.set_key(
      absl::HexStringToBytes("AD7A2BD03EAC835A6F620FDCB506B345"));
  test_vector.set_nonce(absl::HexStringToBytes("12153524C0895E81B2C28465"));
  test_vector.set_aad(
      absl::HexStringToBytes("D609B1F056637A0D46DF998D88E5222A"
                             "B2C2846512153524C0895E8108000F10"
                             "1112131415161718191A1B1C1D1E1F20"
                             "2122232425262728292A2B2C2D2E2F30"
                             "313233340001"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("F09478A9B09007D06F46E9B6A1DA25DD"));
  VerifyGcmTestVector(test_vector);

  // 2.1.2 54-byte auth
  test_vector.set_key(
      absl::HexStringToBytes("E3C08A8F06C6E3AD95A70557B23F7548"
                             "3CE33021A9C72B7025666204C69C0B72"));
  test_vector.set_nonce(absl::HexStringToBytes("12153524C0895E81B2C28465"));
  test_vector.set_aad(
      absl::HexStringToBytes("D609B1F056637A0D46DF998D88E5222A"
                             "B2C2846512153524C0895E8108000F10"
                             "1112131415161718191A1B1C1D1E1F20"
                             "2122232425262728292A2B2C2D2E2F30"
                             "313233340001"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("2F0BC5AF409E06D609EA8B7D0FA5EA50"));
  VerifyGcmTestVector(test_vector);

  // 2.2.1 60-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("AD7A2BD03EAC835A6F620FDCB506B345"));
  test_vector.set_nonce(absl::HexStringToBytes("12153524C0895E81B2C28465"));
  test_vector.set_aad(
      absl::HexStringToBytes("D609B1F056637A0D46DF998D88E52E00"
                             "B2C2846512153524C0895E81"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F303132333435363738393A0002"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("701AFA1CC039C0D765128A665DAB6924"
                             "3899BF7318CCDC81C9931DA17FBE8EDD"
                             "7D17CB8B4C26FC81E3284F2B7FBA713D"
                             "4F8D55E7D3F06FD5A13C0C29B9D5B880"));
  VerifyGcmTestVector(test_vector);

  // 2.2.2 60-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("E3C08A8F06C6E3AD95A70557B23F7548"
                             "3CE33021A9C72B7025666204C69C0B72"));
  test_vector.set_nonce(absl::HexStringToBytes("12153524C0895E81B2C28465"));
  test_vector.set_aad(
      absl::HexStringToBytes("D609B1F056637A0D46DF998D88E52E00"
                             "B2C2846512153524C0895E81"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F303132333435363738393A0002"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("E2006EB42F5277022D9B19925BC419D7"
                             "A592666C925FE2EF718EB4E308EFEAA7"
                             "C5273B394118860A5BE2A97F56AB7836"
                             "5CA597CDBB3EDB8D1A1151EA0AF7B436"));
  VerifyGcmTestVector(test_vector);

  // 2.3.1 60-byte auth
  test_vector.set_key(
      absl::HexStringToBytes("071B113B0CA743FECCCF3D051F737382"));
  test_vector.set_nonce(absl::HexStringToBytes("F0761E8DCD3D000176D457ED"));
  test_vector.set_aad(
      absl::HexStringToBytes("E20106D7CD0DF0761E8DCD3D88E54000"
                             "76D457ED08000F101112131415161718"
                             "191A1B1C1D1E1F202122232425262728"
                             "292A2B2C2D2E2F303132333435363738"
                             "393A0003"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("0C017BC73B227DFCC9BAFA1C41ACC353"));
  VerifyGcmTestVector(test_vector);

  // 2.3.2 60-byte auth
  test_vector.set_key(
      absl::HexStringToBytes("691D3EE909D7F54167FD1CA0B5D76908"
                             "1F2BDE1AEE655FDBAB80BD5295AE6BE7"));
  test_vector.set_nonce(absl::HexStringToBytes("F0761E8DCD3D000176D457ED"));
  test_vector.set_aad(
      absl::HexStringToBytes("E20106D7CD0DF0761E8DCD3D88E54000"
                             "76D457ED08000F101112131415161718"
                             "191A1B1C1D1E1F202122232425262728"
                             "292A2B2C2D2E2F303132333435363738"
                             "393A0003"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("35217C774BBC31B63166BCF9D4ABED07"));
  VerifyGcmTestVector(test_vector);

  // 2.4.1 54-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("071B113B0CA743FECCCF3D051F737382"));
  test_vector.set_nonce(absl::HexStringToBytes("F0761E8DCD3D000176D457ED"));
  test_vector.set_aad(
      absl::HexStringToBytes("E20106D7CD0DF0761E8DCD3D88E54C2A"
                             "76D457ED"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F30313233340004"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("13B4C72B389DC5018E72A171DD85A5D3"
                             "752274D3A019FBCAED09A425CD9B2E1C"
                             "9B72EEE7C9DE7D52B3F3"
                             "D6A5284F4A6D3FE22A5D6C2B960494C3"));
  VerifyGcmTestVector(test_vector);

  // 2.4.2 54-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("691D3EE909D7F54167FD1CA0B5D76908"
                             "1F2BDE1AEE655FDBAB80BD5295AE6BE7"));
  test_vector.set_nonce(absl::HexStringToBytes("F0761E8DCD3D000176D457ED"));
  test_vector.set_aad(
      absl::HexStringToBytes("E20106D7CD0DF0761E8DCD3D88E54C2A"
                             "76D457ED"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F30313233340004"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("C1623F55730C93533097ADDAD2566496"
                             "6125352B43ADACBD61C5EF3AC90B5BEE"
                             "929CE4630EA79F6CE519"
                             "12AF39C2D1FDC2051F8B7B3C9D397EF2"));
  VerifyGcmTestVector(test_vector);

  // 2.5.1 65-byte auth
  test_vector.set_key(
      absl::HexStringToBytes("013FE00B5F11BE7F866D0CBBC55A7A90"));
  test_vector.set_nonce(absl::HexStringToBytes("7CFDE9F9E33724C68932D612"));
  test_vector.set_aad(
      absl::HexStringToBytes("84C5D513D2AAF6E5BBD2727788E52300"
                             "8932D6127CFDE9F9E33724C608000F10"
                             "1112131415161718191A1B1C1D1E1F20"
                             "2122232425262728292A2B2C2D2E2F30"
                             "3132333435363738393A3B3C3D3E3F00"
                             "05"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("217867E50C2DAD74C28C3B50ABDF695A"));
  VerifyGcmTestVector(test_vector);

  // 2.5.2 65-byte auth
  test_vector.set_key(
      absl::HexStringToBytes("83C093B58DE7FFE1C0DA926AC43FB360"
                             "9AC1C80FEE1B624497EF942E2F79A823"));
  test_vector.set_nonce(absl::HexStringToBytes("7CFDE9F9E33724C68932D612"));
  test_vector.set_aad(
      absl::HexStringToBytes("84C5D513D2AAF6E5BBD2727788E52300"
                             "8932D6127CFDE9F9E33724C608000F10"
                             "1112131415161718191A1B1C1D1E1F20"
                             "2122232425262728292A2B2C2D2E2F30"
                             "3132333435363738393A3B3C3D3E3F00"
                             "05"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("6EE160E8FAECA4B36C86B234920CA975"));
  VerifyGcmTestVector(test_vector);

  // 2.6.1 61-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("013FE00B5F11BE7F866D0CBBC55A7A90"));
  test_vector.set_nonce(absl::HexStringToBytes("7CFDE9F9E33724C68932D612"));
  test_vector.set_aad(
      absl::HexStringToBytes("84C5D513D2AAF6E5BBD2727788E52F00"
                             "8932D6127CFDE9F9E33724C6"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F303132333435363738393A3B00"
                             "06"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("3A4DE6FA32191014DBB303D92EE3A9E8"
                             "A1B599C14D22FB080096E13811816A3C"
                             "9C9BCF7C1B9B96DA809204E29D0E2A76"
                             "42"
                             "BFD310A4837C816CCFA5AC23AB003988"));
  VerifyGcmTestVector(test_vector);

  // 2.6.2 61-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("83C093B58DE7FFE1C0DA926AC43FB360"
                             "9AC1C80FEE1B624497EF942E2F79A823"));
  test_vector.set_nonce(absl::HexStringToBytes("7CFDE9F9E33724C68932D612"));
  test_vector.set_aad(
      absl::HexStringToBytes("84C5D513D2AAF6E5BBD2727788E52F00"
                             "8932D6127CFDE9F9E33724C6"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F303132333435363738393A3B00"
                             "06"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("110222FF8050CBECE66A813AD09A73ED"
                             "7A9A089C106B959389168ED6E8698EA9"
                             "02EB1277DBEC2E68E473155A15A7DAEE"
                             "D4"
                             "A10F4E05139C23DF00B3AADC71F0596A"));
  VerifyGcmTestVector(test_vector);

  // 2.7.1 79-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("88EE087FD95DA9FBF6725AA9D757B0CD"));
  test_vector.set_nonce(absl::HexStringToBytes("7AE8E2CA4EC500012E58495C"));
  test_vector.set_aad(
      absl::HexStringToBytes("68F2E77696CE7AE8E2CA4EC588E54100"
                             "2E58495C08000F101112131415161718"
                             "191A1B1C1D1E1F202122232425262728"
                             "292A2B2C2D2E2F303132333435363738"
                             "393A3B3C3D3E3F404142434445464748"
                             "494A4B4C4D0007"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("07922B8EBCF10BB2297588CA4C614523"));
  VerifyGcmTestVector(test_vector);

  // 2.7.2 79-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("4C973DBC7364621674F8B5B89E5C1551"
                             "1FCED9216490FB1C1A2CAA0FFE0407E5"));
  test_vector.set_nonce(absl::HexStringToBytes("7AE8E2CA4EC500012E58495C"));
  test_vector.set_aad(
      absl::HexStringToBytes("68F2E77696CE7AE8E2CA4EC588E54100"
                             "2E58495C08000F101112131415161718"
                             "191A1B1C1D1E1F202122232425262728"
                             "292A2B2C2D2E2F303132333435363738"
                             "393A3B3C3D3E3F404142434445464748"
                             "494A4B4C4D0007"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("00BDA1B7E87608BCBF470F12157F4C07"));
  VerifyGcmTestVector(test_vector);

  // 2.8.1 61-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("88EE087FD95DA9FBF6725AA9D757B0CD"));
  test_vector.set_nonce(absl::HexStringToBytes("7AE8E2CA4EC500012E58495C"));
  test_vector.set_aad(
      absl::HexStringToBytes("68F2E77696CE7AE8E2CA4EC588E54D00"
                             "2E58495C"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F303132333435363738393A3B3C"
                             "3D3E3F404142434445464748490008"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("C31F53D99E5687F7365119B832D2AAE7"
                             "0741D593F1F9E2AB3455779B078EB8FE"
                             "ACDFEC1F8E3E5277F8180B43361F6512"
                             "ADB16D2E38548A2C719DBA7228D840"
                             "88F8757ADB8AA788D8F65AD668BE70E7"));
  VerifyGcmTestVector(test_vector);

  // 2.8.2 61-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("4C973DBC7364621674F8B5B89E5C1551"
                             "1FCED9216490FB1C1A2CAA0FFE0407E5"));
  test_vector.set_nonce(absl::HexStringToBytes("7AE8E2CA4EC500012E58495C"));
  test_vector.set_aad(
      absl::HexStringToBytes("68F2E77696CE7AE8E2CA4EC588E54D00"
                             "2E58495C"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F303132333435363738393A3B3C"
                             "3D3E3F404142434445464748490008"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("BA8AE31BC506486D6873E4FCE460E7DC"
                             "57591FF00611F31C3834FE1C04AD80B6"
                             "6803AFCF5B27E6333FA67C99DA47C2F0"
                             "CED68D531BD741A943CFF7A6713BD0"
                             "2611CD7DAA01D61C5C886DC1A8170107"));
  VerifyGcmTestVector(test_vector);
}

// https://tools.ietf.org/html/rfc7539
TEST(ChaCha20Poly1305, Rfc7539) {
  const CrypterFactory& factory = GetChaCha20Poly1305Factory();
  CrypterInterfaceTestVector test_vector;

  test_vector.set_key(
      absl::HexStringToBytes("808182838485868788898a8b8c8d8e8f"
                             "909192939495969798999a9b9c9d9e9f"));
  test_vector.set_nonce(absl::HexStringToBytes("070000004041424344454647"));
  test_vector.set_aad(absl::HexStringToBytes("50515253c0c1c2c3c4c5c6c7"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("4c616469657320616e642047656e746c"
                             "656d656e206f662074686520636c6173"
                             "73206f66202739393a20496620492063"
                             "6f756c64206f6666657220796f75206f"
                             "6e6c79206f6e652074697020666f7220"
                             "746865206675747572652c2073756e73"
                             "637265656e20776f756c642062652069"
                             "742e"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("d31a8d34648e60db7b86afbc53ef7ec2"
                             "a4aded51296e08fea9e2b5a736ee62d6"
                             "3dbea45e8ca9671282fafb69da92728b"
                             "1a71de0a9e060b2905d6a5b67ecd3b36"
                             "92ddbd7f2d778b8c9803aee328091b58"
                             "fab324e4fad675945585808b4831d7bc"
                             "3ff4def08e4b7a9de576d26586cec64b"
                             "61161ae10b594f09e26a7e902ecbd060"
                             "0691"));
  VerifyTestVector(factory, test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("1c9240a5eb55d38af333888604f6b5f0"
                             "473917c1402b80099dca5cbc207075c0"));
  test_vector.set_nonce(absl::HexStringToBytes("000000000102030405060708"));
  test_vector.set_aad(absl::HexStringToBytes("f33388860000000000004e91"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("496e7465726e65742d44726166747320"
                             "61726520647261667420646f63756d65"
                             "6e74732076616c696420666f72206120"
                             "6d6178696d756d206f6620736978206d"
                             "6f6e74687320616e64206d6179206265"
                             "20757064617465642c207265706c6163"
                             "65642c206f72206f62736f6c65746564"
                             "206279206f7468657220646f63756d65"
                             "6e747320617420616e792074696d652e"
                             "20497420697320696e617070726f7072"
                             "6961746520746f2075736520496e7465"
                             "726e65742d4472616674732061732072"
                             "65666572656e6365206d617465726961"
                             "6c206f7220746f206369746520746865"
                             "6d206f74686572207468616e20617320"
                             "2fe2809c776f726b20696e2070726f67"
                             "726573732e2fe2809d"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("64a0861575861af460f062c79be643bd"
                             "5e805cfd345cf389f108670ac76c8cb2"
                             "4c6cfc18755d43eea09ee94e382d26b0"
                             "bdb7b73c321b0100d4f03b7f355894cf"
                             "332f830e710b97ce98c8a84abd0b9481"
                             "14ad176e008d33bd60f982b1ff37c855"
                             "9797a06ef4f0ef61c186324e2b350638"
                             "3606907b6a7c02b0f9f6157b53c867e4"
                             "b9166c767b804d46a59b5216cde7a4e9"
                             "9040c5a40433225ee282a1b0a06c523e"
                             "af4534d7f83fa1155b0047718cbc546a"
                             "0d072b04b3564eea1b422273f548271a"
                             "0bb2316053fa76991955ebd63159434e"
                             "cebb4e466dae5a1073a6727627097a10"
                             "49e617d91d361094fa68f0ff77987130"
                             "305beaba2eda04df997b714d6c6f2c29"
                             "a6ad5cb4022b02709beead9d67890cbb"
                             "22392336fea1851f38"));
  VerifyTestVector(factory, test_vector);
}

// https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-06
TEST(Aes128GcmSiv, IrtfDraft) {
  const CrypterFactory& factory = GetAes128GcmSivFactory();
  CrypterInterfaceTestVector test_vector;

  test_vector.set_key(
      absl::HexStringToBytes("01000000000000000000000000000000"));
  test_vector.set_nonce(absl::HexStringToBytes("030000000000000000000000"));
  test_vector.set_aad(absl::HexStringToBytes(""));
  test_vector.set_plaintext(absl::HexStringToBytes(""));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("dc20e2d83f25705bb49e439eca56de25"));
  VerifyTestVector(factory, test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("01000000000000000000000000000000"));
  test_vector.set_nonce(absl::HexStringToBytes("030000000000000000000000"));
  test_vector.set_aad(absl::HexStringToBytes(""));
  test_vector.set_plaintext(absl::HexStringToBytes("0100000000000000"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("b5d839330ac7b786578782fff6013b81"
                             "5b287c22493a364c"));
  VerifyTestVector(factory, test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("01000000000000000000000000000000"));
  test_vector.set_nonce(absl::HexStringToBytes("030000000000000000000000"));
  test_vector.set_aad(absl::HexStringToBytes(""));
  test_vector.set_plaintext(
      absl::HexStringToBytes("01000000000000000000000000000000"
                             "02000000000000000000000000000000"
                             "03000000000000000000000000000000"
                             "04000000000000000000000000000000"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("2433668f1058190f6d43e360f4f35cd8"
                             "e475127cfca7028ea8ab5c20f7ab2af0"
                             "2516a2bdcbc08d521be37ff28c152bba"
                             "36697f25b4cd169c6590d1dd39566d3f"
                             "8a263dd317aa88d56bdf3936dba75bb8"));
  VerifyTestVector(factory, test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("01000000000000000000000000000000"));
  test_vector.set_nonce(absl::HexStringToBytes("030000000000000000000000"));
  test_vector.set_aad(absl::HexStringToBytes("01"));
  test_vector.set_plaintext(absl::HexStringToBytes("0200000000000000"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("1e6daba35669f4273b0a1a2560969cdf"
                             "790d99759abd1508"));
  VerifyTestVector(factory, test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("01000000000000000000000000000000"));
  test_vector.set_nonce(absl::HexStringToBytes("030000000000000000000000"));
  test_vector.set_aad(absl::HexStringToBytes("010000000000000000000000"));
  test_vector.set_plaintext(absl::HexStringToBytes("02000000"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("a8fe3e8707eb1f84fb28f8cb73de8e99"
                             "e2f48a14"));
  VerifyTestVector(factory, test_vector);
}

// https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-06
TEST(Aes256, IrtfDraft) {
  const CrypterFactory& factory = GetAes256GcmSivFactory();
  CrypterInterfaceTestVector test_vector;

  test_vector.set_key(
      absl::HexStringToBytes("01000000000000000000000000000000"
                             "00000000000000000000000000000000"));
  test_vector.set_nonce(absl::HexStringToBytes("030000000000000000000000"));
  test_vector.set_aad(absl::HexStringToBytes(""));
  test_vector.set_plaintext(absl::HexStringToBytes(""));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("07f5f4169bbf55a8400cd47ea6fd400f"));
  VerifyTestVector(factory, test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("01000000000000000000000000000000"
                             "00000000000000000000000000000000"));
  test_vector.set_nonce(absl::HexStringToBytes("030000000000000000000000"));
  test_vector.set_aad(absl::HexStringToBytes(""));
  test_vector.set_plaintext(absl::HexStringToBytes("0100000000000000"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("c2ef328e5c71c83b843122130f7364b7"
                             "61e0b97427e3df28"));
  VerifyTestVector(factory, test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("01000000000000000000000000000000"
                             "00000000000000000000000000000000"));
  test_vector.set_nonce(absl::HexStringToBytes("030000000000000000000000"));
  test_vector.set_aad(absl::HexStringToBytes(""));
  test_vector.set_plaintext(
      absl::HexStringToBytes("01000000000000000000000000000000"
                             "02000000000000000000000000000000"
                             "03000000000000000000000000000000"
                             "04000000000000000000000000000000"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("c2d5160a1f8683834910acdafc41fbb1"
                             "632d4a353e8b905ec9a5499ac34f96c7"
                             "e1049eb080883891a4db8caaa1f99dd0"
                             "04d80487540735234e3744512c6f90ce"
                             "112864c269fc0d9d88c61fa47e39aa08"));
  VerifyTestVector(factory, test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("01000000000000000000000000000000"
                             "00000000000000000000000000000000"));
  test_vector.set_nonce(absl::HexStringToBytes("030000000000000000000000"));
  test_vector.set_aad(absl::HexStringToBytes("01"));
  test_vector.set_plaintext(absl::HexStringToBytes("0200000000000000"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("1de22967237a813291213f267e3b452f"
                             "02d01ae33e4ec854"));
  VerifyTestVector(factory, test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("01000000000000000000000000000000"
                             "00000000000000000000000000000000"));
  test_vector.set_nonce(absl::HexStringToBytes("030000000000000000000000"));
  test_vector.set_aad(absl::HexStringToBytes("010000000000000000000000"));
  test_vector.set_plaintext(absl::HexStringToBytes("02000000"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("22b3f4cd1835e517741dfddccfa07fa4"
                             "661b74cf"));
  VerifyTestVector(factory, test_vector);
}

}  // namespace

}  // namespace crunchy

int main(int argc, char** argv) {
  crunchy::InitCrunchyTest(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
