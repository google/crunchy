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

#ifndef CRUNCHY_ALGS_SIGN_SIGNER_TEST_H_
#define CRUNCHY_ALGS_SIGN_SIGNER_TEST_H_

#include <stddef.h>
#include <memory>
#include <string>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/algs/sign/signer_interface.h"
#include "crunchy/internal/algs/sign/testdata/sign_test_vectors.pb.h"
#include "crunchy/internal/common/file.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/test_factory.h"
#include "crunchy/util/status.h"

namespace crunchy {

const size_t kTestVectorMaxMessageSize = 42;

const char kMessage[] = "banana";

inline void SignVerifyTest(const SignerFactory& factory) {
  std::string public_key;
  std::string private_key;

  CRUNCHY_EXPECT_OK(factory.NewKeypair(&public_key, &private_key));

  auto status_or_signer = factory.MakeSigner(private_key);
  CRUNCHY_EXPECT_OK(status_or_signer.status());
  std::unique_ptr<SignerInterface> signer =
      std::move(status_or_signer.ValueOrDie());

  auto status_or_verifier = factory.MakeVerifier(public_key);
  CRUNCHY_EXPECT_OK(status_or_verifier.status());
  std::unique_ptr<VerifierInterface> verifier =
      std::move(status_or_verifier.ValueOrDie());

  auto status_or_signature = signer->Sign(kMessage);
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());
  CRUNCHY_EXPECT_OK(verifier->Verify(kMessage, signature));
}

inline void WrongSignerTest(const SignerFactory& factory) {
  std::string public_key;
  std::string private_key;

  // Generate a keypair to use only for the signer
  CRUNCHY_EXPECT_OK(factory.NewKeypair(&public_key, &private_key));
  auto status_or_signer = factory.MakeSigner(private_key);
  CRUNCHY_EXPECT_OK(status_or_signer.status());
  std::unique_ptr<SignerInterface> signer =
      std::move(status_or_signer.ValueOrDie());

  // Generate a keypair to use only for the verifier
  CRUNCHY_EXPECT_OK(factory.NewKeypair(&public_key, &private_key));
  auto status_or_verifier = factory.MakeVerifier(public_key);
  CRUNCHY_EXPECT_OK(status_or_verifier.status());
  std::unique_ptr<VerifierInterface> verifier =
      std::move(status_or_verifier.ValueOrDie());

  const char kMessage[] = "banana";
  auto status_or_signature = signer->Sign(kMessage);
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());

  EXPECT_FALSE(verifier->Verify(kMessage, signature).ok());
}

inline void BadSignatureTest(const SignerFactory& factory) {
  std::string public_key;
  std::string private_key;

  CRUNCHY_EXPECT_OK(factory.NewKeypair(&public_key, &private_key));

  auto status_or_signer = factory.MakeSigner(private_key);
  CRUNCHY_EXPECT_OK(status_or_signer.status());
  std::unique_ptr<SignerInterface> signer =
      std::move(status_or_signer.ValueOrDie());

  const char kMessage[] = "banana";
  auto status_or_signature = signer->Sign(kMessage);
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());

  auto status_or_verifier = factory.MakeVerifier(public_key);
  CRUNCHY_EXPECT_OK(status_or_verifier.status());
  std::unique_ptr<VerifierInterface> verifier =
      std::move(status_or_verifier.ValueOrDie());

  CRUNCHY_EXPECT_OK(verifier->Verify(kMessage, signature));

  // Corrupt individual bits
  for (size_t i = 0; i < signature.length(); i++) {
    std::string local_signature = signature;
    local_signature[i] ^= 0x01;
    EXPECT_FALSE(verifier->Verify(kMessage, local_signature).ok());
  }

  // Short signature
  EXPECT_FALSE(verifier
                   ->Verify(kMessage, absl::string_view(signature.data(),
                                                        signature.length() - 1))
                   .ok());
}

inline void VerifyTestVector(const SignerFactory& factory,
                             const SignerTestVector& test_vector) {
  auto status_or_signer = factory.MakeSigner(test_vector.private_key());
  CRUNCHY_EXPECT_OK(status_or_signer.status());
  std::unique_ptr<SignerInterface> signer =
      std::move(status_or_signer.ValueOrDie());

  auto status_or_verifier = factory.MakeVerifier(test_vector.public_key());
  CRUNCHY_EXPECT_OK(status_or_verifier.status());
  std::unique_ptr<VerifierInterface> verifier =
      std::move(status_or_verifier.ValueOrDie());
  EXPECT_NE(verifier, nullptr);

  // Verify the test vector.
  CRUNCHY_EXPECT_OK(
      verifier->Verify(test_vector.message(), test_vector.signature()));

  // Sign and verify the message again
  auto status_or_signature = signer->Sign(test_vector.message());
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  std::string another_signature = std::move(status_or_signature.ValueOrDie());
  CRUNCHY_EXPECT_OK(verifier->Verify(test_vector.message(), another_signature));
}

inline SignerTestVector GenerateTestVector(const SignerFactory& factory) {
  SignerTestVector test_vector;
  CRUNCHY_EXPECT_OK(factory.NewKeypair(test_vector.mutable_public_key(),
                                       test_vector.mutable_private_key()));
  size_t message_size = BiasRandInt(kTestVectorMaxMessageSize);

  auto status_or_signer = factory.MakeSigner(test_vector.private_key());
  CRUNCHY_EXPECT_OK(status_or_signer.status());
  std::unique_ptr<SignerInterface> signer =
      std::move(status_or_signer.ValueOrDie());
  EXPECT_NE(signer, nullptr);

  test_vector.set_message(RandString(message_size));

  auto status_or_signature = signer->Sign(test_vector.message());
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  test_vector.set_signature(status_or_signature.ValueOrDie());

  VerifyTestVector(factory, test_vector);
  return test_vector;
}

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_SIGN_SIGNER_TEST_H_
