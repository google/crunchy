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

#include "crunchy/internal/keys/signing_key.h"

#include <utility>

#include "absl/memory/memory.h"
#include "crunchy/internal/port/port.h"

namespace crunchy {

namespace {

class SigningKeyImpl : public SigningKey {
 public:
  explicit SigningKeyImpl(std::unique_ptr<SignerInterface> signer)
      : signer_(std::move(signer)) {}
  StatusOr<std::string> Sign(absl::string_view message) const override {
    return signer_->Sign(message);
  }

 private:
  std::unique_ptr<SignerInterface> signer_;
};

class VerifyingKeyImpl : public VerifyingKey {
 public:
  explicit VerifyingKeyImpl(std::unique_ptr<VerifierInterface> verifier)
      : verifier_(std::move(verifier)) {}
  Status Verify(absl::string_view message,
                absl::string_view signature) const override {
    return verifier_->Verify(message, signature);
  }

 private:
  std::unique_ptr<VerifierInterface> verifier_;
};

class SigningKeyFactoryImpl : public SigningKeyFactory {
 public:
  explicit SigningKeyFactoryImpl(const SignerFactory& factory)
      : factory_(factory) {}

  StatusOr<KeyData> CreateRandomPrivateKeyData() const override {
    KeyData key_data;
    Status status = factory_.NewKeypair(key_data.mutable_public_key(),
                                        key_data.mutable_private_key());
    if (!status.ok()) {
      return status;
    }
    return key_data;
  }
  StatusOr<KeyData> CreatePublicKeyData(
      const KeyData& private_key_data) const override {
    KeyData result = private_key_data;
    if (result.public_key().empty()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "key_data.public_key() is empty";
    }
    result.clear_private_key();
    return result;
  }
  StatusOr<std::unique_ptr<SigningKey>> MakeSigningKey(
      const KeyData& private_key_data) const override {
    if (private_key_data.private_key().empty()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "key_data.private_key() is empty";
    }
    auto status_or_signer = factory_.MakeSigner(private_key_data.private_key());
    if (!status_or_signer.ok()) {
      return status_or_signer.status();
    }
    return {absl::make_unique<SigningKeyImpl>(
        std::move(status_or_signer.ValueOrDie()))};
  }
  StatusOr<std::unique_ptr<VerifyingKey>> MakeVerifyingKey(
      const KeyData& public_key_data) const override {
    if (!public_key_data.private_key().empty()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "key_data.private_key() is non-empty";
    }
    if (public_key_data.public_key().empty()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "key_data.public_key() is empty";
    }
    auto status_or_verifier =
        factory_.MakeVerifier(public_key_data.public_key());
    if (!status_or_verifier.ok()) {
      return status_or_verifier.status();
    }
    return {absl::make_unique<VerifyingKeyImpl>(
        std::move(status_or_verifier.ValueOrDie()))};
  }

 private:
  const SignerFactory& factory_;
};

}  // namespace

std::unique_ptr<SigningKeyFactory> MakeFactory(const SignerFactory& factory) {
  return {absl::make_unique<SigningKeyFactoryImpl>(factory)};
}

}  // namespace crunchy
