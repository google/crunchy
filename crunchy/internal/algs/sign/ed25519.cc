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

#include "crunchy/internal/algs/sign/ed25519.h"

#include <stdint.h>
#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/util/status.h"
#include <openssl/curve25519.h>

namespace crunchy {
namespace {

class Ed25519Signer : public SignerInterface {
 public:
  explicit Ed25519Signer(absl::string_view private_key)
      : private_key_(private_key) {}

  StatusOr<std::string> Sign(absl::string_view input) const override {
    uint8_t out_sig[ED25519_SIGNATURE_LEN];
    if (ED25519_sign(out_sig, reinterpret_cast<const uint8_t*>(input.data()),
                     input.length(),
                     reinterpret_cast<const uint8_t*>(private_key_.data())) !=
        1) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Boringssl internal error computing Ed25519 signature: "
             << GetOpensslErrors();
    }
    return std::string(reinterpret_cast<char*>(out_sig), ED25519_SIGNATURE_LEN);
  }

 private:
  const std::string private_key_;
};

class Ed25519Verifier : public VerifierInterface {
 public:
  explicit Ed25519Verifier(absl::string_view public_key)
      : public_key_(public_key) {}

  Status Verify(absl::string_view input,
                absl::string_view signature) const override {
    if (signature.length() != ED25519_SIGNATURE_LEN) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Length of signature [" << signature.length()
             << "] does not match expected size [" << ED25519_SIGNATURE_LEN
             << "] for Ed25519";
    }
    if (ED25519_verify(
            reinterpret_cast<const uint8_t*>(input.data()), input.length(),
            reinterpret_cast<const uint8_t*>(signature.data()),
            reinterpret_cast<const uint8_t*>(public_key_.data())) != 1) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Ed25519 signature verification failure.";
    }
    return OkStatus();
  }

 private:
  const std::string public_key_;
};

class Ed25519Factory : public SignerFactory {
 public:
  Status NewKeypair(std::string* public_key, std::string* private_key) const override {
    uint8_t out_public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t out_private_key[ED25519_PRIVATE_KEY_LEN];
    ED25519_keypair(out_public_key, out_private_key);
    public_key->assign(reinterpret_cast<char*>(out_public_key),
                       ED25519_PUBLIC_KEY_LEN);
    private_key->assign(reinterpret_cast<char*>(out_private_key),
                        ED25519_PRIVATE_KEY_LEN);
    return OkStatus();
  }

  StatusOr<std::unique_ptr<SignerInterface>> MakeSigner(
      absl::string_view private_key) const override {
    if (private_key.length() != ED25519_PRIVATE_KEY_LEN) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Length of private key [" << private_key.length()
             << "] does not match expected size [" << ED25519_PRIVATE_KEY_LEN
             << "] for Ed25519";
    }
    return {absl::make_unique<Ed25519Signer>(private_key)};
  }

  StatusOr<std::unique_ptr<VerifierInterface>> MakeVerifier(
      absl::string_view public_key) const override {
    if (public_key.length() != ED25519_PUBLIC_KEY_LEN) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Length of public key [" << public_key.length()
             << "] does not match expected size [" << ED25519_PUBLIC_KEY_LEN
             << "] for Ed25519";
    }
    return {absl::make_unique<Ed25519Verifier>(public_key)};
  }
};

}  // namespace

const SignerFactory& GetEd25519Factory() {
  static const SignerFactory& factory = *new Ed25519Factory();
  return factory;
}

}  // namespace crunchy
