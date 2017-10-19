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

#ifndef CRUNCHY_ALGS_SIGN_SIGNER_INTERFACE_H_
#define CRUNCHY_ALGS_SIGN_SIGNER_INTERFACE_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/util/status.h"

namespace crunchy {

// An interface for asymmetric signature schemes such as RSA PKCS #1 v2.
// All methods are thread-safe. Implementations of SignerInterface
// should have a corresponding implementation of VerifierInterface which
// can verify outputs from Sign.
class SignerInterface {
 public:
  virtual ~SignerInterface() = default;

  // Signs the given std::string and returns the signature.
  virtual StatusOr<std::string> Sign(absl::string_view input) const = 0;
};

// An interface for asymmetric signature verification schemes such as RSA
// PKCS#8. All methods are thread-safe.
class VerifierInterface {
 public:
  virtual ~VerifierInterface() = default;

  // Tries to verify the given signature of the input std::string and returns
  // Status::OK if the signature is valid.
  virtual Status Verify(absl::string_view input,
                        absl::string_view signature) const = 0;
};

class SignerFactory {
 public:
  virtual ~SignerFactory() = default;

  // Returns a public/private keypair
  virtual Status NewKeypair(std::string* public_key, std::string* private_key) const = 0;

  // Returns a SignerInterface from a serialized private key.
  virtual StatusOr<std::unique_ptr<SignerInterface>> MakeSigner(
      absl::string_view private_key) const = 0;

  // Returns a VerifierInterface from a serialized public key.
  virtual StatusOr<std::unique_ptr<VerifierInterface>> MakeVerifier(
      absl::string_view public_key) const = 0;
};

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_SIGN_SIGNER_INTERFACE_H_
