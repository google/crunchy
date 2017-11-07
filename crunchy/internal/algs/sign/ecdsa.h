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

#ifndef CRUNCHY_ALGS_SIGN_ECDSA_H_
#define CRUNCHY_ALGS_SIGN_ECDSA_H_

#include <memory>

#include "crunchy/internal/algs/hash/hash_interface.h"
#include "crunchy/internal/algs/sign/signer_interface.h"
#include <openssl/nid.h>

namespace crunchy {

enum class Curve {
  P256,
  P384,
  P521,
};

enum class SignatureFormat {
  ASN1,
  JWT,
};

std::unique_ptr<SignerFactory> MakeEcdsaFactory(
    Curve curve, const Hasher& hash, SignatureFormat signature_format);

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_SIGN_ECDSA_H_
