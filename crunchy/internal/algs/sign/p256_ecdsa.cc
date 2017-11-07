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

#include "crunchy/internal/algs/sign/p256_ecdsa.h"

#include <memory>

#include "crunchy/internal/algs/hash/sha256.h"
#include "crunchy/internal/algs/sign/ecdsa.h"

namespace crunchy {

const SignerFactory& GetP256EcdsaAsn1Factory() {
  static const SignerFactory& factory =
      *MakeEcdsaFactory(Curve::P256, Sha256::Instance(),
                        SignatureFormat::ASN1)
           .release();
  return factory;
}

const SignerFactory& GetP256EcdsaJwtFactory() {
  static const SignerFactory& factory =
      *MakeEcdsaFactory(Curve::P256, Sha256::Instance(),
                        SignatureFormat::JWT)
           .release();
  return factory;
}

}  // namespace crunchy
