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

#ifndef CRUNCHY_ALGS_SIGN_ED25519_H_
#define CRUNCHY_ALGS_SIGN_ED25519_H_

#include "crunchy/internal/algs/sign/signer_interface.h"

namespace crunchy {

// Returns the public and private keys of a new Ed25519 keypair for the
// twisted-Edwards curve that is birationally equivalent to Curve25519.
//
// Public keys are 32 bytes, and private keys are 64 bytes.
const SignerFactory& GetEd25519Factory();

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_SIGN_ED25519_H_
