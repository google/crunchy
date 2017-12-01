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

#ifndef CRUNCHY_ALGS_MAC_OPENSSL_HMAC_H_
#define CRUNCHY_ALGS_MAC_OPENSSL_HMAC_H_

#include <stddef.h>
#include <memory>

#include "crunchy/internal/algs/mac/mac_interface.h"

namespace crunchy {

// Returns an HMAC-SHA256 implmentation with a (truncated) 16-byte (half
// digest) signature. Requires that the key be exactly 32 bytes (full digest).
const MacFactory& GetHmacSha256HalfDigestFactory();

StatusOr<std::unique_ptr<MacFactory>> MakeHmacSha256Factory(
    size_t key_length, size_t signature_length);

StatusOr<std::unique_ptr<MacFactory>> MakeHmacSha384Factory(
    size_t key_length, size_t signature_length);

StatusOr<std::unique_ptr<MacFactory>> MakeHmacSha512Factory(
    size_t key_length, size_t signature_length);

StatusOr<std::unique_ptr<MacFactory>> MakeHmacSha1Factory(
    size_t key_length, size_t signature_length);

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_MAC_OPENSSL_HMAC_H_
