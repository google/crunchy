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

#ifndef CRUNCHY_ALGS_KDF_HKDF_H_
#define CRUNCHY_ALGS_KDF_HKDF_H_

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "crunchy/util/status.h"
#include <openssl/base.h>
#include <openssl/evp.h>

namespace crunchy {

class Hkdf {
 public:
  virtual ~Hkdf() = default;

  // HkdfExpand implements HKDF-Expand from RFC 5869.
  // Derive a pseudo-random number [out_key] of byte length [out_byte_len].
  // [info] stores context information which can be zero-length.
  virtual Status HkdfExpand(absl::string_view info, const size_t out_byte_len,
                            uint8_t* out_key) const = 0;
};

StatusOr<std::unique_ptr<Hkdf>> MakeHkdfSha256(absl::string_view in_key,
                                               absl::string_view salt);

StatusOr<std::unique_ptr<Hkdf>> MakeHkdfSha512(absl::string_view in_key,
                                               absl::string_view salt);

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_KDF_HKDF_H_
