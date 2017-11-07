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

#include "crunchy/internal/algs/hash/sha384.h"

#include <stdint.h>

#include "crunchy/internal/algs/openssl/errors.h"
#include <openssl/digest.h>

namespace crunchy {

const Sha384& Sha384::Instance() {
  static const Sha384& instance = *new Sha384();
  return instance;
}

StatusOr<std::string> Sha384::Hash(absl::string_view input) const {
  uint8_t digest[EVP_MAX_MD_SIZE];
  unsigned int digest_length = 0;
  if (EVP_Digest(input.data(), input.size(), digest, &digest_length,
                 EVP_sha384(), nullptr) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error computing sha384: " << GetOpensslErrors();
  }
  return std::string(reinterpret_cast<const char*>(digest), digest_length);
}

StatusOr<std::string> Sha384Hash(absl::string_view input) {
  return Sha384::Instance().Hash(input);
}

StatusOr<int> Sha384::OpensslNameId() const { return NID_sha384; }
StatusOr<const EVP_MD*> Sha384::OpensslMessageDigest() const {
  return EVP_sha384();
}

}  // namespace crunchy
