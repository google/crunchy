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

#include "crunchy/internal/algs/hash/sha256.h"

#include <stdint.h>

#include "crunchy/internal/algs/openssl/errors.h"
#include <openssl/digest.h>

namespace crunchy {

StatusOr<std::string> Sha256Hash(absl::string_view input) {
  uint8_t digest[EVP_MAX_MD_SIZE];
  unsigned int digest_length = 0;
  if (EVP_Digest(input.data(), input.size(), digest, &digest_length,
                 EVP_sha256(), nullptr) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error computing sha256: " << GetOpensslErrors();
  }
  return std::string(reinterpret_cast<const char*>(digest), digest_length);
}

StatusOr<std::string> Sha256Hash(absl::string_view input1,
                            absl::string_view input2) {
  auto ctx = EVP_MD_CTX_create();
  uint8_t digest[EVP_MAX_MD_SIZE];
  unsigned int digest_length = 0;
  if (!ctx || EVP_DigestInit(ctx, EVP_sha256()) != 1 ||
      EVP_DigestUpdate(ctx, input1.data(), input1.size()) != 1 ||
      EVP_DigestUpdate(ctx, input2.data(), input2.size()) != 1 ||
      EVP_DigestFinal(ctx, digest, &digest_length) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error computing sha256: " << GetOpensslErrors();
  }
  EVP_MD_CTX_destroy(ctx);
  return std::string(reinterpret_cast<const char*>(digest), digest_length);
}

}  // namespace crunchy

