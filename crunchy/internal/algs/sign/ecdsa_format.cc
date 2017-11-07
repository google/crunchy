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

#include "crunchy/internal/algs/sign/ecdsa_format.h"

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <utility>

#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/internal/algs/openssl/openssl_unique_ptr.h"
#include "crunchy/internal/port/port.h"
#include <openssl/base.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/mem.h>

namespace crunchy {

namespace {

constexpr size_t kFiniteFieldByteSize = 32;

StatusOr<std::string> decode_der_integer(absl::string_view n,
                                    size_t* bytes_consumed) {
  if (n.size() < 3 || n[0] != 0x02) {
    return InvalidArgumentError("Input is not a DER integer");
  }
  size_t len = n[1];
  if (len + 2 > n.size()) {
    return InvalidArgumentError(
        "Not enough bytes in input when decoding a DER integer");
  }

  if (len > kFiniteFieldByteSize + 1) {
    return InvalidArgumentError("Integer does not fit in 32 bytes");
  } else if (len == kFiniteFieldByteSize + 1) {
    if (n[2] != 0) {
      return InvalidArgumentError("Integer does not fit in 32 bytes");
    }
    // Skip the leading zero
    *bytes_consumed = 2 + len;
    return std::string(absl::ClippedSubstr(n, 3, len - 1));
  }
  *bytes_consumed = 2 + len;
  return std::string(kFiniteFieldByteSize - len, 0) +
         std::string(absl::ClippedSubstr(n, 2, len));
}

}  // namespace

StatusOr<std::string> ecdsa_raw_signature_to_asn1(absl::string_view r,
                                             absl::string_view s) {
  auto sig = openssl_make_unique<ECDSA_SIG>();

  BN_bin2bn(reinterpret_cast<const uint8_t*>(r.data()), r.size(), sig->r);
  BN_bin2bn(reinterpret_cast<const uint8_t*>(s.data()), s.size(), sig->s);

  uint8_t* sig_bytes = nullptr;
  size_t sig_bytes_length = 0;
  if (ECDSA_SIG_to_bytes(&sig_bytes, &sig_bytes_length, sig.get()) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl failed to generate signature: " << GetOpensslErrors();
  }

  std::string result(reinterpret_cast<char*>(sig_bytes), sig_bytes_length);
  OPENSSL_free(sig_bytes);
  return std::move(result);
}

Status p256_ecdsa_asn1_signature_to_raw(absl::string_view sig, std::string* r,
                                        std::string* s) {
  if (sig.size() < 3 || sig[0] != 0x30) {
    return InvalidArgumentError("Input is not a DER sequence");
  }
  // Ignoring the byte length of the sequence here (sig[1])

  size_t num_decoded;

  // R starts at index 2
  auto r_or = decode_der_integer(absl::ClippedSubstr(sig, 2), &num_decoded);
  if (!r_or.ok()) {
    return r_or.status();
  }
  *r = std::move(r_or.ValueOrDie());

  // S starts where R ended
  auto s_or = decode_der_integer(absl::ClippedSubstr(sig, 2 + num_decoded),
                                 &num_decoded);
  if (!s_or.ok()) {
    return s_or.status();
  }
  *s = std::move(s_or.ValueOrDie());

  return OkStatus();
}

}  // namespace crunchy
