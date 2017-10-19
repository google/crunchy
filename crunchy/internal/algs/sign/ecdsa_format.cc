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
#include <utility>

namespace crunchy {

namespace {

constexpr size_t kFiniteFieldByteSize = 32;

std::string encode_der_integer(absl::string_view src) {
  std::string buf;
  buf.push_back(0x02);  // DER Integer tag

  // Strip excess leading 0s
  size_t start = src.find_first_not_of(0);
  if (start == absl::string_view::npos) {
    // Special case: Input is all zeroes
    buf.push_back(1);  // Length
    buf.push_back(0);  // Value
    return buf;
  }
  if (src[start] & 0x80) {
    // If high bit is set, add a leading zero since DER encoding is signed
    buf.push_back(src.size() - start + 1);  // Length
    buf.push_back(0);  // Leading zero
  } else {
    buf.push_back(src.size() - start);  // Length
  }
  buf.append(std::string(src), start, std::string::npos);  // Value
  return buf;
}

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

StatusOr<std::string> p256_ecdsa_raw_signature_to_asn1(absl::string_view r,
                                                  absl::string_view s) {
  if (r.size() != kFiniteFieldByteSize) {
    return InvalidArgumentError("r has invalid length");
  }
  if (s.size() != kFiniteFieldByteSize) {
    return InvalidArgumentError("s has invalid length");
  }
  std::string r_der = encode_der_integer(r);
  std::string s_der = encode_der_integer(s);

  std::string sig;
  sig.reserve(2 + r_der.length() + s_der.length());
  sig.push_back(0x30);  // Sequence tag
  sig.push_back(r_der.length() + s_der.length());
  sig.append(r_der);
  sig.append(s_der);

  return sig;
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
