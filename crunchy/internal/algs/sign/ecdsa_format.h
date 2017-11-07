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

#ifndef CRUNCHY_ALGS_SIGN_ECDSA_FORMAT_H_
#define CRUNCHY_ALGS_SIGN_ECDSA_FORMAT_H_

#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/util/status.h"

namespace crunchy {

// Construct a signature encoded as the ASN.1 structure (using DER) specified in
// the SEC1 spec from two MSB integers.
StatusOr<std::string> ecdsa_raw_signature_to_asn1(absl::string_view r,
                                             absl::string_view s);

// Parse a signature encoded as the ASN.1 structure (using DER) specified in
// the SEC1 spec into two 32 byte MSB integers. Result is assigned to r and s.
Status p256_ecdsa_asn1_signature_to_raw(absl::string_view sig, std::string* r,
                                        std::string* s);

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_SIGN_ECDSA_FORMAT_H_
