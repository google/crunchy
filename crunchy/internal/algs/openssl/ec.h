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

#ifndef CRUNCHY_ALGS_OPENSSL_EC_H_
#define CRUNCHY_ALGS_OPENSSL_EC_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/openssl/openssl_unique_ptr.h"
#include "crunchy/util/status.h"
#include <openssl/base.h>
#include <openssl/ec.h>

namespace crunchy {

// Returns the juxposition of x and y coordinates of the given point. A point
// is big-endian serialized in the fewest number of bytes required to store
// EC_GROUP_get_degree(group) bits.
StatusOr<std::string> SerializePoint(const EC_GROUP* group, const EC_POINT* point);

// Attempts to deserialize a point from the format given by
// SerializePoint.
StatusOr<openssl_unique_ptr<EC_POINT>> DeserializePoint(
    const EC_GROUP* group, absl::string_view serialized_point);

// Attempts to deserialize a point from the format given by
// SerializePoint to an EC public key.
StatusOr<std::string> DeserializePointAsPemPublicKey(
    int curve_nid, absl::string_view serialized_point);

// Returns a private key as the exponent, big-endian serialized in the fewest
// number of bytes required to store EC_GROUP_get_degree(group) bits.
StatusOr<std::string> SerializePrivateKey(const EC_GROUP* group, const EC_KEY* key);

// Attempts to deserialize a private key from the format given by
// SerializePrivateKey.
StatusOr<openssl_unique_ptr<EC_KEY>> DeserializePrivateKey(
    const EC_GROUP* group, absl::string_view serialized);

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_OPENSSL_EC_H_
