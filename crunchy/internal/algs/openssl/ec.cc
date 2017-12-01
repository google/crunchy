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

#include "crunchy/internal/algs/openssl/ec.h"

#include <stddef.h>
#include <stdint.h>
#include <utility>

#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/internal/common/string_buffer.h"
#include "crunchy/util/status.h"
#include <openssl/bn.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace crunchy {

namespace {

size_t BitsToBytes(size_t bits) { return (bits + 7) / 8; }

size_t GroupByteSize(const EC_GROUP* group) {
  return BitsToBytes(EC_GROUP_get_degree(group));
}

}  // namespace

StatusOr<std::string> SerializePoint(const EC_GROUP* group, const EC_POINT* point) {
  size_t field_byte_length = GroupByteSize(group);

  auto x = openssl_make_unique<BIGNUM>();
  auto y = openssl_make_unique<BIGNUM>();
  if (EC_POINT_get_affine_coordinates_GFp(group, point, x.get(), y.get(),
                                          nullptr) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error extracting coordinates: "
           << GetOpensslErrors();
  }
  StringBuffer serialized_point(field_byte_length * 2);
  if (BN_bn2bin_padded(serialized_point.data(), field_byte_length, x.get()) !=
      1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error serializing BIGNUM: "
           << GetOpensslErrors();
  }
  if (BN_bn2bin_padded(serialized_point.data() + field_byte_length,
                       field_byte_length, y.get()) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error serializing BIGNUM: "
           << GetOpensslErrors();
  }
  return serialized_point.as_string();
}

StatusOr<openssl_unique_ptr<EC_POINT>> DeserializePoint(
    const EC_GROUP* group, absl::string_view serialized_point) {
  size_t field_byte_length = GroupByteSize(group);
  if (2 * field_byte_length != serialized_point.size()) {
    return FailedPreconditionErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "serialized point key is " << serialized_point.size()
           << " bytes, expected " << 2 * field_byte_length << " bytes";
  }
  auto x = openssl_make_unique<BIGNUM>();
  auto y = openssl_make_unique<BIGNUM>();
  if (BN_bin2bn(reinterpret_cast<const uint8_t*>(serialized_point.data()),
                field_byte_length, x.get()) == nullptr) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error extracting x coordinate: "
           << GetOpensslErrors();
  }
  if (BN_bin2bn(reinterpret_cast<const uint8_t*>(serialized_point.data() +
                                                 field_byte_length),
                field_byte_length, y.get()) == nullptr) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error extracting y coordinate: "
           << GetOpensslErrors();
  }
  auto point = openssl_make_unique<EC_POINT>(group);
  if (EC_POINT_set_affine_coordinates_GFp(group, point.get(), x.get(), y.get(),
                                          nullptr) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error setting coordinates: "
           << GetOpensslErrors();
  }
  // Note that this check is not needed in boringssl.
  if (EC_POINT_is_on_curve(group, point.get(), nullptr) != 1) {
    return FailedPreconditionErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Point it not on the curve";
  }
  return std::move(point);
}

StatusOr<std::string> DeserializePointAsPemPublicKey(
    int curve_nid, absl::string_view serialized_point) {
  // serialized_point -> EC_POINT
  openssl_unique_ptr<EC_GROUP> group(EC_GROUP_new_by_curve_name(curve_nid));
  auto status_or_point = DeserializePoint(group.get(), serialized_point);
  if (!status_or_point.ok()) {
    return status_or_point.status();
  }
  openssl_unique_ptr<EC_POINT> point = std::move(status_or_point).ValueOrDie();

  // EC_POINT -> EC_KEY
  openssl_unique_ptr<EC_KEY> key(EC_KEY_new_by_curve_name(curve_nid));
  if (key == nullptr) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error allocating key: " << GetOpensslErrors();
  }
  if (EC_KEY_set_public_key(key.get(), point.get()) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error setting public key: "
           << GetOpensslErrors();
  }

  // EC_KEY -> EC_PKEY
  auto pkey = openssl_make_unique<EVP_PKEY>();
  if (EVP_PKEY_set1_EC_KEY(pkey.get(), key.get()) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error setting ec key: " << GetOpensslErrors();
  }

  // EC_KEY->PEM
  auto bio = openssl_make_unique<BIO>(BIO_s_mem());
  if (PEM_write_bio_PUBKEY(bio.get(), pkey.get()) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error writing bio: " << GetOpensslErrors();
  }

  const uint8_t* pem = nullptr;
  size_t pem_length = 0;
  if (!BIO_mem_contents(bio.get(), &pem, &pem_length) || !pem) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error getting pem: " << GetOpensslErrors();
  }

  return {std::string(reinterpret_cast<const char*>(pem), pem_length)};
}

StatusOr<std::string> SerializePrivateKey(const EC_GROUP* group, const EC_KEY* key) {
  size_t field_byte_length = GroupByteSize(group);
  const BIGNUM* private_key = EC_KEY_get0_private_key(key);
  if (private_key == nullptr) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error obtaining private key: "
           << GetOpensslErrors();
  }
  StringBuffer serialized_key(field_byte_length);
  if (BN_bn2bin_padded(serialized_key.data(), field_byte_length, private_key) !=
      1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error serializing BIGNUM: "
           << GetOpensslErrors();
  }
  return serialized_key.as_string();
}

StatusOr<openssl_unique_ptr<EC_KEY>> DeserializePrivateKey(
    const EC_GROUP* group, absl::string_view serialized) {
  size_t field_byte_length = GroupByteSize(group);
  if (field_byte_length != serialized.size()) {
    return FailedPreconditionErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "serialized private key is " << serialized.size()
           << " bytes, expected " << field_byte_length << " bytes";
  }
  int nid = EC_GROUP_get_curve_name(group);
  if (nid == 0) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "group does not have a curve nid";
  }

  auto bn = openssl_make_unique<BIGNUM>();
  if (BN_bin2bn(reinterpret_cast<const uint8_t*>(serialized.data()),
                field_byte_length, bn.get()) == nullptr) {
    return FailedPreconditionErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error parsing private key: "
           << GetOpensslErrors();
  }

  openssl_unique_ptr<EC_KEY> key(EC_KEY_new_by_curve_name(nid));
  if (EC_KEY_set_private_key(key.get(), bn.get()) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error serializing BIGNUM: "
           << GetOpensslErrors();
  }
  return std::move(key);
}

}  // namespace crunchy
