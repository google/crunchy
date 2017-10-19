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

#include "crunchy/internal/algs/hybrid/openssl_kem.h"

#include <memory>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "crunchy/internal/algs/openssl/ec.h"
#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/internal/common/string_buffer.h"
#include "crunchy/util/status.h"
#include <openssl/base.h>
#include <openssl/ec_key.h>
#include <openssl/ecdh.h>
#include <openssl/nid.h>
#include <openssl/obj.h>
#include <openssl/objects.h>

namespace crunchy {

namespace {

// Returns the least number of bytes required to store the passed number of
// bits.
size_t BitsToBytes(size_t bits) { return (bits + 7) / 8; }

}  // namespace

OpensslKemFactory::OpensslKemFactory(int curve_nid, HkdfFactory* hkdf_factory)
    : curve_nid_(curve_nid),
      group_(EC_GROUP_new_by_curve_name(curve_nid)),
      field_byte_length_(BitsToBytes(EC_GROUP_get_degree(group_))),
      hkdf_factory_(hkdf_factory) {}

Status OpensslKemFactory::NewKeypair(
    std::unique_ptr<KemPublicKey>* public_key,
    std::unique_ptr<KemPrivateKey>* private_key) const {
  if (public_key == nullptr) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "public_key is null";
  }
  if (private_key == nullptr) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "private_key is null";
  }
  openssl_unique_ptr<EC_KEY> openssl_private_key(
      EC_KEY_new_by_curve_name(curve_nid_));
  if (openssl_private_key == nullptr) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error allocating private key: "
           << GetOpensslErrors();
  }
  if (EC_KEY_generate_key(openssl_private_key.get()) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error generating private key: "
           << GetOpensslErrors();
  }

  auto public_key_point = openssl_make_unique<EC_POINT>(group_);
  if (EC_POINT_copy(public_key_point.get(),
                    EC_KEY_get0_public_key(openssl_private_key.get())) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error copying public key: "
           << GetOpensslErrors();
  }

  auto status_or_serialized_public_key = SerializePoint(public_key_point.get());
  if (!status_or_serialized_public_key.ok()) {
    return status_or_serialized_public_key.status();
  }
  const std::string serialized_public_key =
      std::move(status_or_serialized_public_key.ValueOrDie());
  *public_key = absl::make_unique<OpensslKemPublicKey>(
      *this, std::move(public_key_point), serialized_public_key);

  auto status_or_serialized_private_key =
      SerializePrivateKey(openssl_private_key.get());
  if (!status_or_serialized_private_key.ok()) {
    return status_or_serialized_private_key.status();
  }
  const std::string serialized_private_key =
      std::move(status_or_serialized_private_key.ValueOrDie());
  *private_key = absl::make_unique<OpensslKemPrivateKey>(
      *this, std::move(openssl_private_key), serialized_private_key);

  return OkStatus();
}

StatusOr<std::unique_ptr<KemPublicKey>>
OpensslKemFactory::DeserializeKemPublicKey(absl::string_view serialized) const {
  if (serialized.length() != KemPublicKeySerializedSize()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Length of serialized public key [" << serialized.length()
           << "] does not match expected size [" << KemPublicKeySerializedSize()
           << "] for curve " << OBJ_nid2ln(curve_nid_);
  }
  auto status_or_point = DeserializePoint(serialized);
  if (!status_or_point.ok()) {
    return status_or_point.status();
  }
  openssl_unique_ptr<EC_POINT> point = std::move(status_or_point.ValueOrDie());

  return {absl::make_unique<OpensslKemPublicKey>(*this, std::move(point),
                                                 std::string(serialized))};
}

StatusOr<std::unique_ptr<KemPrivateKey>>
OpensslKemFactory::DeserializeKemPrivateKey(
    absl::string_view serialized) const {
  if (serialized.length() != KemPrivateKeySerializedSize()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Length of serialized private key [" << serialized.length()
           << "] does not match expected size ["
           << KemPrivateKeySerializedSize() << "] for curve "
           << OBJ_nid2ln(curve_nid_);
  }
  auto status_or_key = DeserializePrivateKey(serialized);
  if (!status_or_key.ok()) {
    return status_or_key.status();
  }
  openssl_unique_ptr<EC_KEY> key = std::move(status_or_key.ValueOrDie());

  return {absl::make_unique<OpensslKemPrivateKey>(*this, std::move(key),
                                                  std::string(serialized))};
}

size_t OpensslKemFactory::KemPublicTokenSerializedSize() const {
  return field_byte_length_ * 2;
}

size_t OpensslKemFactory::KemPublicKeySerializedSize() const {
  return field_byte_length_ * 2;
}

size_t OpensslKemFactory::KemPrivateKeySerializedSize() const {
  return field_byte_length_;
}

StatusOr<std::string> OpensslKemFactory::ComputeDhAndHkdf(
    const EC_KEY* private_key, const EC_POINT* public_key,
    absl::string_view public_token, absl::string_view info,
    size_t num_bytes) const {
  StringBuffer ecdh_result(field_byte_length_);
  const int ecdh_result_length = ECDH_compute_key(
      ecdh_result.data(), field_byte_length_, public_key, private_key, nullptr);
  if (ecdh_result_length == -1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error computing DH result: "
           << GetOpensslErrors();
  }
  if (ecdh_result_length != field_byte_length_) {
    return FailedPreconditionErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "ECDH result is a different size than expected "
           << (field_byte_length_) << " expected, " << ecdh_result_length
           << " returned by openssl";
  }

  auto status_or_hkdf = CreateHkdf(
      StrCat(public_token, ecdh_result.as_string_view()), "" /* salt */);
  if (!status_or_hkdf.ok()) {
    return status_or_hkdf.status();
  }

  std::unique_ptr<Hkdf> hkdf = std::move(status_or_hkdf.ValueOrDie());
  StringBuffer out_bytes(num_bytes);
  Status status = hkdf->HkdfExpand(info, num_bytes, out_bytes.data());
  if (!status.ok()) {
    return status;
  }
  return std::move(out_bytes.as_string());
}

StatusOr<std::string> OpensslKemFactory::SerializePoint(
    const EC_POINT* point) const {
  return crunchy::SerializePoint(group_, point);
}

StatusOr<openssl_unique_ptr<EC_POINT>> OpensslKemFactory::DeserializePoint(
    absl::string_view serialized_point) const {
  return crunchy::DeserializePoint(group_, serialized_point);
}

StatusOr<std::string> OpensslKemFactory::SerializePrivateKey(
    const EC_KEY* key) const {
  return crunchy::SerializePrivateKey(group_, key);
}

StatusOr<openssl_unique_ptr<EC_KEY>> OpensslKemFactory::DeserializePrivateKey(
    absl::string_view serialized) const {
  return crunchy::DeserializePrivateKey(group_, serialized);
}

Status OpensslKemPublicKey::NewKeyAndToken(size_t num_bytes,
                                           absl::string_view info, std::string* key,
                                           std::string* token) const {
  if (key == nullptr) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo() << "key is null";
  }
  if (token == nullptr) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "token is null";
  }
  openssl_unique_ptr<EC_KEY> openssl_private_key(
      EC_KEY_new_by_curve_name(factory_.curve_nid()));
  if (openssl_private_key == nullptr) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error allocating private key: "
           << GetOpensslErrors();
  }
  if (EC_KEY_generate_key(openssl_private_key.get()) != 1) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error generating private key: "
           << GetOpensslErrors();
  }

  auto status_or_serialized_public_key = factory_.SerializePoint(
      EC_KEY_get0_public_key(openssl_private_key.get()));
  if (!status_or_serialized_public_key.ok()) {
    return status_or_serialized_public_key.status();
  }
  std::string serialized_public_key =
      std::move(status_or_serialized_public_key.ValueOrDie());

  auto status_or_bytes =
      factory_.ComputeDhAndHkdf(openssl_private_key.get(), point_.get(),
                                serialized_public_key, info, num_bytes);
  if (!status_or_bytes.ok()) {
    return status_or_bytes.status();
  }

  *token = std::move(serialized_public_key);
  *key = std::move(status_or_bytes.ValueOrDie());

  return OkStatus();
}

StatusOr<std::string> OpensslKemPrivateKey::DeriveKeyFromToken(
    absl::string_view token, size_t num_bytes, absl::string_view info) const {
  if (token.length() != factory_.KemPublicTokenSerializedSize()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Length of serialized public token ["
           << factory_.KemPublicTokenSerializedSize()
           << "] does not match expected size [" << token.length()
           << "] for curve " << OBJ_nid2ln(factory_.curve_nid());
  }
  auto status_or_public_token = factory_.DeserializePoint(token);
  if (!status_or_public_token.ok()) {
    return status_or_public_token.status();
  }
  openssl_unique_ptr<EC_POINT> public_token =
      std::move(status_or_public_token.ValueOrDie());

  auto status_or_bytes = factory_.ComputeDhAndHkdf(
      key_.get(), public_token.get(), token, info, num_bytes);
  if (!status_or_bytes.ok()) {
    return status_or_bytes.status();
  }
  return std::move(status_or_bytes.ValueOrDie());
}

const KemFactory& GetP256KemFactory() {
  static const KemFactory& factory =
      *new OpensslKemFactory(NID_X9_62_prime256v1, MakeHkdfSha256);
  return factory;
}

const KemFactory& GetP521KemFactory() {
  static const KemFactory& factory =
      *new OpensslKemFactory(NID_secp521r1, MakeHkdfSha512);
  return factory;
}

}  // namespace crunchy
