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

#include "crunchy/internal/algs/sign/ecdsa.h"

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/openssl/ec.h"
#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/internal/algs/openssl/openssl_unique_ptr.h"
#include "crunchy/internal/common/string_buffer.h"
#include "crunchy/internal/port/port.h"
#include "crunchy/util/status.h"
#include <openssl/base.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/mem.h>

namespace crunchy {

namespace {

int NidForCurve(Curve c) {
  switch (c) {
    case Curve::P256:
      return NID_X9_62_prime256v1;
    case Curve::P384:
      return NID_secp384r1;
    case Curve::P521:
      return NID_secp521r1;
  }
  return -1;
}

size_t JwtFieldSize(Curve c) {
  // From: https://tools.ietf.org/html/rfc4754#section-7
  switch (c) {
    case Curve::P256:
      return 32;
    case Curve::P384:
      return 48;
    case Curve::P521:
      return 66;
  }
  return 0;
}

class EcdsaSigner : public SignerInterface {
 public:
  explicit EcdsaSigner(Curve curve, openssl_unique_ptr<EC_KEY> key,
                       const Hasher& hash_algorithm,
                       SignatureFormat signature_format)
      : curve_(curve),
        key_(std::move(key)),
        hash_algorithm_(hash_algorithm),
        signature_format_(signature_format) {}

  StatusOr<std::string> Sign(absl::string_view input) const override {
    auto status_or_digest = hash_algorithm_.Hash(input);
    if (!status_or_digest.ok()) {
      return status_or_digest.status();
    }
    std::string digest = status_or_digest.ValueOrDie();

    openssl_unique_ptr<ECDSA_SIG> sig(
        ECDSA_do_sign(reinterpret_cast<const uint8_t*>(digest.data()),
                      digest.size(), key_.get()));
    if (sig == nullptr) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl internal error signing digest: " << GetOpensslErrors();
    }

    switch (signature_format_) {
      case SignatureFormat::ASN1: {
        uint8_t* sig_bytes = nullptr;
        size_t sig_bytes_length = 0;
        if (ECDSA_SIG_to_bytes(&sig_bytes, &sig_bytes_length, sig.get()) != 1) {
          return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
                 << "Openssl failed to generate signature: "
                 << GetOpensslErrors();
        }

        std::string result(reinterpret_cast<char*>(sig_bytes), sig_bytes_length);
        OPENSSL_free(sig_bytes);
        return result;
      }
      case SignatureFormat::JWT: {
        size_t field_size = JwtFieldSize(curve_);
        StringBuffer serialized_point(field_size * 2);
        if (BN_bn2bin_padded(serialized_point.data(), field_size, sig->r) !=
            1) {
          return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
                 << "Openssl internal error serializing BIGNUM: "
                 << GetOpensslErrors();
        }
        if (BN_bn2bin_padded(serialized_point.data() + field_size, field_size,
                             sig->s) != 1) {
          return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
                 << "Openssl internal error serializing BIGNUM: "
                 << GetOpensslErrors();
        }
        return serialized_point.as_string();
      }
    }
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo() <<
        "Sign internal error: Unknown signature format.";
  }

 private:
  Curve curve_;
  openssl_unique_ptr<EC_KEY> key_;
  const Hasher& hash_algorithm_;
  SignatureFormat signature_format_;
};

class EcdsaVerifier : public VerifierInterface {
 public:
  explicit EcdsaVerifier(Curve curve, openssl_unique_ptr<EC_KEY> key,
                         const Hasher& hash_algorithm,
                         SignatureFormat signature_format)
      : curve_(curve),
        key_(std::move(key)),
        hash_algorithm_(hash_algorithm),
        signature_format_(signature_format) {}

  Status Verify(absl::string_view input,
                absl::string_view signature) const override {
    auto status_or_digest = hash_algorithm_.Hash(input);
    if (!status_or_digest.ok()) {
      return status_or_digest.status();
    }
    std::string digest = status_or_digest.ValueOrDie();

    openssl_unique_ptr<ECDSA_SIG> sig;
    switch (signature_format_) {
      case SignatureFormat::ASN1: {
        sig.reset(ECDSA_SIG_from_bytes(
            reinterpret_cast<const uint8_t*>(signature.data()),
            signature.size()));
        if (sig == nullptr) {
          return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
                 << "Openssl couldn't parse signature: " << GetOpensslErrors();
        }
        break;
      }
      case SignatureFormat::JWT: {
        sig.reset(ECDSA_SIG_new());
        size_t field_size = JwtFieldSize(curve_);
        if (BN_bin2bn(reinterpret_cast<const uint8_t*>(signature.data()),
                      field_size, sig->r) == nullptr) {
          return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
                 << "Openssl internal error extracting x coordinate: "
                 << GetOpensslErrors();
        }
        if (BN_bin2bn(
                reinterpret_cast<const uint8_t*>(signature.data() + field_size),
                field_size, sig->s) == nullptr) {
          return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
                 << "Openssl internal error extracting y coordinate: "
                 << GetOpensslErrors();
        }
        break;
      }
    }

    if (ECDSA_do_verify(reinterpret_cast<const uint8_t*>(digest.data()),
                        digest.size(), sig.get(), key_.get()) != 1) {
      if (!HasOpensslErrors()) {
        return FailedPreconditionErrorBuilder(CRUNCHY_LOC).VLog(2)
               << "Invalid signature";
      }
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl error verifying signature: " << GetOpensslErrors();
    }
    return OkStatus();
  }

 private:
  Curve curve_;
  openssl_unique_ptr<EC_KEY> key_;
  const Hasher& hash_algorithm_;
  SignatureFormat signature_format_;
};

class EcdsaFactory : public SignerFactory {
 public:
  EcdsaFactory(Curve curve, const Hasher& hash_algorithm,
               SignatureFormat signature_format)
      : curve_(curve),
        hash_algorithm_(hash_algorithm),
        signature_format_(signature_format) {}

  Status NewKeypair(std::string* public_key, std::string* private_key) const override {
    openssl_unique_ptr<EC_KEY> openssl_private_key(
        EC_KEY_new_by_curve_name(NidForCurve(curve_)));
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

    openssl_unique_ptr<EC_GROUP> group(
        EC_GROUP_new_by_curve_name(NidForCurve(curve_)));

    auto public_key_point = openssl_make_unique<EC_POINT>(group.get());
    if (EC_POINT_copy(public_key_point.get(),
                      EC_KEY_get0_public_key(openssl_private_key.get())) != 1) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl internal error copying public key: "
             << GetOpensslErrors();
    }

    auto status_or_serialized_public_key =
        SerializePoint(group.get(), public_key_point.get());
    if (!status_or_serialized_public_key.ok()) {
      return status_or_serialized_public_key.status();
    }
    *public_key = std::move(status_or_serialized_public_key.ValueOrDie());

    auto status_or_serialized_private_key =
        SerializePrivateKey(group.get(), openssl_private_key.get());
    if (!status_or_serialized_private_key.ok()) {
      return status_or_serialized_private_key.status();
    }
    *private_key = std::move(status_or_serialized_private_key.ValueOrDie());

    return OkStatus();
  }

  StatusOr<std::unique_ptr<SignerInterface>> MakeSigner(
      absl::string_view private_key) const override {
    openssl_unique_ptr<EC_GROUP> group(
        EC_GROUP_new_by_curve_name(NidForCurve(curve_)));
    auto status_or_key = DeserializePrivateKey(group.get(), private_key);
    if (!status_or_key.ok()) {
      return status_or_key.status();
    }
    return {absl::make_unique<EcdsaSigner>(
        curve_, std::move(status_or_key.ValueOrDie()), hash_algorithm_,
        signature_format_)};
  }

  StatusOr<std::unique_ptr<VerifierInterface>> MakeVerifier(
      absl::string_view public_key) const override {
    openssl_unique_ptr<EC_GROUP> group(
        EC_GROUP_new_by_curve_name(NidForCurve(curve_)));
    auto status_or_point = DeserializePoint(group.get(), public_key);
    if (!status_or_point.ok()) {
      return status_or_point.status();
    }
    openssl_unique_ptr<EC_KEY> key(
        EC_KEY_new_by_curve_name(NidForCurve(curve_)));
    if (key == nullptr) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl internal error allocating key: " << GetOpensslErrors();
    }
    openssl_unique_ptr<EC_POINT> point =
        std::move(status_or_point.ValueOrDie());
    if (EC_KEY_set_public_key(key.get(), point.get()) != 1) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl internal error setting public key: "
             << GetOpensslErrors();
    }
    return {absl::make_unique<EcdsaVerifier>(
        curve_, std::move(key), hash_algorithm_, signature_format_)};
  }

 private:
  Curve curve_;
  const Hasher& hash_algorithm_;
  SignatureFormat signature_format_;
};

}  // namespace

std::unique_ptr<SignerFactory> MakeEcdsaFactory(
    Curve curve, const Hasher& hash, SignatureFormat signature_format) {
  return absl::make_unique<EcdsaFactory>(curve, hash, signature_format);
}

}  // namespace crunchy
