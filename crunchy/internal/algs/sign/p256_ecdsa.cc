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

#include "crunchy/internal/algs/sign/p256_ecdsa.h"

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/hash/sha256.h"
#include "crunchy/internal/algs/openssl/ec.h"
#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/internal/algs/openssl/openssl_unique_ptr.h"
#include "crunchy/internal/common/string_buffer.h"
#include "crunchy/util/status.h"
#include <openssl/base.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

namespace crunchy {

namespace {

const size_t kFieldSize = 32;

const int kCurveNid = NID_X9_62_prime256v1;
const EC_GROUP* group() {
  static const EC_GROUP* group = EC_GROUP_new_by_curve_name(kCurveNid);
  return group;
}

// Wrappers around point/key serialization methods, fixing out group.
StatusOr<std::string> SerializePoint(const EC_POINT* point) {
  return crunchy::SerializePoint(group(), point);
}
StatusOr<openssl_unique_ptr<EC_POINT>> DeserializePoint(
    absl::string_view serialized_point) {
  return crunchy::DeserializePoint(group(), serialized_point);
}
StatusOr<std::string> SerializePrivateKey(const EC_KEY* key) {
  return crunchy::SerializePrivateKey(group(), key);
}
StatusOr<openssl_unique_ptr<EC_KEY>> DeserializePrivateKey(
    absl::string_view serialized) {
  return crunchy::DeserializePrivateKey(group(), serialized);
}

class P256Signer : public SignerInterface {
 public:
  explicit P256Signer(openssl_unique_ptr<EC_KEY> key) : key_(std::move(key)) {}

  // Signs a payload without any hashing. Returning an openssl signature.
  StatusOr<openssl_unique_ptr<ECDSA_SIG>> SignRaw(
      absl::string_view digest) const {
    openssl_unique_ptr<ECDSA_SIG> sig(
        ECDSA_do_sign(reinterpret_cast<const uint8_t*>(digest.data()),
                      digest.size(), key_.get()));
    if (sig == nullptr) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl internal error signing digest: " << GetOpensslErrors();
    }
    return std::move(sig);
  }

 private:
  openssl_unique_ptr<EC_KEY> key_;
};

class P256Verifier : public VerifierInterface {
 public:
  explicit P256Verifier(openssl_unique_ptr<EC_KEY> key)
      : key_(std::move(key)) {}

  Status RawVerify(absl::string_view digest, const ECDSA_SIG* sig) const {
    if (ECDSA_do_verify(reinterpret_cast<const uint8_t*>(digest.data()),
                        digest.size(), sig, key_.get()) != 1) {
      if (!crunchy::HasOpensslErrors()) {
        return FailedPreconditionErrorBuilder(CRUNCHY_LOC).VLog(2)
               << "Invalid signature";
      }
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl error verifying signature: " << GetOpensslErrors();
    }

    return OkStatus();
  }

 private:
  openssl_unique_ptr<EC_KEY> key_;
};

template <class S, class V>
class P256EcdsaFactory : public SignerFactory {
 public:
  // Returns a public/private keypair
  Status NewKeypair(std::string* public_key, std::string* private_key) const override {
    openssl_unique_ptr<EC_KEY> openssl_private_key(
        EC_KEY_new_by_curve_name(kCurveNid));
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

    auto public_key_point = openssl_make_unique<EC_POINT>(group());
    if (EC_POINT_copy(public_key_point.get(),
                      EC_KEY_get0_public_key(openssl_private_key.get())) != 1) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl internal error copying public key: "
             << GetOpensslErrors();
    }

    auto status_or_serialized_public_key =
        SerializePoint(public_key_point.get());
    if (!status_or_serialized_public_key.ok()) {
      return status_or_serialized_public_key.status();
    }
    *public_key = std::move(status_or_serialized_public_key.ValueOrDie());

    auto status_or_serialized_private_key =
        SerializePrivateKey(openssl_private_key.get());
    if (!status_or_serialized_private_key.ok()) {
      return status_or_serialized_private_key.status();
    }
    *private_key = std::move(status_or_serialized_private_key.ValueOrDie());
    return OkStatus();
  }

  // Returns a SignerInterface from a serialized private key.
  // The private key is a 32-byte big-endian exponent.
  StatusOr<std::unique_ptr<SignerInterface>> MakeSigner(
      absl::string_view private_key) const override {
    auto status_or_key = DeserializePrivateKey(private_key);
    if (!status_or_key.ok()) {
      return status_or_key.status();
    }
    openssl_unique_ptr<EC_KEY> key = std::move(status_or_key.ValueOrDie());
    return {absl::make_unique<S>(std::move(key))};
  }

  // Returns a VerifierInterface from a serialized public key.
  // The public key is formatted as the 32-byte x coordinate followed by the
  // 32-byte y coordinate, both big-endian.
  StatusOr<std::unique_ptr<VerifierInterface>> MakeVerifier(
      absl::string_view public_key) const override {
    auto status_or_point = DeserializePoint(public_key);
    if (!status_or_point.ok()) {
      return status_or_point.status();
    }
    openssl_unique_ptr<EC_POINT> point =
        std::move(status_or_point.ValueOrDie());
    openssl_unique_ptr<EC_KEY> key(EC_KEY_new_by_curve_name(kCurveNid));
    if (key == nullptr) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl internal error allocating key: " << GetOpensslErrors();
    }
    if (EC_KEY_set_public_key(key.get(), point.get()) != 1) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl internal error setting public key: "
             << GetOpensslErrors();
    }

    return {absl::make_unique<V>(std::move(key))};
  }
};

class Asn1P256Signer : public P256Signer {
 public:
  explicit Asn1P256Signer(openssl_unique_ptr<EC_KEY> key)
      : P256Signer(std::move(key)) {}

  StatusOr<std::string> Sign(absl::string_view input) const override {
    auto status_or = Sha256Hash(input);
    if (!status_or.ok()) {
      return status_or;
    }
    auto status_or_sig = SignRaw(status_or.ValueOrDie());
    if (!status_or_sig.ok()) {
      return status_or_sig.status();
    }
    openssl_unique_ptr<ECDSA_SIG> sig = std::move(status_or_sig.ValueOrDie());
    uint8_t* sig_bytes = nullptr;
    size_t sig_bytes_length = 0;
    if (ECDSA_SIG_to_bytes(&sig_bytes, &sig_bytes_length, sig.get()) != 1) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl failed to generate signature: "
             << crunchy::GetOpensslErrors();
    }

    std::string result(reinterpret_cast<char*>(sig_bytes), sig_bytes_length);
    OPENSSL_free(sig_bytes);
    return std::move(result);
  }
};

class Asn1P256Verifier : public P256Verifier {
 public:
  explicit Asn1P256Verifier(openssl_unique_ptr<EC_KEY> key)
      : P256Verifier(std::move(key)) {}

  Status Verify(absl::string_view input,
                absl::string_view signature) const override {
    openssl_unique_ptr<ECDSA_SIG> sig(ECDSA_SIG_from_bytes(
        reinterpret_cast<const uint8_t*>(signature.data()), signature.size()));

    if (sig == nullptr) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl couldn't parse signature: " << GetOpensslErrors();
    }

    auto status_or = Sha256Hash(input);
    if (!status_or.ok()) {
      return status_or.status();
    }
    return RawVerify(status_or.ValueOrDie(), sig.get());
  }
};

class JwtP256Signer : public P256Signer {
 public:
  explicit JwtP256Signer(openssl_unique_ptr<EC_KEY> key)
      : P256Signer(std::move(key)) {}

  StatusOr<std::string> Sign(absl::string_view input) const override {
    auto status_or = Sha256Hash(input);
    if (!status_or.ok()) {
      return status_or;
    }
    auto status_or_sig = SignRaw(status_or.ValueOrDie());
    if (!status_or_sig.ok()) {
      return status_or_sig.status();
    }
    openssl_unique_ptr<ECDSA_SIG> sig = std::move(status_or_sig.ValueOrDie());

    StringBuffer serialized_point(kFieldSize * 2);
    if (BN_bn2bin_padded(serialized_point.data(), kFieldSize, sig->r) != 1) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl internal error serializing BIGNUM: "
             << GetOpensslErrors();
    }
    if (BN_bn2bin_padded(serialized_point.data() + kFieldSize, kFieldSize,
                         sig->s) != 1) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl internal error serializing BIGNUM: "
             << GetOpensslErrors();
    }
    return serialized_point.as_string();
  }
};

class JwtP256Verifier : public P256Verifier {
 public:
  explicit JwtP256Verifier(openssl_unique_ptr<EC_KEY> key)
      : P256Verifier(std::move(key)) {}

  Status Verify(absl::string_view input,
                absl::string_view signature) const override {
    auto r = openssl_make_unique<BIGNUM>();
    auto s = openssl_make_unique<BIGNUM>();
    if (BN_bin2bn(reinterpret_cast<const uint8_t*>(signature.data()),
                  kFieldSize, r.get()) == nullptr) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl internal error extracting x coordinate: "
             << GetOpensslErrors();
    }
    if (BN_bin2bn(
            reinterpret_cast<const uint8_t*>(signature.data() + kFieldSize),
            kFieldSize, s.get()) == nullptr) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl internal error extracting y coordinate: "
             << GetOpensslErrors();
    }
    ECDSA_SIG sig{r.get(), s.get()};
    auto status_or = Sha256Hash(input);
    if (!status_or.ok()) {
      return status_or.status();
    }
    return RawVerify(status_or.ValueOrDie(), &sig);
  }
};

}  // namespace

const SignerFactory& GetP256EcdsaAsn1Factory() {
  static const SignerFactory& factory =
      *new P256EcdsaFactory<Asn1P256Signer, Asn1P256Verifier>();
  return factory;
}

const SignerFactory& GetP256EcdsaJwtFactory() {
  static const SignerFactory& factory =
      *new P256EcdsaFactory<JwtP256Signer, JwtP256Verifier>();
  return factory;
}

}  // namespace crunchy
