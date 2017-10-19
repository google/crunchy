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

#include "crunchy/internal/algs/sign/rsa.h"

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/hash/sha256.h"
#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/internal/algs/openssl/openssl_unique_ptr.h"
#include "crunchy/internal/common/pool.h"
#include "crunchy/internal/common/string_buffer.h"
#include "crunchy/util/status.h"
#include <openssl/base.h>
#include <openssl/bn.h>
#include <openssl/digest.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>

namespace crunchy {

namespace {

const size_t kModulusBitLength = 2048;
const int kSha256Nid = NID_sha256;

class RsaPublicPool : public Pool<RSA> {
 public:
  using Pool<RSA>::Pool;

 protected:
  RSA* Clone() override { return RSAPublicKey_dup(GetSeedValue()); }
};

class RsaPrivatePool : public Pool<RSA> {
 public:
  using Pool<RSA>::Pool;

 protected:
  RSA* Clone() override { return RSAPrivateKey_dup(GetSeedValue()); }
};

StatusOr<openssl_unique_ptr<RSA>> DeserializePrivateKey(
    absl::string_view serialized_private_key) {
  openssl_unique_ptr<RSA> rsa(RSA_private_key_from_bytes(
      reinterpret_cast<const uint8_t*>(serialized_private_key.data()),
      serialized_private_key.size()));
  if (rsa == nullptr) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error parsing private key: "
           << GetOpensslErrors();
  }
  return std::move(rsa);
}

StatusOr<openssl_unique_ptr<RSA>> DeserializePublicKey(
    absl::string_view serialized_public_key) {
  openssl_unique_ptr<RSA> rsa(RSA_public_key_from_bytes(
      reinterpret_cast<const uint8_t*>(serialized_public_key.data()),
      serialized_public_key.size()));
  if (rsa == nullptr) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Openssl internal error parsing public key: "
           << GetOpensslErrors();
  }
  return std::move(rsa);
}

class RsaPkcsSigner : public SignerInterface {
 public:
  explicit RsaPkcsSigner(openssl_unique_ptr<RSA> rsa)
      : pool_(absl::make_unique<RsaPrivatePool>(std::move(rsa))) {}

  // Signs the given std::string and returns the signature.
  StatusOr<std::string> Sign(absl::string_view input) const override {
    pool_unique_ptr<RSA> rsa = pool_->get();
    auto status_or = Sha256Hash(input);
    if (!status_or.ok()) {
      return status_or;
    }
    std::string digest = status_or.ValueOrDie();
    StringBuffer signature(RSA_size(rsa.get()));
    unsigned int signature_length;
    if (RSA_sign(kSha256Nid,
                 reinterpret_cast<const unsigned char*>(digest.data()),
                 digest.length(), signature.data(), &signature_length,
                 rsa.get()) == 0) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Call to RSA_sign failed: " << GetOpensslErrors();
    }
    *signature.mutable_limit() = signature_length;
    return std::move(signature.as_string());
  }

 private:
  std::unique_ptr<RsaPrivatePool> pool_;
};

class RsaPkcsVerifier : public VerifierInterface {
 public:
  explicit RsaPkcsVerifier(openssl_unique_ptr<RSA> rsa)
      : pool_(absl::make_unique<RsaPublicPool>(std::move(rsa))) {}

  // Tries to verify the given signature of the input std::string and returns
  // Status::OK if the signature is valid.
  Status Verify(absl::string_view input,
                absl::string_view signature) const override {
    pool_unique_ptr<RSA> rsa = pool_->get();
    auto status_or = Sha256Hash(input);
    if (!status_or.ok()) {
      return status_or.status();
    }
    std::string digest = status_or.ValueOrDie();
    if (RSA_verify(kSha256Nid,
                   reinterpret_cast<const unsigned char*>(digest.data()),
                   digest.length(),
                   reinterpret_cast<const unsigned char*>(signature.data()),
                   signature.size(), rsa.get()) == 0) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Call to RSA_verify failed: " << GetOpensslErrors();
    }
    return OkStatus();
  }

 private:
  std::unique_ptr<RsaPublicPool> pool_;
};

class RsaPssSigner : public SignerInterface {
 public:
  explicit RsaPssSigner(openssl_unique_ptr<RSA> rsa)
      : pool_(absl::make_unique<RsaPrivatePool>(std::move(rsa))) {}

  // Signs the given std::string and returns the signature.
  StatusOr<std::string> Sign(absl::string_view input) const override {
    pool_unique_ptr<RSA> rsa = pool_->get();
    auto status_or = Sha256Hash(input);
    if (!status_or.ok()) {
      return status_or;
    }
    std::string digest = status_or.ValueOrDie();
    StringBuffer signature(RSA_size(rsa.get()));
    if (RSA_sign_pss_mgf1(rsa.get(), signature.mutable_limit(),
                          signature.data(), signature.length(),
                          reinterpret_cast<const uint8_t*>(digest.data()),
                          digest.size(), EVP_sha256(), EVP_sha256(),
                          -1 /* salt_len */) != 1) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Call to RSA_sign_pss_mgf1 failed: " << GetOpensslErrors();
    }
    return std::move(signature.as_string());
  }

 private:
  std::unique_ptr<RsaPrivatePool> pool_;
};

class RsaPssVerifier : public VerifierInterface {
 public:
  explicit RsaPssVerifier(openssl_unique_ptr<RSA> rsa)
      : pool_(absl::make_unique<RsaPublicPool>(std::move(rsa))) {}

  // Tries to verify the given signature of the input std::string and returns
  // Status::OK if the signature is valid.
  Status Verify(absl::string_view input,
                absl::string_view signature) const override {
    pool_unique_ptr<RSA> rsa = pool_->get();
    auto status_or = Sha256Hash(input);
    if (!status_or.ok()) {
      return status_or.status();
    }
    std::string digest = status_or.ValueOrDie();
    if (RSA_verify_pss_mgf1(
            rsa.get(), reinterpret_cast<const uint8_t*>(digest.data()),
            digest.size(), EVP_sha256(), EVP_sha256(), -1 /* salt_len */,
            reinterpret_cast<const uint8_t*>(signature.data()),
            signature.size()) != 1) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Call to RSA_verify_pss_mgf1 failed: " << GetOpensslErrors();
    }
    return OkStatus();
  }

 private:
  std::unique_ptr<RsaPublicPool> pool_;
};

template <class S, class V>
class RsaFactory : public SignerFactory {
 public:
  RsaFactory(int e) : e_(e) {}

  Status NewKeypair(std::string* public_key, std::string* private_key) const override {
    auto rsa = openssl_make_unique<RSA>();
    // Create the rsa key object.
    auto e = openssl_make_unique<BIGNUM>();
    BN_set_word(e.get(), e_);
    RSA_generate_key_ex(rsa.get(), kModulusBitLength, e.get(), nullptr);

    uint8_t* serialized_private_key = nullptr;
    size_t serialized_private_key_length;
    if (RSA_private_key_to_bytes(&serialized_private_key,
                                 &serialized_private_key_length,
                                 rsa.get()) != 1) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl internal error serializing private key: "
             << GetOpensslErrors();
    }
    private_key->assign(reinterpret_cast<char*>(serialized_private_key),
                        serialized_private_key_length);
    OPENSSL_free(serialized_private_key);

    uint8_t* serialized_public_key = nullptr;
    size_t serialized_public_key_length;
    if (RSA_public_key_to_bytes(&serialized_public_key,
                                &serialized_public_key_length,
                                rsa.get()) != 1) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Openssl internal error serializing public key: "
             << GetOpensslErrors();
    }
    public_key->assign(reinterpret_cast<char*>(serialized_public_key),
                       serialized_public_key_length);
    OPENSSL_free(serialized_public_key);

    return OkStatus();
  }

  StatusOr<std::unique_ptr<SignerInterface>> MakeSigner(
      absl::string_view private_key) const override {
    auto status_or_rsa = DeserializePrivateKey(private_key);
    if (!status_or_rsa.ok()) {
      return status_or_rsa.status();
    }
    return {absl::make_unique<S>(std::move(status_or_rsa.ValueOrDie()))};
  }

  StatusOr<std::unique_ptr<VerifierInterface>> MakeVerifier(
      absl::string_view public_key) const override {
    auto status_or_rsa = DeserializePublicKey(public_key);
    if (!status_or_rsa.ok()) {
      return status_or_rsa.status();
    }
    openssl_unique_ptr<RSA> rsa = std::move(status_or_rsa.ValueOrDie());
    return {absl::make_unique<V>(std::move(rsa))};
  }

 private:
  int e_;
};

}  // namespace

const SignerFactory& GetRsa2048PkcsFactory() {
  static const SignerFactory& factory =
      *new RsaFactory<RsaPkcsSigner, RsaPkcsVerifier>(RSA_F4 /* 2^16+1 */);
  return factory;
}

const SignerFactory& GetRsa2048PssFactory() {
  static const SignerFactory& factory =
      *new RsaFactory<RsaPssSigner, RsaPssVerifier>(RSA_F4 /* 2^16+1 */);
  return factory;
}

}  // namespace crunchy
