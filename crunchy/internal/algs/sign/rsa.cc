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
#include "crunchy/internal/algs/hash/sha384.h"
#include "crunchy/internal/algs/hash/sha512.h"
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

StatusOr<std::string> HashInput(PaddingAlgorithm alg, const Hasher& hash,
                           absl::string_view input, const BIGNUM* n) {
  switch (alg) {
    case PaddingAlgorithm::PKCS1:
    case PaddingAlgorithm::PSS:
      return hash.Hash(input);
    default:
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Invalid Padding Algorithm.";
  }
}

class RsaSigner : public SignerInterface {
 public:
  RsaSigner(PaddingAlgorithm alg, openssl_unique_ptr<RSA> rsa, bool hash_input,
            const Hasher& hash)
      : hash_input_(hash_input),
        hash_(hash),
        alg_(alg),
        pool_(absl::make_unique<RsaPrivatePool>(std::move(rsa))) {}

  // Signs the given std::string and returns the signature.
  StatusOr<std::string> Sign(absl::string_view input) const override {
    pool_unique_ptr<RSA> rsa = pool_->get();

    std::string digest(input);
    if (hash_input_) {
      StatusOr<std::string> status_or = HashInput(alg_, hash_, input, rsa->n);
      if (!status_or.ok()) {
        return status_or;
      }
      digest = status_or.ValueOrDie();
    }

    StringBuffer signature(RSA_size(rsa.get()));
    switch (alg_) {
      case PaddingAlgorithm::PKCS1: {
        StatusOr<int> nid = hash_.OpensslNameId();
        if (!nid.ok()) {
          return nid.status();
        }
        unsigned int signature_length;
        if (RSA_sign(nid.ValueOrDie(),
                     reinterpret_cast<const unsigned char*>(digest.data()),
                     digest.length(), signature.data(), &signature_length,
                     rsa.get()) == 0) {
          return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
                 << "Call to RSA_sign failed: " << GetOpensslErrors();
        }
        *signature.mutable_limit() = signature_length;
        break;
      }
      case PaddingAlgorithm::PSS: {
        StatusOr<const EVP_MD*> md = hash_.OpensslMessageDigest();
        if (!md.ok()) {
          return md.status();
        }
        if (RSA_sign_pss_mgf1(rsa.get(), signature.mutable_limit(),
                              signature.data(), signature.length(),
                              reinterpret_cast<const uint8_t*>(digest.data()),
                              digest.size(), md.ValueOrDie(), md.ValueOrDie(),
                              -1 /* salt_len */) != 1) {
          return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
                 << "Call to RSA_sign_pss_mgf1 failed: " << GetOpensslErrors();
        }
        break;
      }
    }

    return std::move(signature.as_string());
  }

 private:
  bool hash_input_;
  const Hasher& hash_;
  PaddingAlgorithm alg_;
  std::unique_ptr<RsaPrivatePool> pool_;
};

class RsaVerifier : public VerifierInterface {
 public:
  explicit RsaVerifier(PaddingAlgorithm alg, openssl_unique_ptr<RSA> rsa,
                       bool hash_input, const Hasher& hash)
      : hash_input_(hash_input),
        hash_(hash),
        alg_(alg),
        pool_(absl::make_unique<RsaPublicPool>(std::move(rsa))) {}

  // Tries to verify the given signature of the input std::string and returns
  // Status::OK if the signature is valid.
  Status Verify(absl::string_view input,
                absl::string_view signature) const override {
    pool_unique_ptr<RSA> rsa = pool_->get();

    std::string digest = std::string(input);
    if (hash_input_) {
      StatusOr<std::string> status_or = HashInput(alg_, hash_, input, rsa.get()->n);
      if (!status_or.ok()) {
        return status_or.status();
      }
      digest = status_or.ValueOrDie();
    }

    switch (alg_) {
      case PaddingAlgorithm::PKCS1: {
        auto nid = hash_.OpensslNameId();
        if (!nid.ok()) {
          return nid.status();
        }
        if (RSA_verify(nid.ValueOrDie(),
                       reinterpret_cast<const unsigned char*>(digest.data()),
                       digest.length(),
                       reinterpret_cast<const unsigned char*>(signature.data()),
                       signature.size(), rsa.get()) == 0) {
          return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
                 << "Call to RSA_verify failed: " << GetOpensslErrors();
        }
        break;
      }
      case PaddingAlgorithm::PSS: {
        auto md = hash_.OpensslMessageDigest();
        if (!md.ok()) {
          return md.status();
        }
        if (RSA_verify_pss_mgf1(
                rsa.get(), reinterpret_cast<const uint8_t*>(digest.data()),
                digest.size(), md.ValueOrDie(), md.ValueOrDie(),
                -1 /* salt_len */,
                reinterpret_cast<const uint8_t*>(signature.data()),
                signature.size()) != 1) {
          return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
                 << "Call to RSA_verify_pss_mgf1 failed: "
                 << GetOpensslErrors();
        }
        break;
      }
    }

    return OkStatus();
  }

 private:
  bool hash_input_;
  const Hasher& hash_;
  PaddingAlgorithm alg_;
  std::unique_ptr<RsaPublicPool> pool_;
};

class RsaFactory : public SignerFactory {
 public:
  RsaFactory(SignModulusBitLength modulus_length, PaddingAlgorithm alg, int e,
             bool hash_input, const Hasher& hash)
      : hash_input_(hash_input),
        hash_(hash),
        e_(e),
        modulus_length_(static_cast<int>(modulus_length)),
        alg_(alg) {}

  Status NewKeypair(std::string* public_key, std::string* private_key) const override {
    auto rsa = openssl_make_unique<RSA>();
    // Create the rsa key object.
    auto e = openssl_make_unique<BIGNUM>();
    BN_set_word(e.get(), e_);
    if (RSA_generate_key_ex(rsa.get(), modulus_length_, e.get(), nullptr) !=
        1) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Error generating private key: "
             << GetOpensslErrors();
    }

    auto status_or_serialized_private_key = SerializePrivateKey(rsa.get());
    if (!status_or_serialized_private_key.ok()) {
      return status_or_serialized_private_key.status();
    }
    *private_key = std::move(status_or_serialized_private_key).ValueOrDie();

    auto status_or_serialized_public_key = SerializePublicKey(rsa.get());
    if (!status_or_serialized_public_key.ok()) {
      return status_or_serialized_public_key.status();
    }
    *public_key = std::move(status_or_serialized_public_key).ValueOrDie();

    return OkStatus();
  }

  virtual bool IsValidModulus(const RSA* rsa) const {
    return RSA_size(rsa) * 8 == modulus_length_;
  }

  StatusOr<std::unique_ptr<SignerInterface>> MakeSigner(
      absl::string_view private_key) const override {
    auto status_or_rsa = DeserializePrivateKey(private_key);
    if (!status_or_rsa.ok()) {
      return status_or_rsa.status();
    }
    openssl_unique_ptr<RSA> rsa = std::move(status_or_rsa).ValueOrDie();
    if (!IsValidModulus(rsa.get())) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << (RSA_size(rsa.get()) * 8) << "-bit modulus given, "
             << modulus_length_ << "-bit modulus expected.";
    }
    return {
        absl::make_unique<RsaSigner>(alg_, std::move(rsa), hash_input_, hash_)};
  }

  StatusOr<std::unique_ptr<VerifierInterface>> MakeVerifier(
      absl::string_view public_key) const override {
    auto status_or_rsa = DeserializePublicKey(public_key);
    if (!status_or_rsa.ok()) {
      return status_or_rsa.status();
    }
    openssl_unique_ptr<RSA> rsa = std::move(status_or_rsa).ValueOrDie();
    if (!IsValidModulus(rsa.get())) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << (RSA_size(rsa.get()) * 8) << "-bit modulus given, "
             << modulus_length_ << "-bit modulus expected.";
    }
    return {absl::make_unique<RsaVerifier>(alg_, std::move(rsa), hash_input_,
                                           hash_)};
  }

 private:
  bool hash_input_;
  const Hasher& hash_;
  int e_;
  size_t modulus_length_;
  PaddingAlgorithm alg_;
};

// An implementation of RsaFactory that skips modulus size checks.
class RsaFactoryNoChecks : public RsaFactory {
  using RsaFactory::RsaFactory;
  bool IsValidModulus(const RSA* /* rsa */) const override { return true; }
};

}  // namespace

std::unique_ptr<SignerFactory> MakeRsaFactory(
    SignModulusBitLength modulus_length, PaddingAlgorithm alg, int e,
    const Hasher& hash) {
  return absl::make_unique<RsaFactory>(modulus_length, alg, e,
                                       /* hash_input= */ true, hash);
}

std::unique_ptr<SignerFactory> MakeRsaFactoryNoChecks(
    SignModulusBitLength modulus_length, PaddingAlgorithm alg, int e,
    const Hasher& hash) {
  return absl::make_unique<RsaFactoryNoChecks>(modulus_length, alg, e,
                                               /* hash_input= */ true, hash);
}

std::unique_ptr<SignerFactory> MakeRsaFactoryWithHashedInput(
    SignModulusBitLength modulus_length, PaddingAlgorithm alg, int e,
    const Hasher& hash) {
  return absl::make_unique<RsaFactory>(modulus_length, alg, e,
                                       /* hash_input= */ false, hash);
}

const SignerFactory& GetRsa2048PkcsFactory() {
  static const SignerFactory& factory =
      *MakeRsaFactory(SignModulusBitLength::B2048, PaddingAlgorithm::PKCS1,
                      RSA_F4 /* 2^16+1 */, Sha256::Instance())
           .release();
  return factory;
}

const SignerFactory& GetRsa2048PssFactory() {
  static const SignerFactory& factory =
      *MakeRsaFactory(SignModulusBitLength::B2048, PaddingAlgorithm::PSS,
                      RSA_F4 /* 2^16+1 */, Sha256::Instance())
           .release();
  return factory;
}
}  // namespace crunchy
