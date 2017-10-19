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

#include "crunchy/internal/algs/crypt/aes_eax.h"

#include <stddef.h>
#include <string.h>
#include <cstdint>
#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/crypt/crypter_base.h"
#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/internal/algs/openssl/openssl_unique_ptr.h"
#include "crunchy/internal/port/port.h"
#include "crunchy/util/status.h"
#include <openssl/aes.h>
#include <openssl/base.h>
#include <openssl/cipher.h>
#include <openssl/evp.h>

namespace crunchy {

namespace {

const size_t kAes128EaxKeyLength = 16;
const size_t kAes256EaxKeyLength = 32;
const size_t kBlockSize = 16;
// Irreducible polynomial used for 128bit block is
// x^128 + x^7 + x^4 + x^2 + x + 1
// Its representation is 0x87
const uint64_t kReductionTable[] = {0, 0x87};

// Returns the smallest length l >= len s.t. l = a*block_size
size_t GetCeilBlockLen(size_t len, size_t block_size) {
  return ((len + block_size - 1) / block_size) * block_size;
}

void Double(const uint8_t in[kBlockSize], uint8_t out[kBlockSize]) {
  uint64_t in_high = BigEndianLoad64(in);
  uint64_t in_low = BigEndianLoad64(in + 8);
  uint64_t out_high = (in_high << 1) ^ (in[8] >> 7);
  // If the most significant bit is set then the result has to
  // be reduced by x^128 + x^7 + x^4 + x^2 + x + 1.
  // The representation of x^7 + x^4 + x^2 + x + 1 is 0x87.
  uint64_t out_low = (in_low << 1) ^ kReductionTable[in[0] >> 7];
  BigEndianStore64(out, out_high);
  BigEndianStore64(out + 8, out_low);
}

void XorBlock(const uint8_t* x, const uint8_t* y, uint8_t* res) {
  uint64_t x64[2];
  memcpy(&x64, x, sizeof(x64));
  uint64_t y64[2];
  memcpy(&y64, y, sizeof(y64));
  uint64_t res64[2];
  res64[0] = x64[0] ^ y64[0];
  res64[1] = x64[1] ^ y64[1];
  memcpy(res, &res64, sizeof(res64));
}

bool EqualBlocks(const uint8_t x[kBlockSize], const uint8_t y[kBlockSize]) {
  uint64_t x64[2];
  memcpy(&x64, x, sizeof(x64));
  uint64_t y64[2];
  memcpy(&y64, y, sizeof(y64));
  return ((x64[0] ^ y64[0]) | (x64[1] ^ y64[1])) == 0;
}

class EvpCipher {
 public:
  EvpCipher() : encrypt_ctx_(openssl_make_unique<EVP_CIPHER_CTX>()) {}

  Status Init(const EVP_CIPHER* evp_cipher, const uint8_t* key) {
    return Init(evp_cipher, key, nullptr);
  }

  Status Init(const EVP_CIPHER* evp_cipher, const uint8_t* key,
              const uint8_t* nonce) {
    if (!EVP_EncryptInit_ex(encrypt_ctx_.get(), evp_cipher, nullptr, key,
                            nullptr)) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Setting key failed: " << GetOpensslErrors();
    }
    // Disable padding as we are doing exact block encryptions.
    EVP_CIPHER_CTX_set_padding(encrypt_ctx_.get(), 0);
    if (nullptr == nonce) return OkStatus();
    if (!EVP_EncryptInit_ex(encrypt_ctx_.get(), nullptr, nullptr, nullptr,
                            nonce)) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Setting nonce failed: " << GetOpensslErrors();
    }
    return OkStatus();
  }

  inline Status Update(const uint8_t* in, int in_len, uint8_t* out) {
    int out_len = 0;
    if (!EVP_EncryptUpdate(encrypt_ctx_.get(), out, &out_len, in, in_len)) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Encryption failed, " << GetOpensslErrors();
    }
    if (out_len != in_len) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Encrypted output of len: " << out_len
             << "is not of expected length: " << in_len;
    }
    return OkStatus();
  }

  Status UpdateOutNotUsed(const uint8_t* in, size_t in_len) {
    uint8_t scratch[kBlockSize];
    while (in_len >= kBlockSize) {
      Status status = Update(in, kBlockSize, scratch);
      if (!status.ok()) return status;
      in_len -= kBlockSize;
      in += kBlockSize;
    }
    return Update(in, in_len, scratch);
  }

  Status Finalize() {
    uint8_t scratch[kBlockSize];
    int out_len = 0;
    if (!EVP_EncryptFinal_ex(encrypt_ctx_.get(), scratch, &out_len)) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "EVP_Final has failed, " << GetOpensslErrors();
    }
    if (0 != out_len) {
      return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "EVP_Final has produced some output of len: " << out_len;
    }
    return OkStatus();
  }

 private:
  openssl_unique_ptr<EVP_CIPHER_CTX> encrypt_ctx_;
};

class AesEaxCrypter : public CrypterBase {
 public:
  explicit AesEaxCrypter(absl::string_view key)
      : CrypterBase(), key_(new uint8_t[key.size()]) {
    memcpy(key_.get(), key.data(), key.size());
    AES_KEY aes_key;
    int status = AES_set_encrypt_key(key_.get(), key.size() * 8, &aes_key);
    // status != 0 happens if key or aeskey_ is invalid. In both cases this
    // indicates a programming error.
    CRUNCHY_CHECK_EQ(0, status);
    memset(full_block_key_, 0, kBlockSize);
    memset(partial_block_key_, 0, kBlockSize);
    uint8_t block[kBlockSize];
    memset(block, 0, kBlockSize);
    AES_encrypt(block, block, &aes_key);
    Double(block, full_block_key_);
    Double(full_block_key_, partial_block_key_);
  }

  ~AesEaxCrypter() override = default;

  Status Encrypt(const uint8_t* nonce, size_t nonce_length, const uint8_t* aad,
                 size_t aad_length, const uint8_t* plaintext,
                 size_t plaintext_length, uint8_t* ciphertext_and_tag,
                 size_t ciphertext_and_tag_length,
                 size_t* bytes_written) override;

  Status Decrypt(const uint8_t* nonce, size_t nonce_length, const uint8_t* aad,
                 size_t aad_length, const uint8_t* ciphertext_and_tag,
                 size_t ciphertext_and_tag_length, uint8_t* plaintext,
                 size_t plaintext_length, size_t* bytes_written) override;

  size_t nonce_length() const override { return kBlockSize; }
  size_t tag_length() const override { return kBlockSize; }

 protected:
  virtual const EVP_CIPHER* GetCbcCipher() const = 0;
  virtual const EVP_CIPHER* GetCtrCipher() const = 0;

 private:
  Status Omac(const uint8_t* data, size_t len, uint8_t tag,
              uint8_t* mac) const {
    uint8_t in[kBlockSize];
    memset(in, 0, kBlockSize);
    in[kBlockSize - 1] = tag;
    EvpCipher cipher;
    Status status = cipher.Init(GetCbcCipher(), key_.get());
    if (!status.ok()) return status;
    if (len == 0) {
      Pad(in, kBlockSize, in);
      status = cipher.Update(in, kBlockSize, mac);
      if (!status.ok()) {
        memset(mac, 0, kBlockSize);
        return status;
      }
    } else {
      status = cipher.UpdateOutNotUsed(in, kBlockSize);
      if (!status.ok()) return status;
      int len_but_last_block = GetCeilBlockLen(len, kBlockSize) - kBlockSize;
      if (len_but_last_block > 0) {
        status = cipher.UpdateOutNotUsed(data, len_but_last_block);
        if (!status.ok()) return status;
      }
      uint8_t padded_block[kBlockSize];
      Pad(data + len_but_last_block, len - len_but_last_block, padded_block);
      status = cipher.Update(padded_block, kBlockSize, mac);
      if (!status.ok()) {
        memset(mac, 0, kBlockSize);
        return status;
      }
    }
    status = cipher.Finalize();
    if (!status.ok()) {
      memset(mac, 0, kBlockSize);
      return status;
    }
    return OkStatus();
  }

  Status Ctr(const uint8_t* nonce, const uint8_t* plaintext,
             size_t plaintext_length, uint8_t* ciphertext,
             size_t* bytes_written) {
    EvpCipher cipher;
    Status status = cipher.Init(GetCtrCipher(), key_.get(), nonce);
    if (!status.ok()) return status;
    status = cipher.Update(plaintext, plaintext_length, ciphertext);
    if (!status.ok()) {
      memset(ciphertext, 0, plaintext_length);
      return status;
    }
    status = cipher.Finalize();
    if (!status.ok()) {
      memset(ciphertext, 0, plaintext_length);
      return status;
    }
    *bytes_written = plaintext_length;
    return OkStatus();
  }

  void Pad(const uint8_t* data, size_t len,
           uint8_t padded_block[kBlockSize]) const {
    CRUNCHY_CHECK(0 <= len && len <= kBlockSize);
    memset(padded_block + len, 0, kBlockSize - len);
    memmove(padded_block, data, len);
    if (len == kBlockSize) {
      XorBlock(padded_block, full_block_key_, padded_block);
    } else {
      padded_block[len] = 0x80;
      XorBlock(padded_block, partial_block_key_, padded_block);
    }
  }

  std::unique_ptr<uint8_t[]> key_;
  uint8_t full_block_key_[kBlockSize];
  uint8_t partial_block_key_[kBlockSize];
};

class Aes128EaxCrypter : public AesEaxCrypter {
 public:
  explicit Aes128EaxCrypter(absl::string_view key) : AesEaxCrypter(key) {}
  ~Aes128EaxCrypter() override = default;
  const EVP_CIPHER* GetCbcCipher() const override { return EVP_aes_128_cbc(); }
  const EVP_CIPHER* GetCtrCipher() const override { return EVP_aes_128_ctr(); }
};

class Aes256EaxCrypter : public AesEaxCrypter {
 public:
  explicit Aes256EaxCrypter(absl::string_view key) : AesEaxCrypter(key) {}
  ~Aes256EaxCrypter() override = default;
  const EVP_CIPHER* GetCbcCipher() const override { return EVP_aes_256_cbc(); }
  const EVP_CIPHER* GetCtrCipher() const override { return EVP_aes_256_ctr(); }
};

Status AesEaxCrypter::Encrypt(const uint8_t* nonce, size_t nonce_length,
                              const uint8_t* aad, size_t aad_length,
                              const uint8_t* plaintext, size_t plaintext_length,
                              uint8_t* ciphertext_and_tag,
                              size_t ciphertext_and_tag_length,
                              size_t* bytes_written) {
  Status status = CheckEncryptInput(
      nonce, nonce_length, aad, aad_length, plaintext, plaintext_length,
      ciphertext_and_tag, ciphertext_and_tag_length, bytes_written);
  if (!status.ok()) return status;
  *bytes_written = 0;
  size_t bytes_written_local = 0;
  uint8_t n[kBlockSize];
  status = Omac(nonce, nonce_length, 0, n);
  if (!status.ok()) return status;
  uint8_t h[kBlockSize];
  status = Omac(aad, aad_length, 1, h);
  if (!status.ok()) return status;

  status = Ctr(n, plaintext, plaintext_length, ciphertext_and_tag,
               &bytes_written_local);
  if (!status.ok()) return status;
  uint8_t c[kBlockSize];
  status = Omac(ciphertext_and_tag, bytes_written_local, 2, c);
  if (!status.ok()) return status;
  XorBlock(c, n, c);
  XorBlock(c, h, c);
  memcpy(ciphertext_and_tag + bytes_written_local, c, kBlockSize);
  *bytes_written = bytes_written_local + kBlockSize;
  return OkStatus();
}

Status AesEaxCrypter::Decrypt(const uint8_t* nonce, size_t nonce_length,
                              const uint8_t* aad, size_t aad_length,
                              const uint8_t* ciphertext_and_tag,
                              size_t ciphertext_and_tag_length,
                              uint8_t* plaintext, size_t plaintext_length,
                              size_t* bytes_written) {
  Status status = CheckDecryptInput(
      nonce, nonce_length, aad, aad_length, plaintext, plaintext_length,
      ciphertext_and_tag, ciphertext_and_tag_length, bytes_written);
  if (!status.ok()) return status;
  if (nullptr != bytes_written) {
    *bytes_written = 0;
  }
  uint8_t n[kBlockSize];
  status = Omac(nonce, nonce_length, 0, n);
  if (!status.ok()) return status;
  uint8_t h[kBlockSize];
  status = Omac(aad, aad_length, 1, h);
  if (!status.ok()) return status;
  uint8_t c[kBlockSize];
  status =
      Omac(ciphertext_and_tag, ciphertext_and_tag_length - kBlockSize, 2, c);
  if (!status.ok()) return status;
  uint8_t t[kBlockSize];
  XorBlock(n, c, t);
  XorBlock(t, h, t);
  if (!EqualBlocks(
          ciphertext_and_tag + (ciphertext_and_tag_length - kBlockSize), t)) {
    memset(plaintext, 0x00, plaintext_length);
    return FailedPreconditionErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Checking tag failed.";
  }
  size_t bytes_written_local = 0;
  status = Ctr(n, ciphertext_and_tag, ciphertext_and_tag_length - kBlockSize,
               plaintext, &bytes_written_local);
  if (!status.ok()) return status;
  if (nullptr != bytes_written) {
    *bytes_written = bytes_written_local;
  }
  return OkStatus();
}

class Aes128AexFactory : public CrypterFactory {
 public:
  size_t GetKeyLength() const override { return kAes128EaxKeyLength; }
  size_t GetNonceLength() const override { return kBlockSize; }
  size_t GetTagLength() const override { return kBlockSize; }

  StatusOr<std::unique_ptr<CrypterInterface>> Make(
      absl::string_view key) const override {
    if (key.size() != GetKeyLength()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Key length was " << key.size() << " expected "
             << GetKeyLength();
    }
    return {absl::make_unique<Aes128EaxCrypter>(key)};
  }
};

class Aes256AexFactory : public CrypterFactory {
 public:
  size_t GetKeyLength() const override { return kAes256EaxKeyLength; }
  size_t GetNonceLength() const override { return kBlockSize; }
  size_t GetTagLength() const override { return kBlockSize; }

  StatusOr<std::unique_ptr<CrypterInterface>> Make(
      absl::string_view key) const override {
    if (key.size() != GetKeyLength()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Key length was " << key.size() << " expected "
             << GetKeyLength();
    }
    return {absl::make_unique<Aes256EaxCrypter>(key)};
  }
};

}  // namespace

const CrypterFactory& GetAes128EaxFactory() {
  static const CrypterFactory& factory = *new Aes128AexFactory();
  return factory;
}

const CrypterFactory& GetAes256EaxFactory() {
  static const CrypterFactory& factory = *new Aes256AexFactory();
  return factory;
}

}  // namespace crunchy
