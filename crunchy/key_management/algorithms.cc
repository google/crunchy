#include "crunchy/key_management/algorithms.h"

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "crunchy/key_management/internal/keyset.pb.h"

namespace crunchy {

namespace {

KeyType* FromString(absl::string_view name) {
  auto type = absl::make_unique<KeyType>();
  *type->mutable_crunchy_label() = std::string(name);
  return type.release();
}

}  // namespace

const KeyType& GetAes128GcmKeyType() {
  static const KeyType& type = *FromString("aes-128-gcm");
  return type;
}

const KeyType& GetAes256GcmKeyType() {
  static const KeyType& type = *FromString("aes-256-gcm");
  return type;
}

const KeyType& GetAes128EaxKeyType() {
  static const KeyType& type = *FromString("aes-128-eax");
  return type;
}

const KeyType& GetAes256EaxKeyType() {
  static const KeyType& type = *FromString("aes-256-eax");
  return type;
}

const KeyType& GetP256Aes128GcmKeyType() {
  static const KeyType& type = *FromString("p128-aes-128-gcm");
  return type;
}

const KeyType& GetP256Aes256GcmKeyType() {
  static const KeyType& type = *FromString("p256-aes-256-gcm");
  return type;
}

const KeyType& GetX25519Aes256GcmKeyType() {
  static const KeyType& type = *FromString("x25519-aes-256-gcm");
  return type;
}

const KeyType& GetHmacSha256HalfDigest() {
  static const KeyType& type = *FromString("hmac-sha256-halfdigest");
  return type;
}

const KeyType& GetP256EcdsaKeyType() {
  static const KeyType& type = *FromString("p256-ecdsa");
  return type;
}

const KeyType& GetP256EcdsaJwtKeyType() {
  static const KeyType& type = *FromString("p256-ecdsa-jwt");
  return type;
}

const KeyType& GetEd25519KeyType() {
  static const KeyType& type = *FromString("ed25519");
  return type;
}

const KeyType& GetRsa2048Pkcs1KeyType() {
  static const KeyType& type = *FromString("rsa2048-pkcs1");
  return type;
}

const KeyType& GetRsa2048PssKeyType() {
  static const KeyType& type = *FromString("rsa2048-pss");
  return type;
}

}  // namespace crunchy
