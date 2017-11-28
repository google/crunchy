#ifndef CRUNCHY_KEY_MANAGEMENT_ALGORITHMS_H_
#define CRUNCHY_KEY_MANAGEMENT_ALGORITHMS_H_

#include <string>

namespace crunchy {

class KeyType;

// Symmetric encryption (AEADs)
const KeyType& GetAes128GcmKeyType();
const KeyType& GetAes256GcmKeyType();
const KeyType& GetAes128EaxKeyType();
const KeyType& GetAes256EaxKeyType();

// Asymmetric encryption (Hybrid Encryption)
const KeyType& GetP256Aes128GcmKeyType();
const KeyType& GetP256Aes256GcmKeyType();
const KeyType& GetX25519Aes256GcmKeyType();

// Symmetric signing (MACs)
const KeyType& GetHmacSha256HalfDigest();

// Asymmetric signing (Digital Signatures)
const KeyType& GetP256EcdsaKeyType();
const KeyType& GetP256EcdsaJwtKeyType();
const KeyType& GetEd25519KeyType();
const KeyType& GetRsa2048Pkcs1KeyType();
const KeyType& GetRsa2048PssKeyType();

}  // namespace crunchy

#endif  // CRUNCHY_KEY_MANAGEMENT_ALGORITHMS_H_
