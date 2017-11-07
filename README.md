# CrunchyCrypt - Safe and Simple Cryptography

CrunchyCrypt is an opensource library offering safe and easy-to-use cryptography
APIs with a built-in key-versioning protocol.

## Table of Contents

- [About CrunchyCrypt](#about)
- [Codemap](#codemap)
- [Compatibility guarantees](#compatibility)
- [License](#license)

Contact us at crunchy-discuss@googlegroups.com
([link](https://groups.google.com/forum/#!forum/crunchy-discuss))

<a name="about"></a>
## About CrunchyCrypt

CrunchyCrypt is an open-source collection of cryptography APIs, safe and
easy-to-use wrappings of lower-level crypto libraries such as boringssl.
Although CrunchyCrypt is intended to primarily be a curated collection of
modern cryptography, CrunchyCrypt is designed to be extendable to both
bleeding-edge and legacy cryptography.

CrunchyCrypt has a built-in key versioning protocol, where cryptographic
payloads (signatures and ciphertexts) are (optionally) prefixed with a few
bytes of key versioning information. This allows project owners to gracefully
rotate new crunchy keys while maintaining backwards compatibility with old keys,
even while switching the underlying algorithm.

Safety and ease-of-use are primary features of CrunchyCrypt, which is good for
most, but not all, use cases. For example, user-specificed nonces is not
something we intend to support. As a consequence, CrunchyCrypt is not meant to
be a comprehensive replacement for openssl/boringssl.

<a name="codemap"></a>
## Codemap

CrunchyCrypt supports crypto and key management in C++. CrunchyCrypt supports
crypto in Java via JNI bindings.

CrunchyCrypt supports the following primitives in C++:

* [`AEAD Encryption`](crunchy/crunchy_crypter.h) Authenticated Encryption with
  Associated Data, aka symmetric encryption
  <br /> We support AES-GCM and AES-EAX at 128 and 256 bits of security.
* [`MACs`](crunchy/crunchy_macer.h) Message authentication code, aka symmetric
  authentication
  <br /> We support HMAC-SHA256 with 16-byte tags and a 32-byte key.
* [`Digital Signatures`](crunchy/crunchy_signer.h), aka asymmetric
  authentication
  <br /> We support P256-ECDSA, Ed25519, and RSA-PKCS1 using SHA256 and a
  2048-bit modulus.
* [`Hybrid Encryption`](crunchy/crunchy_hybrid_crypter.h), aka asymmetric
  encryption
  <br /> We support ECIES using HKDF and AEADs in various combinations,
  including versions using P256 and curve25519.

CrunchyCrypt supports [`key management`](crunchy/key_management/) in C++.
CrunchyCrypt's built-in key-versioning protocol allows for graceful rotation of
keys. [`KeysetManager`](crunchy/key_management/key_manager.h) is used to create,
rotate, and delete keys.  Serialization of unencrypted key material is in a
separate [`keyset_serialization`](crunchy/key_management/keyset_serialization.h)
build target.

[`Java APIs`](crunchy/java/src/main/java/com/google/security/crunchy/) for the
above are implemented via [`JNI
bindings`](crunchy/java/src/main/com/google/security/crunchy/jni).

Some internal APIs may be eventually made user-facing as we gain more experience
as to how they might be used. For example,
[`AdvancedKeysetManager`](crunchy/key_management/) and [`our subtle crypto
APIs`](crunchy/internal/algs) might be made non-internal if they're deemed
useful.

<a name="compatibility"></a>
## Compatibility guarantees

We do not offer any ABI compatibility. We will strive to not break API
compatibility. If we plan to break API compability, we will provide a migration
path.

We ask that you:

* Don't open the crunchy namespace.
* Don't forward-declare crunchy types.
* Don't depend on internal details, namespaces or files that contain the word
  "internal".

<a name="license"></a>
## License

CrunchyCrypt is licensed under the terms of the Apache License, Version 2.0. See
[LICENSE](LICENSE) for more information.
