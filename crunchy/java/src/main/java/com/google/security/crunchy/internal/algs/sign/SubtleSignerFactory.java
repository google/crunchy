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

package com.google.security.crunchy.algs.sign;

import com.google.auto.value.AutoValue;
import java.security.GeneralSecurityException;

/** An interface for generating asymmetric cryptographic signing/verifying objects. */
public interface SubtleSignerFactory {
  /**
   * Returns a pair of serialized public/private keys used to create SubtleSigner and SubtleVerifier
   * objects.
   */
  KeyPair newKeyPair() throws GeneralSecurityException;

  /** Returns a SubtleSigner backed by privateKey. */
  SubtleSigner newSigner(byte[] privateKey) throws GeneralSecurityException;

  /** Returns a SubtleVerifier backed by publiceKey. */
  SubtleVerifier newVerifier(byte[] publicKey) throws GeneralSecurityException;

  /** A container for a public/private keyPair. */
  @AutoValue
  abstract static class KeyPair {
    static KeyPair create(byte[] publicKey, byte[] privateKey) {
      return new AutoValue_SubtleSignerFactory_KeyPair(publicKey, privateKey);
    }

    @SuppressWarnings("mutable")
    public abstract byte[] getPublicKey();

    @SuppressWarnings("mutable")
    public abstract byte[] getPrivateKey();
  }
}
