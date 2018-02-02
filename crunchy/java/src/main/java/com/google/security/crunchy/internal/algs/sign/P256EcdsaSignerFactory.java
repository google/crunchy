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

import com.google.security.crunchy.algs.jce.P256;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * An implementation of SubtleSignerFactory that uses P256-ECDSA signatures with an asn1 encoding.
 */
public class P256EcdsaSignerFactory implements SubtleSignerFactory {
  private static final String SHA256_ECDSA = "SHA256withECDSA";

  private static SubtleSignerFactory factory = new P256EcdsaSignerFactory();

  public static SubtleSignerFactory getFactory() {
    return factory;
  }

  private P256EcdsaSignerFactory() {}

  @Override
  public KeyPair newKeyPair() throws GeneralSecurityException {
    java.security.KeyPair keyPair = P256.newKeyPair();
    byte[] publicKey = P256.serializePublicKey(keyPair.getPublic());
    byte[] privateKey = P256.serializePrivateKey(keyPair.getPrivate());
    return KeyPair.create(publicKey, privateKey);
  }

  @Override
  public SubtleSigner newSigner(byte[] privateKey) throws GeneralSecurityException {
    return new Signer(privateKey);
  }

  @Override
  public SubtleVerifier newVerifier(byte[] publicKey) throws GeneralSecurityException {
    return new Verifier(publicKey);
  }

  private static class Signer implements SubtleSigner {
    private final PrivateKey privateKey;

    private Signer(byte[] privateKey) throws GeneralSecurityException {
      this.privateKey = P256.deserializePrivateKey(privateKey);
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
      Signature sig = Signature.getInstance(SHA256_ECDSA);
      sig.initSign(privateKey);
      sig.update(message);
      return sig.sign();
    }
  }

  private static class Verifier implements SubtleVerifier {
    private final PublicKey publicKey;

    private Verifier(byte[] publicKey) throws GeneralSecurityException {
      this.publicKey = P256.deserializePublicKey(publicKey);
    }

    @Override
    public void verify(byte[] message, byte[] signature) throws GeneralSecurityException {
      Signature sig = Signature.getInstance(SHA256_ECDSA);
      sig.initVerify(publicKey);
      sig.update(message);
      if (!sig.verify(signature)) {
        throw new SignatureException("Could not verify signature");
      }
    }
  }
}
