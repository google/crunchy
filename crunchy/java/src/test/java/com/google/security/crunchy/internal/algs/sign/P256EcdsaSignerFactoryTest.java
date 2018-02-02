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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.fail;

import com.google.security.crunchy.internal.common.Hex;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link P256EcdsaSignerFactory}. */
@RunWith(JUnit4.class)
public class P256EcdsaSignerFactoryTest {
  @Test
  public void testSignVerify() throws GeneralSecurityException {
    SubtleSignerFactory factory = P256EcdsaSignerFactory.getFactory();
    SubtleSignerFactory.KeyPair keyPair = factory.newKeyPair();

    SubtleSigner signer = factory.newSigner(keyPair.getPrivateKey());
    SubtleVerifier verifier = factory.newVerifier(keyPair.getPublicKey());

    byte[] message = "banana".getBytes(UTF_8);
    byte[] signature = signer.sign(message);
    verifier.verify(message, signature);
  }

  @Test
  public void testWrongSigner() throws GeneralSecurityException {
    SubtleSignerFactory factory = P256EcdsaSignerFactory.getFactory();
    SubtleSignerFactory.KeyPair keyPair = factory.newKeyPair();

    SubtleSigner signer = factory.newSigner(keyPair.getPrivateKey());

    // Use a different keyPair for the verifier
    keyPair = factory.newKeyPair();
    SubtleVerifier verifier = factory.newVerifier(keyPair.getPublicKey());

    byte[] message = "banana".getBytes(UTF_8);
    byte[] signature = signer.sign(message);
    try {
      verifier.verify(message, signature);
      fail();
    } catch (GeneralSecurityException expected) {
      assertThat(expected).hasMessageThat().contains("Could not verify signature");
    }
  }

  @Test
  public void testBadSignature() throws GeneralSecurityException {
    SubtleSignerFactory factory = P256EcdsaSignerFactory.getFactory();
    SubtleSignerFactory.KeyPair keyPair = factory.newKeyPair();

    SubtleSigner signer = factory.newSigner(keyPair.getPrivateKey());
    SubtleVerifier verifier = factory.newVerifier(keyPair.getPublicKey());

    byte[] message = "banana".getBytes(UTF_8);
    byte[] signature = signer.sign(message);
    verifier.verify(message, signature);

    // Corrupt the signature
    for (int i = 0; i < signature.length; i++) {
      signature[i]++;
      try {
        verifier.verify(message, signature);
        fail();
      } catch (GeneralSecurityException expected) {
        assertThat(expected).hasMessageThat().contains("Could not verify signature");
      }
      signature[i]--;
    }

    // Corrupt the message
    message[0]++;
    try {
      verifier.verify(message, signature);
      fail();
    } catch (GeneralSecurityException expected) {
      assertThat(expected).hasMessageThat().contains("Could not verify signature");
    }
    message[0]--;
  }

  @Test
  public void testVectors() throws GeneralSecurityException {
    SubtleSignerFactory factory = P256EcdsaSignerFactory.getFactory();

    // RFC 4754 section 8.1
    // https://www.ietf.org/rfc/rfc4754
    String publicKeyHex =
        "2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970"
            + "6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D";
    String privateKeyHex = "DC51D3866A15BACDE33D96F992FCA99DA7E6EF0934E7097559C27F1614C88A7F";

    byte[] message = "abc".getBytes(UTF_8);
    // asn1 encoding harvested from the c++ version of this test.
    String signatureHex =
        "3046022100cb28e0999b9c7715fd0a80d8e47a77079716cbbf917dd72e97566ea1c066957c022100"
            + "86fa3bb4e26cad5bf90b7f81899256ce7594bb1ea0c89212748bff3b3d5b0315";
    byte[] signature = Hex.fromHex(signatureHex);

    SubtleVerifier verifier = factory.newVerifier(Hex.fromHex(publicKeyHex));

    // Verify the test vector's message/signature
    verifier.verify(message, signature);

    // Sign and verify the test vector's message
    SubtleSigner signer = factory.newSigner(Hex.fromHex(privateKeyHex));
    signature = signer.sign(message);
    verifier.verify(message, signature);
  }

  @Test
  public void testBadPublicKey() throws GeneralSecurityException {
    SubtleSignerFactory factory = P256EcdsaSignerFactory.getFactory();

    String publicKeyHex =
        "2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970"
            + "6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D";

    byte[] publicKey = Hex.fromHex(publicKeyHex);

    publicKey[0]++;
    try {
      factory.newVerifier(publicKey);
      fail();
    } catch (GeneralSecurityException expected) {
      assertThat(expected).hasMessageThat().contains("point is not on the curve");
    }
    publicKey[0]--;
  }

  /** Returns canonical test vectors. */
  private static SignerTestVectors getTestVectors() {
    try {
      byte[] serialized = Files.readAllBytes(FileSystems.getDefault().getPath(
          "crunchy/internal/algs/sign/testdata/p256_ecdsa_asn1.proto.bin"));
      return SignerTestVectors.parseFrom(serialized);
    } catch (IOException exception) {
      fail(exception.toString());
    }
    return null;
  }

  @Test
  public void testCrunchyTestVectors() throws GeneralSecurityException {
    SubtleSignerFactory factory = P256EcdsaSignerFactory.getFactory();
    for (SignerTestVector testVector : getTestVectors().getTestVectorList()) {
      SubtleSigner signer = factory.newSigner(testVector.getPrivateKey().toByteArray());
      SubtleVerifier verifier = factory.newVerifier(testVector.getPublicKey().toByteArray());

      // Sign/verify using the test vector's message
      byte[] message = testVector.getMessage().toByteArray();
      byte[] signature = signer.sign(message);
      verifier.verify(message, signature);

      // Verify using the test vector's message/signature
      signature = testVector.getSignature().toByteArray();
      verifier.verify(message, signature);
    }
  }
}
