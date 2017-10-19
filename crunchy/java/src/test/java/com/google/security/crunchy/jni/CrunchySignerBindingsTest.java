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

package com.google.security.crunchy.jni;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.fail;

import com.google.security.crunchy.CrunchySigner;
import com.google.security.crunchy.CrunchyVerifier;
import com.google.security.crunchy.internal.keyset.testdata.SignerFactoryTestVector;
import com.google.security.crunchy.internal.keyset.testdata.SignerFactoryTestVectors;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link CrunchySignerBindings} and {@link CrunchyVerifierBindings}. */
@RunWith(JUnit4.class)
public class CrunchySignerBindingsTest {
  static final String SRCDIR =
      "crunchy/internal/keyset/testdata/signer_factory_test_vectors.proto.bin";

  private static SignerFactoryTestVectors testVectors;

  private static SignerFactoryTestVectors getTestVectors() {
    if (testVectors != null) {
      return testVectors;
    }
    try {
      byte[] serialized = Files.readAllBytes(FileSystems.getDefault().getPath(SRCDIR));
      testVectors = SignerFactoryTestVectors.parseFrom(serialized);
      return testVectors;
    } catch (IOException e) {
      fail(e.toString());
    }
    return null;
  }

  private static byte[] getSerializedPrivateKeyset() {
    SignerFactoryTestVectors testVectors = getTestVectors();
    return testVectors.getTestVector(0).getPrivateKeyset().toByteArray();
  }

  public static byte[] getSerializedPublicKeyset() {
    SignerFactoryTestVectors testVectors = getTestVectors();
    return testVectors.getTestVector(0).getPublicKeyset().toByteArray();
  }

  @Test
  public void testSignVerify() throws GeneralSecurityException {
    SignerFactoryTestVectors testVectors = getTestVectors();
    for (SignerFactoryTestVector testVector : testVectors.getTestVectorList()) {
      CrunchySigner signer =
          CrunchySignerBindings.newInstance(testVector.getPrivateKeyset().toByteArray());
      CrunchyVerifier verifier =
          CrunchyVerifierBindings.newInstance(testVector.getPublicKeyset().toByteArray());

      // Sign/verify the test vector's message
      byte[] message = "banana".getBytes(UTF_8);
      byte[] signature = signer.sign(message);
      verifier.verify(message, signature);

      // Verify the test vector's message
      message = testVector.getMessage().toByteArray();
      signature = testVector.getSignature().toByteArray();
      verifier.verify(message, signature);
    }
  }

  @Test
  public void testEmptyKeyset() {
    byte[] emptyKeyset = new byte[0];
    try {
      CrunchySignerBindings.newInstance(emptyKeyset);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    try {
      CrunchyVerifierBindings.newInstance(emptyKeyset);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
  }

  @Test
  public void testSignVerifyBadPayload() throws GeneralSecurityException {
    byte[] serializedKeyset = getSerializedPrivateKeyset();
    CrunchySigner signer = CrunchySignerBindings.newInstance(serializedKeyset);
    serializedKeyset = getSerializedPublicKeyset();
    CrunchyVerifier verifier = CrunchyVerifierBindings.newInstance(serializedKeyset);

    byte[] message = "banana".getBytes(UTF_8);
    byte[] signature = signer.sign(message);

    // Wrong message
    try {
      verifier.verify("apple".getBytes(UTF_8), signature);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }

    // Corrupt header
    signature[1]++;
    try {
      verifier.verify(message, signature);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    signature[1]--;

    // Corrupt middle
    signature[signature.length / 2]++;
    try {
      verifier.verify(message, signature);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    signature[signature.length / 2]--;

    // Corrupt tag
    signature[signature.length - 1]++;
    try {
      verifier.verify(message, signature);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    signature[signature.length - 1]--;
  }

  @Test
  public void testFinalize() throws GeneralSecurityException {
    byte[] serializedKeyset = getSerializedPrivateKeyset();
    CrunchySignerBindings signer = new CrunchySignerBindings(serializedKeyset);
    serializedKeyset = getSerializedPublicKeyset();
    CrunchyVerifierBindings verifier = new CrunchyVerifierBindings(serializedKeyset);

    byte[] message = "banana".getBytes(UTF_8);
    byte[] signature = signer.sign(message);
    verifier.verify(message, signature);

    signer.finalize();
    try {
      signer.sign(message);
      fail("Expected a IllegalStateException");
    } catch (IllegalStateException expected) {
    }
    signer.finalize();
    verifier.finalize();
    try {
      verifier.verify(message, signature);
      fail("Expected a IllegalStateException");
    } catch (IllegalStateException expected) {
    }
    verifier.finalize();
  }

  @Test
  public void testNull() throws GeneralSecurityException {
    try {
      CrunchySignerBindings.newInstance(null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
    try {
      CrunchyVerifierBindings.newInstance(null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }

    byte[] serializedKeyset = getSerializedPrivateKeyset();
    CrunchySigner signer = CrunchySignerBindings.newInstance(serializedKeyset);
    serializedKeyset = getSerializedPublicKeyset();
    CrunchyVerifier verifier = CrunchyVerifierBindings.newInstance(serializedKeyset);

    byte[] message = "banana".getBytes(UTF_8);
    byte[] signature = signer.sign(message);
    verifier.verify(message, signature);
    try {
      signer.sign(null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
    try {
      verifier.verify(message, null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
    try {
      verifier.verify(null, signature);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
  }
}
