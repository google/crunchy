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

import com.google.security.crunchy.CrunchyMacer;
import com.google.security.crunchy.internal.keyset.testdata.MacerFactoryTestVector;
import com.google.security.crunchy.internal.keyset.testdata.MacerFactoryTestVectors;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link CrunchyMacerBindings}. */
@RunWith(JUnit4.class)
public class CrunchyMacerBindingsTest {
  static final String SRCDIR =
      "crunchy/internal/keyset/testdata/macer_factory_test_vectors.proto.bin";

  private static MacerFactoryTestVectors testVectors;

  private static MacerFactoryTestVectors getTestVectors() {
    if (testVectors != null) {
      return testVectors;
    }
    try {
      byte[] serialized = Files.readAllBytes(FileSystems.getDefault().getPath(SRCDIR));
      testVectors = MacerFactoryTestVectors.parseFrom(serialized);
      return testVectors;
    } catch (IOException e) {
      fail(e.toString());
    }
    return null;
  }

  private static byte[] getSerializedKeyset() {
    MacerFactoryTestVectors testVectors = getTestVectors();
    return testVectors.getTestVector(0).getKeyset().toByteArray();
  }

  @Test
  public void testSignVerify() throws GeneralSecurityException {
    MacerFactoryTestVectors testVectors = getTestVectors();
    for (MacerFactoryTestVector testVector : testVectors.getTestVectorList()) {
      CrunchyMacer macer = CrunchyMacerBindings.newInstance(testVector.getKeyset().toByteArray());

      // Sign/verify the test vector's message
      byte[] message = testVector.getMessage().toByteArray();
      byte[] signature = macer.sign(message);
      macer.verify(message, signature);

      // Verify the test vector's message
      message = testVector.getMessage().toByteArray();
      signature = testVector.getSignature().toByteArray();
      macer.verify(message, signature);
    }
  }

  @Test
  public void testEmptyKeyset() {
    byte[] emptyKeyset = new byte[0];
    try {
      CrunchyMacerBindings.newInstance(emptyKeyset);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
  }

  @Test
  public void testSignVerifyBadPayload() throws GeneralSecurityException {
    byte[] serializedKeyset = getSerializedKeyset();
    CrunchyMacer macer = CrunchyMacerBindings.newInstance(serializedKeyset);
    byte[] message = "banana".getBytes(UTF_8);
    byte[] signature = macer.sign(message);

    // Wrong message
    try {
      macer.verify("apple".getBytes(UTF_8), signature);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }

    // Corrupt header
    signature[1]++;
    try {
      macer.verify(message, signature);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    signature[1]--;

    // Corrupt middle
    signature[signature.length / 2]++;
    try {
      macer.verify(message, signature);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    signature[signature.length / 2]--;

    // Corrupt tag
    signature[signature.length - 1]++;
    try {
      macer.verify(message, signature);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    signature[signature.length - 1]--;
  }

  @Test
  public void testFinalize() throws GeneralSecurityException {
    byte[] serializedKeyset = getSerializedKeyset();
    CrunchyMacerBindings macer = new CrunchyMacerBindings(serializedKeyset);
    byte[] message = "banana".getBytes(UTF_8);
    byte[] signature = macer.sign(message);
    macer.verify(message, signature);

    macer.finalize();
    try {
      macer.sign(message);
      fail("Expected a IllegalStateException");
    } catch (IllegalStateException expected) {
    }
    try {
      macer.verify(message, signature);
      fail("Expected a IllegalStateException");
    } catch (IllegalStateException expected) {
    }
    macer.finalize();
  }

  @Test
  public void testNull() throws GeneralSecurityException {
    try {
      CrunchyMacerBindings.newInstance(null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
    byte[] serializedKeyset = getSerializedKeyset();
    CrunchyMacer macer = CrunchyMacerBindings.newInstance(serializedKeyset);
    byte[] message = "banana".getBytes(UTF_8);
    byte[] signature = macer.sign(message);
    macer.verify(message, signature);
    try {
      macer.sign(null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
    try {
      macer.verify(message, null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
    try {
      macer.verify(null, signature);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
  }
}
