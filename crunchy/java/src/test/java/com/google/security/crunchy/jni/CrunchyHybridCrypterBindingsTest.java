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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.fail;

import com.google.security.crunchy.CrunchyHybridDecrypter;
import com.google.security.crunchy.CrunchyHybridEncrypter;
import com.google.security.crunchy.internal.keyset.testdata.HybridCrypterFactoryTestVector;
import com.google.security.crunchy.internal.keyset.testdata.HybridCrypterFactoryTestVectors;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link CrunchyHybridEncrypterBindings} and {@link CrunchyHybridDecrypterBindings}.
 */
@RunWith(JUnit4.class)
public class CrunchyHybridCrypterBindingsTest {
  static final String SRCDIR =
      "crunchy/internal/keyset/testdata/hybrid_crypter_factory_test_vectors.proto.bin";

  private static HybridCrypterFactoryTestVectors testVectors;

  private static HybridCrypterFactoryTestVectors getTestVectors() {
    if (testVectors != null) {
      return testVectors;
    }
    try {
      byte[] serialized = Files.readAllBytes(FileSystems.getDefault().getPath(SRCDIR));
      testVectors = HybridCrypterFactoryTestVectors.parseFrom(serialized);
      return testVectors;
    } catch (IOException e) {
      fail(e.toString());
    }
    return null;
  }

  private static byte[] getSerializedPrivateKeyset() {
    HybridCrypterFactoryTestVectors testVectors = getTestVectors();
    return testVectors.getTestVector(0).getPrivateKeyset().toByteArray();
  }

  public static byte[] getSerializedPublicKeyset() {
    HybridCrypterFactoryTestVectors testVectors = getTestVectors();
    return testVectors.getTestVector(0).getPublicKeyset().toByteArray();
  }

  @Test
  public void testEncryptDecrypt() throws GeneralSecurityException {
    HybridCrypterFactoryTestVectors testVectors = getTestVectors();
    for (HybridCrypterFactoryTestVector testVector : testVectors.getTestVectorList()) {
      CrunchyHybridEncrypter encrypter =
          CrunchyHybridEncrypterBindings.newInstance(testVector.getPublicKeyset().toByteArray());
      CrunchyHybridDecrypter decrypter =
          CrunchyHybridDecrypterBindings.newInstance(testVector.getPrivateKeyset().toByteArray());

      // Encrypt/decrypt the test vector's plaintext
      byte[] plaintext = testVector.getPlaintext().toByteArray();
      byte[] ciphertext = encrypter.encrypt(plaintext);
      byte[] decrypted = decrypter.decrypt(ciphertext);
      assertThat(plaintext).isEqualTo(decrypted);

      // Decrypt the test vector's ciphertext
      ciphertext = testVector.getCiphertext().toByteArray();
      decrypted = decrypter.decrypt(ciphertext);
      assertThat(plaintext).isEqualTo(decrypted);
    }
  }

  @Test
  public void testEmptyKeyset() {
    byte[] emptyKeyset = new byte[0];
    try {
      CrunchyHybridEncrypterBindings.newInstance(emptyKeyset);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    try {
      CrunchyHybridDecrypterBindings.newInstance(emptyKeyset);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
  }

  @Test
  public void testEncryptDecryptBadPayload() throws GeneralSecurityException {
    byte[] serializedKeyset = getSerializedPublicKeyset();
    CrunchyHybridEncrypter encrypter = CrunchyHybridEncrypterBindings.newInstance(serializedKeyset);
    serializedKeyset = getSerializedPrivateKeyset();
    CrunchyHybridDecrypter decrypter = CrunchyHybridDecrypterBindings.newInstance(serializedKeyset);

    byte[] plaintext = "banana".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext);

    // Corrupt header
    ciphertext[1]++;
    try {
      decrypter.decrypt(ciphertext);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    ciphertext[1]--;

    // Corrupt middle
    ciphertext[ciphertext.length / 2]++;
    try {
      decrypter.decrypt(ciphertext);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    ciphertext[ciphertext.length / 2]--;

    // Corrupt tag
    ciphertext[ciphertext.length - 1]++;
    try {
      decrypter.decrypt(ciphertext);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    ciphertext[ciphertext.length - 1]--;
  }

  @Test
  public void testFinalize() throws GeneralSecurityException {
    byte[] serializedKeyset = getSerializedPublicKeyset();
    CrunchyHybridEncrypterBindings encrypter = new CrunchyHybridEncrypterBindings(serializedKeyset);
    serializedKeyset = getSerializedPrivateKeyset();
    CrunchyHybridDecrypterBindings decrypter = new CrunchyHybridDecrypterBindings(serializedKeyset);

    byte[] plaintext = "banana".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext);
    byte[] decrypted = decrypter.decrypt(ciphertext);
    assertThat(new String(decrypted, UTF_8)).isEqualTo(new String(plaintext, UTF_8));

    encrypter.finalize();
    try {
      encrypter.encrypt(plaintext);
      fail("Expected a IllegalStateException");
    } catch (IllegalStateException expected) {
    }
    encrypter.finalize();

    decrypter.finalize();
    try {
      decrypter.decrypt(ciphertext);
      fail("Expected a IllegalStateException");
    } catch (IllegalStateException expected) {
    }
    decrypter.finalize();
  }

  @Test
  public void testNull() throws GeneralSecurityException {
    try {
      CrunchyHybridEncrypterBindings.newInstance(null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
    try {
      CrunchyHybridDecrypterBindings.newInstance(null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }

    byte[] serializedKeyset = getSerializedPublicKeyset();
    CrunchyHybridEncrypter encrypter = CrunchyHybridEncrypterBindings.newInstance(serializedKeyset);
    try {
      encrypter.encrypt(null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }

    serializedKeyset = getSerializedPrivateKeyset();
    CrunchyHybridDecrypter decrypter = CrunchyHybridDecrypterBindings.newInstance(serializedKeyset);
    try {
      decrypter.decrypt(null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
  }
}
