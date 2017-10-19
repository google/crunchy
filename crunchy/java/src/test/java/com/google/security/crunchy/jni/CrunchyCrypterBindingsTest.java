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

import com.google.security.crunchy.CrunchyCrypter;
import com.google.security.crunchy.internal.keyset.testdata.CrypterFactoryTestVector;
import com.google.security.crunchy.internal.keyset.testdata.CrypterFactoryTestVectors;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link CrunchyCrypterBindings}. */
@RunWith(JUnit4.class)
public class CrunchyCrypterBindingsTest {
  static final String SRCDIR =
      "crunchy/internal/keyset/testdata/crypter_factory_test_vectors.proto.bin";

  private static CrypterFactoryTestVectors testVectors;

  private static CrypterFactoryTestVectors getTestVectors() {
    if (testVectors != null) {
      return testVectors;
    }
    try {
      byte[] serialized = Files.readAllBytes(FileSystems.getDefault().getPath(SRCDIR));
      testVectors = CrypterFactoryTestVectors.parseFrom(serialized);
      return testVectors;
    } catch (IOException e) {
      fail(e.toString());
    }
    return null;
  }

  private static byte[] getSerializedKeyset() {
    CrypterFactoryTestVectors testVectors = getTestVectors();
    return testVectors.getTestVector(0).getKeyset().toByteArray();
  }

  @Test
  public void testEncryptDecrypt() throws GeneralSecurityException {
    CrypterFactoryTestVectors testVectors = getTestVectors();
    for (CrypterFactoryTestVector testVector : testVectors.getTestVectorList()) {
      CrunchyCrypter crypter =
          CrunchyCrypterBindings.newInstance(testVector.getKeyset().toByteArray());

      // Encrypt/decrypt the test vector's plaintext/aad
      byte[] plaintext = testVector.getPlaintext().toByteArray();
      byte[] aad = testVector.getAad().toByteArray();

      byte[] ciphertext = crypter.encrypt(plaintext, aad);
      byte[] decrypted = crypter.decrypt(ciphertext, aad);
      assertThat(plaintext).isEqualTo(decrypted);

      // Decrypt the test vector ciphertext/aad
      ciphertext = testVector.getCiphertext().toByteArray();
      decrypted = crypter.decrypt(ciphertext, aad);
      assertThat(plaintext).isEqualTo(decrypted);
    }
  }

  @Test
  public void testEmptyKeyset() {
    byte[] emptyKeyset = new byte[0];
    try {
      CrunchyCrypterBindings.newInstance(emptyKeyset);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
  }

  @Test
  public void testEncryptDecryptBadPayload() throws GeneralSecurityException {
    byte[] serializedKeyset = getSerializedKeyset();
    CrunchyCrypter crypter = CrunchyCrypterBindings.newInstance(serializedKeyset);
    byte[] plaintext = "banana".getBytes(UTF_8);
    byte[] aad = "apple".getBytes(UTF_8);
    byte[] ciphertext = crypter.encrypt(plaintext, aad);

    // Corrupt header
    ciphertext[1]++;
    try {
      crypter.decrypt(ciphertext, aad);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    ciphertext[1]--;

    // Corrupt middle
    ciphertext[ciphertext.length / 2]++;
    try {
      crypter.decrypt(ciphertext, aad);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    ciphertext[ciphertext.length / 2]--;

    // Corrupt tag
    ciphertext[ciphertext.length - 1]++;
    try {
      crypter.decrypt(ciphertext, aad);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    ciphertext[ciphertext.length - 1]--;

    // Corrupt aad
    aad[0]++;
    try {
      crypter.decrypt(ciphertext, aad);
      fail("Expected a GeneralSecurityException");
    } catch (GeneralSecurityException expected) {
    }
    aad[0]--;
  }

  @Test
  public void testFinalize() throws GeneralSecurityException {
    byte[] serializedKeyset = getSerializedKeyset();
    CrunchyCrypterBindings crypter = new CrunchyCrypterBindings(serializedKeyset);

    byte[] plaintext = "banana".getBytes(UTF_8);
    byte[] aad = "apple".getBytes(UTF_8);
    byte[] ciphertext = crypter.encrypt(plaintext, aad);
    byte[] decrypted = crypter.decrypt(ciphertext, aad);
    assertThat(new String(decrypted, UTF_8)).isEqualTo(new String(plaintext, UTF_8));

    crypter.finalize();
    try {
      crypter.encrypt(plaintext, aad);
      fail("Expected an IllegalStateException");
    } catch (IllegalStateException expected) {
    }
    try {
      crypter.decrypt(ciphertext, aad);
      fail("Expected an IllegalStateException");
    } catch (IllegalStateException expected) {
    }
    crypter.finalize();
  }

  @Test
  public void testNull() throws GeneralSecurityException {
    try {
      CrunchyCrypterBindings.newInstance(null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
    byte[] serializedKeyset = getSerializedKeyset();
    CrunchyCrypter crypter = CrunchyCrypterBindings.newInstance(serializedKeyset);

    try {
      crypter.encrypt(null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
    try {
      crypter.decrypt(null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }

    byte[] plaintext = "banana".getBytes(UTF_8);
    byte[] aad = "apple".getBytes(UTF_8);
    byte[] ciphertext = crypter.encrypt(plaintext, aad);

    try {
      crypter.encrypt(plaintext, null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }

    try {
      crypter.encrypt(null, aad);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
    try {
      crypter.decrypt(ciphertext, null);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
    try {
      crypter.decrypt(null, aad);
      fail("Expected a NullPointerException");
    } catch (NullPointerException expected) {
    }
  }
}
