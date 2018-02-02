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

package com.google.security.crunchy.algs.jce;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

import com.google.security.crunchy.internal.common.Hex;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link P256}. */
@RunWith(JUnit4.class)
public class P256Test {
  @Test
  public void testPointOnCurve() throws GeneralSecurityException {
    // Valid point
    String xHex = "2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970";
    String yHex = "6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D";
    BigInteger x = new BigInteger(1 /* positive */, Hex.fromHex(xHex));
    BigInteger y = new BigInteger(1 /* positive */, Hex.fromHex(yHex));
    ECPoint point = new ECPoint(x, y);
    assertThat(P256.isPointOnCurve(point)).isTrue();

    // Invalid point
    xHex = "2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E971";
    yHex = "6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D";
    x = new BigInteger(1 /* positive */, Hex.fromHex(xHex));
    y = new BigInteger(1 /* positive */, Hex.fromHex(yHex));
    point = new ECPoint(x, y);
    assertThat(P256.isPointOnCurve(point)).isFalse();

    // Point at infinity
    try {
      P256.isPointOnCurve(ECPoint.POINT_INFINITY);
      fail();
    } catch (GeneralSecurityException expected) {
      assertThat(expected).hasMessageThat().contains("point is at infinity");
    }

    // Negative x
    try {
      point = new ECPoint(x.subtract(P256.FIELD.getP()), y);
      P256.isPointOnCurve(point);
      fail();
    } catch (GeneralSecurityException expected) {
      assertThat(expected).hasMessageThat().contains("x is out of range");
    }

    // Negative y
    try {
      point = new ECPoint(x, y.subtract(P256.FIELD.getP()));
      P256.isPointOnCurve(point);
      fail();
    } catch (GeneralSecurityException expected) {
      assertThat(expected).hasMessageThat().contains("y is out of range");
    }

    // Large x
    try {
      point = new ECPoint(x.add(P256.FIELD.getP()), y);
      P256.isPointOnCurve(point);
      fail();
    } catch (GeneralSecurityException expected) {
      assertThat(expected).hasMessageThat().contains("x is out of range");
    }

    // Large y
    try {
      point = new ECPoint(x, y.add(P256.FIELD.getP()));
      P256.isPointOnCurve(point);
      fail();
    } catch (GeneralSecurityException expected) {
      assertThat(expected).hasMessageThat().contains("y is out of range");
    }
  }

  @Test
  public void ecdhTest() throws GeneralSecurityException {
    // RFC 5114 section A.6.
    // https://tools.ietf.org/html/rfc5114.html#appendix-A.6
    {
      byte[] publicKey =
          Hex.fromHex(
              "b120de4aa36492795346e8de6c2c8646ae06aaea279fa775b3ab0715f6ce51b0"
                  + "9f1b7eece20d7b5ed8ec685fa3f071d83727027092a8411385c34dde5708b2b6");
      byte[] privateKey =
          Hex.fromHex("814264145f2f56f2e96a8e337a1284993faf432a5abce59e867b7291d507a3af");
      String expectedEcdhResultHex =
          "dd0f5396219d1ea393310412d19a08f1f5811e9dc8ec8eea7f80d21c820c2788";
      byte[] computedEcdhResult = P256.ecdh(publicKey, privateKey);
      assertThat(expectedEcdhResultHex).isEqualTo(Hex.toHex(computedEcdhResult));
    }
    {
      byte[] publicKey =
          Hex.fromHex(
              "2af502f3be8952f2c9b5a8d4160d09e97165be50bc42ae4a5e8d3b4ba83aeb15"
                  + "eb0faf4ca986c4d38681a0f9872d79d56795bd4bff6e6de3c0f5015ece5efd85");
      byte[] privateKey =
          Hex.fromHex("2ce1788ec197e096db95a200cc0ab26a19ce6bccad562b8eee1b593761cf7f41");
      String expectedEcdhResultHex =
          "dd0f5396219d1ea393310412d19a08f1f5811e9dc8ec8eea7f80d21c820c2788";
      byte[] computedEcdhResult = P256.ecdh(publicKey, privateKey);
      assertThat(expectedEcdhResultHex).isEqualTo(Hex.toHex(computedEcdhResult));
    }
  }

  @Test
  public void testSerializePublicKey() throws GeneralSecurityException {
    PublicKey key = P256.newKeyPair().getPublic();
    byte[] serialized = P256.serializePublicKey(key);
    PublicKey deserialized = P256.deserializePublicKey(serialized);
    assertThat(key).isEqualTo(deserialized);

    // Small array
    try {
      P256.deserializePublicKey(Arrays.copyOfRange(serialized, 0, serialized.length - 1));
      fail();
    } catch (IllegalArgumentException expected) {
      assertThat(expected).hasMessageThat().contains("publicKey is the wrong size");
    }

    // Invalid Point
    try {
      P256.deserializePublicKey(
          Hex.fromHex(
              "2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E971"
                  + "6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D"));
      fail();
    } catch (GeneralSecurityException expected) {
      assertThat(expected).hasMessageThat().contains("point is not on the curve");
    }
  }

  @Test
  public void testSerializePrivateKey() throws GeneralSecurityException {
    PrivateKey key = P256.newKeyPair().getPrivate();
    byte[] serialized = P256.serializePrivateKey(key);
    PrivateKey deserialized = P256.deserializePrivateKey(serialized);
    assertThat(key).isEqualTo(deserialized);

    // Small array
    try {
      P256.deserializePrivateKey(Arrays.copyOfRange(serialized, 0, serialized.length - 1));
      fail();
    } catch (IllegalArgumentException expected) {
      assertThat(expected).hasMessageThat().contains("privateKey is the wrong size");
    }
  }
}
