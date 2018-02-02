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

import com.google.common.annotations.VisibleForTesting;
import com.google.security.crunchy.internal.common.BigIntegerUtil;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import javax.crypto.KeyAgreement;

/** Static functions for serializing/deserializing P256 points/exponents and point validation. */
public final class P256 {
  @VisibleForTesting static final int FIELD_LENGTH = 32;
  private static final int POINT_LENGTH = FIELD_LENGTH * 2;
  @VisibleForTesting static final ECFieldFp FIELD;
  private static final EllipticCurve CURVE;
  private static final ECParameterSpec CURVE_SPEC;

  static {
    // Curve P-256
    // http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    BigInteger p =
        new BigInteger(
            "115792089210356248762697446949407573530086143415290314195533631308867097853951");
    BigInteger n =
        new BigInteger(
            "115792089210356248762697446949407573529996955224135760342422259061068512044369");
    BigInteger a = p.subtract(new BigInteger("3"));
    BigInteger b =
        new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    BigInteger gx =
        new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    BigInteger gy =
        new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
    int h = 1;
    ECPoint g = new ECPoint(gx, gy);

    FIELD = new ECFieldFp(p);
    CURVE = new EllipticCurve(FIELD, a, b);
    CURVE_SPEC = new ECParameterSpec(CURVE, g, n, h);
  }

  /** Returns a random P256 keyPair. */
  public static KeyPair newKeyPair() throws GeneralSecurityException {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(CURVE_SPEC);
    return gen.genKeyPair();
  }

  /** Returns true if the given point is on the curve and not the identity point. */
  public static boolean isPointOnCurve(ECPoint point) throws GeneralSecurityException {
    BigInteger p = FIELD.getP();
    BigInteger x = point.getAffineX();
    BigInteger y = point.getAffineY();
    if (ECPoint.POINT_INFINITY.equals(point)) {
      throw new GeneralSecurityException("point is at infinity");
    }
    // Check 0 <= x < p and 0 <= y < p
    if (x.signum() == -1 || x.compareTo(p) != -1) {
      throw new GeneralSecurityException("x is out of range");
    }
    if (y.signum() == -1 || y.compareTo(p) != -1) {
      throw new GeneralSecurityException("y is out of range");
    }
    // Check y^2 == x^3 + a x + b (mod p)
    BigInteger lhs = y.multiply(y).mod(p);
    BigInteger rhs = x.multiply(x).add(CURVE.getA()).multiply(x).add(CURVE.getB()).mod(p);
    return lhs.equals(rhs);
  }

  /** Performs a Diffie-Hellman key exchange and returns the result. */
  public static byte[] ecdh(byte[] publicKey, byte[] privateKey) throws GeneralSecurityException {
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    ka.init(P256.deserializePrivateKey(privateKey));
    ka.doPhase(P256.deserializePublicKey(publicKey), true);
    return ka.generateSecret();
  }

  /**
   * Returns the concatenation of the two serialized {@code ECPoint} coordinates contained in the
   * publicKey, where each point is serialized as a 32-byte big-endian integer.
   */
  public static byte[] serializePublicKey(PublicKey publicKey) throws GeneralSecurityException {
    if (!(publicKey instanceof ECPublicKey)) {
      throw new IllegalArgumentException("publicKey is not of type ECPublicKey");
    }
    ECPoint point = ((ECPublicKey) publicKey).getW();
    byte[] result = new byte[POINT_LENGTH];
    BigIntegerUtil.fitBigInteger(point.getAffineX(), result, 0, FIELD_LENGTH);
    BigIntegerUtil.fitBigInteger(point.getAffineY(), result, FIELD_LENGTH, FIELD_LENGTH);
    return result;
  }

  /**
   * The inverse of the serializePublicKey function above, takes the concatenation of two big-endian
   * 32-bit integers and uses them as coordinates in a {@code ECPoint} inside the returned {@code
   * PublicKey}.
   */
  public static PublicKey deserializePublicKey(byte[] serializedPoint)
      throws GeneralSecurityException {
    if (serializedPoint.length != 2 * FIELD_LENGTH) {
      throw new IllegalArgumentException(
          "publicKey is the wrong size, expected "
              + FIELD_LENGTH * 2
              + " bytes got "
              + serializedPoint.length);
    }
    BigInteger x =
        new BigInteger(1 /* positive */, Arrays.copyOfRange(serializedPoint, 0, FIELD_LENGTH));
    BigInteger y =
        new BigInteger(
            1 /* positive */, Arrays.copyOfRange(serializedPoint, FIELD_LENGTH, 2 * FIELD_LENGTH));

    ECPoint publicPoint = new ECPoint(x, y);
    if (!isPointOnCurve(publicPoint)) {
      throw new GeneralSecurityException("point is not on the curve");
    }
    ECPublicKeySpec publicSpec = new ECPublicKeySpec(publicPoint, CURVE_SPEC);
    KeyFactory kf = KeyFactory.getInstance("EC");
    return kf.generatePublic(publicSpec);
  }

  /** Returns a 32-byte big endian integer representing the p256 exponent of the private key. */
  public static byte[] serializePrivateKey(PrivateKey privateKey) {
    if (!(privateKey instanceof ECPrivateKey)) {
      throw new IllegalArgumentException("publicKey is not of type ECPrivateKey");
    }
    BigInteger s = ((ECPrivateKey) privateKey).getS();
    byte[] result = new byte[FIELD_LENGTH];
    BigIntegerUtil.fitBigInteger(s, result, 0, FIELD_LENGTH);
    return result;
  }

  /**
   * Converts a 32-byte big-endian serialization of p256 exponent into an {@code PrivateKey} object.
   */
  public static PrivateKey deserializePrivateKey(byte[] privateKey)
      throws GeneralSecurityException {
    if (privateKey.length != FIELD_LENGTH) {
      throw new IllegalArgumentException(
          "privateKey is the wrong size, expected "
              + FIELD_LENGTH
              + " bytes got "
              + privateKey.length);
    }
    BigInteger s = new BigInteger(1 /* positive */, privateKey);

    ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(s, CURVE_SPEC);
    KeyFactory kf = KeyFactory.getInstance("EC");
    return kf.generatePrivate(privateSpec);
  }

  private P256() {}
}
