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

package com.google.security.crunchy.internal.common;

import java.math.BigInteger;

/** Conversion between Hex strings and byte[]. */
public final class Hex {
  private Hex() {}

  /** Returns a byte[] representation of the hex values. */
  public static byte[] fromHex(String string) {
    if (string.length() % 2 != 0) {
      throw new IllegalArgumentException("Byte hex must contain an even number of hex digits");
    }
    BigInteger bigInt = new BigInteger(string, 16);
    byte[] result = new byte[string.length() / 2];
    BigIntegerUtil.fitBigInteger(bigInt, result, 0, result.length);
    return result;
  }

  /** Returns a hex representation of the byte array. */
  public static String toHex(byte[] hex) {
    String result = new BigInteger(1 /* positive */, hex).toString(16);
    // Fill out any leading zeros that might have been dropped.
    while (result.length() < hex.length * 2) {
      result = "0" + result;
    }
    return result;
  }
}
