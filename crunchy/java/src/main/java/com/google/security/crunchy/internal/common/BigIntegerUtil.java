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

/**
 * Serialize an unsigned big integer into a fixed-width array, perserving leading zeros and
 * excluding a sign bit.
 */
public class BigIntegerUtil {
  private BigIntegerUtil() {}

  /**
   * Copies a BigInteger to a fixed-sized array as an unsigned big-endian integer, padding with
   * leading zeros. The output array is assumed to contain |length| zero bytes starting at
   * output[offset]. This is used as an alternative to BigInteger.toByteArray(), which will not
   * return a fixed-sized array. In particular, BigInteger.toByteArray() would add an extra sign
   * byte and drop leading zeros.
   *
   * @param bigInt The integer to fit.
   * @param output The output buffer.
   * @param offset The offset in output where the output starts.
   * @param length The number of bytes we are allowed to write to output.
   */
  public static void fitBigInteger(BigInteger bigInt, byte[] output, int offset, int length) {
    byte[] array = bigInt.toByteArray();
    if (array.length > length + 1) {
      throw new IllegalArgumentException("Array is too small to hold this BigInteger");
    } else if (array.length == length + 1) {
      if (array[0] != 0x00) {
        throw new IllegalArgumentException("Array is too small to hold this BigInteger");
      }
      // Clip off extra sign bit
      System.arraycopy(array, 1, output, offset, length);
    } else {
      // Preserve leading zeros
      System.arraycopy(array, 0, output, offset + length - array.length, array.length);
    }
  }
}
