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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link BigIntegerUtil}. */
@RunWith(JUnit4.class)
public final class BigIntegerUtilTest {
  @Test
  public void testFitBigInteger() {
    BigInteger p =
        new BigInteger(
            "115792089210356248762697446949407573530086143415290314195533631308867097853951");
    int size = 32;

    // Serialize/deserialize
    byte[] serialized = new byte[size];
    BigIntegerUtil.fitBigInteger(p, serialized, 0, size);
    BigInteger deserialized = new BigInteger(1 /* positive */, serialized);
    assertThat(p).isEqualTo(deserialized);

    // Small array
    try {
      BigIntegerUtil.fitBigInteger(p, serialized, 0, size - 1);
      fail();
    } catch (IllegalArgumentException expected) {
      assertThat(expected).hasMessageThat().contains("Array is too small");
    }

    // Small array
    try {
      BigIntegerUtil.fitBigInteger(BigInteger.valueOf(511), serialized, 0, 1);
      fail();
    } catch (IllegalArgumentException expected) {
      assertThat(expected).hasMessageThat().contains("Array is too small");
    }
  }
}
