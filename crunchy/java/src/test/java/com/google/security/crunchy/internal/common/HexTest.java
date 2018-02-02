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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Hex}. */
@RunWith(JUnit4.class)
public final class HexTest {
  @Test
  public void testHex() {
    String hex = "2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970";
    byte[] bytes = Hex.fromHex(hex);
    assertThat(hex.toUpperCase()).isEqualTo(Hex.toHex(bytes).toUpperCase());

    // Test a leading 0
    hex = "0442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970";
    bytes = Hex.fromHex(hex);
    assertThat(hex.toUpperCase()).isEqualTo(Hex.toHex(bytes).toUpperCase());

    // Test a leading high bit
    hex = "8442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970";
    bytes = Hex.fromHex(hex);
    assertThat(hex.toUpperCase()).isEqualTo(Hex.toHex(bytes).toUpperCase());

    // Test adding leading zeros
    hex = "0001";
    bytes = new byte[] {0, 1};
    assertThat(hex.toUpperCase()).isEqualTo(Hex.toHex(bytes).toUpperCase());

    try {
      Hex.fromHex("101");
      fail();
    } catch (IllegalArgumentException expected) {
      assertThat(expected)
          .hasMessageThat()
          .contains("Byte hex must contain an even number of hex digits");
    }
  }
}
