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

import com.google.common.primitives.Bytes;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ByteUtilTest {

  @Test
  public void testConsume() {
    byte[] left = RandUtil.randomArray(42);
    byte[] right = RandUtil.randomArray(1215);
    byte[] combined = Bytes.concat(left, right);

    Optional<byte[]> consumed = ByteUtil.consumePrefix(combined, left);
    assertThat(consumed.isPresent()).isTrue();
    assertThat(consumed.get()).isEqualTo(right);
  }

  @Test
  public void testConsumeShort() {
    byte[] payload = RandUtil.randomArray(41);
    byte[] nonPrefix = RandUtil.randomArray(42);
    Optional<byte[]> consumed = ByteUtil.consumePrefix(payload, nonPrefix);
    assertThat(consumed.isPresent()).isFalse();
  }

  @Test
  public void testConsumeMiss() {
    byte[] payload = RandUtil.randomArray(1024);
    byte[] nonPrefix = RandUtil.randomArray(1024);
    Optional<byte[]> consumed = ByteUtil.consumePrefix(payload, nonPrefix);
    assertThat(consumed.isPresent()).isFalse();
  }
}
