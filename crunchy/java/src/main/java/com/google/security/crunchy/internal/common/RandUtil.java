// Copyright 2018 The CrunchyCrypt Authors.
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

import java.security.SecureRandom;

/** A helper class dealing with randomness. */
public final class RandUtil {
  private static final SecureRandom random = new SecureRandom();

  /** Returns random bytes. */
  public static byte[] randomArray(int size) {
    byte[] array = new byte[size];
    random.nextBytes(array);
    return array;
  }

  private RandUtil() {}
}
