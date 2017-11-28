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

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

import com.google.security.crunchy.CrunchyHybridEncrypter;
import java.security.GeneralSecurityException;

/** A jni-based implementation of CrunchyHybridEncrypter. */
public class CrunchyHybridEncrypterBindings implements CrunchyHybridEncrypter {
  static {
    InitJni.InitJni();
  }

  private long nativePointer;

  public static CrunchyHybridEncrypter newInstance(byte[] keyset) throws GeneralSecurityException {
    return new CrunchyHybridEncrypterBindings(keyset);
  }

  CrunchyHybridEncrypterBindings(byte[] keyset) throws GeneralSecurityException {
    checkNotNull(keyset);
    nativePointer = createCrunchyHybridEncrypterBindings(keyset);
  }

  @Override
  public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException {
    checkNotNull(plaintext);
    checkState(nativePointer != 0, "nativePointer is 0, possible use after a call to finalize()");
    return encrypt(nativePointer, plaintext);
  }

  @Override
  protected void finalize() {
    destroyCrunchyHybridEncrypterBindings(nativePointer);
    nativePointer = 0;
  }

  /**
   * Creates a object in the jni to back this CrunchyHybridEncrypter.
   *
   * @param keyset A serialized Keyset
   * @return The value of the native pointer behind the jni.
   * @throws GeneralSecurityException If the keyset is malformed, contains unsupported
   *     types, or if underlying crypto library returns an error.
   */
  private static native long createCrunchyHybridEncrypterBindings(byte[] keyset)
      throws GeneralSecurityException;

  /**
   * Frees any native memory that was constructed by createCrunchyHybridEncrypterBindings.
   *
   * @param nativePointer The value of the native pointer behind the jni.
   */
  private native void destroyCrunchyHybridEncrypterBindings(long nativePointer);

  /**
   * Encrypts a payload.
   *
   * @param nativePointer The value of the native pointer behind the jni.
   * @param plaintext The plaintext to be encrypted.
   * @return The encrypted plaintext.
   * @throws GeneralSecurityException If the underlying crypto library returns an error.
   */
  private native byte[] encrypt(long nativePointer, byte[] plaintext)
      throws GeneralSecurityException;
}
