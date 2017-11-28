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

import com.google.security.crunchy.CrunchyHybridDecrypter;
import java.security.GeneralSecurityException;

/** A jni-based implementation of CrunchyHybridDecrypter. */
public class CrunchyHybridDecrypterBindings implements CrunchyHybridDecrypter {
  static {
    InitJni.InitJni();
  }

  private long nativePointer;

  public static CrunchyHybridDecrypter newInstance(byte[] keyset) throws GeneralSecurityException {
    return new CrunchyHybridDecrypterBindings(keyset);
  }

  CrunchyHybridDecrypterBindings(byte[] keyset) throws GeneralSecurityException {
    checkNotNull(keyset);
    nativePointer = createCrunchyHybridDecrypterBindings(keyset);
  }

  @Override
  public byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException {
    checkNotNull(ciphertext);
    checkState(nativePointer != 0, "nativePointer is 0, possible use after a call to finalize()");
    return decrypt(nativePointer, ciphertext);
  }

  @Override
  protected void finalize() {
    destroyCrunchyHybridDecrypterBindings(nativePointer);
    nativePointer = 0;
  }

  /**
   * Creates a object in the jni to back this CrunchyHybridDecrypter.
   *
   * @param keyset A serialized Keyset
   * @return The value of the native pointer behind the jni.
   * @throws GeneralSecurityException If the keyset is malformed, contains unsupported
   *     types, or if underlying crypto library returns an error.
   */
  private static native long createCrunchyHybridDecrypterBindings(byte[] keyset)
      throws GeneralSecurityException;

  /**
   * Frees any native memory that was constructed by createCrunchyHybridDecrypterBindings.
   *
   * @param nativePointer The value of the native pointer behind the jni.
   */
  private native void destroyCrunchyHybridDecrypterBindings(long nativePointer);

  /**
   * Decrypts a payload.
   *
   * @param nativePointer The value of the native pointer behind the jni.
   * @param ciphertext The ciphertext to be decrypted.
   * @return The encrypted plaintext.
   * @throws GeneralSecurityException If the ciphertext failed an authentication check, if the key
   *     identifier in the ciphertext cannot be found, or if the underlying crypto library returns
   *     an error.
   */
  private native byte[] decrypt(long nativePointer, byte[] ciphertext)
      throws GeneralSecurityException;
}
