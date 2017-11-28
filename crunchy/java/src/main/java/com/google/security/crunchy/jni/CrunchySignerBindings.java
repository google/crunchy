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

import com.google.security.crunchy.CrunchySigner;
import java.security.GeneralSecurityException;

/** A jni-based implementation of CrunchySigner. */
public class CrunchySignerBindings implements CrunchySigner {
  static {
    InitJni.InitJni();
  }

  private long nativePointer;

  public static CrunchySigner newInstance(byte[] keyset) throws GeneralSecurityException {
    return new CrunchySignerBindings(keyset);
  }

  CrunchySignerBindings(byte[] keyset) throws GeneralSecurityException {
    checkNotNull(keyset);
    nativePointer = createCrunchySignerBindings(keyset);
  }

  @Override
  public byte[] sign(byte[] message) throws GeneralSecurityException {
    checkNotNull(message);
    checkState(nativePointer != 0, "nativePointer is 0, possible use after a call to finalize()");
    return sign(nativePointer, message);
  }

  @Override
  protected void finalize() {
    destroyCrunchySignerBindings(nativePointer);
    nativePointer = 0;
  }

  /**
   * Creates a object in the jni to back this CrunchySigner.
   *
   * @param keyset A serialized Keyset
   * @return The value of the native pointer behind the jni.
   * @throws GeneralSecurityException If the keyset is malformed, contains unsupported
   *     types, or if underlying crypto library returns an error.
   */
  private static native long createCrunchySignerBindings(byte[] keyset)
      throws GeneralSecurityException;

  /**
   * Frees any native memory that was constructed by createCrunchySignerBindings.
   *
   * @param nativePointer The value of the native pointer behind the jni.
   */
  private native void destroyCrunchySignerBindings(long nativePointer);

  /**
   * Signs a message.
   *
   * @param nativePointer The value of the native pointer behind the jni.
   * @param message The message to be signed.
   * @return The signature of the message.
   * @throws GeneralSecurityException If the underlying crypto library returns an error.
   */
  public native byte[] sign(long nativePointer, byte[] message) throws GeneralSecurityException;
}
