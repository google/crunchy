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

import com.google.security.crunchy.CrunchyMacer;
import java.security.GeneralSecurityException;

/** A jni-based implementation of CrunchyMacer. */
public class CrunchyMacerBindings implements CrunchyMacer {
  static {
    InitJni.InitJni();
  }

  private long nativePointer;

  public static CrunchyMacer newInstance(byte[] keyset) throws GeneralSecurityException {
    return new CrunchyMacerBindings(keyset);
  }

  CrunchyMacerBindings(byte[] keyset) throws GeneralSecurityException {
    checkNotNull(keyset);
    nativePointer = createCrunchyMacerBindings(keyset);
  }

  @Override
  public byte[] sign(byte[] message) throws GeneralSecurityException {
    checkNotNull(message);
    checkState(nativePointer != 0, "nativePointer is 0, possible use after a call to finalize()");
    return sign(nativePointer, message);
  }

  @Override
  public void verify(byte[] message, byte[] signature) throws GeneralSecurityException {
    checkNotNull(message);
    checkNotNull(signature);
    checkState(nativePointer != 0, "nativePointer is 0, possible use after a call to finalize()");
    verify(nativePointer, message, signature);
  }

  @Override
  protected void finalize() {
    destroyCrunchyMacerBindings(nativePointer);
    nativePointer = 0;
  }

  /**
   * Creates a object in the jni to back this CrunchyMacer.
   *
   * @param keyset A serialized Keyset
   * @return The value of the native pointer behind the jni.
   * @throws GeneralSecurityException If the keyset is malformed, contains unsupported
   *     types, or if underlying crypto library returns an error.
   */
  private static native long createCrunchyMacerBindings(byte[] keyset)
      throws GeneralSecurityException;

  /**
   * Frees any native memory that was constructed by createCrunchyMacerBindings.
   *
   * @param nativePointer The value of the native pointer behind the jni.
   */
  private native void destroyCrunchyMacerBindings(long nativePointer);

  /**
   * Signs a message.
   *
   * @param nativePointer The value of the native pointer behind the jni.
   * @param message The message to be signed.
   * @return The signature of the message.
   * @throws GeneralSecurityException If the underlying crypto library returns an error.
   */
  public native byte[] sign(long nativePointer, byte[] message) throws GeneralSecurityException;

  /**
   * Verifies a message.
   *
   * @param nativePointer The value of the native pointer behind the jni.
   * @param message The message to be verified.
   * @param message The signature to be verified.
   * @throws GeneralSecurityException If the signature is invalid or if the underlying crypto
   *     library returns an error.
   */
  public native void verify(long nativePointer, byte[] message, byte[] signature)
      throws GeneralSecurityException;
}
