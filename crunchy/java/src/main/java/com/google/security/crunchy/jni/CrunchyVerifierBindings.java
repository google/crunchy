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

import com.google.security.crunchy.CrunchyVerifier;
import java.security.GeneralSecurityException;

/** A jni-based implementation of CrunchyVerifier. */
public class CrunchyVerifierBindings implements CrunchyVerifier {
  static {
    InitJni.InitJni();
  }

  private long nativePointer;

  public static CrunchyVerifier newInstance(byte[] keyset) throws GeneralSecurityException {
    return new CrunchyVerifierBindings(keyset);
  }

  CrunchyVerifierBindings(byte[] keyset) throws GeneralSecurityException {
    checkNotNull(keyset);
    nativePointer = createCrunchyVerifierBindings(keyset);
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
    destroyCrunchyVerifierBindings(nativePointer);
    nativePointer = 0;
  }

  /**
   * Creates a object in the jni to back this CrunchyVerifier.
   *
   * @param keyset A serialized Keyset
   * @return The value of the native pointer behind the jni.
   * @throws GeneralSecurityException If the keyset is malformed, contains unsupported
   *     types, or if underlying crypto library returns an error.
   */
  private static native long createCrunchyVerifierBindings(byte[] keyset)
      throws GeneralSecurityException;

  /**
   * Frees any native memory that was constructed by createCrunchyVerifierBindings.
   *
   * @param nativePointer The value of the native pointer behind the jni.
   */
  private static native void destroyCrunchyVerifierBindings(long nativePointer);

  /**
   * Verifies a message.
   *
   * @param nativePointer The value of the native pointer behind the jni.
   * @param message The message to be verified.
   * @param message The signature to be verified.
   * @throws GeneralSecurityException If the signature is invalid or if the underlying crypto
   *     library returns an error.
   */
  public static native void verify(long nativePointer, byte[] message, byte[] signature)
      throws GeneralSecurityException;
}
