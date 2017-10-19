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

package com.google.security.crunchy;

import java.security.GeneralSecurityException;

/**
 * An interface for symmetric encryption and decryption. Implementations may use authenticated
 * encryption and key versioning.
 */
public interface CrunchyCrypter {
  /**
   * Encrypts a payload.
   *
   * @param plaintext The plaintext to be encrypted.
   * @return The encrypted plaintext.
   * @throws GeneralSecurityException If the underlying crypto library returns an error.
   */
  public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException;

  /**
   * Encrypts a payload.
   *
   * @param plaintext The plaintext to be encrypted.
   * @param aad Additional authenticated data that is authenticated with the plaintext, if
   *     supported.
   * @return The encrypted plaintext.
   * @throws GeneralSecurityException If the underlying crypto library returns an error or aad is
   *     used but not supported.
   */
  public byte[] encrypt(byte[] plaintext, byte[] aad) throws GeneralSecurityException;

  /**
   * Decrypts a payload.
   *
   * @param ciphertext The ciphertext to be decrypted.
   * @return The encrypted plaintext.
   * @throws GeneralSecurityException If the ciphertext failed an authentication check, if the key
   * identifier in the ciphertext cannot be found, or if the underlying crypto library returns an
   * error.
   */
  public byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException;

  /**
   * Decrypts a payload.
   *
   * @param ciphertext The ciphertext to be decrypted.
   * @param aad Additional authenticated data that is authenticated with the plaintext, if
   *     supported.
   * @return The encrypted plaintext.
   * @throws GeneralSecurityException If the ciphertext failed an authentication check, if the key
   *     identifier in the ciphertext cannot be found, if aad is used but not supported, or if the
   *     underlying crypto library returns an error.
   */
  public byte[] decrypt(byte[] ciphertext, byte[] aad) throws GeneralSecurityException;
}
