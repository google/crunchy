/*
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "crunchy/java/src/main/java/com/google/security/crunchy/jni/crypto.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "crunchy/internal/bindings/crypto.h"
#include "crunchy/internal/pure_c/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

static const char kGeneralSecurityExceptionClassName[] =
    "java/security/GeneralSecurityException";
static const char kNoErrorString[] = "Native method gave no error";

static void throw_exception(JNIEnv *env, const ccr_error *error) {
  jclass exception_class =
      (*env)->FindClass(env, kGeneralSecurityExceptionClassName);
  const char *error_message = error->message;
  if (error_message == NULL) {
    error_message = kNoErrorString;
  }
  (*env)->ThrowNew(env, exception_class, error_message);
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyCrypterBindings
 * Method:    createCrunchyCrypterBindings
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL
Java_com_google_security_crunchy_jni_CrunchyCrypterBindings_createCrunchyCrypterBindings(
    JNIEnv *env, jclass clazz, jbyteArray serialized_keyset) {
  ccr_error error;
  ccr_error_init(&error);
  size_t keyset_length = (*env)->GetArrayLength(env, serialized_keyset);
  int8_t *native_keyset =
      (*env)->GetByteArrayElements(env, serialized_keyset, JNI_FALSE);
  ccr_crypter *crypter = ccr_crypter_new_from_serialized_keyset(
      (uint8_t *)native_keyset, keyset_length, &error);
  (*env)->ReleaseByteArrayElements(env, serialized_keyset, native_keyset,
                                   JNI_ABORT);
  if (crypter == NULL) {
    throw_exception(env, &error);
  }
  ccr_error_cleanup(&error);
  return (jlong)(intptr_t)crypter;
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyCrypterBindings
 * Method:    destroyCrunchyCrypterBindings
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_google_security_crunchy_jni_CrunchyCrypterBindings_destroyCrunchyCrypterBindings(
    JNIEnv *env, jobject obj, jlong native_pointer) {
  ccr_crypter *crypter = (ccr_crypter *)(intptr_t)native_pointer;
  ccr_crypter_free(crypter);
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyCrypterBindings
 * Method:    encrypt
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_google_security_crunchy_jni_CrunchyCrypterBindings_encrypt__J_3B(
    JNIEnv *env, jobject obj, jlong native_pointer, jbyteArray plaintext) {
  ccr_crypter *crypter = (ccr_crypter *)(intptr_t)native_pointer;

  ccr_error error;
  ccr_error_init(&error);
  size_t plaintext_length = (*env)->GetArrayLength(env, plaintext);
  int8_t *native_plaintext =
      (*env)->GetByteArrayElements(env, plaintext, JNI_FALSE);

  size_t ciphertext_length =
      ccr_crypter_max_ciphertext_length(crypter, plaintext_length);

  int8_t *native_ciphertext = malloc(ciphertext_length);
  assert(native_ciphertext != NULL);
  jbyteArray ciphertext = NULL;

  size_t bytes_written = 0;
  int result = ccr_crypter_encrypt(
      crypter, (uint8_t *)native_plaintext, plaintext_length, NULL /* aad */,
      0 /* aad_length */, (uint8_t *)native_ciphertext, ciphertext_length,
      &bytes_written, &error);
  (*env)->ReleaseByteArrayElements(env, plaintext, native_plaintext, JNI_ABORT);
  if (result == 0) {
    throw_exception(env, &error);
  } else {
    ciphertext = (*env)->NewByteArray(env, bytes_written);
    (*env)->SetByteArrayRegion(env, ciphertext, 0 /* start */, bytes_written,
                               native_ciphertext);
  }
  free(native_ciphertext);
  ccr_error_cleanup(&error);

  return ciphertext;
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyCrypterBindings
 * Method:    decrypt
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_google_security_crunchy_jni_CrunchyCrypterBindings_decrypt__J_3B(
    JNIEnv *env, jobject obj, jlong native_pointer, jbyteArray ciphertext) {
  ccr_crypter *crypter = (ccr_crypter *)(intptr_t)native_pointer;

  ccr_error error;
  ccr_error_init(&error);
  size_t ciphertext_length = (*env)->GetArrayLength(env, ciphertext);
  int8_t *native_ciphertext =
      (*env)->GetByteArrayElements(env, ciphertext, JNI_FALSE);

  size_t plaintext_length =
      ccr_crypter_max_plaintext_length(crypter, ciphertext_length);

  int8_t *native_plaintext = malloc(plaintext_length);
  assert(native_plaintext != NULL);
  jbyteArray plaintext = NULL;

  size_t bytes_written = 0;
  int result = ccr_crypter_decrypt(
      crypter, (uint8_t *)native_ciphertext, ciphertext_length, NULL /* aad */,
      0 /* aad_length */, (uint8_t *)native_plaintext, plaintext_length,
      &bytes_written, &error);
  (*env)->ReleaseByteArrayElements(env, ciphertext, native_ciphertext,
                                   JNI_ABORT);
  if (result == 0) {
    throw_exception(env, &error);
  } else {
    plaintext = (*env)->NewByteArray(env, bytes_written);
    (*env)->SetByteArrayRegion(env, plaintext, 0 /* start */, bytes_written,
                               native_plaintext);
  }
  free(native_plaintext);
  ccr_error_cleanup(&error);

  return plaintext;
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyCrypterBindings
 * Method:    encrypt
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_google_security_crunchy_jni_CrunchyCrypterBindings_encrypt__J_3B_3B(
    JNIEnv *env, jobject obj, jlong native_pointer, jbyteArray plaintext,
    jbyteArray aad) {
  ccr_crypter *crypter = (ccr_crypter *)(intptr_t)native_pointer;

  ccr_error error;
  ccr_error_init(&error);
  size_t plaintext_length = (*env)->GetArrayLength(env, plaintext);
  int8_t *native_plaintext =
      (*env)->GetByteArrayElements(env, plaintext, JNI_FALSE);

  size_t aad_length = (*env)->GetArrayLength(env, aad);
  int8_t *native_aad = (*env)->GetByteArrayElements(env, aad, JNI_FALSE);

  size_t ciphertext_length =
      ccr_crypter_max_ciphertext_length(crypter, plaintext_length);

  int8_t *native_ciphertext = malloc(ciphertext_length);
  assert(native_ciphertext != NULL);
  jbyteArray ciphertext = NULL;

  size_t bytes_written = 0;
  int result = ccr_crypter_encrypt(
      crypter, (uint8_t *)native_plaintext, plaintext_length,
      (uint8_t *)native_aad, aad_length, (uint8_t *)native_ciphertext,
      ciphertext_length, &bytes_written, &error);
  (*env)->ReleaseByteArrayElements(env, plaintext, native_plaintext, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, aad, native_aad, JNI_ABORT);
  if (result == 0) {
    throw_exception(env, &error);
  } else {
    ciphertext = (*env)->NewByteArray(env, bytes_written);
    (*env)->SetByteArrayRegion(env, ciphertext, 0 /* start */, bytes_written,
                               native_ciphertext);
  }
  free(native_ciphertext);
  ccr_error_cleanup(&error);

  return ciphertext;
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyCrypterBindings
 * Method:    decrypt
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_google_security_crunchy_jni_CrunchyCrypterBindings_decrypt__J_3B_3B(
    JNIEnv *env, jobject obj, jlong native_pointer, jbyteArray ciphertext,
    jbyteArray aad) {
  ccr_crypter *crypter = (ccr_crypter *)(intptr_t)native_pointer;

  ccr_error error;
  ccr_error_init(&error);
  size_t ciphertext_length = (*env)->GetArrayLength(env, ciphertext);
  int8_t *native_ciphertext =
      (*env)->GetByteArrayElements(env, ciphertext, JNI_FALSE);

  size_t aad_length = (*env)->GetArrayLength(env, aad);
  int8_t *native_aad = (*env)->GetByteArrayElements(env, aad, JNI_FALSE);

  size_t plaintext_length =
      ccr_crypter_max_plaintext_length(crypter, ciphertext_length);

  // CHECK malloc result
  int8_t *native_plaintext = malloc(plaintext_length);
  assert(native_plaintext != NULL);
  jbyteArray plaintext = NULL;

  size_t bytes_written = 0;
  int result = ccr_crypter_decrypt(
      crypter, (uint8_t *)native_ciphertext, ciphertext_length,
      (uint8_t *)native_aad, aad_length, (uint8_t *)native_plaintext,
      plaintext_length, &bytes_written, &error);
  (*env)->ReleaseByteArrayElements(env, ciphertext, native_ciphertext,
                                   JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, aad, native_aad, JNI_ABORT);
  if (result == 0) {
    throw_exception(env, &error);
  } else {
    plaintext = (*env)->NewByteArray(env, bytes_written);
    (*env)->SetByteArrayRegion(env, plaintext, 0 /* start */, bytes_written,
                               native_plaintext);
  }
  free(native_plaintext);
  ccr_error_cleanup(&error);

  return plaintext;
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyHybridDecrypterBindings
 * Method:    createCrunchyHybridDecrypterBindings
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL
Java_com_google_security_crunchy_jni_CrunchyHybridDecrypterBindings_createCrunchyHybridDecrypterBindings(
    JNIEnv *env, jclass clazz, jbyteArray serialized_keyset) {
  ccr_error error;
  ccr_error_init(&error);
  size_t keyset_length = (*env)->GetArrayLength(env, serialized_keyset);
  int8_t *native_keyset =
      (*env)->GetByteArrayElements(env, serialized_keyset, JNI_FALSE);
  ccr_hybrid_decrypter *hybrid_decrypter =
      ccr_hybrid_decrypter_new_from_serialized_keyset((uint8_t *)native_keyset,
                                                      keyset_length, &error);
  (*env)->ReleaseByteArrayElements(env, serialized_keyset, native_keyset,
                                   JNI_ABORT);
  if (hybrid_decrypter == NULL) {
    throw_exception(env, &error);
  }
  ccr_error_cleanup(&error);
  return (jlong)(intptr_t)hybrid_decrypter;
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyHybridDecrypterBindings
 * Method:    destroyCrunchyHybridDecrypterBindings
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_google_security_crunchy_jni_CrunchyHybridDecrypterBindings_destroyCrunchyHybridDecrypterBindings(
    JNIEnv *env, jobject obj, jlong native_pointer) {
  ccr_hybrid_decrypter *hybrid_decrypter =
      (ccr_hybrid_decrypter *)(intptr_t)native_pointer;
  ccr_hybrid_decrypter_free(hybrid_decrypter);
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyHybridDecrypterBindings
 * Method:    decrypt
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_google_security_crunchy_jni_CrunchyHybridDecrypterBindings_decrypt(
    JNIEnv *env, jobject obj, jlong native_pointer, jbyteArray ciphertext) {
  ccr_hybrid_decrypter *hybrid_decrypter =
      (ccr_hybrid_decrypter *)(intptr_t)native_pointer;

  ccr_error error;
  ccr_error_init(&error);
  size_t ciphertext_length = (*env)->GetArrayLength(env, ciphertext);
  int8_t *native_ciphertext =
      (*env)->GetByteArrayElements(env, ciphertext, JNI_FALSE);

  size_t plaintext_length = ccr_hybrid_decrypter_max_plaintext_length(
      hybrid_decrypter, ciphertext_length);

  int8_t *native_plaintext = malloc(plaintext_length);
  assert(native_plaintext != NULL);
  jbyteArray plaintext = NULL;

  size_t bytes_written = 0;
  int result = ccr_hybrid_decrypter_decrypt(
      hybrid_decrypter, (uint8_t *)native_ciphertext, ciphertext_length,
      (uint8_t *)native_plaintext, plaintext_length, &bytes_written, &error);
  (*env)->ReleaseByteArrayElements(env, ciphertext, native_ciphertext,
                                   JNI_ABORT);
  if (result == 0) {
    throw_exception(env, &error);
  } else {
    plaintext = (*env)->NewByteArray(env, bytes_written);
    (*env)->SetByteArrayRegion(env, plaintext, 0 /* start */, bytes_written,
                               native_plaintext);
  }
  free(native_plaintext);
  ccr_error_cleanup(&error);

  return plaintext;
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyHybridEncrypterBindings
 * Method:    createCrunchyHybridEncrypterBindings
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL
Java_com_google_security_crunchy_jni_CrunchyHybridEncrypterBindings_createCrunchyHybridEncrypterBindings(
    JNIEnv *env, jclass clazz, jbyteArray serialized_keyset) {
  ccr_error error;
  ccr_error_init(&error);
  size_t keyset_length = (*env)->GetArrayLength(env, serialized_keyset);
  int8_t *native_keyset =
      (*env)->GetByteArrayElements(env, serialized_keyset, JNI_FALSE);
  ccr_hybrid_encrypter *hybrid_encrypter =
      ccr_hybrid_encrypter_new_from_serialized_keyset((uint8_t *)native_keyset,
                                                      keyset_length, &error);
  (*env)->ReleaseByteArrayElements(env, serialized_keyset, native_keyset,
                                   JNI_ABORT);
  if (hybrid_encrypter == NULL) {
    throw_exception(env, &error);
  }
  ccr_error_cleanup(&error);
  return (jlong)(intptr_t)hybrid_encrypter;
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyHybridEncrypterBindings
 * Method:    destroyCrunchyHybridEncrypterBindings
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_google_security_crunchy_jni_CrunchyHybridEncrypterBindings_destroyCrunchyHybridEncrypterBindings(
    JNIEnv *env, jobject obj, jlong native_pointer) {
  ccr_hybrid_encrypter *hybrid_encrypter =
      (ccr_hybrid_encrypter *)(intptr_t)native_pointer;
  ccr_hybrid_encrypter_free(hybrid_encrypter);
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyHybridEncrypterBindings
 * Method:    encrypt
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_google_security_crunchy_jni_CrunchyHybridEncrypterBindings_encrypt(
    JNIEnv *env, jobject obj, jlong native_pointer, jbyteArray plaintext) {
  ccr_hybrid_encrypter *hybrid_encrypter =
      (ccr_hybrid_encrypter *)(intptr_t)native_pointer;

  ccr_error error;
  ccr_error_init(&error);
  size_t plaintext_length = (*env)->GetArrayLength(env, plaintext);
  int8_t *native_plaintext =
      (*env)->GetByteArrayElements(env, plaintext, JNI_FALSE);

  size_t ciphertext_length = ccr_hybrid_encrypter_max_ciphertext_length(
      hybrid_encrypter, plaintext_length);

  int8_t *native_ciphertext = malloc(ciphertext_length);
  assert(native_ciphertext != NULL);
  jbyteArray ciphertext = NULL;

  size_t bytes_written = 0;
  int result = ccr_hybrid_encrypter_encrypt(
      hybrid_encrypter, (uint8_t *)native_plaintext, plaintext_length,
      (uint8_t *)native_ciphertext, ciphertext_length, &bytes_written, &error);
  (*env)->ReleaseByteArrayElements(env, plaintext, native_plaintext, JNI_ABORT);
  if (result == 0) {
    throw_exception(env, &error);
  } else {
    ciphertext = (*env)->NewByteArray(env, bytes_written);
    (*env)->SetByteArrayRegion(env, ciphertext, 0 /* start */, bytes_written,
                               native_ciphertext);
  }
  free(native_ciphertext);
  ccr_error_cleanup(&error);

  return ciphertext;
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyMacerBindings
 * Method:    createCrunchyMacerBindings
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL
Java_com_google_security_crunchy_jni_CrunchyMacerBindings_createCrunchyMacerBindings(
    JNIEnv *env, jclass clazz, jbyteArray serialized_keyset) {
  ccr_error error;
  ccr_error_init(&error);
  size_t keyset_length = (*env)->GetArrayLength(env, serialized_keyset);
  int8_t *native_keyset =
      (*env)->GetByteArrayElements(env, serialized_keyset, JNI_FALSE);
  ccr_macer *macer = ccr_macer_new_from_serialized_keyset(
      (uint8_t *)native_keyset, keyset_length, &error);
  (*env)->ReleaseByteArrayElements(env, serialized_keyset, native_keyset,
                                   JNI_ABORT);
  if (macer == NULL) {
    throw_exception(env, &error);
  }
  ccr_error_cleanup(&error);
  return (jlong)(intptr_t)macer;
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyMacerBindings
 * Method:    destroyCrunchyMacerBindings
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_google_security_crunchy_jni_CrunchyMacerBindings_destroyCrunchyMacerBindings(
    JNIEnv *env, jobject obj, jlong native_pointer) {
  ccr_macer *macer = (ccr_macer *)(intptr_t)native_pointer;
  ccr_macer_free(macer);
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyMacerBindings
 * Method:    sign
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_google_security_crunchy_jni_CrunchyMacerBindings_sign(
    JNIEnv *env, jobject obj, jlong native_pointer, jbyteArray message) {
  ccr_macer *macer = (ccr_macer *)(intptr_t)native_pointer;

  ccr_error error;
  ccr_error_init(&error);
  size_t message_length = (*env)->GetArrayLength(env, message);
  int8_t *native_message =
      (*env)->GetByteArrayElements(env, message, JNI_FALSE);

  size_t signature_length = ccr_macer_max_signature_length(macer);

  int8_t *native_signature = malloc(signature_length);
  assert(native_signature != NULL);
  jbyteArray signature = NULL;

  size_t bytes_written = 0;
  int result = ccr_macer_sign(macer, (uint8_t *)native_message, message_length,
                              (uint8_t *)native_signature, signature_length,
                              &bytes_written, &error);
  (*env)->ReleaseByteArrayElements(env, message, native_message, JNI_ABORT);
  if (result == 0) {
    throw_exception(env, &error);
  } else {
    signature = (*env)->NewByteArray(env, bytes_written);
    (*env)->SetByteArrayRegion(env, signature, 0 /* start */, bytes_written,
                               native_signature);
  }
  free(native_signature);
  ccr_error_cleanup(&error);

  return signature;
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyMacerBindings
 * Method:    verify
 * Signature: (J[B[B)V
 */
JNIEXPORT void JNICALL
Java_com_google_security_crunchy_jni_CrunchyMacerBindings_verify(
    JNIEnv *env, jobject obj, jlong native_pointer, jbyteArray message,
    jbyteArray signature) {
  ccr_macer *macer = (ccr_macer *)(intptr_t)native_pointer;

  ccr_error error;
  ccr_error_init(&error);
  size_t message_length = (*env)->GetArrayLength(env, message);
  int8_t *native_message =
      (*env)->GetByteArrayElements(env, message, JNI_FALSE);

  size_t signature_length = (*env)->GetArrayLength(env, signature);
  int8_t *native_signature =
      (*env)->GetByteArrayElements(env, signature, JNI_FALSE);

  int result =
      ccr_macer_verify(macer, (uint8_t *)native_message, message_length,
                       (uint8_t *)native_signature, signature_length, &error);
  (*env)->ReleaseByteArrayElements(env, message, native_message, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, signature, native_signature, JNI_ABORT);
  if (result == 0) {
    throw_exception(env, &error);
  }
  ccr_error_cleanup(&error);
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchySignerBindings
 * Method:    createCrunchySignerBindings
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL
Java_com_google_security_crunchy_jni_CrunchySignerBindings_createCrunchySignerBindings(
    JNIEnv *env, jclass clazz, jbyteArray serialized_keyset) {
  ccr_error error;
  ccr_error_init(&error);
  size_t keyset_length = (*env)->GetArrayLength(env, serialized_keyset);
  int8_t *native_keyset =
      (*env)->GetByteArrayElements(env, serialized_keyset, JNI_FALSE);
  ccr_signer *signer = ccr_signer_new_from_serialized_keyset(
      (uint8_t *)native_keyset, keyset_length, &error);
  (*env)->ReleaseByteArrayElements(env, serialized_keyset, native_keyset,
                                   JNI_ABORT);
  if (signer == NULL) {
    throw_exception(env, &error);
  }
  ccr_error_cleanup(&error);
  return (jlong)(intptr_t)signer;
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchySignerBindings
 * Method:    destroyCrunchySignerBindings
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_google_security_crunchy_jni_CrunchySignerBindings_destroyCrunchySignerBindings(
    JNIEnv *env, jobject obj, jlong native_pointer) {
  ccr_signer *signer = (ccr_signer *)(intptr_t)native_pointer;
  ccr_signer_free(signer);
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchySignerBindings
 * Method:    sign
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_google_security_crunchy_jni_CrunchySignerBindings_sign(
    JNIEnv *env, jobject obj, jlong native_pointer, jbyteArray message) {
  ccr_signer *signer = (ccr_signer *)(intptr_t)native_pointer;

  ccr_error error;
  ccr_error_init(&error);
  size_t message_length = (*env)->GetArrayLength(env, message);
  int8_t *native_message =
      (*env)->GetByteArrayElements(env, message, JNI_FALSE);

  size_t signature_length = ccr_signer_max_signature_length(signer);

  // CHECK malloc result
  int8_t *native_signature = malloc(signature_length);
  assert(native_signature != NULL);
  jbyteArray signature = NULL;

  size_t bytes_written = 0;
  int result = ccr_signer_sign(signer, (uint8_t *)native_message,
                               message_length, (uint8_t *)native_signature,
                               signature_length, &bytes_written, &error);
  (*env)->ReleaseByteArrayElements(env, message, native_message, JNI_ABORT);
  if (result == 0) {
    throw_exception(env, &error);
  } else {
    signature = (*env)->NewByteArray(env, bytes_written);
    (*env)->SetByteArrayRegion(env, signature, 0 /* start */, bytes_written,
                               native_signature);
  }
  free(native_signature);
  ccr_error_cleanup(&error);

  return signature;
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyVerifierBindings
 * Method:    createCrunchyVerifierBindings
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL
Java_com_google_security_crunchy_jni_CrunchyVerifierBindings_createCrunchyVerifierBindings(
    JNIEnv *env, jclass clazz, jbyteArray serialized_keyset) {
  ccr_error error;
  ccr_error_init(&error);
  size_t keyset_length = (*env)->GetArrayLength(env, serialized_keyset);
  int8_t *native_keyset =
      (*env)->GetByteArrayElements(env, serialized_keyset, JNI_FALSE);
  ccr_verifier *verifier = ccr_verifier_new_from_serialized_keyset(
      (uint8_t *)native_keyset, keyset_length, &error);
  (*env)->ReleaseByteArrayElements(env, serialized_keyset, native_keyset,
                                   JNI_ABORT);
  if (verifier == NULL) {
    throw_exception(env, &error);
  }
  ccr_error_cleanup(&error);
  return (jlong)(intptr_t)verifier;
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyVerifierBindings
 * Method:    destroyCrunchyVerifierBindings
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_google_security_crunchy_jni_CrunchyVerifierBindings_destroyCrunchyVerifierBindings(
    JNIEnv *env, jobject obj, jlong native_pointer) {
  ccr_verifier *verifier = (ccr_verifier *)(intptr_t)native_pointer;
  ccr_verifier_free(verifier);
}

/*
 * Class:     com_google_security_crunchy_jni_CrunchyVerifierBindings
 * Method:    verify
 * Signature: (J[B[B)V
 */
JNIEXPORT void JNICALL
Java_com_google_security_crunchy_jni_CrunchyVerifierBindings_verify(
    JNIEnv *env, jobject obj, jlong native_pointer, jbyteArray message,
    jbyteArray signature) {
  ccr_verifier *verifier = (ccr_verifier *)(intptr_t)native_pointer;

  ccr_error error;
  ccr_error_init(&error);
  size_t message_length = (*env)->GetArrayLength(env, message);
  int8_t *native_message =
      (*env)->GetByteArrayElements(env, message, JNI_FALSE);

  size_t signature_length = (*env)->GetArrayLength(env, signature);
  int8_t *native_signature =
      (*env)->GetByteArrayElements(env, signature, JNI_FALSE);

  int result = ccr_verifier_verify(verifier, (uint8_t *)native_message,
                                   message_length, (uint8_t *)native_signature,
                                   signature_length, &error);
  (*env)->ReleaseByteArrayElements(env, message, native_message, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, signature, native_signature, JNI_ABORT);
  if (result == 0) {
    throw_exception(env, &error);
  }
  ccr_error_cleanup(&error);
}

#ifdef __cplusplus
}
#endif
