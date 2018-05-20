/*
 * Copyright 2018 The Android Open Source Project
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
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include <iostream>
#include <algorithm>
//#include <keystore/keystore.h>

#include <hardware/hardware.h>
#include <hardware/keymaster0.h>
#include <hardware/keymaster1.h>
#include <hardware/keymaster2.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <UniquePtr.h>
#include <cutils/log.h>

#include <keymaster/logger.h>
#include <keymaster/android_keymaster_utils.h>
#include <keymaster/authorization_set.h>
#include <keymaster/keymaster_enforcement.h>

// For debugging
#define LOG_NDEBUG 1
#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "OpteeKeyMaster2"
#endif

using namespace keymaster;

/* keymaster2 APIs */
keymaster_error_t optee_configure(const keymaster2_device_t* dev,
                                                 const keymaster_key_param_set_t* params) {
	LOG_D("%s:%d\n", __func__, __LINE__);
	return KM_ERROR_OK;
}

keymaster_error_t optee_add_rng_entropy(const keymaster1_device_t* dev,
                                                       const uint8_t* data, size_t data_length) {
	LOG_D("%s:%d\n", __func__, __LINE__);
	return KM_ERROR_OK;
}

keymaster_error_t optee_add_rng_entropy(const keymaster2_device_t* dev,
                                                       const uint8_t* data, size_t data_length) {
	LOG_D("%s:%d\n", __func__, __LINE__);
	return KM_ERROR_OK;
}

keymaster_error_t optee_generate_key(const keymaster2_device_t* dev,  //
                                  const keymaster_key_param_set_t* params,
                                  keymaster_key_blob_t* key_blob,
                                  keymaster_key_characteristics_t* characteristics) {
    keymaster_error_t error = KM_ERROR_OK;
    KeymasterKeyBlob generated_blob;
    KeymasterKeyBlob ret_blob;
    AuthorizationSet key_description;
    AuthorizationSet sw_enforced, hw_enforced;
    keymaster_algorithm_t algorithm;
    uint32_t key_len;

	LOG_D("%s:%d\n", __func__, __LINE__);
    if (!dev || !params) {
        LOG_D("%s:%d\n", __func__, __LINE__);
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }

    if (!key_blob) {
        LOG_D("%s:%d\n", __func__, __LINE__);
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    if (!key_description.Reinitialize(*params)) {
        LOG_D("%s:%d\n", __func__, __LINE__);
        LOG_D("Reinitialize failed !", 0);
        error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        goto out;
    }

    if (!key_description.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        LOG_D("%s:%d\n", __func__, __LINE__);
        LOG_D("Cannot get algorithm!", 0);
        error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }

    if (algorithm == KM_ALGORITHM_AES) {
        if (!key_description.GetTagValue(TAG_KEY_SIZE, key_len) ||
                (key_len != 128 && key_len != 256 && key_len != 192)) {
            error = KM_ERROR_UNSUPPORTED_KEY_SIZE;
            goto out;
        }

        // TODO generate aes key n save to key_blob
    }

    return KM_ERROR_OK;
}

keymaster_error_t optee_get_key_characteristics(
    const keymaster2_device_t* dev, const keymaster_key_blob_t* key_blob,
    const keymaster_blob_t* client_id, const keymaster_blob_t* app_data,
    keymaster_key_characteristics_t* characteristics) {
	LOG_D("%s:%d\n", __func__, __LINE__);
	return KM_ERROR_OK;
}

keymaster_error_t optee_import_key(
    const keymaster2_device_t* dev, const keymaster_key_param_set_t* params,
    keymaster_key_format_t key_format, const keymaster_blob_t* key_data,
    keymaster_key_blob_t* key_blob, keymaster_key_characteristics_t* characteristics) {
	LOG_D("%s:%d\n", __func__, __LINE__);
	return KM_ERROR_OK;
}

keymaster_error_t optee_export_key(const keymaster2_device_t* dev,
                                                  keymaster_key_format_t export_format,
                                                  const keymaster_key_blob_t* key_to_export,
                                                  const keymaster_blob_t* client_id,
                                                  const keymaster_blob_t* app_data,
                                                  keymaster_blob_t* export_data) {
	LOG_D("%s:%d\n", __func__, __LINE__);
	return KM_ERROR_OK;
}

keymaster_error_t optee_attest_key(const keymaster2_device_t* dev,
                                                  const keymaster_key_blob_t* key_to_attest,
                                                  const keymaster_key_param_set_t* attest_params,
                                                  keymaster_cert_chain_t* cert_chain) {
	LOG_D("%s:%d\n", __func__, __LINE__);
	return KM_ERROR_OK;
}

keymaster_error_t optee_upgrade_key(const keymaster2_device_t* dev,
                                                   const keymaster_key_blob_t* key_to_upgrade,
                                                   const keymaster_key_param_set_t* upgrade_params,
                                                   keymaster_key_blob_t* upgraded_key) {
	LOG_D("%s:%d\n", __func__, __LINE__);
	return KM_ERROR_OK;
}

keymaster_error_t optee_delete_key(const keymaster2_device_t* dev,
                                                  const keymaster_key_blob_t* key) {
	LOG_D("%s:%d\n", __func__, __LINE__);
	return KM_ERROR_OK;
}

keymaster_error_t optee_delete_all_keys(const keymaster2_device_t* dev) {
	LOG_D("%s:%d\n", __func__, __LINE__);
	return KM_ERROR_OK;
}

keymaster_error_t optee_begin(const keymaster2_device_t* dev,
                                             keymaster_purpose_t purpose,
                                             const keymaster_key_blob_t* key,
                                             const keymaster_key_param_set_t* in_params,
                                             keymaster_key_param_set_t* out_params,
                                             keymaster_operation_handle_t* operation_handle) {
	LOG_D("%s:%d\n", __func__, __LINE__);
	return KM_ERROR_OK;
}

keymaster_error_t optee_update(const keymaster2_device_t* dev,
                                              keymaster_operation_handle_t operation_handle,
                                              const keymaster_key_param_set_t* in_params,
                                              const keymaster_blob_t* input, size_t* input_consumed,
                                              keymaster_key_param_set_t* out_params,
                                              keymaster_blob_t* output) {
	LOG_D("%s:%d\n", __func__, __LINE__);
	return KM_ERROR_OK;
}

keymaster_error_t optee_finish(const keymaster2_device_t* dev,
                                              keymaster_operation_handle_t operation_handle,
                                              const keymaster_key_param_set_t* params,
                                              const keymaster_blob_t* input,
                                              const keymaster_blob_t* signature,
                                              keymaster_key_param_set_t* out_params,
                                              keymaster_blob_t* output) {
	LOG_D("%s:%d\n", __func__, __LINE__);
	return KM_ERROR_OK;
}

keymaster_error_t optee_abort(const keymaster2_device_t* dev,
                                             keymaster_operation_handle_t operation_handle) {
	LOG_D("%s:%d\n", __func__, __LINE__);
	return KM_ERROR_OK;
}
