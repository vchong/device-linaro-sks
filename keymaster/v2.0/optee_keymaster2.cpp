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

#include <pkcs11.h>
#include <sks_ck_debug.h>

// For debugging
#define LOG_NDEBUG 1
#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "OpteeKeyMaster2"
#endif

/** The current stored key version. */
const static uint32_t KEY_VERSION = 2;

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

static CK_MECHANISM mecha_generate_aes_generic = {
	CKM_AES_KEY_GEN, NULL_PTR, 0
};

/*
 * Util to find a slot on which to open a session
 */
static CK_RV close_lib(void)
{
	LOG_D("%s:%d\n", __func__, __LINE__);
	return C_Finalize(0);
}

static CK_RV init_lib_and_find_token_slot(CK_SLOT_ID *slot)
{
	CK_RV rv;
	CK_SLOT_ID_PTR slots = NULL;
	CK_ULONG count;

	LOG_D("%s:%d\n", __func__, __LINE__);

	rv = C_Initialize(0);
	if (rv) {
		LOG_D("%s:%d\n", __func__, __LINE__);
		return rv;
	}

	rv = C_GetSlotList(CK_TRUE, NULL, &count);
	if (rv != CKR_BUFFER_TOO_SMALL) {
		LOG_D("%s:%d\n", __func__, __LINE__);
		goto bail;
	}

	if (count < 1) {
		rv = CKR_GENERAL_ERROR;
		LOG_D("%s:%d\n", __func__, __LINE__);
		goto bail;
	}

	slots = malloc(count * sizeof(CK_SLOT_ID));
	if (!slots) {
		rv = CKR_HOST_MEMORY;
		LOG_D("%s:%d\n", __func__, __LINE__);
		goto bail;
	}

	rv = C_GetSlotList(CK_TRUE, slots, &count);
	if (rv) {
		LOG_D("%s:%d\n", __func__, __LINE__);
		goto bail;
	}

	/* Use the 1st slot */
	*slot = *slots;

bail:
	LOG_D("%s:%d\n", __func__, __LINE__);
	free(slots);
	if (rv)
		close_lib();

	LOG_D("%s:%d\n", __func__, __LINE__);
	return rv;
}

static int keyblob_save(ByteArray* objId, uint8_t** key_blob, size_t* key_blob_length) {
    Unique_ByteArray handleBlob(new ByteArray(sizeof(uint32_t) + objId->length()));
    if (handleBlob.get() == NULL) {
        LOG_E("%s:%d\n", __func__, __LINE__);
        ALOGE("Could not allocate key blob");
        return -1;
    }
    uint8_t* tmp = handleBlob->get();
    for (size_t i = 0; i < sizeof(uint32_t); i++) {
        *tmp++ = KEY_VERSION >> ((sizeof(uint32_t) - i - 1) * 8);
    }
    memcpy(tmp, objId->get(), objId->length());

    *key_blob_length = handleBlob->length();
    *key_blob = handleBlob->get();
    ByteArray* unused __attribute__((unused)) = handleBlob.release();

    return 0;
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

	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hld;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (rv != CKR_OK) {
		LOG_D("%s:%d\n", __func__, __LINE__);
		return KM_ERROR_UNKNOWN_ERROR;
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv != CKR_OK)
		goto bail;

    if (algorithm == KM_ALGORITHM_AES) {
        if (!key_description.GetTagValue(TAG_KEY_SIZE, key_len) ||
                (key_len != 128 && key_len != 256 && key_len != 192)) {
            error = KM_ERROR_UNSUPPORTED_KEY_SIZE;
            goto out;
        }

		/*  Valid template to generate an all AES purpose key */
		CK_ATTRIBUTE cktest_generate_aes_object[] = {
			{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
								sizeof(CK_OBJECT_CLASS) },
			{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
			{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
			{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
			{ CKA_COPYABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
			{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
			{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
			{ CKA_VALUE_LEN, &(CK_ULONG){key_len/8}, sizeof(CK_ULONG) },
		};

		/*
		 * Generate a 128-, 192- or 256-bit AES symmetric key
		 */
		rv = C_GenerateKey(session, &mecha_generate_aes_generic,
				   cktest_generate_aes_object,
				   ARRAY_SIZE(cktest_generate_aes_object),
				   &obj_hld);
		if (rv != CKR_OK)
			goto bail;

		Unique_ByteArray objId(reinterpret_cast<ByteArray*>(&obj_hld));
		keyblob_save(objId.get(), key_blob, key_len/8);

		rv = C_DestroyObject(session, obj_hld);
		if (rv != CKR_OK)
			goto bail;
    }

bail:
	rv = C_CloseSession(session);
	rv = close_lib();

out:
    if (error != KM_ERROR_OK) {
        LOG_D("%s:%d\n", __func__, __LINE__);
        // TODO: km2_delete_key(key_handle, sizeof(key_handle));
    }

    return error;
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
