/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <keystore/keystore.h>

#include <hardware/hardware.h>
#include <hardware/keymaster_common.h>

#include <openssl/err.h>

#include <UniquePtr.h>
#include "include/keymaster/keymaster_linaro.h"

// For debugging
#define LOG_NDEBUG 1

#define LOG_TAG "LinaroKeyMaster"
#include <cutils/log.h>

typedef UniquePtr<keymaster1_device_t> Unique_keymaster1_device_t;

/* Close an keymaster instance */
static int linaro_km_close(hw_device_t *dev)
{
	linaro_terminate();
	delete dev;
	return 0;
}

/*
 * Generic device handling
 */
static int linaro_km_open(const hw_module_t* module, const char* name,
		hw_device_t** device)
{

	/* Check name */
	if (strcmp(name, KEYSTORE_KEYMASTER) != 0)
		return -EINVAL;

	/* Allocate dev */
	Unique_keymaster1_device_t dev(new keymaster1_device_t);
	if (dev.get() == NULL)
		return -ENOMEM;

	/* Init dev */
	dev->common.tag = HARDWARE_DEVICE_TAG;
	dev->common.version = 1;
	dev->common.module = (struct hw_module_t*) module;
	dev->common.close = linaro_km_close;

	/* For KEYMASTER_MODULE_API_VERSION_0_3,
	   Set flags to KEYMASTER_SUPPORTS_DSA | KEYMASTER_SUPPORTS_EC */
	dev->flags = KEYMASTER_SUPPORTS_DSA | KEYMASTER_SUPPORTS_EC;

	/* keymaster0 APIs */
	dev->generate_keypair = nullptr;
	dev->import_keypair = nullptr;
	dev->get_keypair_public = nullptr;
	dev->delete_keypair = nullptr;
	dev->delete_all = nullptr;
	dev->sign_data = nullptr;
	dev->verify_data = nullptr;

	/* keymaster1 APIs */
	dev->get_supported_algorithms = linaro_get_supported_algorithms;
	dev->get_supported_block_modes = linaro_get_supported_block_modes;
	dev->get_supported_padding_modes = linaro_get_supported_padding_modes;
	dev->get_supported_digests = linaro_get_supported_digests;
	dev->get_supported_import_formats = linaro_get_supported_import_formats;
	dev->get_supported_export_formats = linaro_get_supported_export_formats;
	dev->add_rng_entropy = linaro_add_rng_entropy;
	dev->generate_key = linaro_generate_key;
	dev->get_key_characteristics = linaro_get_key_characteristics;
	dev->import_key = linaro_import_key;
	dev->export_key = linaro_export_key;
	dev->delete_key = linaro_delete_key;
	dev->delete_all_keys = linaro_delete_all_keys;
	dev->begin = linaro_begin;
	dev->update = linaro_update;
	dev->finish = linaro_finish;
	dev->abort = linaro_abort;

	ERR_load_crypto_strings();
	ERR_load_BIO_strings();

	*device = reinterpret_cast<hw_device_t*>(dev.release());

	return 0;
}

static struct hw_module_methods_t keystore_module_methods =
{
	.open = linaro_km_open,
};

struct keystore_module HAL_MODULE_INFO_SYM
__attribute__ ((visibility ("default"))) =
{
    .common = {
        .tag = HARDWARE_MODULE_TAG,
        .module_api_version = KEYMASTER_MODULE_API_VERSION_1_0,
        .hal_api_version = HARDWARE_HAL_API_VERSION,
        .id = KEYSTORE_HARDWARE_MODULE_ID,
        .name = "Keymaster Linaro HAL(1.0)",
        .author = "The Android Open Source Project",
        .methods = &keystore_module_methods,
        .dso = 0,
        .reserved = {},
    },
};
