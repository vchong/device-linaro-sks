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

#include <keystore/keystore.h>

#include <hardware/hardware.h>
#include <hardware/keymaster_common.h>
#include <hardware/keymaster0.h>

#include <openssl/err.h>

#include <UniquePtr.h>

#include "optee_keymaster2.h"

// For debugging
#define LOG_NDEBUG 1

#define LOG_TAG "OpteeKeyMaster2"
#include <cutils/log.h>

typedef UniquePtr<keymaster2_device_t> Unique_keymaster2_device_t;

/* Close a keymaster instance */
static int optee_km_close(hw_device_t *dev)
{
	delete dev;
	return 0;
}

/*
 * Generic device handling
 */
static int optee_km_open(const hw_module_t* module, const char* name,
		hw_device_t** device)
{

	/* Check name */
	if (strcmp(name, KEYSTORE_KEYMASTER) != 0)
		return -EINVAL;

	/* Allocate dev */
	Unique_keymaster2_device_t dev(new keymaster2_device_t);
	if (dev.get() == NULL)
		return -ENOMEM;

	/* Init dev */
	dev->common.tag = HARDWARE_DEVICE_TAG;
	dev->common.version = 1;
	dev->common.module = (struct hw_module_t*) module;
	dev->common.close = optee_km_close;

	//keymaster2.h
	//keymaster2 hardware devices must set this to zero
	//keymaster2 software devices set this to some flags
	dev->flags = 0;

    dev->configure = optee_configure;
    dev->add_rng_entropy = optee_add_rng_entropy;
    dev->generate_key = optee_generate_key;
    dev->get_key_characteristics = optee_get_key_characteristics;
    dev->import_key = optee_import_key;
    dev->export_key = optee_export_key;
    dev->attest_key = optee_attest_key;
    dev->upgrade_key = optee_upgrade_key;
    dev->delete_key = optee_delete_key;
    dev->delete_all_keys = optee_delete_all_keys;
    dev->begin = optee_begin;
    dev->update = optee_update;
    dev->finish = optee_finish;
    dev->abort = optee_abort;

	ERR_load_crypto_strings();
	ERR_load_BIO_strings();

	*device = reinterpret_cast<hw_device_t*>(dev.release());

	return 0;
}

static struct hw_module_methods_t keystore_module_methods =
{
	.open = optee_km_open,
};

struct keystore_module HAL_MODULE_INFO_SYM
__attribute__ ((visibility ("default"))) =
{
    .common =
        {
            .tag = HARDWARE_MODULE_TAG,
            .module_api_version = KEYMASTER_MODULE_API_VERSION_2_0,
            .hal_api_version = HARDWARE_HAL_API_VERSION,
            .id = KEYSTORE_HARDWARE_MODULE_ID,
            .name = "Keymaster OP-TEE HAL(2.0)",
            .author = "The Android Open Source Project",
            .methods = &keystore_module_methods,
            .dso = 0,
            .reserved = {},
        },
};
