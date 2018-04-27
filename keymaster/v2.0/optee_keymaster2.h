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

#include <hardware/keymaster0.h>
#include <hardware/keymaster1.h>
#include <hardware/keymaster2.h>

#ifndef OPTEE_KEYMASTER_DEVICE_H_
#define OPTEE_KEYMASTER_DEVICE_H_

extern "C" {
extern struct keystore_module optee_keymaster_device_module;
}

// Keymaster2 methods
keymaster_error_t optee_configure(const keymaster2_device_t* dev,
                                       const keymaster_key_param_set_t* params);
keymaster_error_t optee_add_rng_entropy(const keymaster2_device_t* dev, const uint8_t* data,
                                             size_t data_length);
keymaster_error_t optee_generate_key(const keymaster2_device_t* dev,
                                          const keymaster_key_param_set_t* params,
                                          keymaster_key_blob_t* key_blob,
                                          keymaster_key_characteristics_t* characteristics);
keymaster_error_t optee_get_key_characteristics(const keymaster2_device_t* dev,
                                                     const keymaster_key_blob_t* key_blob,
                                                     const keymaster_blob_t* client_id,
                                                     const keymaster_blob_t* app_data,
                                                     keymaster_key_characteristics_t* character);
keymaster_error_t optee_import_key(const keymaster2_device_t* dev,  //
                                        const keymaster_key_param_set_t* params,
                                        keymaster_key_format_t key_format,
                                        const keymaster_blob_t* key_data,
                                        keymaster_key_blob_t* key_blob,
                                        keymaster_key_characteristics_t* characteristics);
keymaster_error_t optee_export_key(const keymaster2_device_t* dev,  //
                                        keymaster_key_format_t export_format,
                                        const keymaster_key_blob_t* key_to_export,
                                        const keymaster_blob_t* client_id,
                                        const keymaster_blob_t* app_data,
                                        keymaster_blob_t* export_data);
keymaster_error_t optee_attest_key(const keymaster2_device_t* dev,
                                        const keymaster_key_blob_t* key_to_attest,
                                        const keymaster_key_param_set_t* attest_params,
                                        keymaster_cert_chain_t* cert_chain);
keymaster_error_t optee_upgrade_key(const keymaster2_device_t* dev,
                                         const keymaster_key_blob_t* key_to_upgrade,
                                         const keymaster_key_param_set_t* upgrade_params,
                                         keymaster_key_blob_t* upgraded_key);
keymaster_error_t optee_delete_key(const keymaster2_device_t* dev,
                                        const keymaster_key_blob_t* key);
keymaster_error_t optee_delete_all_keys(const keymaster2_device_t* dev);
keymaster_error_t optee_begin(const keymaster2_device_t* dev, keymaster_purpose_t purpose,
                                   const keymaster_key_blob_t* key,
                                   const keymaster_key_param_set_t* in_params,
                                   keymaster_key_param_set_t* out_params,
                                   keymaster_operation_handle_t* operation_handle);
keymaster_error_t optee_update(const keymaster2_device_t* dev,  //
                                    keymaster_operation_handle_t operation_handle,
                                    const keymaster_key_param_set_t* in_params,
                                    const keymaster_blob_t* input, size_t* input_consumed,
                                    keymaster_key_param_set_t* out_params,
                                    keymaster_blob_t* output);
keymaster_error_t optee_finish(const keymaster2_device_t* dev,  //
                                    keymaster_operation_handle_t operation_handle,
                                    const keymaster_key_param_set_t* in_params,
                                    const keymaster_blob_t* input,
                                    const keymaster_blob_t* signature,
                                    keymaster_key_param_set_t* out_params,
                                    keymaster_blob_t* output);
keymaster_error_t optee_abort(const keymaster2_device_t* dev,
                                   keymaster_operation_handle_t operation_handle);

#endif  // OPTEE_KEYMASTER_DEVICE_H_
