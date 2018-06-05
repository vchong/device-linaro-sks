# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LOCAL_PATH := $(call my-dir)

#https://android-git.linaro.org/device/linaro/hikey.git/tree/gralloc/Android.mk
# HAL module implemenation, not prelinked and stored in
# hw/<OVERLAY_HARDWARE_MODULE_ID>.<ro.product.board>.so
include $(CLEAR_VARS)
ifeq ($(USE_32_BIT_KEYSTORE), true)
LOCAL_MULTILIB := 32
endif
LOCAL_MODULE := keystore0_2.$(TARGET_BOARD_PLATFORM)
#LOCAL_MODULE := keystore.$(TARGET_PRODUCT)

#ifeq ($(shell test $(PLATFORM_SDK_VERSION) -ge 21 && echo OK),OK)
#	LOCAL_MODULE_RELATIVE_PATH := hw
#else
#	LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)/hw
#endif
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_VENDOR_MODULE := true

LOCAL_HEADER_LIBRARIES += libhardware_headers

LOCAL_SRC_FILES := module.cpp
LOCAL_C_INCLUDES := system/security/keystore
#LOCAL_CFLAGS = -fvisibility=hidden -Wall -Werror
LOCAL_CFLAGS = -Wall -Wno-error
LOCAL_SHARED_LIBRARIES := libcrypto liblog libkeystore_binder liblinarokeymaster
LOCAL_MODULE_TAGS := optional
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
ifeq ($(USE_32_BIT_KEYSTORE), true)
LOCAL_MULTILIB := 32
endif
LOCAL_MODULE := liblinarokeymaster
LOCAL_SRC_FILES := keymaster_linaro.cpp
LOCAL_C_INCLUDES := system/security/keystore \
	$(LOCAL_PATH)/include
#LOCAL_CFLAGS = -fvisibility=hidden -Wall -Werror
LOCAL_CFLAGS = -Wall -Wno-error
LOCAL_SHARED_LIBRARIES := libcrypto liblog libkeystore_binder
LOCAL_MODULE_TAGS := optional
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_SHARED_LIBRARY)
