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

## include variants like TA_DEV_KIT_DIR
## and OPTEE_BIN
INCLUDE_FOR_BUILD_TA := false
include $(BUILD_OPTEE_MK)
INCLUDE_FOR_BUILD_TA :=

VERSION = $(shell git describe --always --dirty=-dev 2>/dev/null || echo Unknown)

# TA_DEV_KIT_DIR must be set to non-empty value to
# avoid the Android build scripts complaining about
# includes pointing outside the Android source tree.
# This var is expected to be set when OPTEE OS built.
# We set the default value to an invalid path.
TA_DEV_KIT_DIR ?= ../invalid_include_path

-include $(TA_DEV_KIT_DIR)/host_include/conf.mk

include $(CLEAR_VARS)
ifeq ($(USE_32_BIT_KEYSTORE), true)
LOCAL_MULTILIB := 32
endif
LOCAL_MODULE := keystore2_0.$(TARGET_BOARD_PLATFORM)

#ifeq ($(shell test $(PLATFORM_SDK_VERSION) -ge 21 && echo OK),OK)
#	LOCAL_MODULE_RELATIVE_PATH := hw
#else
#	LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)/hw
#endif

LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_VENDOR_MODULE := true

LOCAL_HEADER_LIBRARIES += libhardware_headers

LOCAL_SRC_FILES := module.cpp \
		   optee_keymaster2_device.cpp \
		   optee_keymaster2_cwrapper.cpp \
		   optee_keymaster2_ca.c

LOCAL_C_INCLUDES := \
    system/security/keystore \
    $(LOCAL_PATH)/include \
    system/keymaster/ \
    system/keymaster/include \
    $(TA_DEV_KIT_DIR)/host_include \
    external/boringssl/include

#LOCAL_CFLAGS = -fvisibility=hidden -Wall -Werror
LOCAL_CFLAGS = -Wall -Werror -Wno-unused-function -Wno-unused-const-variable
LOCAL_CFLAGS += -DANDROID_BUILD

# Include configuration file generated by OP-TEE OS (CFG_* macros)
LOCAL_CFLAGS += -include conf.h
LOCAL_CFLAGS += -pthread
LOCAL_CFLAGS += -g3
LOCAL_CFLAGS += -Wno-missing-field-initializers -Wno-format-zero-length
LOCAL_CFLAGS += -Wno-unused-parameter

## $(OPTEE_BIN) is the path of tee.bin like
## out/target/product/hikey/optee/arm-plat-hikey/core/tee.bin
## it will be generated after build the optee_os with target BUILD_OPTEE_OS
## which is defined in the common ta build mk file included before,
LOCAL_ADDITIONAL_DEPENDENCIES := $(OPTEE_BIN)

LOCAL_SHARED_LIBRARIES := libcrypto \
			  liblog \
			  libkeystore_binder \
			  libteec \
			  libkeymaster_messages \
			  libkeymaster_portable \
			  libcutils

LOCAL_MODULE_TAGS := optional
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
#LOCAL_REQUIRED_MODULES := $(KEYMASTER_TA_BINARY)
include $(BUILD_SHARED_LIBRARY)
