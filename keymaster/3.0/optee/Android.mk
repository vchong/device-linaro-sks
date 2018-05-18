LOCAL_PATH := $(call my-dir)

#include $(CLEAR_VARS)
#LOCAL_MODULE := android.hardware.keymaster@3.0-impl.optee
#LOCAL_PROPRIETARY_MODULE := true
#LOCAL_MODULE_RELATIVE_PATH := hw
#LOCAL_SRC_FILES := \
    KeymasterDevice.cpp

#LOCAL_SHARED_LIBRARIES := \
    libhidlbase \
    libhidltransport \
    libutils \
    liblog \
    libcutils \
    libhardware \
    libbase \
    libcutils \
    android.hardware.keymaster@3.0

#include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_PROPRIETARY_MODULE := true
LOCAL_MODULE := android.hardware.keymaster@3.0-service.optee
LOCAL_INIT_RC := android.hardware.keymaster@3.0-service.optee.rc
LOCAL_SRC_FILES := \
    service.cpp \
    KeymasterDevice.cpp

LOCAL_SHARED_LIBRARIES := \
    liblog \
    libcutils \
    libdl \
    libbase \
    libutils \
    libhardware \

# assume CFG_SECURE_KEY_SERVICES=y for liboptee_cryptoki
LOCAL_SHARED_LIBRARIES += \
    libhidlbase \
    libhidltransport \
    liboptee_cryptoki \
    android.hardware.keymaster@3.0
#    android.hardware.keymaster@3.0-impl.optee

include $(BUILD_EXECUTABLE)
