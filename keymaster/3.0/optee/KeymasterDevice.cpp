
#define LOG_TAG "android.hardware.keymaster@3.0-impl.optee"

#include "KeymasterDevice.h"

#include <assert.h>
#include <cutils/log.h>

#include <hardware/keymaster_defs.h>
#include <keymaster/keymaster_configuration.h>

namespace android {
namespace hardware {
namespace keymaster {
namespace V3_0 {
namespace implementation {
//namespace optee {

static int keymaster2_device_initialize(const hw_module_t* mod, keymaster2_device_t** dev) {
    assert(mod->module_api_version >= KEYMASTER_MODULE_API_VERSION_2_0);
    ALOGI("Found keymaster2 module %s, version %x", mod->name, mod->module_api_version);

    keymaster2_device_t* km2_device = nullptr;

    int rc = keymaster2_open(mod, &km2_device);
    if (rc) {
        ALOGE("Error %d opening keystore keymaster2 device", rc);
        goto err;
    }

    *dev = km2_device;
    return 0;

err:
    if (km2_device) km2_device->common.close(&km2_device->common);
    *dev = nullptr;
    return rc;
}

static int keymaster_device_initialize(keymaster2_device_t** dev, uint32_t* version,
                                       bool* supports_ec, bool* supports_all_digests) {
    const hw_module_t* mod;

    // TODO set actual bool value
    *supports_ec = true;

    int rc = hw_get_module_by_class(KEYSTORE_HARDWARE_MODULE_ID, NULL, &mod);
    if (rc) {
        ALOGI("Could not find any keystore module.");
        *version = -1;
        return 0;
    }

    if (mod->module_api_version == KEYMASTER_MODULE_API_VERSION_2_0) {
        ALOGI("Found keystore keymaster 2.0 module.");
        *version = 2;
        // TODO set actual bool value
        *supports_all_digests = true;
        return keymaster2_device_initialize(mod, dev);
    } else {
        ALOGI("Found keystore keymaster module but not 2.0.");
        *version = -1;
        return 0;
    }
}

KeymasterDevice::~KeymasterDevice() {
    if (keymaster_device_) keymaster_device_->common.close(&keymaster_device_->common);
}

// Methods from ::android::hardware::keymaster::V3_0::IKeymasterDevice follow.
Return<void> KeymasterDevice::getHardwareFeatures(getHardwareFeatures_cb _hidl_cb) {
    bool is_secure = !(keymaster_device_->flags & KEYMASTER_SOFTWARE_ONLY);
    // TODO set actual bool value
    bool supports_symmetric_cryptography = true;
    bool supports_attestation = false;

    switch (hardware_version_) {
    case 2:
        supports_attestation = true;
        break;
    };

    _hidl_cb(is_secure, hardware_supports_ec_, supports_symmetric_cryptography,
             supports_attestation, hardware_supports_all_digests_,
             keymaster_device_->common.module->name, keymaster_device_->common.module->author);
    return Void();
}

Return<ErrorCode> KeymasterDevice::addRngEntropy(const hidl_vec<uint8_t>& data) {
    // TODO implement
    return ErrorCode {};
}

Return<void> KeymasterDevice::generateKey(const hidl_vec<KeyParameter>& keyParams, generateKey_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<void> KeymasterDevice::importKey(const hidl_vec<KeyParameter>& params, KeyFormat keyFormat, const hidl_vec<uint8_t>& keyData, importKey_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<void> KeymasterDevice::getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, getKeyCharacteristics_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<void> KeymasterDevice::exportKey(KeyFormat keyFormat, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, exportKey_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<void> KeymasterDevice::attestKey(const hidl_vec<uint8_t>& keyToAttest, const hidl_vec<KeyParameter>& attestParams, attestKey_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<void> KeymasterDevice::upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade, const hidl_vec<KeyParameter>& upgradeParams, upgradeKey_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<ErrorCode> KeymasterDevice::deleteKey(const hidl_vec<uint8_t>& keyBlob) {
    // TODO implement
    return ErrorCode {};
}

Return<ErrorCode> KeymasterDevice::deleteAllKeys() {
    // TODO implement
    return ErrorCode {};
}

Return<ErrorCode> KeymasterDevice::destroyAttestationIds() {
    // TODO implement
    return ErrorCode {};
}

Return<void> KeymasterDevice::begin(KeyPurpose purpose, const hidl_vec<uint8_t>& key, const hidl_vec<KeyParameter>& inParams, begin_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<void> KeymasterDevice::update(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams, const hidl_vec<uint8_t>& input, update_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<void> KeymasterDevice::finish(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const hidl_vec<uint8_t>& signature, finish_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<ErrorCode> KeymasterDevice::abort(uint64_t operationHandle) {
    // TODO implement
    return ErrorCode {};
}

IKeymasterDevice *KeymasterDevice::getInstance(void){
  //compare with BiometricsFingerprint.cpp
  //need to return new instance every time?
  //return new KeymasterDevice();

    keymaster2_device_t* dev = nullptr;

    ALOGI("*KeymasterDevice::getInstance");

    uint32_t version = -1;
    bool supports_ec = false;
    bool supports_all_digests = false;

    auto rc = keymaster_device_initialize(&dev, &version, &supports_ec, &supports_all_digests);
    if (rc) return nullptr;

    auto kmrc = ::keymaster::ConfigureDevice(dev);
    if (kmrc != KM_ERROR_OK) {
        dev->common.close(&dev->common);
        return nullptr;
    }

    return new KeymasterDevice(dev, version, supports_ec, supports_all_digests);
}

// Methods from ::android::hidl::base::V1_0::IBase follow.

IKeymasterDevice* HIDL_FETCH_IKeymasterDevice(const char* name) {
    keymaster2_device_t* dev = nullptr;

    ALOGI("Fetching keymaster device name %s", name);

    uint32_t version = -1;
    bool supports_ec = false;
    bool supports_all_digests = false;

    if (name && (strcmp(name, "optee") || strcmp(name, "default")) == 0) {
        auto rc = keymaster_device_initialize(&dev, &version, &supports_ec, &supports_all_digests);
        if (rc) return nullptr;
    }

    auto kmrc = ::keymaster::ConfigureDevice(dev);
    if (kmrc != KM_ERROR_OK) {
        dev->common.close(&dev->common);
        return nullptr;
    }

    return new KeymasterDevice(dev, version, supports_ec, supports_all_digests);
}

//}  // namespace optee
}  // namespace implementation
}  // namespace V3_0
}  // namespace keymaster
}  // namespace hardware
}  // namespace android
