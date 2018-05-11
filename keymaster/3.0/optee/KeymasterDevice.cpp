#define LOG_TAG "android.hardware.keymaster@3.0-impl.optee"

#include "KeymasterDevice.h"

namespace android {
namespace hardware {
namespace keymaster {
namespace V3_0 {
namespace implementation {

// Methods from IKeymasterDevice follow.
Return<void> KeymasterDevice::getHardwareFeatures(getHardwareFeatures_cb _hidl_cb) {
    // TODO implement
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


// Methods from ::android::hidl::base::V1_0::IBase follow.

//IKeymasterDevice* HIDL_FETCH_IKeymasterDevice(const char* /* name */) {
//    return new KeymasterDevice();
//}

}  // namespace implementation
}  // namespace V3_0
}  // namespace keymaster
}  // namespace hardware
}  // namespace android
