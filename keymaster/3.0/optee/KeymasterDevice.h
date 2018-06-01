#ifndef ANDROID_HARDWARE_KEYMASTER_V3_0_KEYMASTERDEVICE_H
#define ANDROID_HARDWARE_KEYMASTER_V3_0_KEYMASTERDEVICE_H

#include <hardware/keymaster2.h>

#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

namespace android {
namespace hardware {
namespace keymaster {
namespace V3_0 {
namespace implementation {
//namespace optee {

using ::android::hardware::keymaster::V3_0::ErrorCode;
using ::android::hardware::keymaster::V3_0::IKeymasterDevice;
using ::android::hardware::keymaster::V3_0::KeyCharacteristics;
using ::android::hardware::keymaster::V3_0::KeyFormat;
using ::android::hardware::keymaster::V3_0::KeyParameter;
using ::android::hardware::keymaster::V3_0::KeyPurpose;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

//struct KeymasterDevice : public IKeymasterDevice {
class KeymasterDevice : public IKeymasterDevice {
  public:
    KeymasterDevice(keymaster2_device_t* dev, uint32_t hardware_version, bool hardware_supports_ec,
                    bool hardware_supports_all_digests)
        : keymaster_device_(dev), hardware_version_(hardware_version),
          hardware_supports_ec_(hardware_supports_ec),
          hardware_supports_all_digests_(hardware_supports_all_digests) {}
    virtual ~KeymasterDevice();

    // Methods from ::android::hardware::keymaster::V3_0::IKeymasterDevice follow.
    Return<void> getHardwareFeatures(getHardwareFeatures_cb _hidl_cb) override;
    Return<ErrorCode> addRngEntropy(const hidl_vec<uint8_t>& data) override;
    Return<void> generateKey(const hidl_vec<KeyParameter>& keyParams, generateKey_cb _hidl_cb) override;
    Return<void> importKey(const hidl_vec<KeyParameter>& params, KeyFormat keyFormat, const hidl_vec<uint8_t>& keyData, importKey_cb _hidl_cb) override;
    Return<void> getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, getKeyCharacteristics_cb _hidl_cb) override;
    Return<void> exportKey(KeyFormat keyFormat, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, exportKey_cb _hidl_cb) override;
    Return<void> attestKey(const hidl_vec<uint8_t>& keyToAttest, const hidl_vec<KeyParameter>& attestParams, attestKey_cb _hidl_cb) override;
    Return<void> upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade, const hidl_vec<KeyParameter>& upgradeParams, upgradeKey_cb _hidl_cb) override;
    Return<ErrorCode> deleteKey(const hidl_vec<uint8_t>& keyBlob) override;
    Return<ErrorCode> deleteAllKeys() override;
    Return<ErrorCode> destroyAttestationIds() override;
    Return<void> begin(KeyPurpose purpose, const hidl_vec<uint8_t>& key, const hidl_vec<KeyParameter>& inParams, begin_cb _hidl_cb) override;
    Return<void> update(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams, const hidl_vec<uint8_t>& input, update_cb _hidl_cb) override;
    Return<void> finish(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const hidl_vec<uint8_t>& signature, finish_cb _hidl_cb) override;
    Return<ErrorCode> abort(uint64_t operationHandle) override;

    // Methods from ::android::hidl::base::V1_0::IBase follow.
    // static function to return the service object (usually as a singleton)
    static IKeymasterDevice* getInstance(void);

  private:
    keymaster2_device_t* keymaster_device_;
    uint32_t hardware_version_;
    bool hardware_supports_ec_;
    bool hardware_supports_all_digests_;
};

// FIXME: most likely delete, this is only for passthrough implementations
extern "C" IKeymasterDevice* HIDL_FETCH_IKeymasterDevice(const char* name);

//}  // namespace optee
}  // namespace implementation
}  // namespace V3_0
}  // namespace keymaster
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_KEYMASTER_V3_0_KEYMASTERDEVICE_H
