#ifndef ANDROID_HARDWARE_GATEKEEPER_V1_0_GATEKEEPER_H
#define ANDROID_HARDWARE_GATEKEEPER_V1_0_GATEKEEPER_H

#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

namespace android {
namespace hardware {
namespace gatekeeper {
namespace V1_0 {
namespace implementation {

using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

struct Gatekeeper : public IGatekeeper {
    // Methods from IGatekeeper follow.
    Return<void> enroll(uint32_t uid, const hidl_vec<uint8_t>& currentPasswordHandle, const hidl_vec<uint8_t>& currentPassword, const hidl_vec<uint8_t>& desiredPassword, enroll_cb _hidl_cb) override;
    Return<void> verify(uint32_t uid, uint64_t challenge, const hidl_vec<uint8_t>& enrolledPasswordHandle, const hidl_vec<uint8_t>& providedPassword, verify_cb _hidl_cb) override;
    Return<void> deleteUser(uint32_t uid, deleteUser_cb _hidl_cb) override;
    Return<void> deleteAllUsers(deleteAllUsers_cb _hidl_cb) override;

    // Methods from ::android::hidl::base::V1_0::IBase follow.

};

// FIXME: most likely delete, this is only for passthrough implementations
// extern "C" IGatekeeper* HIDL_FETCH_IGatekeeper(const char* name);

}  // namespace implementation
}  // namespace V1_0
}  // namespace gatekeeper
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_GATEKEEPER_V1_0_GATEKEEPER_H
