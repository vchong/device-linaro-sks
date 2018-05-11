#define LOG_TAG "android.hardware.gatekeeper@1.0-impl.optee"

#include "Gatekeeper.h"

namespace android {
namespace hardware {
namespace gatekeeper {
namespace V1_0 {
namespace implementation {

// Methods from IGatekeeper follow.
Return<void> Gatekeeper::enroll(uint32_t uid, const hidl_vec<uint8_t>& currentPasswordHandle, const hidl_vec<uint8_t>& currentPassword, const hidl_vec<uint8_t>& desiredPassword, enroll_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<void> Gatekeeper::verify(uint32_t uid, uint64_t challenge, const hidl_vec<uint8_t>& enrolledPasswordHandle, const hidl_vec<uint8_t>& providedPassword, verify_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<void> Gatekeeper::deleteUser(uint32_t uid, deleteUser_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<void> Gatekeeper::deleteAllUsers(deleteAllUsers_cb _hidl_cb) {
    // TODO implement
    return Void();
}


// Methods from ::android::hidl::base::V1_0::IBase follow.

//IGatekeeper* HIDL_FETCH_IGatekeeper(const char* /* name */) {
//    return new Gatekeeper();
//}

}  // namespace implementation
}  // namespace V1_0
}  // namespace gatekeeper
}  // namespace hardware
}  // namespace android
