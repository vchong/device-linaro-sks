#ifndef ANDROID_HARDWARE_SIMPLE_V2_0_SIMPHW_H
#define ANDROID_HARDWARE_SIMPLE_V2_0_SIMPHW_H

#include <android/hardware/simple/2.0/ISimphw.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

namespace android {
namespace hardware {
namespace simple {
namespace V2_0 {
namespace implementation {

using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

struct Simphw : public ISimphw {
    // Methods from ISimphw follow.
    Return<int32_t> simpfn(int32_t valueIn) override;

    // Methods from ::android::hidl::base::V1_0::IBase follow.
    static ISimphw* getInstance(void);
};

// FIXME: most likely delete, this is only for passthrough implementations
// extern "C" ISimphw* HIDL_FETCH_ISimphw(const char* name);

}  // namespace implementation
}  // namespace V2_0
}  // namespace simple
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_SIMPLE_V2_0_SIMPHW_H
