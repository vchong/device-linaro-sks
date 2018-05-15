#include "Simphw.h"

namespace android {
namespace hardware {
namespace simple {
namespace V2_0 {
namespace implementation {

// Methods from ISimphw follow.
Return<int32_t> Simphw::simpfn(int32_t valueIn) {
    // TODO implement
    return valueIn+100;
}

ISimphw *Simphw::getInstance(void){
  return new Simphw();
}

// Methods from ::android::hidl::base::V1_0::IBase follow.

//ISimphw* HIDL_FETCH_ISimphw(const char* /* name */) {
//    return new Simphw();
//}

}  // namespace implementation
}  // namespace V2_0
}  // namespace simple
}  // namespace hardware
}  // namespace android
