#define LOG_TAG "android.hardware.simple@2.0-service"

#include <android/hardware/simple/2.0/ISimphw.h>

#include <hidl/LegacySupport.h>

#include "Simphw.h"

using android::hardware::simple::V2_0::ISimphw;
using android::hardware::simple::V2_0::implementation::Simphw;
using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;
using android::sp;

int main() {
      int res;
      android::sp<ISimphw> ser = Simphw::getInstance();
      ALOGE("simp main");
      configureRpcThreadpool(1, true /*callerWillJoin*/);

      if (ser != nullptr) {
          res = ser->registerAsService();
          if(res != 0) {
            ALOGE("Can't register instance of SimpleHardware, nullptr");
	    return res;
	  }
      } else {
          ALOGE("Can't create instance of SimpleHardware, nullptr");
	  return res;
       }

      joinRpcThreadpool();

      return res; // should never get here
}
