/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define LOG_TAG "android.hardware.gatekeeper@1.0-service.optee"

#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>
#include <android/hardware/gatekeeper/1.0/types.h>

#include <android/log.h>
#include <hidl/HidlSupport.h>
#include <hidl/HidlTransportSupport.h>
#include <hidl/LegacySupport.h>
#include <utils/Log.h>

#include "Gatekeeper.h"

// libhwbinder:
using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;

// Generated HIDL files
using android::hardware::gatekeeper::V1_0::IGatekeeper;
using android::hardware::gatekeeper::V1_0::implementation::Gatekeeper;

using android::sp;
using android::status_t;
using android::OK;

int main() {
	  status_t status;
	  android::sp<IGatekeeper> service = Gatekeeper::getInstance();

	  configureRpcThreadpool(1, true /*callerWillJoin*/);
	  status = service->registerAsService();

	  if (service != nullptr) {
		  status = service->registerAsService();
		  if (status != OK) //!= 0
			  ALOGE("Can't register Gatekeeper HAL service, nullptr");
		  else
			  ALOGI("Gatekeeper HAL Ready.");
	  } else {
	      ALOGE("Can't create instance of Gatekeeper, nullptr");
	  }

	  joinRpcThreadpool(); //doesn't return

	  return 0; // should never get here
}
