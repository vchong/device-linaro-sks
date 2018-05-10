/*
**
** Copyright 2016, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define LOG_TAG "android.hardware.keymaster@3.0-service"

#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>

#include <hidl/HidlSupport.h>
#include <hidl/HidlTransportSupport.h>
#include <hidl/LegacySupport.h>
#include <utils/Log.h>

#include "KeymasterDevice.h"

// libhwbinder:
using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;

// Generated HIDL files
using android::hardware::keymaster::V3_0::IKeymasterDevice;

using android::sp;
using android::status_t;
using android::OK;

int main() {

	  sp<IKeymasterDevice> service = new KeymasterDevice();

	  configureRpcThreadpool(1, true /*callerWillJoin*/);

	  status_t status = service->registerAsService();
	  if (status == OK) {
		ALOGI("Keymaster HAL Ready.");
	    joinRpcThreadpool(); //doesn't return
	  }
	  else
	    ALOGE("Cannot register Keymaster HAL service!");

	  return 1; //never here if registered
}
