#define LOG_TAG "android.hardware.keymaster@3.0-impl.optee"

#include "KeymasterDevice.h"
#include <pkcs11.h>
#include <sks_ck_debug.h>

namespace android {
namespace hardware {
namespace keymaster {
namespace V3_0 {
namespace implementation {

/* Valid template to generate a generic secret */
static CK_ATTRIBUTE cktest_generate_gensecret_object[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_GENERIC_SECRET},
						sizeof(CK_KEY_TYPE) },
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_COPYABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

/*  Valid template to generate an all AES purpose key */
static CK_ATTRIBUTE cktest_generate_aes_object[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_COPYABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

static CK_MECHANISM mecha_generate_gensecret = {
	CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0
};

static CK_MECHANISM mecha_generate_aes_generic = {
	CKM_AES_KEY_GEN, NULL_PTR, 0
};

/*
 * Util to find a slot on which to open a session
 */
static CK_RV close_lib(void)
{
	ALOGI("%s", __FUNCTION__, );
	return C_Finalize(0);
}

static CK_RV init_lib_and_find_token_slot(CK_SLOT_ID *slot)
{
	CK_RV rv;
	CK_SLOT_ID_PTR slots = NULL;
	CK_ULONG count;

	ALOGI("%s in", __FUNCTION__, );

	rv = C_Initialize(0);
	if (rv) {
		ALOGE("%s C_Initialize failed", __FUNCTION__, );
		return rv;
	}

	rv = C_GetSlotList(CK_TRUE, NULL, &count);
	if (rv != CKR_BUFFER_TOO_SMALL) {
		ALOGE("%s CKR_BUFFER_TOO_SMALL", __FUNCTION__, );
		goto bail;
	}

	if (count < 1) {
		rv = CKR_GENERAL_ERROR;
		ALOGE("%s CKR_GENERAL_ERROR", __FUNCTION__, );
		goto bail;
	}

	slots = malloc(count * sizeof(CK_SLOT_ID));
	if (!slots) {
		rv = CKR_HOST_MEMORY;
		ALOGE("%s CKR_HOST_MEMORY", __FUNCTION__, );
		goto bail;
	}

	rv = C_GetSlotList(CK_TRUE, slots, &count);
	if (rv) {
		ALOGE("%s C_GetSlotList failed", __FUNCTION__, );
		goto bail;
	}

	/* Use the 1st slot */
	*slot = *slots;

bail:
	ALOGI("%s bail", __FUNCTION__, );
	free(slots);
	if (rv)
		close_lib();

	ALOGI("%s out", __FUNCTION__, );
	return rv;
}

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
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hld;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    // result variables for the wire
    KeyCharacteristics resultCharacteristics;
    hidl_vec<uint8_t> resultKeyBlob;

    for (size_t i = 0; i < keyParams.size(); ++i) {
		ALOGD("%s keyParams[%d].tag:%d", __FUNCTION__, i, keyParams[i].tag);
		if (keyParams[i].tag == Tag::ALGORITHM)
			ALOGD("%s keyParams[%d].f.algorithm:%d", __FUNCTION__, i, keyParams[i].f.algorithm);
    }

	rv = init_lib_and_find_token_slot(&slot);
	if (rv != CKR_OK) {
		ALOGE("%s init_lib_and_find_token_slot failed", __FUNCTION__, );
		return Void();
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv != CKR_OK)
		goto bail;

	switch (keyParams[i].tag) {
	case Tag::ALGORITHM:
		switch (keyParams[i].f.algorithm) {
		case 1: //RSA
			break;
		case 3: //EC
			break;
		case 32: //AES
			break;
		case 128: //HMAC
			break;
		default:
			ALOGE("%s invalid Tag::ALGORITHM", __FUNCTION__, );
			break;
		}
		break;
	default:
		ALOGE("%s not Tag::ALGORITHM", __FUNCTION__, );
		break;
	}

	/*
	 * Generate a Generic Secret object.
	 */
	rv = C_GenerateKey(session, &mecha_generate_gensecret,
			   cktest_generate_gensecret_object,
			   ARRAY_SIZE(cktest_generate_gensecret_object),
			   &obj_hld);
	if (rv != CKR_OK)
		goto bail;

	/*
	 * Generate a 128bit AES symmetric key
	 */
	rv = C_GenerateKey(session, &mecha_generate_aes_generic,
			   cktest_generate_aes_object,
			   ARRAY_SIZE(cktest_generate_aes_object),
			   &obj_hld);
	if (rv != CKR_OK)
		goto bail;

	rv = C_DestroyObject(session, obj_hld);
	if (rv != CKR_OK)
		goto bail;

bail:
	rv = C_CloseSession(session);
	rv = close_lib();

    // send results off to the client
    _hidl_cb(legacy_enum_conversion(rc), resultKeyBlob, resultCharacteristics);

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
  return new KeymasterDevice();
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
