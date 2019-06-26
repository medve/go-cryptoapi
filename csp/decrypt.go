package csp

//#include "common.h"
import "C"
import (
	"unsafe"
)

// Decrypt decrypts message
func (ctx Ctx) Decrypt(key Key, data []byte) (res []byte, err error) {
	dataLen := C.DWORD(len(data))

	res = make([]byte, len(data))
	copy(res, data)

	if C.CryptDecrypt(key.hKey, 0, C.BOOL(1), 0, (*C.BYTE)(unsafe.Pointer(&res[0])), &dataLen) == 0 {
		err = getErr("Error decrypt message")
		return nil, err
	}
	return res, err
}
