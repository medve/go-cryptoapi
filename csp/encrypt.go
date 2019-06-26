package csp

//#include "common.h"
import "C"
import (
	"unsafe"
)

func (ctx Ctx) GetBufferSize(key Key, data []byte) (resDataLen int, err error) {
	dataLen := C.DWORD(len(data))

	if C.CryptEncrypt(key.hKey, 0, C.BOOL(1), 0, (*C.BYTE)(C.NULL), &dataLen, C.DWORD(0)) == 0 {
		err = getErr("Error measure buffer length")
		return 0, err
	}
	return int(dataLen), err
}

// Decrypt decrypts message
func (ctx Ctx) Encrypt(key Key, data []byte) (res []byte, err error) {
	dataLen := C.DWORD(len(data))

	bufferSize, err := ctx.GetBufferSize(key, data)

	if err != nil {
		return nil, err
	}

	res = make([]byte, bufferSize)
	copy(res, data)

	if C.CryptEncrypt(key.hKey, 0, C.BOOL(1), 0, (*C.BYTE)(unsafe.Pointer(&res[0])), &dataLen, C.DWORD(bufferSize)) == 0 {
		err = getErr("Error encrypt message")
		return nil, err
	}

	return res, err
}
