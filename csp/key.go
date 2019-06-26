package csp

//#include "common.h"
import "C"

import (
	"unsafe"
)

// KeyFlag sets options on created key pair
type KeyFlag C.DWORD

// Key flags
const (
	KeyArchivable KeyFlag = C.CRYPT_ARCHIVABLE
	KeyExportable KeyFlag = C.CRYPT_EXPORTABLE
	//KeyForceProtectionHigh KeyFlag = C.CRYPT_FORCE_KEY_PROTECTION_HIGH
)

// KeyPairID selects public/private key pair from CSP container
type KeyPairID C.DWORD

// Key specification
const (
	AtKeyExchange KeyPairID = C.AT_KEYEXCHANGE
	AtSignature   KeyPairID = C.AT_SIGNATURE
	G28147        KeyPairID = C.CALG_G28147
)

// KeyParamID represents key parameters that can be retrieved for key.
type KeyParamID C.DWORD

// Certificate parameter IDs
const (
	KeyCertificateParam KeyParamID = C.KP_CERTIFICATE // X.509 certificate that has been encoded by using DER
	KeyIVParam          KeyParamID = C.KP_IV          // use it to get or set initialization vector
	KeyAlgID            KeyParamID = C.KP_ALGID
)

type ExportType C.DWORD

// Export types
const (
	ExportSimple ExportType = C.SIMPLEBLOB
	ExportPublic ExportType = C.PUBLICKEYBLOB
)

// Key incapsulates key pair functions
type Key struct {
	Ctx  Ctx
	hKey C.HCRYPTKEY
}

// KeyIV incapsulates initialization vector type
type KeyIV []byte

// Key extracts public key from container represented by context ctx, from
// key pair given by at parameter. It must be released after use by calling
// Close method.
func (ctx Ctx) Key(at KeyPairID) (res Key, err error) {
	if C.CryptGetUserKey(ctx.hProv, C.DWORD(at), &res.hKey) == 0 {
		err = getErr("Error getting key for container")
		return
	}
	return
}

// GenKey generates public/private key pair for given context. Flags parameter
// determines if generated key will be exportable or archivable and at
// parameter determines KeyExchange or Signature key pair. Resulting key must
// be eventually closed by calling Close.
func (ctx Ctx) GenKey(at KeyPairID, flags KeyFlag) (res Key, err error) {
	if C.CryptGenKey(ctx.hProv, C.ALG_ID(at), C.DWORD(flags), &res.hKey) == 0 {
		// BUG: CryptGenKey raises error NTE_FAIL. Looking into it...
		// NOTE: works with G28147 parameter
		err = getErr("Error creating key for container")
		return
	}
	return
}

// DuplicateKey duplicates key, so you can use it more than once
func (key Key) DuplicateKey() (dstKey Key, err error) {
	if C.CryptDuplicateKey(key.hKey, (*C.DWORD)(unsafe.Pointer(C.NULL)), 0, &dstKey.hKey) == 0 {
		err = getErr("Error duplicate key")
		return
	}
	return
}

// TODO импорт скорее лучше сделать принадлежащим контексту
// ImportKey decrypts encrypted session key and returns it as result
func (key Key) ImportKey(srcKey []byte) (res Key, err error) {

	if C.CryptImportKey(key.Ctx.hProv, (*C.BYTE)(unsafe.Pointer(&srcKey[0])), C.DWORD(len(srcKey)), key.hKey, 0, &res.hKey) == 0 {
		err = getErr("Error import session key")
		return
	}
	return
}

func (key Key) GetKeyLen(exportableKey Key, keyType ExportType) (res int, err error) {
	var keyLen C.DWORD
	if C.CryptExportKey(exportableKey.hKey, key.hKey, C.DWORD(keyType), 0, (*C.BYTE)(unsafe.Pointer(C.NULL)), &keyLen) == 0 {
		err = getErr("Error export session key")
		return
	}
	return int(keyLen), nil
}

// TODO возможно лучше чтобы ключ экспортировал себя, а ключ шифрования и тип передавались, как аргумент
// TODO возможно тип можно брать прямо из ключа
// ExportSessionKey encrypts session key and returns it as result
func (key Key) ExportSessionKey(exportableKey Key) (res []byte, err error) {
	keyLen, err := key.GetKeyLen(exportableKey, C.SIMPLEBLOB)
	if err != nil {
		return nil, err
	}

	keyLenDword := C.DWORD(keyLen)

	res = make([]byte, keyLen)
	if C.CryptExportKey(exportableKey.hKey, key.hKey, C.SIMPLEBLOB, 0, (*C.BYTE)(unsafe.Pointer(&res[0])), &keyLenDword) == 0 {
		err = getErr("Error export session key")
		return
	}
	return
}

// ExportPublicKey gets public key blob from key pair
func (key Key) ExportPublicKey() (res []byte, err error) {
	var keyLen C.DWORD
	if C.CryptExportKey(key.hKey, 0, C.PUBLICKEYBLOB, 0, (*C.BYTE)(unsafe.Pointer(C.NULL)), &keyLen) == 0 {
		err = getErr("Error export public key")
		return
	}

	keyLenDword := C.DWORD(keyLen)
	res = make([]byte, keyLen)
	if C.CryptExportKey(key.hKey, 0, C.PUBLICKEYBLOB, 0, (*C.BYTE)(unsafe.Pointer(&res[0])), &keyLenDword) == 0 {
		err = getErr("Error export public key")
		return
	}
	return
}

// GetParam retrieves data that governs the operations of a key.
func (key Key) GetParam(param KeyParamID) (res []byte, err error) {
	var slen C.DWORD
	if C.CryptGetKeyParam(key.hKey, C.DWORD(param), nil, &slen, 0) == 0 {
		err = getErr("Error getting param's value length for key")
		return
	}

	buf := make([]byte, slen)
	if C.CryptGetKeyParam(key.hKey, C.DWORD(param), (*C.BYTE)(unsafe.Pointer(&buf[0])), &slen, 0) == 0 {
		err = getErr("Error getting param for key")
		return
	}

	res = buf[0:int(slen)]
	return
}

// SetParam sets data that governs the operations of a key.
func (key Key) SetParam(param KeyParamID, data []byte) (err error) {

	if C.CryptSetKeyParam(key.hKey, C.DWORD(param), (*C.BYTE)(unsafe.Pointer(&data[0])), 0) == 0 {
		err = getErr("Error setting param for key")
		return
	}

	return
}

func (key Key) GetInitializationVector() (iv KeyIV, err error) {
	return key.GetParam(KeyIVParam)
}

func (key Key) SetInitializationVector(iv KeyIV) (err error) {
	return key.SetParam(KeyIVParam, iv)
}

// Close releases key handle.
func (key Key) Close() error {
	if C.CryptDestroyKey(key.hKey) == 0 {
		return getErr("Error releasing key")
	}
	return nil
}
