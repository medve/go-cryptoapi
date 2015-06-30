// Package cryptoapi provides mid-level cryptographic API based on CryptoAPI
// 2.0 on Windows and CryptoPro CSP on Linux.
package cryptoapi

/*
#cgo linux CFLAGS: -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/asn1data/
#cgo linux,amd64 LDFLAGS: -L/opt/cprocsp/lib/amd64/ -lcapi10 -lcapi20 -lasn1data -lssp
#cgo linux,386 LDFLAGS: -L/opt/cprocsp/lib/ia32/ -lcapi10 -lcapi20 -lasn1data -lssp
#cgo windows LDFLAGS: -lcrypt32 -lpthread
#include "common.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

type CryptFlag C.DWORD

const (
	CryptVerifyContext CryptFlag = C.CRYPT_VERIFYCONTEXT
	CryptNewKeyset     CryptFlag = C.CRYPT_NEWKEYSET
	CryptMachineKeyset CryptFlag = C.CRYPT_MACHINE_KEYSET
	CryptDeleteKeyset  CryptFlag = C.CRYPT_DELETEKEYSET
	CryptSilent        CryptFlag = C.CRYPT_SILENT
)

type ProvType C.DWORD

const (
	ProvRsa      ProvType = C.PROV_RSA_FULL
	ProvGost94   ProvType = 71
	ProvGost2001 ProvType = 75
)

func charPtr(s string) *C.CHAR {
	if s != "" {
		return (*C.CHAR)(unsafe.Pointer(C.CString(s)))
	}
	return nil
}

func freePtr(s *C.CHAR) {
	C.free(unsafe.Pointer(s))
}

func getErr(msg string) error {
	return errors.New(fmt.Sprintf("%s: %x", msg, C.GetLastError()))
}
