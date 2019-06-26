// Package csp provides mid-level cryptographic API based on CryptoAPI
// 2.0 on Windows and CryptoPro CSP on Linux.
package csp

/*
#cgo linux CFLAGS: -I/opt/cprocsp/include/cpcsp
#cgo linux,amd64 LDFLAGS: -L/opt/cprocsp/lib/amd64/ -lcapi10 -lcapi20 -lrdrsup -lssp
#cgo linux,386 LDFLAGS: -L/opt/cprocsp/lib/ia32/ -lcapi10 -lcapi20 -lrdrsup -lssp
#cgo windows LDFLAGS: -lcrypt32 -lpthread
#include "common.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// ErrorCode corresponds to a C type DWORD
type ErrorCode C.DWORD

// Some C error codes translated to Go constants
const (
	ErrBadKeysetParam ErrorCode = C.NTE_BAD_KEYSET_PARAM & (1<<32 - 1) // Typically occurs when trying to acquire context
	ErrFail           ErrorCode = C.NTE_FAIL & (1<<32 - 1)             // Misc error
	//ErrInvalidParameter ErrorCode = C.NTE_INVALID_PARAMETER & (1<<32 - 1) // Bad parameter to cryptographic function
	ErrNoKey        ErrorCode = C.NTE_NO_KEY & (1<<32 - 1)         // Key not found
	ErrExists       ErrorCode = C.NTE_EXISTS & (1<<32 - 1)         // Object already exists
	ErrNotFound     ErrorCode = C.NTE_NOT_FOUND & (1<<32 - 1)      // Object not found
	ErrKeysetNotDef ErrorCode = C.NTE_KEYSET_NOT_DEF & (1<<32 - 1) // Operation on unknown container
	ErrBadKeyset    ErrorCode = C.NTE_BAD_KEYSET & (1<<32 - 1)     // Operation on unknown container
	ErrBadAlgID     ErrorCode = C.NTE_BAD_ALGID & (1<<32 - 1)      // Operation on unknown container
	ErrBadKeyState  ErrorCode = C.NTE_BAD_KEY_STATE & (1<<32 - 1)
)

// Error provides error type
type Error struct {
	Code        ErrorCode // Code indicates exact CryptoAPI error code
	Description string
	msg         string
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %X, %s", e.msg, e.Code, e.Description)
}

func charPtr(s string) *C.CHAR {
	if s != "" {
		return (*C.CHAR)(unsafe.Pointer(C.CString(s)))
	}
	return nil
}

func freePtr(s *C.CHAR) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

func getErr(msg string) error {
	errCode := ErrorCode(C.GetLastError())

	description := ""
	switch errCode {
	case ErrBadKeysetParam:
		description = "Typically occurs when trying to acquire context"
	case ErrFail:
		description = "Misc error"
	case ErrNoKey:
		description = "Key not found"
	case ErrExists:
		description = "Object already exists"
	case ErrNotFound:
		description = "Object not found"
	case ErrKeysetNotDef:
		description = "ErrKeysetNotDef"
	case ErrBadKeyset:
		description = "ErrBadKeyset"
	case ErrBadAlgID:
		description = "ErrBadAlgID"
	case ErrBadKeyState:
		description = "ErrBadKeyState"
	}

	return Error{msg: msg, Code: errCode, Description: description}
}

func extractBlob(pb *C.DATA_BLOB) []byte {
	return C.GoBytes(unsafe.Pointer(pb.pbData), C.int(pb.cbData))
}
