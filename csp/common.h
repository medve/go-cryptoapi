#ifndef COMMON_H_INCLUDED
#define COMMON_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <CSP_WinDef.h>
#include <CSP_WinCrypt.h>
// some strange dirty things are happening here
#define UNIX 1
#define CSP_LITE 1
#include <WinCryptEx.h>
#define MY_ENC_TYPE (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define BLOCK_LENGTH 4096
#endif

