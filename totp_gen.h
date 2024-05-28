#pragma once
#ifndef TOTP_GEN_H
#define TOTP_GEN_H

#define STRICT
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <wincrypt.h>

#include <wchar.h>

#define CODE_LEN 6

int GenerateTOTP(const WCHAR* secret);

typedef struct 
{
    BLOBHEADER header;
    DWORD len;
    BYTE key[32];
}AES_256_KEY_BLOB;

#endif

