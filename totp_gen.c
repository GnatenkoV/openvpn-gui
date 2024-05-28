#include "totp_gen.h"
#include <winbase.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

unsigned int wcharToChar(const WCHAR* src, char* dest, unsigned int destLen)
{
    unsigned int i;
    WCHAR code;

    i = 0;

    while (src[i] != '\0' && i < (destLen - 1)) {
        code = src[i];
        if (code < 128)
        {
            dest[i] = (char)code;
        }
        else
        {
            dest[i] = '?';
            if (code >= 0xD800 && code <= 0xD8FF)
            {
                // lead surrogate, skip the next code unit, which is the trail
                i++;
            }
        }
        i++;
    }

    dest[i] = '\0';

    return i - 1;
}

#define FILETIME_TICKS_PER_SECOND	10000000LL

#define decode_char( c ) ( ( c >= 'A' && c <= 'Z' ) ? c - 'A' : ( ( c >= '2' && c <= '7' ) ? ( c - '2' ) + 26 : -1 ) )

int decode_sequence(unsigned char* str_in, unsigned char* str_out)
{
    static char offset_map[] = { 3, -2, 1, -4, -1, 2, -3, 0 };

    str_out[0] = 0;

    for (char block = 0, octet = 0; block < 8; ++block, octet = (block * 5) / 8)
    {
        int c = decode_char(str_in[block]);
        if (c < 0)
        {
            return octet;
        }

        if (offset_map[block] < 0)
        {
            str_out[octet] |= (c >> -offset_map[block]);
            str_out[octet + 1] = c << (8 + offset_map[block]);
        }
        else
        {
            str_out[octet] |= (c << offset_map[block]);
        }
    }

    return 5;
}

unsigned int base32_decode(unsigned char* str_in, unsigned char* str_out)
{
    unsigned int written = 0;

    if (str_in != NULL)
    {
        for (unsigned int i = 0, j = 0; ; i += 8, j += 5)
        {
            int n = decode_sequence(&str_in[i], &str_out[j]);

            written += n;

            if (n < 5)
            {
                break;
            }
        }
    }

    return written;
}

unsigned long GetUnixTimestamp()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    // Convert the time into a 32bit Unix timestamp.
    ULARGE_INTEGER ts;
    ts.HighPart = ft.dwHighDateTime;
    ts.LowPart = ft.dwLowDateTime;

    return (unsigned long)((ts.QuadPart - (11644473600000 * 10000)) / FILETIME_TICKS_PER_SECOND);
}

void UnixTimeToSystemTime(DWORD t, SYSTEMTIME* st)
{
    FILETIME ft;
    LARGE_INTEGER li;
    li.QuadPart = Int32x32To64(t, 10000000) + 116444736000000000;

    ft.dwLowDateTime = li.LowPart;
    ft.dwHighDateTime = li.HighPart;

    FileTimeToSystemTime(&ft, st);
}

int GenerateTOTP(const WCHAR* secret)
{
    char* key[32];

    unsigned int key_length = wcharToChar(secret, key, 32);

    unsigned long code = -1;

    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHmacHash = NULL;
    PBYTE pbHash = NULL;
    DWORD dwDataLen = 0;
    HMAC_INFO HmacInfo;

    AES_256_KEY_BLOB* kb = NULL;
    DWORD kbSize = 0;
    unsigned long data = 0;
    unsigned char offset = 0;

    unsigned char* dkey = (unsigned char*)GlobalAlloc(GMEM_FIXED, sizeof(unsigned char) * key_length);
    unsigned int dkey_length = base32_decode((unsigned char*)key, dkey);

    if (dkey_length == 0)
    {
        goto CLEANUP;
    }

    ZeroMemory(&HmacInfo, sizeof(HmacInfo));
    HmacInfo.HashAlgid = CALG_SHA1;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET))
    {
        goto CLEANUP;
    }

    kbSize = sizeof(AES_256_KEY_BLOB) + dkey_length;

    kb = (AES_256_KEY_BLOB*)GlobalAlloc(GMEM_FIXED, kbSize);
    kb->header.bType = PLAINTEXTKEYBLOB;
    kb->header.bVersion = CUR_BLOB_VERSION;
    kb->header.reserved = 0;
    kb->header.aiKeyAlg = CALG_RC2;
    memcpy(&kb->key, dkey, dkey_length);
    kb->len = dkey_length;

    if (!CryptImportKey(hProv, (BYTE*)kb, kbSize, 0, CRYPT_IPSEC_HMAC_KEY, &hKey))
    {
        goto CLEANUP;
    }

    if (!CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHmacHash))
    {
        goto CLEANUP;
    }

    if (!CryptSetHashParam(hHmacHash, HP_HMAC_INFO, (BYTE*)&HmacInfo, 0))
    {
        goto CLEANUP;
    }

    data = GetUnixTimestamp() / 30;

    BYTE cdata[8];
    ZeroMemory(&cdata, sizeof(cdata));

    cdata[7] = (BYTE)(data & 0xFF);
    cdata[6] = (BYTE)((data & 0xFF00) >> 8);
    cdata[5] = (BYTE)((data & 0xFF0000) >> 16);
    cdata[4] = (BYTE)((data & 0xFF000000) >> 24);

    if (!CryptHashData(hHmacHash, cdata, sizeof(cdata), 0))
    {
        goto CLEANUP;
    }

    if (!CryptGetHashParam(hHmacHash, HP_HASHVAL, NULL, &dwDataLen, 0))
    {
        goto CLEANUP;
    }

    pbHash = (BYTE*)GlobalAlloc(GMEM_FIXED, dwDataLen);
    if (pbHash == NULL)
    {
        goto CLEANUP;
    }

    if (!CryptGetHashParam(hHmacHash, HP_HASHVAL, pbHash, &dwDataLen, 0))
    {
        goto CLEANUP;
    }

    offset = pbHash[dwDataLen - 1] & 0x0F;

    code = ((pbHash[offset + 0] & 0x7F) << 24) |
        ((pbHash[offset + 1] & 0xFF) << 16) |
        ((pbHash[offset + 2] & 0xFF) << 8) |
        (pbHash[offset + 3] & 0xFF);

    code %= 1000000;

CLEANUP:

    // Free resources.
    if (hHmacHash) { CryptDestroyHash(hHmacHash); }
    if (hKey) { CryptDestroyKey(hKey); }
    if (hHash) { CryptDestroyHash(hHash); }
    if (hProv) { CryptReleaseContext(hProv, 0); }
    if (pbHash) { GlobalFree(pbHash); }
    if (dkey) { GlobalFree(dkey); }
    if (kb) { GlobalFree(kb); }

    return code;
}
