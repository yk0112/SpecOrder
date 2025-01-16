/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * CAST low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <klee/klee.h>
#
#include <openssl/cast.h>
#include "cast_local.h"
#include "cast_s.h"


#define SPECTRE_VARIANT
#define KLEE

#ifdef SPECTRE_VARIANT
  #define ARRAY1_SIZE 16
  uint8_t array1[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  uint8_t array2[256 * 512];
  uint8_t temp = 0;
  uint8_t spec_idx = 0;
#endif

#define CAST_exp(l,A,a,n) \
        A[n/4]=l; \
        a[n+3]=(l    )&0xff; \
        a[n+2]=(l>> 8)&0xff; \
        a[n+1]=(l>>16)&0xff; \
        a[n+0]=(l>>24)&0xff;

#define S4 CAST_S_table4
#define S5 CAST_S_table5
#define S6 CAST_S_table6
#define S7 CAST_S_table7

void CAST_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                        long length, const CAST_KEY *schedule,
                        unsigned char *ivec, int *num, int enc)
{
    register CAST_LONG v0, v1, t;
    register int n = *num;
    register long l = length;
    CAST_LONG ti[2];
    unsigned char *iv, c, cc;

    iv = ivec;
    if (enc) {
        while (l--) {
            if (n == 0) {
                n2l(iv, v0);
                ti[0] = v0;
                n2l(iv, v1);
                ti[1] = v1;
                // CAST_encrypt((CAST_LONG *)ti, schedule);
                iv = ivec;
                t = ti[0];
                l2n(t, iv);
                t = ti[1];
                l2n(t, iv);
                iv = ivec;
            }
            c = *(in++) ^ iv[n];
            *(out++) = c;
            iv[n] = c;
            n = (n + 1) & 0x07;
        }
    } else {
        while (l--) {
            if (n == 0) {
                n2l(iv, v0);
                ti[0] = v0;
                n2l(iv, v1);
                ti[1] = v1;
                // CAST_encrypt((CAST_LONG *)ti, schedule);
                iv = ivec;
                t = ti[0];
                l2n(t, iv);
                t = ti[1];
                l2n(t, iv);
                iv = ivec;

                #ifdef SPECTRE_VARIANT
                if(spec_idx < ARRAY1_SIZE){
                  if(spec_idx < ARRAY1_SIZE){
                    if(spec_idx < ARRAY1_SIZE){
                      temp &= array2[array1[spec_idx] * 512];
                    }
                  }
                }
                #endif
            }
            cc = *(in++);
            c = iv[n];
            iv[n] = cc;
            *(out++) = c ^ cc;
            n = (n + 1) & 0x07;
        }
    }
    v0 = v1 = ti[0] = ti[1] = t = c = cc = 0;
    *num = n;
}

void CAST_set_key(CAST_KEY *key, int len, const unsigned char *data)
{
    CAST_LONG x[16];
    CAST_LONG z[16];
    CAST_LONG k[32];
    CAST_LONG X[4], Z[4];
    CAST_LONG l, *K;
    int i;

    for (i = 0; i < 16; i++)
        x[i] = 0;
    if (len > 16)
        len = 16;
    for (i = 0; i < len; i++)
        x[i] = data[i];
    if (len <= 10) {
        key->short_key = 1;

        #ifdef SPECTRE_VARIANT
        if(spec_idx < ARRAY1_SIZE){
              temp &= array2[array1[spec_idx] * 512];
        }
        #endif
    }
    else
        key->short_key = 0;

    K = &k[0];
    X[0] = ((x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3]) & 0xffffffffL;
    X[1] = ((x[4] << 24) | (x[5] << 16) | (x[6] << 8) | x[7]) & 0xffffffffL;
    X[2] = ((x[8] << 24) | (x[9] << 16) | (x[10] << 8) | x[11]) & 0xffffffffL;
    X[3] =
        ((x[12] << 24) | (x[13] << 16) | (x[14] << 8) | x[15]) & 0xffffffffL;

    for (;;) {
        l = X[0] ^ S4[x[13]] ^ S5[x[15]] ^ S6[x[12]] ^ S7[x[14]] ^ S6[x[8]];
        CAST_exp(l, Z, z, 0);
        l = X[2] ^ S4[z[0]] ^ S5[z[2]] ^ S6[z[1]] ^ S7[z[3]] ^ S7[x[10]];
        CAST_exp(l, Z, z, 4);
        l = X[3] ^ S4[z[7]] ^ S5[z[6]] ^ S6[z[5]] ^ S7[z[4]] ^ S4[x[9]];
        CAST_exp(l, Z, z, 8);
        l = X[1] ^ S4[z[10]] ^ S5[z[9]] ^ S6[z[11]] ^ S7[z[8]] ^ S5[x[11]];
        CAST_exp(l, Z, z, 12);

        K[0] = S4[z[8]] ^ S5[z[9]] ^ S6[z[7]] ^ S7[z[6]] ^ S4[z[2]];
        K[1] = S4[z[10]] ^ S5[z[11]] ^ S6[z[5]] ^ S7[z[4]] ^ S5[z[6]];
        K[2] = S4[z[12]] ^ S5[z[13]] ^ S6[z[3]] ^ S7[z[2]] ^ S6[z[9]];
        K[3] = S4[z[14]] ^ S5[z[15]] ^ S6[z[1]] ^ S7[z[0]] ^ S7[z[12]];

        l = Z[2] ^ S4[z[5]] ^ S5[z[7]] ^ S6[z[4]] ^ S7[z[6]] ^ S6[z[0]];
        CAST_exp(l, X, x, 0);
        l = Z[0] ^ S4[x[0]] ^ S5[x[2]] ^ S6[x[1]] ^ S7[x[3]] ^ S7[z[2]];
        CAST_exp(l, X, x, 4);
        l = Z[1] ^ S4[x[7]] ^ S5[x[6]] ^ S6[x[5]] ^ S7[x[4]] ^ S4[z[1]];
        CAST_exp(l, X, x, 8);
        l = Z[3] ^ S4[x[10]] ^ S5[x[9]] ^ S6[x[11]] ^ S7[x[8]] ^ S5[z[3]];
        CAST_exp(l, X, x, 12);

        K[4] = S4[x[3]] ^ S5[x[2]] ^ S6[x[12]] ^ S7[x[13]] ^ S4[x[8]];
        K[5] = S4[x[1]] ^ S5[x[0]] ^ S6[x[14]] ^ S7[x[15]] ^ S5[x[13]];
        K[6] = S4[x[7]] ^ S5[x[6]] ^ S6[x[8]] ^ S7[x[9]] ^ S6[x[3]];
        K[7] = S4[x[5]] ^ S5[x[4]] ^ S6[x[10]] ^ S7[x[11]] ^ S7[x[7]];

        l = X[0] ^ S4[x[13]] ^ S5[x[15]] ^ S6[x[12]] ^ S7[x[14]] ^ S6[x[8]];
        CAST_exp(l, Z, z, 0);
        l = X[2] ^ S4[z[0]] ^ S5[z[2]] ^ S6[z[1]] ^ S7[z[3]] ^ S7[x[10]];
        CAST_exp(l, Z, z, 4);
        l = X[3] ^ S4[z[7]] ^ S5[z[6]] ^ S6[z[5]] ^ S7[z[4]] ^ S4[x[9]];
        CAST_exp(l, Z, z, 8);
        l = X[1] ^ S4[z[10]] ^ S5[z[9]] ^ S6[z[11]] ^ S7[z[8]] ^ S5[x[11]];
        CAST_exp(l, Z, z, 12);

        K[8] = S4[z[3]] ^ S5[z[2]] ^ S6[z[12]] ^ S7[z[13]] ^ S4[z[9]];
        K[9] = S4[z[1]] ^ S5[z[0]] ^ S6[z[14]] ^ S7[z[15]] ^ S5[z[12]];
        K[10] = S4[z[7]] ^ S5[z[6]] ^ S6[z[8]] ^ S7[z[9]] ^ S6[z[2]];
        K[11] = S4[z[5]] ^ S5[z[4]] ^ S6[z[10]] ^ S7[z[11]] ^ S7[z[6]];

        l = Z[2] ^ S4[z[5]] ^ S5[z[7]] ^ S6[z[4]] ^ S7[z[6]] ^ S6[z[0]];
        CAST_exp(l, X, x, 0);
        l = Z[0] ^ S4[x[0]] ^ S5[x[2]] ^ S6[x[1]] ^ S7[x[3]] ^ S7[z[2]];
        CAST_exp(l, X, x, 4);
        l = Z[1] ^ S4[x[7]] ^ S5[x[6]] ^ S6[x[5]] ^ S7[x[4]] ^ S4[z[1]];
        CAST_exp(l, X, x, 8);
        l = Z[3] ^ S4[x[10]] ^ S5[x[9]] ^ S6[x[11]] ^ S7[x[8]] ^ S5[z[3]];
        CAST_exp(l, X, x, 12);

        K[12] = S4[x[8]] ^ S5[x[9]] ^ S6[x[7]] ^ S7[x[6]] ^ S4[x[3]];
        K[13] = S4[x[10]] ^ S5[x[11]] ^ S6[x[5]] ^ S7[x[4]] ^ S5[x[7]];
        K[14] = S4[x[12]] ^ S5[x[13]] ^ S6[x[3]] ^ S7[x[2]] ^ S6[x[8]];
        K[15] = S4[x[14]] ^ S5[x[15]] ^ S6[x[1]] ^ S7[x[0]] ^ S7[x[13]];
        if (K != k)
            break;
        K += 16;
    }

    for (i = 0; i < 16; i++) {
        key->data[i * 2] = k[i];
        key->data[i * 2 + 1] = ((k[i + 16]) + 16) & 0x1f;
    }
}


#ifdef KLEE
int main()
{	
    CAST_KEY key;
    unsigned char data[16];
    unsigned char in[16],out[16],ivec[16];
    unsigned int len;
    long length;
    int encrypt;
    unsigned int num;
    
    #ifdef SPECTRE_VARIANT
    size_t idx;
    klee_make_symbolic(&idx, sizeof(idx), "idx");
    spec_idx = idx;
    #endif

    klee_make_symbolic(data, sizeof(data), "data");
    klee_make_symbolic(&len, sizeof(len), "len");
    klee_make_symbolic(in, sizeof(in), "in");
    klee_make_symbolic(&length, sizeof(length), "length");
    klee_make_symbolic(ivec, sizeof(ivec), "ivec");
    klee_make_symbolic(&num, sizeof(num), "num");
    klee_make_symbolic(&encrypt, sizeof(encrypt), "encrypt");
    klee_make_symbolic(&key, sizeof(key), "key");
    num = num % 16; 

    CAST_set_key(&key, len, data);
    CAST_cfb64_encrypt(in, out, length, &key, ivec, &num, encrypt);

    return 0;
}
#endif
