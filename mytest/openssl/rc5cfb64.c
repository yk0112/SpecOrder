/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * RC5 low level APIs are deprecated for public use, but still ok for internal
 * use.
 */


/*
 * The input and output encrypted as though 64bit cfb mode is being used.
 * The extra state information to record how much of the 64bit block we have
 * used is contained in *num;
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <klee/klee.h>
#include <stdio.h>
#include <stdlib.h>
#include <klee/klee.h>

#define SPECTRE_VARIANT
#define FUZZ

#ifdef SPECTRE_VARIANT
  #define ARRAY1_SIZE 16
  uint8_t array1[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  uint8_t array2[256 * 512];
  uint8_t temp = 0;
  uint8_t spec_idx;
#endif

#define RC5_8_ROUNDS    8
#define RC5_12_ROUNDS   12
#define RC5_16_ROUNDS   16
#define RC5_32_INT unsigned int
#define RC5_32_MASK     0xffffffffL
#define RC5_32_P        0xB7E15163L
#define RC5_32_Q        0x9E3779B9L

#define c2l(c,l)        (l =((unsigned long)(*((c)++)))    , \
                         l|=((unsigned long)(*((c)++)))<< 8L, \
                         l|=((unsigned long)(*((c)++)))<<16L, \
                         l|=((unsigned long)(*((c)++)))<<24L)

#define l2c(l,c)        (*((c)++)=(unsigned char)(((l)     )&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>24L)&0xff))

#define ROTATE_l32(a,n)     (((a)<<(n&0x1f))|(((a)&0xffffffff)>>((32-n)&0x1f)))

#define E_RC5_32(a,b,s,n) \
        a^=b; \
        a=ROTATE_l32(a,b); \
        a+=s[n]; \
        a&=RC5_32_MASK; \
        b^=a; \
        b=ROTATE_l32(b,a); \
        b+=s[n+1]; \
        b&=RC5_32_MASK;

typedef struct rc5_key_st {
    /* Number of rounds */
    int rounds;
    RC5_32_INT data[2 * (RC5_16_ROUNDS + 1)];
} RC5_32_KEY;


void RC5_32_encrypt(unsigned long *d, RC5_32_KEY *key)
{
    RC5_32_INT a, b, *s;

    s = key->data;

    a = d[0] + s[0];
    b = d[1] + s[1];
    E_RC5_32(a, b, s, 2);
    E_RC5_32(a, b, s, 4);
    E_RC5_32(a, b, s, 6);
    E_RC5_32(a, b, s, 8);
    E_RC5_32(a, b, s, 10);
    E_RC5_32(a, b, s, 12);
    E_RC5_32(a, b, s, 14);
    E_RC5_32(a, b, s, 16);
    if (key->rounds == 12) {
        E_RC5_32(a, b, s, 18);
        E_RC5_32(a, b, s, 20);
        E_RC5_32(a, b, s, 22);
        E_RC5_32(a, b, s, 24);
    } else if (key->rounds == 16) {
        /* Do a full expansion to avoid a jump */
        E_RC5_32(a, b, s, 18);
        E_RC5_32(a, b, s, 20);
        E_RC5_32(a, b, s, 22);
        E_RC5_32(a, b, s, 24);
        E_RC5_32(a, b, s, 26);
        E_RC5_32(a, b, s, 28);
        E_RC5_32(a, b, s, 30);
        E_RC5_32(a, b, s, 32);
    }
    d[0] = a;
    d[1] = b;
}

void RC5_32_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                          long length, RC5_32_KEY *schedule,
                          unsigned char *ivec, int *num, int encrypt)
{
    register unsigned long v0, v1, t;
    register int n = *num;
    register long l = length;
    unsigned long ti[2];
    unsigned char *iv, c, cc;

    iv = (unsigned char *)ivec;
    if (encrypt) {
        while (l--) {
            if (n == 0) {
                c2l(iv, v0);
                ti[0] = v0;
                c2l(iv, v1);
                ti[1] = v1;
                RC5_32_encrypt((unsigned long *)ti, schedule);
                iv = (unsigned char *)ivec;
                t = ti[0];
                l2c(t, iv);
                t = ti[1];
                l2c(t, iv);
                iv = (unsigned char *)ivec;
            }
            c = *(in++) ^ iv[n];
            *(out++) = c;
            iv[n] = c;
            n = (n + 1) & 0x07;
        }
    } else {
        while (l--) {
            if (n == 0) {
                c2l(iv, v0);
                ti[0] = v0;
                c2l(iv, v1);
                ti[1] = v1;
                RC5_32_encrypt((unsigned long *)ti, schedule);
                iv = (unsigned char *)ivec;
                t = ti[0];
                l2c(t, iv);
                t = ti[1];
                l2c(t, iv);
                iv = (unsigned char *)ivec;
                
                #ifdef SPECTRE_VARIANT
                if(spec_idx < ARRAY1_SIZE){
                  temp &= array2[array1[spec_idx] * 512];
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

#ifdef KLEE
int main()
{	
    unsigned char in[16], out[16], ivec[16];
    long length;  
    RC5_32_KEY schedule;
    int num, encrypt;

    #ifdef SPECTRE_VARIANT
    size_t idx;
    klee_make_symbolic(&idx, sizeof(idx), "idx");
    spec_idx = idx;
    #endif

    // klee_make_symbolic(&in, sizeof(in), "in");
    // klee_make_symbolic(&out, sizeof(out), "out");
    // klee_make_symbolic(&ivec, sizeof(ivec), "ivec");
    klee_make_symbolic(&length, sizeof(length), "length");
    klee_make_symbolic(&schedule, sizeof(schedule), "schedule");
    klee_make_symbolic(&num, sizeof(num), "num");
    klee_make_symbolic(&encrypt, sizeof(encrypt), "encrypt");

    RC5_32_cfb64_encrypt(in, out, length, &schedule, ivec, &num, encrypt);
    return 0;
}
#endif

#ifdef FUZZ
int main(int argc, char **argv)
{	
    FILE *file = fopen(argv[1], "r");
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    unsigned char *buffer = malloc(file_size);
    
    if (!buffer) {
      fclose(file);
      return 1;
    }

    if (fread(buffer, 1, file_size, file) != file_size) {
        free(buffer);
        fclose(file);
        return 1;
    }
    fclose(file);

    unsigned char in[16] = {0}, out[16] = {0}, ivec[16] = {0};
    long length;  
    RC5_32_KEY schedule;
    int num, encrypt;

    if (file_size < sizeof(RC5_32_KEY) + 13) {
        free(buffer);
        fclose(file);
        return 1;
    }

    memcpy(&spec_idx, buffer, sizeof(uint8_t));
    memcpy(&schedule, buffer + sizeof(uint8_t), sizeof(RC5_32_KEY));
    memcpy(&num, buffer + sizeof(uint8_t) + sizeof(RC5_32_KEY), sizeof(int));
    memcpy(&encrypt, buffer + sizeof(uint8_t) + sizeof(RC5_32_KEY) + sizeof(int), sizeof(int));
  
    num = num % 16;
    RC5_32_cfb64_encrypt(in, out, 16, &schedule, ivec, &num, encrypt);
    
    free(buffer);
    return 0;
}
#endif
