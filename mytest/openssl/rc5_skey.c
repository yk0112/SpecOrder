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
#include <stddef.h>
#include <stdint.h>
#include <klee/klee.h>
#include <stdio.h>

#define SPECTRE_VARIANT
#define FUZZ

#ifdef SPECTRE_VARIANT
  #define ARRAY1_SIZE 16
  uint8_t array1[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  uint8_t array2[256 * 512];
  uint8_t temp = 0;
  uint8_t spec_idx;
#endif

uint32_t _lrotl(uint32_t value, int shift) {
    const int bits = sizeof(value) * 8; 
    shift %= bits;                  
    if (shift == 0) return value;   
    return (value << shift) | (value >> (bits - shift));
}

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


#define c2ln(c,l1,l2,n) { \
                        c+=n; \
                        l1=l2=0; \
                        switch (n) { \
                        case 8: l2 =((unsigned long)(*(--(c))))<<24L; \
                        /* fall through */                               \
                        case 7: l2|=((unsigned long)(*(--(c))))<<16L; \
                        /* fall through */                               \
                        case 6: l2|=((unsigned long)(*(--(c))))<< 8L; \
                        /* fall through */                               \
                        case 5: l2|=((unsigned long)(*(--(c))));      \
                        /* fall through */                               \
                        case 4: l1 =((unsigned long)(*(--(c))))<<24L; \
                        /* fall through */                               \
                        case 3: l1|=((unsigned long)(*(--(c))))<<16L; \
                        /* fall through */                               \
                        case 2: l1|=((unsigned long)(*(--(c))))<< 8L; \
                        /* fall through */                               \
                        case 1: l1|=((unsigned long)(*(--(c))));      \
                                } \
                        }

# define ROTATE_l32(a,n)     _lrotl(a,n)

typedef struct rc5_key_st {
    /* Number of rounds */
    int rounds;
    RC5_32_INT data[2 * (RC5_16_ROUNDS + 1)];
} RC5_32_KEY;

int RC5_32_set_key(RC5_32_KEY *key, int len, const unsigned char *data,
                   int rounds)
{
    RC5_32_INT L[64], l, ll, A, B, *S, k;
    int i, j, m, c, t, ii, jj;
    

    if (len > 255)
        return 0;

    if ((rounds != RC5_16_ROUNDS) &&
        (rounds != RC5_12_ROUNDS) && (rounds != RC5_8_ROUNDS))
        rounds = RC5_16_ROUNDS;
    key->rounds = rounds;
    S = &(key->data[0]);
     
    j = 0;
    for (i = 0; i <= (len - 8); i += 8) {
        c2l(data, l);
        L[j++] = l;
        c2l(data, l);
        L[j++] = l;

    #ifdef SPECTRE_VARIANT
       if(spec_idx < ARRAY1_SIZE){
         if(spec_idx < ARRAY1_SIZE){
            temp &= array2[array1[spec_idx] * 512];
         }
        }
    #endif
    }
    ii = len - i;
    if (ii) {
        k = len & 0x07;
        c2ln(data, l, ll, k);
        L[j + 0] = l;
        L[j + 1] = ll;
    }

    c = (len + 3) / 4;
    t = (rounds + 1) * 2;
    S[0] = RC5_32_P;

    for (i = 1; i < t; i++) {
        S[i] = (S[i - 1] + RC5_32_Q) & RC5_32_MASK;
    }

    j = (t > c) ? t : c;
    j *= 3;
    ii = jj = 0;
    A = B = 0;
    for (i = 0; i < j; i++) {
        k = (S[ii] + A + B) & RC5_32_MASK;
        A = S[ii] = ROTATE_l32(k, 3);
        m = (int)(A + B);
        k = (L[jj] + A + B) & RC5_32_MASK;
        B = L[jj] = ROTATE_l32(k, m);
        if (++ii >= t)
            ii = 0;
        if (++jj >= c)
            jj = 0;
    }

    return 1;
}

#ifdef KLEE
int main()
{	
    RC5_32_KEY key;
    int len, rounds;
    unsigned char data[16];
    
    #ifdef SPECTRE_VARIANT
    size_t idx;
    klee_make_symbolic(&idx, sizeof(idx), "idx");
    spec_idx = idx;
    #endif

    klee_make_symbolic(&key, sizeof(key), "key");
    klee_make_symbolic(&len, sizeof(len), "len");
    klee_make_symbolic(&rounds, sizeof(rounds), "rounds");
    klee_make_symbolic(&data, sizeof(data), "data");

  	RC5_32_set_key(&key, len, data, rounds);
    return 0;
}
#endif


#ifdef FUZZ
int main(int argc, char **argv)
{	
    FILE *f = fopen(argv[1], "r");
    char buffer[1024];
    size_t read_len = fread(buffer, 1, sizeof(buffer), f);
    fclose(f);

    if (read_len < 2) {
        return 0;
    }

    int rounds = buffer[0];
    int len = buffer[1];
    spec_idx = buffer[3];
    const unsigned char *data = (unsigned char *)(buffer + 3);
    RC5_32_KEY key;

  	RC5_32_set_key(&key, len, data, rounds);
    return 0;
}
#endif
