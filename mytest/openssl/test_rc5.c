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

#include "internal/deprecated.h"
#include "rc5_local.h"
#include <openssl/rc5.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SPECTRE_VARIANT
#define FUZZ

#ifdef SPECTRE_VARIANT
#define ARRAY1_SIZE 16
uint8_t array1[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
uint8_t array2[256 * 512];
uint8_t temp = 0;
uint8_t spec_idx = 0;
#endif

#ifdef KLEE
#include <klee/klee.h>
#endif
 
int RC5_32_set_key(RC5_32_KEY *key, int len, const unsigned char *data,
                   int rounds) {
  RC5_32_INT L[64], l, ll, A, B, *S, k;
  int i, j, m, c, t, ii, jj;

  if (len > 255)
    return 0;

  if ((rounds != RC5_16_ROUNDS) && (rounds != RC5_12_ROUNDS) &&
      (rounds != RC5_8_ROUNDS))
    rounds = RC5_16_ROUNDS;

  key->rounds = rounds;
  S = &(key->data[0]);
  j = 0;
  for (i = 0; i <= (len - 8); i += 8) {
    c2l(data, l);
    L[j++] = l;
    c2l(data, l);
    L[j++] = l;
  }
  ii = len - i;
  if (ii) {
    k = len & 0x07;
    c2ln(data, l, ll, k);
    L[j + 0] = l;
    L[j + 1] = ll;

    #ifdef SPECTRE_VARIANT
    if (spec_idx < ARRAY1_SIZE) {
      if (spec_idx < ARRAY1_SIZE) {
        if (spec_idx < ARRAY1_SIZE) {
          temp &= array2[array1[spec_idx] * 512];
        }
      }
    }
    #endif
  }

  c = (len + 3) / 4;
  t = (rounds + 1) * 2;
  S[0] = RC5_32_P;
  for (i = 1; i < t; i++)
    S[i] = (S[i - 1] + RC5_32_Q) & RC5_32_MASK;

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

void RC5_32_encrypt(unsigned long *d, RC5_32_KEY *key) {
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

    #ifdef SPECTRE_VARIANT
    if (spec_idx < ARRAY1_SIZE) {
        temp &= array2[array1[spec_idx] * 512];
    }
    #endif
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
                          unsigned char *ivec, int *num, int encrypt) {
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

        #ifdef SPECTRE_VARIANT
        if (spec_idx < ARRAY1_SIZE) {
          if (spec_idx < ARRAY1_SIZE) {
          temp &= array2[array1[spec_idx] * 512];
          }
        }
        #endif
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
int main() {
  RC5_32_KEY key;
  unsigned char out[16], buf2[16], ivb[16], in[16];
  unsigned int len;
  unsigned char data[16];
  long length;
  int rounds, encrypt;
  unsigned int num;

  #ifdef SPECTRE_VARIANT
  size_t idx;
  klee_make_symbolic(&idx, sizeof(idx), "idx");
  spec_idx = idx;
  #endif

  klee_make_symbolic(&len, sizeof(len), "len");
  klee_make_symbolic(data, sizeof(data), "data");
  klee_make_symbolic(&rounds, sizeof(rounds), "rounds");
  klee_make_symbolic(ivb, sizeof(ivb), "iv");
  klee_make_symbolic(in, sizeof(in), "in");
  klee_make_symbolic(&num, sizeof(num), "num");
  klee_make_symbolic(&length, sizeof(length), "length");
  klee_make_symbolic(&encrypt, sizeof(encrypt), "encrypt");
  num = num % 16;

  RC5_32_set_key(&key, len, data, rounds);
  RC5_32_cfb64_encrypt(in, out, length, &key, ivb, &num, encrypt);

  return 0;
}
#endif

#ifdef FUZZ
int main(int argc, char **argv) {
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

  if (file_size < 67) {
    fprintf(stderr, "Insufficient data in file\n");
    free(buffer);
    return 1;
  }

  RC5_32_KEY key;
  unsigned char buf[16], buf2[16], ivb[16], plain[16];
  unsigned int key_len;
  unsigned char key_data[16];
  int num, rounds, encrypt;

  #ifdef SPECTRE_VARIANT
  memcpy(&spec_idx, buffer, sizeof(uint8_t));
  #endif

  memcpy(key_data, buffer + sizeof(uint8_t), 16);
  memcpy(&rounds, buffer + sizeof(uint8_t) + 16, sizeof(int));
  memcpy(plain, buffer + sizeof(uint8_t) + 16 + sizeof(int), 16);
  memcpy(ivb, buffer + sizeof(uint8_t) + 16 + sizeof(int) + 16, 16);
  memcpy(&num, buffer + sizeof(uint8_t) + 16 + sizeof(int) + 16 + 16, sizeof(int));
  memcpy(&encrypt, buffer + sizeof(uint8_t) + 16 + sizeof(int) + 16 + 16 + sizeof(int), sizeof(int));
  memcpy(&key_len, buffer + sizeof(uint8_t) + 16 + sizeof(int) + 16 + 16 + sizeof(int) * 2, sizeof(unsigned int));

  num = num % 16;
   
  RC5_32_set_key(&key, key_len, key_data, rounds);
  RC5_32_cfb64_encrypt(plain, buf, 16, &key, ivb, &num, encrypt);

  return 0;
}
#endif
