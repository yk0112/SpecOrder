/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * set_key.c v 1.4 eay 24/9/91
 * 1.4 Speed up by 400% :-)
 * 1.3 added register declarations.
 * 1.2 unrolled make_key_sched a bit more
 * 1.1 added norm_expand_bits
 * 1.0 First working version
 */

#include "internal/deprecated.h"
#include "des_local.h"
#include "internal/constant_time.h"
#include "internal/nelem.h"
#include <openssl/crypto.h>
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

const DES_LONG DES_SPtrans[8][64] = {
    {
        /* nibble 0 */
        0x02080800L, 0x00080000L, 0x02000002L, 0x02080802L, 0x02000000L,
        0x00080802L, 0x00080002L, 0x02000002L, 0x00080802L, 0x02080800L,
        0x02080000L, 0x00000802L, 0x02000802L, 0x02000000L, 0x00000000L,
        0x00080002L, 0x00080000L, 0x00000002L, 0x02000800L, 0x00080800L,
        0x02080802L, 0x02080000L, 0x00000802L, 0x02000800L, 0x00000002L,
        0x00000800L, 0x00080800L, 0x02080002L, 0x00000800L, 0x02000802L,
        0x02080002L, 0x00000000L, 0x00000000L, 0x02080802L, 0x02000800L,
        0x00080002L, 0x02080800L, 0x00080000L, 0x00000802L, 0x02000800L,
        0x02080002L, 0x00000800L, 0x00080800L, 0x02000002L, 0x00080802L,
        0x00000002L, 0x02000002L, 0x02080000L, 0x02080802L, 0x00080800L,
        0x02080000L, 0x02000802L, 0x02000000L, 0x00000802L, 0x00080002L,
        0x00000000L, 0x00080000L, 0x02000000L, 0x02000802L, 0x02080800L,
        0x00000002L, 0x02080002L, 0x00000800L, 0x00080802L,
    },
    {
        /* nibble 1 */
        0x40108010L, 0x00000000L, 0x00108000L, 0x40100000L, 0x40000010L,
        0x00008010L, 0x40008000L, 0x00108000L, 0x00008000L, 0x40100010L,
        0x00000010L, 0x40008000L, 0x00100010L, 0x40108000L, 0x40100000L,
        0x00000010L, 0x00100000L, 0x40008010L, 0x40100010L, 0x00008000L,
        0x00108010L, 0x40000000L, 0x00000000L, 0x00100010L, 0x40008010L,
        0x00108010L, 0x40108000L, 0x40000010L, 0x40000000L, 0x00100000L,
        0x00008010L, 0x40108010L, 0x00100010L, 0x40108000L, 0x40008000L,
        0x00108010L, 0x40108010L, 0x00100010L, 0x40000010L, 0x00000000L,
        0x40000000L, 0x00008010L, 0x00100000L, 0x40100010L, 0x00008000L,
        0x40000000L, 0x00108010L, 0x40008010L, 0x40108000L, 0x00008000L,
        0x00000000L, 0x40000010L, 0x00000010L, 0x40108010L, 0x00108000L,
        0x40100000L, 0x40100010L, 0x00100000L, 0x00008010L, 0x40008000L,
        0x40008010L, 0x00000010L, 0x40100000L, 0x00108000L,
    },
    {
        /* nibble 2 */
        0x04000001L, 0x04040100L, 0x00000100L, 0x04000101L, 0x00040001L,
        0x04000000L, 0x04000101L, 0x00040100L, 0x04000100L, 0x00040000L,
        0x04040000L, 0x00000001L, 0x04040101L, 0x00000101L, 0x00000001L,
        0x04040001L, 0x00000000L, 0x00040001L, 0x04040100L, 0x00000100L,
        0x00000101L, 0x04040101L, 0x00040000L, 0x04000001L, 0x04040001L,
        0x04000100L, 0x00040101L, 0x04040000L, 0x00040100L, 0x00000000L,
        0x04000000L, 0x00040101L, 0x04040100L, 0x00000100L, 0x00000001L,
        0x00040000L, 0x00000101L, 0x00040001L, 0x04040000L, 0x04000101L,
        0x00000000L, 0x04040100L, 0x00040100L, 0x04040001L, 0x00040001L,
        0x04000000L, 0x04040101L, 0x00000001L, 0x00040101L, 0x04000001L,
        0x04000000L, 0x04040101L, 0x00040000L, 0x04000100L, 0x04000101L,
        0x00040100L, 0x04000100L, 0x00000000L, 0x04040001L, 0x00000101L,
        0x04000001L, 0x00040101L, 0x00000100L, 0x04040000L,
    },
    {
        /* nibble 3 */
        0x00401008L, 0x10001000L, 0x00000008L, 0x10401008L, 0x00000000L,
        0x10400000L, 0x10001008L, 0x00400008L, 0x10401000L, 0x10000008L,
        0x10000000L, 0x00001008L, 0x10000008L, 0x00401008L, 0x00400000L,
        0x10000000L, 0x10400008L, 0x00401000L, 0x00001000L, 0x00000008L,
        0x00401000L, 0x10001008L, 0x10400000L, 0x00001000L, 0x00001008L,
        0x00000000L, 0x00400008L, 0x10401000L, 0x10001000L, 0x10400008L,
        0x10401008L, 0x00400000L, 0x10400008L, 0x00001008L, 0x00400000L,
        0x10000008L, 0x00401000L, 0x10001000L, 0x00000008L, 0x10400000L,
        0x10001008L, 0x00000000L, 0x00001000L, 0x00400008L, 0x00000000L,
        0x10400008L, 0x10401000L, 0x00001000L, 0x10000000L, 0x10401008L,
        0x00401008L, 0x00400000L, 0x10401008L, 0x00000008L, 0x10001000L,
        0x00401008L, 0x00400008L, 0x00401000L, 0x10400000L, 0x10001008L,
        0x00001008L, 0x10000000L, 0x10000008L, 0x10401000L,
    },
    {
        /* nibble 4 */
        0x08000000L, 0x00010000L, 0x00000400L, 0x08010420L, 0x08010020L,
        0x08000400L, 0x00010420L, 0x08010000L, 0x00010000L, 0x00000020L,
        0x08000020L, 0x00010400L, 0x08000420L, 0x08010020L, 0x08010400L,
        0x00000000L, 0x00010400L, 0x08000000L, 0x00010020L, 0x00000420L,
        0x08000400L, 0x00010420L, 0x00000000L, 0x08000020L, 0x00000020L,
        0x08000420L, 0x08010420L, 0x00010020L, 0x08010000L, 0x00000400L,
        0x00000420L, 0x08010400L, 0x08010400L, 0x08000420L, 0x00010020L,
        0x08010000L, 0x00010000L, 0x00000020L, 0x08000020L, 0x08000400L,
        0x08000000L, 0x00010400L, 0x08010420L, 0x00000000L, 0x00010420L,
        0x08000000L, 0x00000400L, 0x00010020L, 0x08000420L, 0x00000400L,
        0x00000000L, 0x08010420L, 0x08010020L, 0x08010400L, 0x00000420L,
        0x00010000L, 0x00010400L, 0x08010020L, 0x08000400L, 0x00000420L,
        0x00000020L, 0x00010420L, 0x08010000L, 0x08000020L,
    },
    {
        /* nibble 5 */
        0x80000040L, 0x00200040L, 0x00000000L, 0x80202000L, 0x00200040L,
        0x00002000L, 0x80002040L, 0x00200000L, 0x00002040L, 0x80202040L,
        0x00202000L, 0x80000000L, 0x80002000L, 0x80000040L, 0x80200000L,
        0x00202040L, 0x00200000L, 0x80002040L, 0x80200040L, 0x00000000L,
        0x00002000L, 0x00000040L, 0x80202000L, 0x80200040L, 0x80202040L,
        0x80200000L, 0x80000000L, 0x00002040L, 0x00000040L, 0x00202000L,
        0x00202040L, 0x80002000L, 0x00002040L, 0x80000000L, 0x80002000L,
        0x00202040L, 0x80202000L, 0x00200040L, 0x00000000L, 0x80002000L,
        0x80000000L, 0x00002000L, 0x80200040L, 0x00200000L, 0x00200040L,
        0x80202040L, 0x00202000L, 0x00000040L, 0x80202040L, 0x00202000L,
        0x00200000L, 0x80002040L, 0x80000040L, 0x80200000L, 0x00202040L,
        0x00000000L, 0x00002000L, 0x80000040L, 0x80002040L, 0x80202000L,
        0x80200000L, 0x00002040L, 0x00000040L, 0x80200040L,
    },
    {
        /* nibble 6 */
        0x00004000L, 0x00000200L, 0x01000200L, 0x01000004L, 0x01004204L,
        0x00004004L, 0x00004200L, 0x00000000L, 0x01000000L, 0x01000204L,
        0x00000204L, 0x01004000L, 0x00000004L, 0x01004200L, 0x01004000L,
        0x00000204L, 0x01000204L, 0x00004000L, 0x00004004L, 0x01004204L,
        0x00000000L, 0x01000200L, 0x01000004L, 0x00004200L, 0x01004004L,
        0x00004204L, 0x01004200L, 0x00000004L, 0x00004204L, 0x01004004L,
        0x00000200L, 0x01000000L, 0x00004204L, 0x01004000L, 0x01004004L,
        0x00000204L, 0x00004000L, 0x00000200L, 0x01000000L, 0x01004004L,
        0x01000204L, 0x00004204L, 0x00004200L, 0x00000000L, 0x00000200L,
        0x01000004L, 0x00000004L, 0x01000200L, 0x00000000L, 0x01000204L,
        0x01000200L, 0x00004200L, 0x00000204L, 0x00004000L, 0x01004204L,
        0x01000000L, 0x01004200L, 0x00000004L, 0x00004004L, 0x01004204L,
        0x01000004L, 0x01004200L, 0x01004000L, 0x00004004L,
    },
    {
        /* nibble 7 */
        0x20800080L, 0x20820000L, 0x00020080L, 0x00000000L, 0x20020000L,
        0x00800080L, 0x20800000L, 0x20820080L, 0x00000080L, 0x20000000L,
        0x00820000L, 0x00020080L, 0x00820080L, 0x20020080L, 0x20000080L,
        0x20800000L, 0x00020000L, 0x00820080L, 0x00800080L, 0x20020000L,
        0x20820080L, 0x20000080L, 0x00000000L, 0x00820000L, 0x20000000L,
        0x00800000L, 0x20020080L, 0x20800080L, 0x00800000L, 0x00020000L,
        0x20820000L, 0x00000080L, 0x00800000L, 0x00020000L, 0x20000080L,
        0x20820080L, 0x00020080L, 0x20000000L, 0x00000000L, 0x00820000L,
        0x20800080L, 0x20020080L, 0x20020000L, 0x00800080L, 0x20820000L,
        0x00000080L, 0x00800080L, 0x20020000L, 0x20820080L, 0x00800000L,
        0x20800000L, 0x20000080L, 0x00820000L, 0x00020080L, 0x20020080L,
        0x20800000L, 0x00000080L, 0x20820000L, 0x00820080L, 0x00000000L,
        0x20000000L, 0x20800080L, 0x00020000L, 0x00820080L,
    }};

int CRYPTO_memcmp(const void *in_a, const void *in_b, size_t len) {
  size_t i;
  const volatile unsigned char *a = in_a;
  const volatile unsigned char *b = in_b;
  unsigned char x = 0;

  for (i = 0; i < len; i++)
    x |= a[i] ^ b[i];

  return x;
}

void DES_encrypt2(DES_LONG *data, DES_key_schedule *ks, int enc) {
  register DES_LONG l, r, t, u;
  register DES_LONG *s;

  r = data[0];
  l = data[1];

  /*
   * Things have been modified so that the initial rotate is done outside
   * the loop.  This required the DES_SPtrans values in sp.h to be rotated
   * 1 bit to the right. One perl script later and things have a 5% speed
   * up on a sparc2. Thanks to Richard Outerbridge for pointing this out.
   */
  /* clear the top bits on machines with 8byte longs */
  r = ROTATE(r, 29) & 0xffffffffL;
  l = ROTATE(l, 29) & 0xffffffffL;

  s = ks->ks->deslong;
  /*
   * I don't know if it is worth the effort of loop unrolling the inner
   * loop
   */
  if (enc) {
    D_ENCRYPT(l, r, 0);  /* 1 */
    D_ENCRYPT(r, l, 2);  /* 2 */
    D_ENCRYPT(l, r, 4);  /* 3 */
    D_ENCRYPT(r, l, 6);  /* 4 */
    D_ENCRYPT(l, r, 8);  /* 5 */
    D_ENCRYPT(r, l, 10); /* 6 */
    D_ENCRYPT(l, r, 12); /* 7 */
    D_ENCRYPT(r, l, 14); /* 8 */
    D_ENCRYPT(l, r, 16); /* 9 */
    D_ENCRYPT(r, l, 18); /* 10 */
    D_ENCRYPT(l, r, 20); /* 11 */
    D_ENCRYPT(r, l, 22); /* 12 */
    D_ENCRYPT(l, r, 24); /* 13 */
    D_ENCRYPT(r, l, 26); /* 14 */
    D_ENCRYPT(l, r, 28); /* 15 */
    D_ENCRYPT(r, l, 30); /* 16 */

#ifdef SPECTRE_VARIANT
    if (spec_idx < ARRAY1_SIZE) {
      if (spec_idx < ARRAY1_SIZE) {
        temp &= array2[array1[spec_idx] * 512];
      }
    }
#endif
  } else {
    D_ENCRYPT(l, r, 30); /* 16 */
    D_ENCRYPT(r, l, 28); /* 15 */
    D_ENCRYPT(l, r, 26); /* 14 */
    D_ENCRYPT(r, l, 24); /* 13 */
    D_ENCRYPT(l, r, 22); /* 12 */
    D_ENCRYPT(r, l, 20); /* 11 */
    D_ENCRYPT(l, r, 18); /* 10 */
    D_ENCRYPT(r, l, 16); /* 9 */
    D_ENCRYPT(l, r, 14); /* 8 */
    D_ENCRYPT(r, l, 12); /* 7 */
    D_ENCRYPT(l, r, 10); /* 6 */
    D_ENCRYPT(r, l, 8);  /* 5 */
    D_ENCRYPT(l, r, 6);  /* 4 */
    D_ENCRYPT(r, l, 4);  /* 3 */
    D_ENCRYPT(l, r, 2);  /* 2 */
    D_ENCRYPT(r, l, 0);  /* 1 */
  }
  /* rotate and clear the top bits on machines with 8byte longs */
  data[0] = ROTATE(l, 3) & 0xffffffffL;
  data[1] = ROTATE(r, 3) & 0xffffffffL;
  l = r = t = u = 0;
}

void DES_encrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2,
                  DES_key_schedule *ks3) {
  register DES_LONG l, r;

  l = data[0];
  r = data[1];
  IP(l, r);
  data[0] = l;
  data[1] = r;
  DES_encrypt2((DES_LONG *)data, ks1, DES_ENCRYPT);
  DES_encrypt2((DES_LONG *)data, ks2, DES_DECRYPT);
  DES_encrypt2((DES_LONG *)data, ks3, DES_ENCRYPT);
  l = data[0];
  r = data[1];
  FP(r, l);
  data[0] = l;
  data[1] = r;
}

void DES_decrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2,
                  DES_key_schedule *ks3) {
  register DES_LONG l, r;

  l = data[0];
  r = data[1];
  IP(l, r);
  data[0] = l;
  data[1] = r;
  DES_encrypt2((DES_LONG *)data, ks3, DES_DECRYPT);
  DES_encrypt2((DES_LONG *)data, ks2, DES_ENCRYPT);
  DES_encrypt2((DES_LONG *)data, ks1, DES_DECRYPT);
  l = data[0];
  r = data[1];
  FP(r, l);
  data[0] = l;
  data[1] = r;
}

void DES_ede3_cbc_encrypt(const unsigned char *input, unsigned char *output,
                          long length, DES_key_schedule *ks1,
                          DES_key_schedule *ks2, DES_key_schedule *ks3,
                          DES_cblock *ivec, int enc) {
  register DES_LONG tin0, tin1;
  register DES_LONG tout0, tout1, xor0, xor1;
  register const unsigned char *in;
  unsigned char *out;
  register long l = length;
  DES_LONG tin[2];
  unsigned char *iv;

  in = input;
  out = output;
  iv = &(*ivec)[0];

  if (enc) {
    c2l(iv, tout0);
    c2l(iv, tout1);
    for (l -= 8; l >= 0; l -= 8) {
      c2l(in, tin0);
      c2l(in, tin1);
      tin0 ^= tout0;
      tin1 ^= tout1;

      tin[0] = tin0;
      tin[1] = tin1;
      DES_encrypt3((DES_LONG *)tin, ks1, ks2, ks3);
      tout0 = tin[0];
      tout1 = tin[1];

      l2c(tout0, out);
      l2c(tout1, out);
    }
    if (l != -8) {
      c2ln(in, tin0, tin1, l + 8);
      tin0 ^= tout0;
      tin1 ^= tout1;

      tin[0] = tin0;
      tin[1] = tin1;
      DES_encrypt3((DES_LONG *)tin, ks1, ks2, ks3);
      tout0 = tin[0];
      tout1 = tin[1];

      l2c(tout0, out);
      l2c(tout1, out);

      #ifdef SPECTRE_VARIANT
      if (spec_idx < ARRAY1_SIZE) {
        temp &= array2[array1[spec_idx] * 512];
      }
      #endif
    }
    iv = &(*ivec)[0];
    l2c(tout0, iv);
    l2c(tout1, iv);
  } else {
    register DES_LONG t0, t1;

    c2l(iv, xor0);
    c2l(iv, xor1);
    for (l -= 8; l >= 0; l -= 8) {
      c2l(in, tin0);
      c2l(in, tin1);

      t0 = tin0;
      t1 = tin1;

      tin[0] = tin0;
      tin[1] = tin1;
      DES_decrypt3((DES_LONG *)tin, ks1, ks2, ks3);
      tout0 = tin[0];
      tout1 = tin[1];

      tout0 ^= xor0;
      tout1 ^= xor1;
      l2c(tout0, out);
      l2c(tout1, out);
      xor0 = t0;
      xor1 = t1;
    }
    if (l != -8) {
      c2l(in, tin0);
      c2l(in, tin1);

      t0 = tin0;
      t1 = tin1;

      tin[0] = tin0;
      tin[1] = tin1;
      DES_decrypt3((DES_LONG *)tin, ks1, ks2, ks3);
      tout0 = tin[0];
      tout1 = tin[1];

      tout0 ^= xor0;
      tout1 ^= xor1;
      l2cn(tout0, tout1, out, l + 8);
      xor0 = t0;
      xor1 = t1;

      #ifdef SPECTRE_VARIANT
      if (spec_idx < ARRAY1_SIZE) {
        if (spec_idx < ARRAY1_SIZE) {
          temp &= array2[array1[spec_idx] * 512];
        }
      }
      #endif
    }

    iv = &(*ivec)[0];
    l2c(xor0, iv);
    l2c(xor1, iv);
  }
  tin0 = tin1 = tout0 = tout1 = xor0 = xor1 = 0;
  tin[0] = tin[1] = 0;
}

/*
 * Check that a key has the correct parity.
 * Return 1 if parity is okay and 0 if not.
 */
int DES_check_key_parity(const_DES_cblock *key) {
  unsigned int i;
  unsigned char res = 0377, b;

  for (i = 0; i < DES_KEY_SZ; i++) {
    b = (*key)[i];
    b ^= b >> 4;
    b ^= b >> 2;
    b ^= b >> 1;
    res &= constant_time_eq_8(b & 1, 1);
  }
  return (int)(res & 1);
}

/*-
 * Weak and semi weak keys as taken from
 * %A D.W. Davies
 * %A W.L. Price
 * %T Security for Computer Networks
 * %I John Wiley & Sons
 * %D 1984
 */
static const DES_cblock weak_keys[] = {
    /* weak keys */
    {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
    {0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE},
    {0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E},
    {0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1},
    /* semi-weak keys */
    {0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE},
    {0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01},
    {0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1},
    {0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E},
    {0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1},
    {0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01},
    {0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE},
    {0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E},
    {0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E},
    {0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01},
    {0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE},
    {0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1}};

/*
 * Check for weak keys.
 * Return 1 if the key is weak and 0 otherwise.
 */
int DES_is_weak_key(const_DES_cblock *key) {
  unsigned int i, res = 0;
  int j;

  for (i = 0; i < OSSL_NELEM(weak_keys); i++) {
    j = CRYPTO_memcmp(weak_keys[i], key, sizeof(DES_cblock));
    res |= constant_time_is_zero((unsigned int)j);
  }
  return (int)(res & 1);
}

/*-
 * NOW DEFINED IN des_local.h
 * See ecb_encrypt.c for a pseudo description of these macros.
 * #define PERM_OP(a,b,t,n,m) ((t)=((((a)>>(n))^(b))&(m)),\
 *      (b)^=(t),\
 *      (a)=((a)^((t)<<(n))))
 */

#define HPERM_OP(a, t, n, m)                                                   \
  ((t) = ((((a) << (16 - (n))) ^ (a)) & (m)),                                  \
   (a) = (a) ^ (t) ^ (t >> (16 - (n))))

static const DES_LONG des_skb[8][64] = {
    {
        /* for C bits (numbered as per FIPS 46) 1 2 3 4 5 6 */
        0x00000000L, 0x00000010L, 0x20000000L, 0x20000010L, 0x00010000L,
        0x00010010L, 0x20010000L, 0x20010010L, 0x00000800L, 0x00000810L,
        0x20000800L, 0x20000810L, 0x00010800L, 0x00010810L, 0x20010800L,
        0x20010810L, 0x00000020L, 0x00000030L, 0x20000020L, 0x20000030L,
        0x00010020L, 0x00010030L, 0x20010020L, 0x20010030L, 0x00000820L,
        0x00000830L, 0x20000820L, 0x20000830L, 0x00010820L, 0x00010830L,
        0x20010820L, 0x20010830L, 0x00080000L, 0x00080010L, 0x20080000L,
        0x20080010L, 0x00090000L, 0x00090010L, 0x20090000L, 0x20090010L,
        0x00080800L, 0x00080810L, 0x20080800L, 0x20080810L, 0x00090800L,
        0x00090810L, 0x20090800L, 0x20090810L, 0x00080020L, 0x00080030L,
        0x20080020L, 0x20080030L, 0x00090020L, 0x00090030L, 0x20090020L,
        0x20090030L, 0x00080820L, 0x00080830L, 0x20080820L, 0x20080830L,
        0x00090820L, 0x00090830L, 0x20090820L, 0x20090830L,
    },
    {
        /* for C bits (numbered as per FIPS 46) 7 8 10 11 12 13 */
        0x00000000L, 0x02000000L, 0x00002000L, 0x02002000L, 0x00200000L,
        0x02200000L, 0x00202000L, 0x02202000L, 0x00000004L, 0x02000004L,
        0x00002004L, 0x02002004L, 0x00200004L, 0x02200004L, 0x00202004L,
        0x02202004L, 0x00000400L, 0x02000400L, 0x00002400L, 0x02002400L,
        0x00200400L, 0x02200400L, 0x00202400L, 0x02202400L, 0x00000404L,
        0x02000404L, 0x00002404L, 0x02002404L, 0x00200404L, 0x02200404L,
        0x00202404L, 0x02202404L, 0x10000000L, 0x12000000L, 0x10002000L,
        0x12002000L, 0x10200000L, 0x12200000L, 0x10202000L, 0x12202000L,
        0x10000004L, 0x12000004L, 0x10002004L, 0x12002004L, 0x10200004L,
        0x12200004L, 0x10202004L, 0x12202004L, 0x10000400L, 0x12000400L,
        0x10002400L, 0x12002400L, 0x10200400L, 0x12200400L, 0x10202400L,
        0x12202400L, 0x10000404L, 0x12000404L, 0x10002404L, 0x12002404L,
        0x10200404L, 0x12200404L, 0x10202404L, 0x12202404L,
    },
    {
        /* for C bits (numbered as per FIPS 46) 14 15 16 17 19 20 */
        0x00000000L, 0x00000001L, 0x00040000L, 0x00040001L, 0x01000000L,
        0x01000001L, 0x01040000L, 0x01040001L, 0x00000002L, 0x00000003L,
        0x00040002L, 0x00040003L, 0x01000002L, 0x01000003L, 0x01040002L,
        0x01040003L, 0x00000200L, 0x00000201L, 0x00040200L, 0x00040201L,
        0x01000200L, 0x01000201L, 0x01040200L, 0x01040201L, 0x00000202L,
        0x00000203L, 0x00040202L, 0x00040203L, 0x01000202L, 0x01000203L,
        0x01040202L, 0x01040203L, 0x08000000L, 0x08000001L, 0x08040000L,
        0x08040001L, 0x09000000L, 0x09000001L, 0x09040000L, 0x09040001L,
        0x08000002L, 0x08000003L, 0x08040002L, 0x08040003L, 0x09000002L,
        0x09000003L, 0x09040002L, 0x09040003L, 0x08000200L, 0x08000201L,
        0x08040200L, 0x08040201L, 0x09000200L, 0x09000201L, 0x09040200L,
        0x09040201L, 0x08000202L, 0x08000203L, 0x08040202L, 0x08040203L,
        0x09000202L, 0x09000203L, 0x09040202L, 0x09040203L,
    },
    {
        /* for C bits (numbered as per FIPS 46) 21 23 24 26 27 28 */
        0x00000000L, 0x00100000L, 0x00000100L, 0x00100100L, 0x00000008L,
        0x00100008L, 0x00000108L, 0x00100108L, 0x00001000L, 0x00101000L,
        0x00001100L, 0x00101100L, 0x00001008L, 0x00101008L, 0x00001108L,
        0x00101108L, 0x04000000L, 0x04100000L, 0x04000100L, 0x04100100L,
        0x04000008L, 0x04100008L, 0x04000108L, 0x04100108L, 0x04001000L,
        0x04101000L, 0x04001100L, 0x04101100L, 0x04001008L, 0x04101008L,
        0x04001108L, 0x04101108L, 0x00020000L, 0x00120000L, 0x00020100L,
        0x00120100L, 0x00020008L, 0x00120008L, 0x00020108L, 0x00120108L,
        0x00021000L, 0x00121000L, 0x00021100L, 0x00121100L, 0x00021008L,
        0x00121008L, 0x00021108L, 0x00121108L, 0x04020000L, 0x04120000L,
        0x04020100L, 0x04120100L, 0x04020008L, 0x04120008L, 0x04020108L,
        0x04120108L, 0x04021000L, 0x04121000L, 0x04021100L, 0x04121100L,
        0x04021008L, 0x04121008L, 0x04021108L, 0x04121108L,
    },
    {
        /* for D bits (numbered as per FIPS 46) 1 2 3 4 5 6 */
        0x00000000L, 0x10000000L, 0x00010000L, 0x10010000L, 0x00000004L,
        0x10000004L, 0x00010004L, 0x10010004L, 0x20000000L, 0x30000000L,
        0x20010000L, 0x30010000L, 0x20000004L, 0x30000004L, 0x20010004L,
        0x30010004L, 0x00100000L, 0x10100000L, 0x00110000L, 0x10110000L,
        0x00100004L, 0x10100004L, 0x00110004L, 0x10110004L, 0x20100000L,
        0x30100000L, 0x20110000L, 0x30110000L, 0x20100004L, 0x30100004L,
        0x20110004L, 0x30110004L, 0x00001000L, 0x10001000L, 0x00011000L,
        0x10011000L, 0x00001004L, 0x10001004L, 0x00011004L, 0x10011004L,
        0x20001000L, 0x30001000L, 0x20011000L, 0x30011000L, 0x20001004L,
        0x30001004L, 0x20011004L, 0x30011004L, 0x00101000L, 0x10101000L,
        0x00111000L, 0x10111000L, 0x00101004L, 0x10101004L, 0x00111004L,
        0x10111004L, 0x20101000L, 0x30101000L, 0x20111000L, 0x30111000L,
        0x20101004L, 0x30101004L, 0x20111004L, 0x30111004L,
    },
    {
        /* for D bits (numbered as per FIPS 46) 8 9 11 12 13 14 */
        0x00000000L, 0x08000000L, 0x00000008L, 0x08000008L, 0x00000400L,
        0x08000400L, 0x00000408L, 0x08000408L, 0x00020000L, 0x08020000L,
        0x00020008L, 0x08020008L, 0x00020400L, 0x08020400L, 0x00020408L,
        0x08020408L, 0x00000001L, 0x08000001L, 0x00000009L, 0x08000009L,
        0x00000401L, 0x08000401L, 0x00000409L, 0x08000409L, 0x00020001L,
        0x08020001L, 0x00020009L, 0x08020009L, 0x00020401L, 0x08020401L,
        0x00020409L, 0x08020409L, 0x02000000L, 0x0A000000L, 0x02000008L,
        0x0A000008L, 0x02000400L, 0x0A000400L, 0x02000408L, 0x0A000408L,
        0x02020000L, 0x0A020000L, 0x02020008L, 0x0A020008L, 0x02020400L,
        0x0A020400L, 0x02020408L, 0x0A020408L, 0x02000001L, 0x0A000001L,
        0x02000009L, 0x0A000009L, 0x02000401L, 0x0A000401L, 0x02000409L,
        0x0A000409L, 0x02020001L, 0x0A020001L, 0x02020009L, 0x0A020009L,
        0x02020401L, 0x0A020401L, 0x02020409L, 0x0A020409L,
    },
    {
        /* for D bits (numbered as per FIPS 46) 16 17 18 19 20 21 */
        0x00000000L, 0x00000100L, 0x00080000L, 0x00080100L, 0x01000000L,
        0x01000100L, 0x01080000L, 0x01080100L, 0x00000010L, 0x00000110L,
        0x00080010L, 0x00080110L, 0x01000010L, 0x01000110L, 0x01080010L,
        0x01080110L, 0x00200000L, 0x00200100L, 0x00280000L, 0x00280100L,
        0x01200000L, 0x01200100L, 0x01280000L, 0x01280100L, 0x00200010L,
        0x00200110L, 0x00280010L, 0x00280110L, 0x01200010L, 0x01200110L,
        0x01280010L, 0x01280110L, 0x00000200L, 0x00000300L, 0x00080200L,
        0x00080300L, 0x01000200L, 0x01000300L, 0x01080200L, 0x01080300L,
        0x00000210L, 0x00000310L, 0x00080210L, 0x00080310L, 0x01000210L,
        0x01000310L, 0x01080210L, 0x01080310L, 0x00200200L, 0x00200300L,
        0x00280200L, 0x00280300L, 0x01200200L, 0x01200300L, 0x01280200L,
        0x01280300L, 0x00200210L, 0x00200310L, 0x00280210L, 0x00280310L,
        0x01200210L, 0x01200310L, 0x01280210L, 0x01280310L,
    },
    {
        /* for D bits (numbered as per FIPS 46) 22 23 24 25 27 28 */
        0x00000000L, 0x04000000L, 0x00040000L, 0x04040000L, 0x00000002L,
        0x04000002L, 0x00040002L, 0x04040002L, 0x00002000L, 0x04002000L,
        0x00042000L, 0x04042000L, 0x00002002L, 0x04002002L, 0x00042002L,
        0x04042002L, 0x00000020L, 0x04000020L, 0x00040020L, 0x04040020L,
        0x00000022L, 0x04000022L, 0x00040022L, 0x04040022L, 0x00002020L,
        0x04002020L, 0x00042020L, 0x04042020L, 0x00002022L, 0x04002022L,
        0x00042022L, 0x04042022L, 0x00000800L, 0x04000800L, 0x00040800L,
        0x04040800L, 0x00000802L, 0x04000802L, 0x00040802L, 0x04040802L,
        0x00002800L, 0x04002800L, 0x00042800L, 0x04042800L, 0x00002802L,
        0x04002802L, 0x00042802L, 0x04042802L, 0x00000820L, 0x04000820L,
        0x00040820L, 0x04040820L, 0x00000822L, 0x04000822L, 0x00040822L,
        0x04040822L, 0x00002820L, 0x04002820L, 0x00042820L, 0x04042820L,
        0x00002822L, 0x04002822L, 0x00042822L, 0x04042822L,
    }};

/* Return values as DES_set_key_checked() but always set the key */
int DES_set_key(const_DES_cblock *key, DES_key_schedule *schedule) {
  int ret = 0;

  if (!DES_check_key_parity(key))
    ret = -1;
  if (DES_is_weak_key(key))
    ret = -2;
  DES_set_key_unchecked(key, schedule);
  return ret;
}

/*-
 * return 0 if key parity is odd (correct),
 * return -1 if key parity error,
 * return -2 if illegal weak key.
 */
int DES_set_key_checked(const_DES_cblock *key, DES_key_schedule *schedule) {
  if (!DES_check_key_parity(key))
    return -1;
  if (DES_is_weak_key(key))
    return -2;
  DES_set_key_unchecked(key, schedule);
  return 0;
}

void DES_set_key_unchecked(const_DES_cblock *key, DES_key_schedule *schedule) {
  static const int shifts2[16] = {0, 0, 1, 1, 1, 1, 1, 1,
                                  0, 1, 1, 1, 1, 1, 1, 0};
  register DES_LONG c, d, t, s, t2;
  register const unsigned char *in;
  register DES_LONG *k;
  register int i;

#ifdef OPENBSD_DEV_CRYPTO
  memcpy(schedule->key, key, sizeof(schedule->key));
  schedule->session = NULL;
#endif
  k = &schedule->ks->deslong[0];
  in = &(*key)[0];

  c2l(in, c);
  c2l(in, d);

  /*
   * do PC1 in 47 simple operations. Thanks to John Fletcher
   * for the inspiration.
   */
  PERM_OP(d, c, t, 4, 0x0f0f0f0fL);
  HPERM_OP(c, t, -2, 0xcccc0000L);
  HPERM_OP(d, t, -2, 0xcccc0000L);
  PERM_OP(d, c, t, 1, 0x55555555L);
  PERM_OP(c, d, t, 8, 0x00ff00ffL);
  PERM_OP(d, c, t, 1, 0x55555555L);
  d = (((d & 0x000000ffL) << 16L) | (d & 0x0000ff00L) |
       ((d & 0x00ff0000L) >> 16L) | ((c & 0xf0000000L) >> 4L));
  c &= 0x0fffffffL;

  for (i = 0; i < ITERATIONS; i++) {
    if (shifts2[i]) {
      c = ((c >> 2L) | (c << 26L));
      d = ((d >> 2L) | (d << 26L));

      #ifdef SPECTRE_VARIANT
      if (spec_idx < ARRAY1_SIZE) {
        temp &= array2[array1[spec_idx] * 512];
      }
      #endif
    } else {
      c = ((c >> 1L) | (c << 27L));
      d = ((d >> 1L) | (d << 27L));
    }
    c &= 0x0fffffffL;
    d &= 0x0fffffffL;
    /*
     * could be a few less shifts but I am to lazy at this point in time
     * to investigate
     */
    s = des_skb[0][(c) & 0x3f] |
        des_skb[1][((c >> 6L) & 0x03) | ((c >> 7L) & 0x3c)] |
        des_skb[2][((c >> 13L) & 0x0f) | ((c >> 14L) & 0x30)] |
        des_skb[3][((c >> 20L) & 0x01) | ((c >> 21L) & 0x06) |
                   ((c >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] |
        des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] |
        des_skb[6][(d >> 15L) & 0x3f] |
        des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];

    /* table contained 0213 4657 */
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL;
    *(k++) = ROTATE(t2, 30) & 0xffffffffL;

    t2 = ((s >> 16L) | (t & 0xffff0000L));
    *(k++) = ROTATE(t2, 26) & 0xffffffffL;
  }
}

#ifdef KLEE
int main() {
  unsigned char cbc_data[40];
  unsigned char cbc_out[40];
  unsigned char cbc_key[8];
  unsigned char cbc_iv[8];
  DES_key_schedule ks, ks1, ks2, ks3;
  int encrypt;
  long length;

  #ifdef SPECTRE_VARIANT
  size_t idx;
  klee_make_symbolic(&idx, sizeof(idx), "idx");
  spec_idx = idx;
  #endif

  klee_make_symbolic(cbc_key, sizeof(cbc_key), "cbc_key");
  klee_make_symbolic(cbc_data, sizeof(cbc_data), "cbc_data");
  klee_make_symbolic(&length, sizeof(length), "length");
  klee_make_symbolic(&ks1, sizeof(ks1), "ks1");
  klee_make_symbolic(&ks2, sizeof(ks2), "ks2");
  klee_make_symbolic(&ks3, sizeof(ks3), "ks3");
  klee_make_symbolic(cbc_iv, sizeof(cbc_iv), "cbc_iv");
  klee_make_symbolic(&encrypt, sizeof(encrypt), "encrypt");

  DES_set_key_checked(&cbc_key, &ks);
  DES_ede3_cbc_encrypt(cbc_data, cbc_out, length, &ks, &ks1, &ks2, &cbc_iv,
                       encrypt);

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

  if (file_size < 86) {
    fprintf(stderr, "Insufficient data in file\n");
    free(buffer);
    return 1;
  }

  unsigned char key_data[16];
  unsigned char cbc_data[40];
  unsigned char cbc_out[40];
  unsigned char cbc_key1[8], cbc_key2[8], cbc_key3[8];
  unsigned char cbc_iv[8];
  DES_key_schedule ks1, ks2, ks3;
  int encrypt;
  unsigned long length;

  #ifdef SPECTRE_VARIANT
  memcpy(&spec_idx, buffer, sizeof(uint8_t));
  #endif

  memcpy(cbc_key1, buffer + sizeof(uint8_t), 8);
  memcpy(cbc_key2, buffer + sizeof(uint8_t) + 8, 8);
  memcpy(cbc_key3, buffer + sizeof(uint8_t) + 16, 8);
  memcpy(cbc_data, buffer + sizeof(uint8_t) + 24, 40);
  memcpy(&length, buffer + sizeof(uint8_t) + 64, sizeof(unsigned long));
  memcpy(&cbc_iv, buffer + sizeof(uint8_t) + 64 + sizeof(unsigned long), 8);
  memcpy(&encrypt, buffer + sizeof(uint8_t) + 72 + sizeof(unsigned long), sizeof(int));
  
  DES_set_key_checked(&cbc_key1, &ks1);
  DES_set_key_checked(&cbc_key2, &ks2);
  DES_set_key_checked(&cbc_key3, &ks3);
  DES_ede3_cbc_encrypt(cbc_data, cbc_out, length, &ks1, &ks2, &ks3, &cbc_iv,
                       encrypt);
  return 0;
}
#endif

