#ifndef _ARIA_HPP_
#define _ARIA_HPP_

#include <stdint.h>
#include <stdio.h>

typedef unsigned char Byte;
typedef unsigned int Word;

void printBlockOfLength(Byte *b, int len);
void printBlock(Byte *b);
void Crypt(const Byte *i, int Nr, const Byte *rk, Byte *o);
int EncKeySetup(const Byte *mk, Byte *rk, int keyBits);
int DecKeySetup(const Byte *mk, Byte *rk, int keyBits);
void EncryptCBC(const Byte *mk, uint32_t keyBits, Byte *indata, uint32_t indata_len, uint8_t *outdata);
void DecryptCBC(const Byte *mk, uint32_t keyBits, Byte *indata, uint32_t indata_len, uint8_t *outdata);
void testEncryptAria();

#endif /* _ARIA_HPP_ */