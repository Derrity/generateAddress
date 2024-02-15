#ifndef BITADDRESS_KECCAK_H
#define BITADDRESS_KECCAK_H
#include <iostream>
void keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen);
void keccak_256(const uint8_t *in, int inlen, uint8_t *md);
#endif //BITADDRESS_KECCAK_H
