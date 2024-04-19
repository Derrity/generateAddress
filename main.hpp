#include <iostream>
std::string GenerateMnemonic(int wordCount);
void keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen);
void keccak_256(const uint8_t *in, int inlen, uint8_t *md);
std::string base58_encode(unsigned char *data, size_t len);
class Bitcoin {
public:
    static std::string generate_keypair_and_get_address_from_mnemonic(const char *mnemonic);
    static std::string pubkey_to_address(unsigned char *pub_key, size_t pub_key_len);
};

class Tron {
public:
    static std::string pubkey_to_address(unsigned char *pub_key, size_t pub_key_len);
    static std::string generate_keypair_and_get_address_from_mnemonic(const char *mnemonic);
};

