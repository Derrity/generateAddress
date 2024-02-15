#ifndef APPLICATION_PROCESSADDRESS_H
#define APPLICATION_PROCESSADDRESS_H

#include <iostream>
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

#endif //APPLICATION_PROCESSADDRESS_H
