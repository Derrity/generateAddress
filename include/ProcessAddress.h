#ifndef APPLICATION_PROCESSADDRESS_H
#define APPLICATION_PROCESSADDRESS_H

#include <iostream>

class Bitcoin {
public:
    static std::string generate_keypair_and_get_address_from_mnemonic(const char *mnemonic);

    static std::string base58_encode(unsigned char *data, size_t len);

    static std::string pubkey_to_address(unsigned char *pub_key, size_t pub_key_len);
};

#endif //APPLICATION_PROCESSADDRESS_H
