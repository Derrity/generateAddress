#ifndef APPLICATION_PROCESSADDRESS_H
#define APPLICATION_PROCESSADDRESS_H
#include <iostream>
std::string base58_encode(unsigned char *data, size_t len);
std::string pubkey_to_address(unsigned char *pub_key, size_t pub_key_len);
std::string generate_keypair_and_get_address_from_mnemonic(const char *mnemonic);
#endif //APPLICATION_PROCESSADDRESS_H
