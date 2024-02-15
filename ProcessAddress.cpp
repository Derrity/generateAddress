#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <iostream>
#include <string>
#include <cstring>
#include "ProcessAddress.h"
#include "keccak.h"

const char *base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";


std::string base58_encode(unsigned char *data, size_t len) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn = BN_new();
    BIGNUM *bn58 = BN_new();
    BIGNUM *bn0 = BN_new();
    BIGNUM *dv = BN_new();
    BIGNUM *rem = BN_new();

    BN_bin2bn(data, len, bn);
    BN_set_word(bn58, 58);
    BN_set_word(bn0, 0);

    std::string result = "";

    while (BN_cmp(bn, bn0) > 0) {
        if (!BN_div(dv, rem, bn, bn58, ctx)) {
            // Handle error
        }
        BN_copy(bn, dv);
        unsigned long l = BN_get_word(rem);
        result.insert(0, 1, base58_chars[l]);
    }

    for (size_t i = 0; i < len; i++) {
        if (data[i] == 0) {
            result.insert(0, 1, base58_chars[0]);
        } else {
            break;
        }
    }

    BN_clear_free(bn);
    BN_clear_free(bn58);
    BN_clear_free(bn0);
    BN_clear_free(dv);
    BN_clear_free(rem);
    BN_CTX_free(ctx);

    return result;
}

std::string Bitcoin::pubkey_to_address(unsigned char *pub_key, size_t pub_key_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, pub_key, pub_key_len);
    SHA256_Final(hash, &sha256);

    unsigned char ripe_hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160_CTX ripe;
    RIPEMD160_Init(&ripe);
    RIPEMD160_Update(&ripe, hash, SHA256_DIGEST_LENGTH);
    RIPEMD160_Final(ripe_hash, &ripe);

    unsigned char versioned[21];
    versioned[0] = 0x00;
    memcpy(versioned + 1, ripe_hash, RIPEMD160_DIGEST_LENGTH);

    unsigned char check_hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, versioned, 21);
    SHA256_Final(check_hash, &sha256);

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, check_hash, SHA256_DIGEST_LENGTH);
    SHA256_Final(check_hash, &sha256);

    unsigned char addr[25];
    memcpy(addr, versioned, 21);
    memcpy(addr + 21, check_hash, 4);

    return base58_encode(addr, 25);
}

std::string Bitcoin::generate_keypair_and_get_address_from_mnemonic(const char *mnemonic) {
    unsigned char seed[64];
    std::string salt = std::string(mnemonic);
    int r = PKCS5_PBKDF2_HMAC_SHA1(
            mnemonic, strlen(mnemonic),
            reinterpret_cast<const unsigned char *>(salt.c_str()), salt.size(),
            2048, 64, seed);

    if (r != 1) {
        throw std::runtime_error("Error generating seed");
    }

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM *bn = BN_bin2bn(seed, 64, NULL);
    if (!EC_KEY_set_private_key(key, bn)) {
        throw std::runtime_error("Error setting private key");
    }

    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pub_key = EC_POINT_new(group);
    if (!EC_POINT_mul(group, pub_key, bn, NULL, NULL, NULL)) {
        throw std::runtime_error("Error multiplying private key with generator");
    }

    if (!EC_KEY_set_public_key(key, pub_key)) {
        throw std::runtime_error("Error setting public key");
    }

    // Convert public key to byte array
    size_t pub_key_len = EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    unsigned char *pub_key_bytes = new unsigned char[pub_key_len];
    EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, pub_key_bytes, pub_key_len, NULL);

    // Convert public key bytes to Bitcoin address
    std::string address = Bitcoin::pubkey_to_address(pub_key_bytes, pub_key_len);

    // Clean up
    BN_free(bn);
    EC_POINT_free(pub_key);
    delete[] pub_key_bytes;

    return address;
}

std::string Tron::pubkey_to_address(unsigned char *pub_key, size_t pub_key_len) {
    unsigned char hash[32];  // Keccak-256 hash size is 32 bytes
    keccak_256(pub_key, pub_key_len, hash);  // Replace with your Keccak-256 function

    unsigned char versioned[21];
    versioned[0] = 0x41;  // Tron mainnet version
    memcpy(versioned + 1, hash + 12, 20);  // Take the last 20 bytes of the hash

    unsigned char check_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, versioned, 21);
    SHA256_Final(check_hash, &sha256);

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, check_hash, SHA256_DIGEST_LENGTH);
    SHA256_Final(check_hash, &sha256);

    unsigned char addr[25];
    memcpy(addr, versioned, 21);
    memcpy(addr + 21, check_hash, 4);

    return base58_encode(addr, 25);
}

std::string Tron::generate_keypair_and_get_address_from_mnemonic(const char *mnemonic) {
    unsigned char seed[64];
    std::string salt = std::string(mnemonic);
    int r = PKCS5_PBKDF2_HMAC_SHA1(
            mnemonic, strlen(mnemonic),
            reinterpret_cast<const unsigned char *>(salt.c_str()), salt.size(),
            2048, 64, seed);

    if (r != 1) {
        throw std::runtime_error("Error generating seed");
    }

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM *bn = BN_bin2bn(seed, 64, NULL);
    if (!EC_KEY_set_private_key(key, bn)) {
        throw std::runtime_error("Error setting private key");
    }

    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pub_key = EC_POINT_new(group);
    if (!EC_POINT_mul(group, pub_key, bn, NULL, NULL, NULL)) {
        throw std::runtime_error("Error multiplying private key with generator");
    }

    if (!EC_KEY_set_public_key(key, pub_key)) {
        throw std::runtime_error("Error setting public key");
    }

    // Convert public key to byte array
    size_t pub_key_len = EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    unsigned char *pub_key_bytes = new unsigned char[pub_key_len];
    EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, pub_key_bytes, pub_key_len, NULL);

    // Convert public key bytes to Tron address
    std::string address = Tron::pubkey_to_address(pub_key_bytes, pub_key_len);

    // Clean up
    BN_free(bn);
    EC_POINT_free(pub_key);
    delete[] pub_key_bytes;

    return address;
}
