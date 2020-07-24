//
// Created by ISU on 18/07/2020.
//

#ifndef HENCRYPT_CIPHERTEXT_FRAGMENT_HPP
#define HENCRYPT_CIPHERTEXT_FRAGMENT_HPP

#include <string>
#include <memory>

#include "cipher/cipher_definitions.hpp"

using byte = unsigned char;
using byte_len = unsigned long long;

struct CiphertextFragment
{
    std::string lib;
    Cipher cipher;
    std::shared_ptr<byte> bytes;
    byte_len len;
    std::string next_fragment_path;
};

#endif //HENCRYPT_CIPHERTEXT_FRAGMENT_HPP
