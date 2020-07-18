//
// Created by ISU on 18/07/2020.
//

#ifndef CRYPTOBENCH_CIPHERTEXT_FRAGMENT_HPP
#define CRYPTOBENCH_CIPHERTEXT_FRAGMENT_HPP

#include <string>
#include <memory>

#include "cipher/cipher_definitions.hpp"

using byte = unsigned char;
using byte_len = unsigned long long;

typedef struct
{
    std::string lib;
    Cipher cipher;
    std::shared_ptr<byte[]> bytes;
    byte_len len;
} CiphertextFragment;

#endif //CRYPTOBENCH_CIPHERTEXT_FRAGMENT_HPP
