//
// Created by ISU on 04/02/2020.
//

#ifndef CRYPTOBENCH_SYMMETRIC_CIPHER_HPP
#define CRYPTOBENCH_SYMMETRIC_CIPHER_HPP

#include <string>
#include <memory>

#include "secure_string.hpp"

typedef unsigned char byte;

class SymmetricCipher
{
public:

    virtual void encrypt(const byte* key, const byte* plain_text, size_t plain_text_len
            , const byte* cipher_text, size_t cipher_text_len) = 0;
    virtual void decrypt(const byte* key, const byte* cipher_text, size_t cipher_text_len
            , const byte* recovered_text, size_t recovered_text_len) = 0;

    virtual int getBlockLen() = 0;

    virtual int getKeyLen() = 0;

};


#endif //CRYPTOBENCH_SYMMETRIC_CIPHER_HPP
