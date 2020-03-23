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

    virtual void encrypt(const byte* key, const security::secure_string& plain_text
            , security::secure_string& cipher_text) = 0;
    virtual void decrypt(const byte* key, const security::secure_string &cipher_text
                         , security::secure_string &recovered_text) = 0;

    virtual int getBlockLen() = 0;

    virtual int getKeyLen() = 0;

};


#endif //CRYPTOBENCH_SYMMETRIC_CIPHER_HPP
