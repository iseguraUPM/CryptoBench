//
// Created by ISU on 04/02/2020.
//

#ifndef HENCRYPT_SYMMETRIC_CIPHER_HPP
#define HENCRYPT_SYMMETRIC_CIPHER_HPP

typedef unsigned char byte;

typedef unsigned long long int byte_len;

class SymmetricCipher
{
public:

    virtual void encrypt(const byte* key, const byte * plain_text, byte_len plain_text_len
            , byte * cipher_text, byte_len & cipher_text_len) = 0;
    virtual void decrypt(const byte* key, const byte * cipher_text, byte_len cipher_text_len
            , byte * recovered_text, byte_len & recovered_text_len) = 0;

    virtual int getBlockLen() = 0;

    virtual int getKeyLen() = 0;

};


#endif //HENCRYPT_SYMMETRIC_CIPHER_HPP
