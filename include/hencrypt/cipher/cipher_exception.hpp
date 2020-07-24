//
// Created by ISU on 30/03/2020.
//

#ifndef HENCRYPT_CIPHER_EXCEPTION_HPP
#define HENCRYPT_CIPHER_EXCEPTION_HPP

#include <exception>

class GenericCipherException : public std::exception
{
public:
    explicit GenericCipherException(const char* msg);

    GenericCipherException(const char* tag, const char* msg);

    const char * what() const noexcept override;

private:
    const char * msg;
};

class PaddingException : public GenericCipherException
{
public:
    explicit PaddingException(const char * msg = "Wrong buffer padding");
};

class UnsupportedCipherException : public GenericCipherException
{
public:

    explicit UnsupportedCipherException(const char * msg = "Unsupported Cipher");
};

#endif //HENCRYPT_CIPHER_EXCEPTION_HPP
