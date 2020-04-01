//
// Created by ISU on 30/03/2020.
//

#ifndef CRYPTOBENCH_CIPHER_EXCEPTION_HPP
#define CRYPTOBENCH_CIPHER_EXCEPTION_HPP

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

class UnsupportedCipherException : public GenericCipherException
{
public:

    explicit UnsupportedCipherException(const char * msg = "Unsupported Cipher");
};

#endif //CRYPTOBENCH_CIPHER_EXCEPTION_HPP
