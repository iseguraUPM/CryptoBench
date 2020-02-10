//
// Created by ISU on 09/02/2020.
//

#include "CryptoBench/open_ssl_cipher_factory.hpp"

#include "CryptoBench/openssl_cipher.hpp"

template <int KEY_LENGTH>
class OpenSSLCipherImpl : public OpenSSLCipher<KEY_LENGTH, 16>
{
private:
    const EVP_CIPHER* cipher;

    inline const EVP_CIPHER* getCipherMode() override
    {
        return cipher;
    }

public:
    explicit inline OpenSSLCipherImpl(const EVP_CIPHER* cipher) : cipher(cipher) {}
};

CipherPtr OpenSSLCipherFactory::getCipher(Cipher cipher)
{
    switch (cipher)
    {
        case Cipher::AES_256_CBC:
            return CipherPtr(new OpenSSLCipherImpl<32>(EVP_aes_256_cbc()));
        case Cipher::AES_128_CBC:
            return CipherPtr(new OpenSSLCipherImpl<16>(EVP_aes_128_cbc()));
        case Cipher::ARIA_256_CBC:
            return CipherPtr(new OpenSSLCipherImpl<32>(EVP_aria_256_cbc()));
        case Cipher::ARIA_128_CBC:
            return CipherPtr(new OpenSSLCipherImpl<16>(EVP_aria_128_cbc()));
        case Cipher::CAMELLIA_256_CBC:
            return CipherPtr(new OpenSSLCipherImpl<32>(EVP_camellia_256_cbc()));
        case Cipher::CAMELLIA_128_CBC:
            return CipherPtr(new OpenSSLCipherImpl<16>(EVP_camellia_128_cbc()));
    }
}