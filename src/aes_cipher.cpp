//
// Created by ISU on 09/02/2020.
//

#include "CryptoBench/aes_cipher.hpp"

template<>
const EVP_CIPHER *AesCipher<32>::getCipherMode()
{
    switch (cipher_mode)
    {
        case Mode::CBC:
            return EVP_aes_256_cbc();
        case Mode::CFB:
            return EVP_aes_256_cfb();
        case Mode::ECB:
            return EVP_aes_256_ecb();
    }
}

template<>
const EVP_CIPHER *AesCipher<16>::getCipherMode()
{
    switch (cipher_mode)
    {
        case Mode::CBC:
            return EVP_aes_128_cbc();
        case Mode::CFB:
            return EVP_aes_128_cfb();
        case Mode::ECB:
            return EVP_aes_128_ecb();
    }
}