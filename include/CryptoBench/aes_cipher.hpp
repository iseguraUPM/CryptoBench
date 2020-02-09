//
// Created by ISU on 09/02/2020.
//

#ifndef CRYPTOBENCH_AES_CIPHER_HPP
#define CRYPTOBENCH_AES_CIPHER_HPP

#include "openssl_cipher.hpp"

enum class Mode
{
    CBC, ECB, CFB
};

template <int KEY_SIZE>
class AesCipher : public OpenSSLCipher<KEY_SIZE, 16>
{
private:

    const Mode cipher_mode;


public:

    AesCipher(Mode mode);


private:

    const EVP_CIPHER* getCipherMode() override;

};

template<int KEY_SIZE>
AesCipher<KEY_SIZE>::AesCipher(Mode mode) : cipher_mode(mode)
{
}


#endif //CRYPTOBENCH_AES_CIPHER_HPP
