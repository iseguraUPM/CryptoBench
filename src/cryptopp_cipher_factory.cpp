//
// Created by Juan Pablo Melgarejo on 3/24/20.
//

#include "CryptoBench/cryptopp_cipher_factory.hpp"
#include "CryptoBench/symmetric_cipher.hpp"

#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/default.h>
#include <cryptopp/aria.h>
#include <cryptopp/ccm.h>
#include <cryptopp/eax.h>
#include <cryptopp/gcm.h>
#include <cryptopp/authenc.h>

#include <cryptopp/blowfish.h>

#include "CryptoBench/random_bytes.hpp"

#define CRYPTOPP_CIPHER(key_len, block_len, cipher) (CipherPtr(new CryptoppCipher<key_len, block_len, cipher>()))
#define CRYPTOPP_CIPHER_ECB(key_len, block_len, cipher) (CipherPtr(new CryptoppCipherECB<key_len, block_len, cipher>()))

#define KEY_128 16
#define KEY_192 24
#define KEY_256 32
#define KEY_512 64
#define KEY_448 56



CipherPtr CryptoppCipherFactory::getCipher(Cipher cipher)
{

    switch(cipher)
    {
        case Cipher::AES_256_CBC:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CBC_Mode<CryptoPP::AES>);
        case Cipher::AES_256_CFB:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CFB_Mode<CryptoPP::AES>);
        case Cipher::AES_256_ECB:
            return CRYPTOPP_CIPHER_ECB(KEY_256, 16, CryptoPP::ECB_Mode<CryptoPP::AES>);
        case Cipher::AES_256_CTR:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CTR_Mode<CryptoPP::AES>);
        case Cipher::AES_256_OCB:
            return nullptr;
            //return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::OCB<CryptoPP::AES>);
        case Cipher::AES_256_OFB:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::OFB_Mode<CryptoPP::AES>);
        case Cipher::AES_256_XTS:
            return nullptr;
            //return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::XTR<CryptoPP::AES>);
        case Cipher::AES_256_GCM:
            return nullptr;
            //return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::GCM<CryptoPP::AES>);
        case Cipher::AES_192_CBC:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CBC_Mode<CryptoPP::AES>);
        case Cipher::AES_192_CFB:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CFB_Mode<CryptoPP::AES>);
        case Cipher::AES_192_ECB:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::ECB_Mode<CryptoPP::AES>);
        case Cipher::AES_192_CTR:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CTR_Mode<CryptoPP::AES>);
        case Cipher::AES_192_OFB:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::OFB_Mode<CryptoPP::AES>);
        case Cipher::AES_192_OCB:
            return nullptr;
            //return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::OCB_Mode<CryptoPP::AES>);
        case Cipher::AES_192_GCM:
            return nullptr;
            //return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::GCM<CryptoPP::AES>);
        case Cipher::AES_128_CBC:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CBC_Mode<CryptoPP::AES>);
        case Cipher::AES_128_CFB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CFB_Mode<CryptoPP::AES>);
        case Cipher::AES_128_ECB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::ECB_Mode<CryptoPP::AES>);
        case Cipher::AES_128_CTR:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CTR_Mode<CryptoPP::AES>);
        case Cipher::AES_128_OFB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::OFB_Mode<CryptoPP::AES>);
        case Cipher::AES_128_OCB:
            return nullptr;
            //return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::OCB_Mode<CryptoPP::AES>);
        case Cipher::AES_128_XTS:
            return nullptr;
            //return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::XTS_Mode<CryptoPP::AES>);
        case Cipher::AES_128_GCM:
            return nullptr;
            //return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::GCM<CryptoPP::AES>);
        case Cipher::ARIA_256_CBC:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CBC_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_256_CFB:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CFB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_256_ECB:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::ECB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_256_OFB:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CFB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_256_CTR:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CTR_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_256_GCM:
            return nullptr;
            //return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::GCM<CryptoPP::ARIA>);
        case Cipher::ARIA_192_CBC:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CBC_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_192_CFB:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CFB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_192_ECB:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::ECB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_192_OFB:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::OFB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_192_CTR:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CTR_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_192_GCM:
            return nullptr;
            //return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::GCM<CryptoPP::ARIA>);
        case Cipher::ARIA_128_CBC:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CBC_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_128_CFB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CFB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_128_ECB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::ECB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_128_OFB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::OFB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_128_CTR:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CTR_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_128_GCM:
            return nullptr;
            //return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::GCM<CryptoPP::ARIA>);
        default:
            return nullptr;
    }
}