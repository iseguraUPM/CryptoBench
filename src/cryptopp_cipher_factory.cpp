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
#include <cryptopp/sm4.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/camellia.h>
#include <cryptopp/gcm.h>
#include <cryptopp/seed.h>
#include <cryptopp/authenc.h>

#include <cryptopp/blowfish.h>
#include <CryptoBench/cipher_exception.hpp>

#include "CryptoBench/random_bytes.hpp"

#define CRYPTOPP_CIPHER(key_len, block_len, cipher) (CipherPtr(new CryptoppCipher<key_len, block_len, cipher>()))
#define CRYPTOPP_CIPHER_ECB(key_len, block_len, cipher) (CipherPtr(new CryptoppCipherECB<key_len, block_len, cipher>()))
#define CRYPTOPP_CIPHER_AUTH(key_len, block_len, iv_len, cipher) (CipherPtr(new CryptoppCipherAuth<key_len, block_len, iv_len, cipher>()))

#define KEY_128 16
#define KEY_192 24
#define KEY_256 32
#define KEY_512 64
#define KEY_448 56



CipherPtr CryptoppCipherFactory::getCipher(Cipher cipher)
{

    switch(cipher)
    {
        case Cipher::AES_256_ECB:
            return CRYPTOPP_CIPHER_ECB(KEY_256, 16, CryptoPP::ECB_Mode<CryptoPP::AES>);
        case Cipher::AES_256_CBC:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CBC_Mode<CryptoPP::AES>);
        case Cipher::AES_256_CFB:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CFB_Mode<CryptoPP::AES>);
        case Cipher::AES_256_OFB:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::OFB_Mode<CryptoPP::AES>);
        case Cipher::AES_256_CTR:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CTR_Mode<CryptoPP::AES>);
        case Cipher::AES_256_GCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_256, 16, 12, CryptoPP::GCM<CryptoPP::AES>);
        case Cipher::AES_256_XTS:
            throw UnsupportedCipherException();
        case Cipher::AES_256_CCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_256, 16,12, CryptoPP::CCM<CryptoPP::AES>);
        case Cipher::AES_256_EAX:
            return CRYPTOPP_CIPHER_AUTH(KEY_256, 16,12, CryptoPP::EAX<CryptoPP::AES>);
        case Cipher::AES_256_OCB:
            throw UnsupportedCipherException();
        case Cipher::AES_256_SIV:
            throw UnsupportedCipherException();

        case Cipher::AES_192_ECB:
            return CRYPTOPP_CIPHER_ECB(KEY_192, 16, CryptoPP::ECB_Mode<CryptoPP::AES>);
        case Cipher::AES_192_CBC:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CBC_Mode<CryptoPP::AES>);
        case Cipher::AES_192_CFB:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CFB_Mode<CryptoPP::AES>);
        case Cipher::AES_192_OFB:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::OFB_Mode<CryptoPP::AES>);
        case Cipher::AES_192_CTR:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CTR_Mode<CryptoPP::AES>);
        case Cipher::AES_192_GCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_192, 16, 12, CryptoPP::GCM<CryptoPP::AES>);
        case Cipher::AES_192_XTS:
            throw UnsupportedCipherException();
        case Cipher::AES_192_CCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_192, 16,12, CryptoPP::CCM<CryptoPP::AES>);
        case Cipher::AES_192_EAX:
            return CRYPTOPP_CIPHER_AUTH(KEY_192, 16,12, CryptoPP::EAX<CryptoPP::AES>);
        case Cipher::AES_192_OCB:
            throw UnsupportedCipherException();
        case Cipher::AES_192_SIV:
            throw UnsupportedCipherException();

        case Cipher::AES_128_ECB:
            return CRYPTOPP_CIPHER_ECB(KEY_128, 16, CryptoPP::ECB_Mode<CryptoPP::AES>);
        case Cipher::AES_128_CBC:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CBC_Mode<CryptoPP::AES>);
        case Cipher::AES_128_CFB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CFB_Mode<CryptoPP::AES>);
        case Cipher::AES_128_OFB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::OFB_Mode<CryptoPP::AES>);
        case Cipher::AES_128_CTR:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CTR_Mode<CryptoPP::AES>);
        case Cipher::AES_128_GCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16, 12, CryptoPP::GCM<CryptoPP::AES>);
        case Cipher::AES_128_XTS:
            throw UnsupportedCipherException();
        case Cipher::AES_128_CCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16,12, CryptoPP::CCM<CryptoPP::AES>);
        case Cipher::AES_128_EAX:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16,12, CryptoPP::EAX<CryptoPP::AES>);
        case Cipher::AES_128_OCB:
            throw UnsupportedCipherException();
        case Cipher::AES_128_SIV:
            throw UnsupportedCipherException();

        case Cipher::CAMELLIA_256_ECB:
            return CRYPTOPP_CIPHER_ECB(KEY_256, 16, CryptoPP::ECB_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_256_CBC:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CBC_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_256_CFB:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CFB_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_256_OFB:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::OFB_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_256_CTR:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CTR_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_256_GCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_256, 16, 12, CryptoPP::GCM<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_256_XTS:
            throw UnsupportedCipherException();
        case Cipher::CAMELLIA_256_CCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_256, 16,12, CryptoPP::CCM<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_256_EAX:
            return CRYPTOPP_CIPHER_AUTH(KEY_256, 16,12, CryptoPP::EAX<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_256_OCB:
            throw UnsupportedCipherException();
        case Cipher::CAMELLIA_256_SIV:
            throw UnsupportedCipherException();

        case Cipher::CAMELLIA_192_ECB:
            return CRYPTOPP_CIPHER_ECB(KEY_192, 16, CryptoPP::ECB_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_192_CBC:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CBC_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_192_CFB:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CFB_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_192_OFB:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::OFB_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_192_CTR:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CTR_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_192_GCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_192, 16, 12, CryptoPP::GCM<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_192_XTS:
            throw UnsupportedCipherException();
        case Cipher::CAMELLIA_192_CCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_192, 16,12, CryptoPP::CCM<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_192_EAX:
            return CRYPTOPP_CIPHER_AUTH(KEY_192, 16,12, CryptoPP::EAX<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_192_OCB:
            throw UnsupportedCipherException();
        case Cipher::CAMELLIA_192_SIV:
            throw UnsupportedCipherException();

        case Cipher::CAMELLIA_128_ECB:
            return CRYPTOPP_CIPHER_ECB(KEY_128, 16, CryptoPP::ECB_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_128_CBC:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CBC_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_128_CFB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CFB_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_128_OFB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::OFB_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_128_CTR:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CTR_Mode<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_128_GCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16, 12, CryptoPP::GCM<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_128_XTS:
            throw UnsupportedCipherException();
        case Cipher::CAMELLIA_128_CCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16,12, CryptoPP::CCM<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_128_EAX:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16,12, CryptoPP::EAX<CryptoPP::Camellia>);
        case Cipher::CAMELLIA_128_OCB:
            throw UnsupportedCipherException();
        case Cipher::CAMELLIA_128_SIV:
            throw UnsupportedCipherException();

        case Cipher::ARIA_256_ECB:
            return CRYPTOPP_CIPHER_ECB(KEY_256, 16, CryptoPP::ECB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_256_CBC:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CBC_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_256_CFB:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CFB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_256_OFB:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::OFB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_256_CTR:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CTR_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_256_GCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_256, 16, 12, CryptoPP::GCM<CryptoPP::ARIA>);
        case Cipher::ARIA_256_XTS:
            throw UnsupportedCipherException();
        case Cipher::ARIA_256_CCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_256, 16,12, CryptoPP::CCM<CryptoPP::ARIA>);
        case Cipher::ARIA_256_EAX:
            return CRYPTOPP_CIPHER_AUTH(KEY_256, 16,12, CryptoPP::EAX<CryptoPP::ARIA>);
        case Cipher::ARIA_256_OCB:
            throw UnsupportedCipherException();
        case Cipher::ARIA_256_SIV:
            throw UnsupportedCipherException();

        case Cipher::ARIA_192_ECB:
            return CRYPTOPP_CIPHER_ECB(KEY_192, 16, CryptoPP::ECB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_192_CBC:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CBC_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_192_CFB:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CFB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_192_OFB:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::OFB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_192_CTR:
            return CRYPTOPP_CIPHER(KEY_192, 16, CryptoPP::CTR_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_192_GCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_192, 16, 12, CryptoPP::GCM<CryptoPP::ARIA>);
        case Cipher::ARIA_192_XTS:
            throw UnsupportedCipherException();
        case Cipher::ARIA_192_CCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_192, 16,12, CryptoPP::CCM<CryptoPP::ARIA>);
        case Cipher::ARIA_192_EAX:
            return CRYPTOPP_CIPHER_AUTH(KEY_192, 16,12, CryptoPP::EAX<CryptoPP::ARIA>);
        case Cipher::ARIA_192_OCB:
            throw UnsupportedCipherException();
        case Cipher::ARIA_192_SIV:
            throw UnsupportedCipherException();

        case Cipher::ARIA_128_ECB:
            return CRYPTOPP_CIPHER_ECB(KEY_128, 16, CryptoPP::ECB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_128_CBC:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CBC_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_128_CFB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CFB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_128_OFB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::OFB_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_128_CTR:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CTR_Mode<CryptoPP::ARIA>);
        case Cipher::ARIA_128_GCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16, 12, CryptoPP::GCM<CryptoPP::ARIA>);
        case Cipher::ARIA_128_XTS:
            throw UnsupportedCipherException();
        case Cipher::ARIA_128_CCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16,12, CryptoPP::CCM<CryptoPP::ARIA>);
        case Cipher::ARIA_128_EAX:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16,12, CryptoPP::EAX<CryptoPP::ARIA>);
        case Cipher::ARIA_128_OCB:
            throw UnsupportedCipherException();
        case Cipher::ARIA_128_SIV:
            throw UnsupportedCipherException();

        case Cipher::SM4_ECB:
            return CRYPTOPP_CIPHER_ECB(KEY_128, 16, CryptoPP::ECB_Mode<CryptoPP::SM4>);
        case Cipher::SM4_CBC:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CBC_Mode<CryptoPP::SM4>);
        case Cipher::SM4_CFB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CFB_Mode<CryptoPP::SM4>);
        case Cipher::SM4_OFB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::OFB_Mode<CryptoPP::SM4>);
        case Cipher::SM4_CTR:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CTR_Mode<CryptoPP::SM4>);
        case Cipher::SM4_GCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16, 16, CryptoPP::GCM<CryptoPP::SM4>);
        case Cipher::SM4_XTS:
            throw UnsupportedCipherException();
        case Cipher::SM4_CCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16, 12, CryptoPP::CCM<CryptoPP::SM4>);
        case Cipher::SM4_EAX:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16, 12, CryptoPP::EAX<CryptoPP::SM4>);
        case Cipher::SM4_OCB:
            throw UnsupportedCipherException();
        case Cipher::SM4_SIV:
            throw UnsupportedCipherException();

        case Cipher::SEED_ECB:
            return CRYPTOPP_CIPHER_ECB(KEY_128, 16, CryptoPP::ECB_Mode<CryptoPP::SEED>);
        case Cipher::SEED_CBC:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CBC_Mode<CryptoPP::SEED>);
        case Cipher::SEED_CFB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CFB_Mode<CryptoPP::SEED>);
        case Cipher::SEED_OFB:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::OFB_Mode<CryptoPP::SEED>);
        case Cipher::SEED_CTR:
            return CRYPTOPP_CIPHER(KEY_128, 16, CryptoPP::CTR_Mode<CryptoPP::SEED>);
        case Cipher::SEED_GCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16, 16, CryptoPP::GCM<CryptoPP::SEED>);
        case Cipher::SEED_XTS:
            throw UnsupportedCipherException();
        case Cipher::SEED_CCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16, 12, CryptoPP::CCM<CryptoPP::SEED>);
        case Cipher::SEED_EAX:
            return CRYPTOPP_CIPHER_AUTH(KEY_128, 16, 12, CryptoPP::EAX<CryptoPP::SEED>);
        case Cipher::SEED_OCB:
            throw UnsupportedCipherException();
        case Cipher::SEED_SIV:
            throw UnsupportedCipherException();

        case Cipher::BLOWFISH_ECB:
            return CRYPTOPP_CIPHER_ECB(KEY_448, 8, CryptoPP::ECB_Mode<CryptoPP::Blowfish>);
        case Cipher::BLOWFISH_CBC:
            return CRYPTOPP_CIPHER(KEY_448, 8, CryptoPP::CBC_Mode<CryptoPP::Blowfish>);
        case Cipher::BLOWFISH_CFB:
            return CRYPTOPP_CIPHER(KEY_448, 8, CryptoPP::CFB_Mode<CryptoPP::Blowfish>);
        case Cipher::BLOWFISH_OFB:
            return CRYPTOPP_CIPHER(KEY_448, 8, CryptoPP::OFB_Mode<CryptoPP::Blowfish>);
        case Cipher::BLOWFISH_CTR:
            return CRYPTOPP_CIPHER(KEY_448, 8, CryptoPP::CTR_Mode<CryptoPP::Blowfish>);
        case Cipher::BLOWFISH_GCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_448, 16, 8, CryptoPP::GCM<CryptoPP::Blowfish>);
        case Cipher::BLOWFISH_XTS:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_CCM:
            return CRYPTOPP_CIPHER_AUTH(KEY_448, 8, 8, CryptoPP::CCM<CryptoPP::Blowfish>);
        case Cipher::BLOWFISH_EAX:
            return CRYPTOPP_CIPHER_AUTH(KEY_448, 8, 8, CryptoPP::EAX<CryptoPP::Blowfish>);
        case Cipher::BLOWFISH_OCB:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_SIV:
            throw UnsupportedCipherException();
    }
}