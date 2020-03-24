//
// Created by Juan Pablo Melgarejo on 3/24/20.
//

#include "CryptoBench/cryptopp_cipher_factory.hpp"
#include "CryptoBench/symmetric_cipher.hpp"

#include <cryptopp/hex.h>
#include <cryptopp/default.h>
#include "CryptoBench/random_bytes.hpp"



class CryptoPPAesTest : public SymmetricCipher
{
public:

    explicit inline CryptoPPAesTest() : random_bytes()
    {}

    inline void encrypt(const byte* key, const security::secure_string& plain_text
                        , security::secure_string& cipher_text) override
    {

        CryptoPP::ECB_Mode< CryptoPP::AES >::Encryption e( key, CryptoPP::AES::DEFAULT_KEYLENGTH);

        std::string cipherTxt;

        cipher_text.resize(plain_text.size());
        CryptoPP::StringSource ss1(plain_text.data(), true,
                new CryptoPP::StreamTransformationFilter( e,
                        new CryptoPP::StringSinkTemplate<security::secure_string>(cipher_text)
                )
        );
    }

    inline void decrypt(const byte* key, const security::secure_string &cipher_text
                        , security::secure_string &recovered_text) override
    {
        CryptoPP::ECB_Mode< CryptoPP::AES >::Decryption d( key, CryptoPP::AES::DEFAULT_KEYLENGTH );

        std::string recoveredTxt;

        recovered_text.resize(cipher_text.size());
        CryptoPP::StringSource ss3( cipher_text.data(), true,
                new CryptoPP::StreamTransformationFilter( d,
                        new CryptoPP::StringSinkTemplate<security::secure_string>(recovered_text)
                )
        );
    }

    inline int getBlockLen() override
    {
        return CryptoPP::AES::BLOCKSIZE;
    }

    inline int getKeyLen() override
    {
        return CryptoPP::AES::DEFAULT_KEYLENGTH;
    }

private:

    RandomBytes random_bytes;

};


CipherPtr CryptoppCipherFactory::getCipher(Cipher cipher)
{
    if (cipher != Cipher::AES_256_CBC) {
        return nullptr;
    }

    return CipherPtr(new CryptoPPAesTest());
}