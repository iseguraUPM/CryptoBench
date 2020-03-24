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
        //TODO: hardcodeado
        int iv_length = 16;

        unsigned char iv[iv_length];

        random_bytes.generateRandomBytes(iv, iv_length);

        cipher_text.resize(plain_text.size());

        CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);
        cfbEncryption.ProcessData((byte *) &cipher_text[0], (byte *) &plain_text[0], plain_text.size());

        cipher_text.append((char *) iv, iv_length);

    }

    inline void decrypt(const byte* key, const security::secure_string &cipher_text
                        , security::secure_string &recovered_text) override
    {
        //TODO: hardcodeado
        int iv_length = 16;

        byte iv[iv_length];
        cipher_text.copy((char *) iv, iv_length, cipher_text.size() - iv_length);

        recovered_text.resize(cipher_text.size() - iv_length);

        CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption cfbDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);
        cfbDecryption.ProcessData((byte *) &recovered_text[0], (byte *) &cipher_text[0]
                                  , cipher_text.size() - iv_length);
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