//
// Created by ISU on 08/03/2020.
//

#include "CryptoBench/wolfcrypt_cipher_factory.hpp"

#include <wolfssl/wolfcrypt/aes.h>

enum class BlockMode
{
    CBC,
    CTR,
    GCM,
    CCM
};

template <int KEY_SIZE>
class AesCipher : public SymmetricCipher
{
    explicit AesCipher(BlockMode mode) : blockMode(mode) {};

    void encrypt(const byte key[KEY_SIZE], const byte iv[16], const security::secure_string& plain_text
                 , security::secure_string& cipher_text) override;

    void decrypt(const byte key[KEY_SIZE], const byte iv[16], const security::secure_string &cipher_text
                 , security::secure_string &recovered_text) override;

    inline int getBlockLen() override
    {
        return 16;
    }

    inline int getKeyLen() override
    {
        return KEY_SIZE;
    }

private:

    BlockMode blockMode;

};

template<int KEY_SIZE>
void AesCipher<KEY_SIZE>::encrypt(const byte key[KEY_SIZE], const byte iv[16], const security::secure_string& plain_text
                                  , security::secure_string& cipher_text)
{
    Aes enc;
}

template<int KEY_SIZE>
void AesCipher<KEY_SIZE>::decrypt(const byte key[KEY_SIZE], const byte iv[16], const security::secure_string &cipher_text
                                  , security::secure_string &recovered_text)
{

}

CipherPtr WolfCryptCipherFactory::getCipher(Cipher cipher)
{
    return nullptr;
}
