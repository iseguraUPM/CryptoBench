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
    explicit AesCipher(BlockMode mode) : block_mode(mode) {};

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

    BlockMode block_mode;

};

template<int KEY_SIZE>
void AesCipher<KEY_SIZE>::encrypt(const byte key[KEY_SIZE], const byte iv[16], const security::secure_string& plain_text
                                  , security::secure_string& cipher_text)
{
    Aes enc;

    switch (block_mode)
    {
        case BlockMode::CBC:
            wc_AesSetKey(&enc, key, KEY_SIZE, iv, 16);
            wc_AesCbcEncrypt(&enc, (byte *) cipher_text.c_str(), (byte *) plain_text.c_str(), plain_text.length());
        case BlockMode::GCM:
            wc_AesGcmSetKey(&enc, key, KEY_SIZE);
            security::secure_string auth_tag;
            wc_AesGcmEncrypt(&enc, (byte *) cipher_text.c_str(), (byte *) plain_text.c_str(), plain_text.length(), iv, 12, auth_tag, 16, nullptr, 0);
    }




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
