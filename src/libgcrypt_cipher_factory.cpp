//
// Created by ISU on 29/03/2020.
//

#include "CryptoBench/libgcrypt_cipher_factory.hpp"

#include <gcrypt.h>

#include <cstring>

#include "CryptoBench/random_bytes.hpp"

#define CIPHER(key_len, block_len, alg, mode) (CipherPtr(new LibgcryptCipher<key_len, block_len>(alg, mode)))

#define KEY_128 16
#define KEY_192 24
#define KEY_256 32
#define KEY_512 64
#define KEY_448 56

#define BLK_128 16
#define BLK_64 8

template <int KEY_LEN, int BLOCK_LEN>
class LibgcryptCipher : public SymmetricCipher
{
public:
    explicit inline LibgcryptCipher(gcry_cipher_algos alg, gcry_cipher_modes mode) : alg(alg), mode(mode), random_bytes()
    {}

    virtual void encrypt(const byte key[KEY_LEN],  const byte * plain_text, byte_len plain_text_len
                         , byte * cipher_text, byte_len & cipher_text_len);

    virtual void decrypt(const byte key[KEY_LEN], const byte * cipher_text, byte_len cipher_text_len
                         , byte * recovered_text, byte_len & recovered_text_len);

    void handleGcryError(gcry_error_t err);

    inline int getKeyLen() override
    {
        return KEY_LEN;
    }

    inline int getBlockLen() override
    {
        return BLOCK_LEN;
    }

protected:

    RandomBytes random_bytes;

private:

    const gcry_cipher_algos alg;
    const gcry_cipher_modes mode;

};

template<int KEY_LEN, int BLOCK_LEN>
void LibgcryptCipher<KEY_LEN, BLOCK_LEN>::encrypt(const byte key[KEY_LEN],  const byte * plain_text, byte_len plain_text_len
                                                  , byte * cipher_text, byte_len & cipher_text_len)
{
    byte_len padded_plain_text_len = plain_text_len + BLOCK_LEN - (plain_text_len % BLOCK_LEN);
    if (cipher_text_len < padded_plain_text_len)
    {
        throw std::runtime_error("Libgcrypt Error: Invalid cipher text length. Must be at least: " + padded_plain_text_len);
    }

    gcry_cipher_hd_t handle;
    gcry_error_t err = 0;

    err = gcry_cipher_open(&handle, alg, mode, 0);
    handleGcryError(err);

    err = gcry_cipher_setkey(handle, key, KEY_LEN);
    handleGcryError(err);

    byte iv[BLOCK_LEN];
    random_bytes.generateRandomBytes(iv, BLOCK_LEN);
    err = gcry_cipher_setiv(handle, iv, BLOCK_LEN);
    handleGcryError(err);

    byte padded_plain_text[padded_plain_text_len];
    memcpy(padded_plain_text, plain_text, plain_text_len);

    err = gcry_cipher_encrypt(handle, cipher_text, cipher_text_len, padded_plain_text, padded_plain_text_len);
    handleGcryError(err);

    gcry_cipher_close(handle);

    memcpy(cipher_text + cipher_text_len, iv, BLOCK_LEN);
}

template<int KEY_LEN, int BLOCK_LEN>
void LibgcryptCipher<KEY_LEN, BLOCK_LEN>::decrypt(const byte key[KEY_LEN], const byte * cipher_text, byte_len cipher_text_len
                                                  , byte * recovered_text, byte_len & recovered_text_len)
{
    auto req_len = cipher_text_len - BLOCK_LEN;
    if (recovered_text_len < cipher_text_len - BLOCK_LEN)
    {
        throw std::runtime_error("Libgcrypt Error: Invalid recovered text length. Must be at least: " + req_len);
    }

    gcry_cipher_hd_t handle;
    gcry_error_t err = 0;

    err = gcry_cipher_open(&handle, alg, mode, 0);
    handleGcryError(err);

    err = gcry_cipher_setkey(handle, key, KEY_LEN);
    handleGcryError(err);

    byte iv[BLOCK_LEN];
    memcpy(iv, cipher_text + cipher_text_len, BLOCK_LEN);

    err = gcry_cipher_setiv(handle, iv, BLOCK_LEN);
    handleGcryError(err);

    recovered_text_len = cipher_text_len - BLOCK_LEN;
    err = gcry_cipher_decrypt(handle, recovered_text, recovered_text_len
            , cipher_text, cipher_text_len - BLOCK_LEN);
    handleGcryError(err);

    gcry_cipher_close(handle);
}

template<int KEY_LEN, int BLOCK_LEN>
void LibgcryptCipher<KEY_LEN, BLOCK_LEN>::handleGcryError(gcry_error_t err)
{
    if (err != GPG_ERR_NO_ERROR)
    {
        throw std::runtime_error("Libgcrypt error: " + std::string(gcry_strsource(err)) + " " + std::string(gcry_strerror(err)));
    }
}

CipherPtr LibgcryptCipherFactory::getCipher(Cipher cipher)
{
    switch (cipher)
    {
        case Cipher::AES_256_CBC:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC);
        case Cipher::AES_256_CFB:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB);
        case Cipher::AES_256_ECB:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB);
        case Cipher::AES_256_CTR:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR);
        case Cipher::AES_256_OCB:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OCB);
        case Cipher::AES_256_OFB:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB);
        case Cipher::AES_256_XTS:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_XTS);
        case Cipher::AES_256_GCM:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM);
        case Cipher::AES_192_CBC:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC);
        case Cipher::AES_192_CFB:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CFB);
        case Cipher::AES_192_ECB:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB);
        case Cipher::AES_192_CTR:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CTR);
        case Cipher::AES_192_OFB:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OFB);
        case Cipher::AES_192_OCB:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OCB);
        case Cipher::AES_192_GCM:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_GCM);
        case Cipher::AES_128_CBC:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC);
        case Cipher::AES_128_ECB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB);
        case Cipher::AES_128_CTR:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR);
        case Cipher::AES_128_OFB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_OFB);
        case Cipher::AES_128_OCB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_OCB);
        case Cipher::AES_128_XTS:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_XTS);
        case Cipher::AES_128_GCM:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM);
        case Cipher::SEED_CBC:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_CBC);
        case Cipher::SEED_CFB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_CFB);
        case Cipher::SEED_ECB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_ECB);
        case Cipher::SEED_OFB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_OFB);
        case Cipher::BLOWFISH_CBC:
            return CIPHER(KEY_448, BLK_64, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CBC);
        case Cipher::BLOWFISH_ECB:
            return CIPHER(KEY_448, BLK_64, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB);
        case Cipher::BLOWFISH_CFB:
            return CIPHER(KEY_448, BLK_64, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CFB);
        case Cipher::BLOWFISH_OFB:
            return CIPHER(KEY_448, BLK_64, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_OFB);
        default:
            return nullptr;
    }
}
