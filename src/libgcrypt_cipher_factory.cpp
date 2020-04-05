//
// Created by ISU on 29/03/2020.
//

#include "CryptoBench/libgcrypt_cipher_factory.hpp"

#include <gcrypt.h>

#include <cstring>

#include "CryptoBench/cipher_exception.hpp"
#include "CryptoBench/random_bytes.hpp"

#define CIPHER(key_len, block_len, alg, mode) (CipherPtr(new LibgcryptCipher<key_len, block_len>(alg, mode)))
#define CIPHER_AUTH(key_len, block_len, alg, mode) (CipherPtr(new LibgcryptAuthCipher<key_len, block_len>(alg, mode)))

#define KEY_128 16
#define KEY_192 24
#define KEY_256 32
#define KEY_384 48
#define KEY_512 64
#define KEY_448 56

#define BLK_128 16
#define BLK_96 12
#define BLK_64 8

#define AEAD_TAG_LEN 16
#define AEAD_IV_LEN 12

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

    void handleGcryError(gcry_error_t err);

    const gcry_cipher_algos alg;
    const gcry_cipher_modes mode;

};

template <int KEY_LEN, int BLOCK_LEN>
class LibgcryptAuthCipher : public LibgcryptCipher<KEY_LEN, BLOCK_LEN>
{
public:

    explicit inline LibgcryptAuthCipher(gcry_cipher_algos alg, gcry_cipher_modes mode) : LibgcryptCipher<KEY_LEN, BLOCK_LEN>(alg, mode)
    {}

    virtual void encrypt(const byte key[KEY_LEN],  const byte * plain_text, byte_len plain_text_len
                         , byte * cipher_text, byte_len & cipher_text_len);

    virtual void decrypt(const byte key[KEY_LEN], const byte * cipher_text, byte_len cipher_text_len
                         , byte * recovered_text, byte_len & recovered_text_len);

};

template<int KEY_LEN, int BLOCK_LEN>
void LibgcryptAuthCipher<KEY_LEN, BLOCK_LEN>::encrypt(const byte key[KEY_LEN], const byte *plain_text, byte_len plain_text_len
                                                      , byte *cipher_text, byte_len &cipher_text_len)
{
    using super = LibgcryptCipher<KEY_LEN, BLOCK_LEN>;

    byte_len padded_plain_text_len = plain_text_len + BLOCK_LEN - (plain_text_len % BLOCK_LEN);

    if (cipher_text_len < padded_plain_text_len)
    {
        throw LibgcryptException("Libgcrypt Error: Invalid cipher text length. Must be at least: " + std::to_string(padded_plain_text_len));
    }

    gcry_cipher_hd_t handle;
    gcry_error_t err = 0;

    err = gcry_cipher_open(&handle, super::alg, super::mode, 0);
    super::handleGcryError(err);

    /*byte single[] = { 0xFF };
    err = gcry_cipher_authenticate(handle, single, 1);
    super::handleGcryError(err);
    */

    err = gcry_cipher_setkey(handle, key, KEY_LEN);
    super::handleGcryError(err);

    auto iv = std::shared_ptr<byte>(new byte[AEAD_IV_LEN], std::default_delete<byte[]>());
    super::random_bytes.generateRandomBytes(iv.get(), AEAD_IV_LEN);
    err = gcry_cipher_setiv(handle, iv.get(), AEAD_IV_LEN);
    super::handleGcryError(err);

    {
        int tag_len = AEAD_TAG_LEN;
        err = gcry_cipher_ctl(handle, GCRYCTL_SET_TAGLEN, &tag_len, sizeof(int));
        super::handleGcryError(err);
    }

    auto padded_plain_text = std::shared_ptr<byte>(new byte[padded_plain_text_len], std::default_delete<byte[]>());
    memcpy(padded_plain_text.get(), plain_text, plain_text_len);

    err = gcry_cipher_final(handle);
    super::handleGcryError(err);

    err = gcry_cipher_encrypt(handle, cipher_text, cipher_text_len, padded_plain_text.get(), padded_plain_text_len);
    super::handleGcryError(err);

    auto tag = std::shared_ptr<byte>(new byte[AEAD_TAG_LEN], std::default_delete<byte[]>());
    err = gcry_cipher_gettag(handle, iv.get(), AEAD_TAG_LEN);
    super::handleGcryError(err);

    cipher_text_len = padded_plain_text_len;

    gcry_cipher_close(handle);

    memcpy(cipher_text + cipher_text_len, iv.get(), AEAD_IV_LEN);
    cipher_text_len += AEAD_IV_LEN;
    memcpy(cipher_text + cipher_text_len, tag.get(), AEAD_TAG_LEN);
    cipher_text_len += AEAD_TAG_LEN;
}

template<int KEY_LEN, int BLOCK_LEN>
void LibgcryptAuthCipher<KEY_LEN, BLOCK_LEN>::decrypt(const byte key[KEY_LEN], const byte *cipher_text, byte_len cipher_text_len
                                                      , byte *recovered_text, byte_len &recovered_text_len)
{
    using super = LibgcryptCipher<KEY_LEN, BLOCK_LEN>;

    auto req_len = AEAD_IV_LEN + AEAD_TAG_LEN;
    if (recovered_text_len < req_len)
    {
        throw LibgcryptException("Libgcrypt Error: Invalid recovered text length. Must be at least: " + std::to_string(req_len));
    }

    gcry_cipher_hd_t handle;
    gcry_error_t err = 0;

    err = gcry_cipher_open(&handle, super::alg, super::mode, 0);
    super::handleGcryError(err);

    err = gcry_cipher_setkey(handle, key, KEY_LEN);
    super::handleGcryError(err);

    auto iv = std::shared_ptr<byte>(new byte[AEAD_IV_LEN], std::default_delete<byte[]>());
    memcpy(iv.get(), cipher_text + cipher_text_len - AEAD_IV_LEN - AEAD_TAG_LEN, AEAD_IV_LEN);
    err = gcry_cipher_setiv(handle, iv.get(), AEAD_IV_LEN);
    super::handleGcryError(err);

    auto tag = std::shared_ptr<byte>(new byte[AEAD_TAG_LEN], std::default_delete<byte[]>());
    memcpy(tag.get(), cipher_text + cipher_text_len - AEAD_TAG_LEN, AEAD_TAG_LEN);
    {
        int tag_len = AEAD_TAG_LEN;
        err = gcry_cipher_ctl(handle, GCRYCTL_SET_TAGLEN, &tag_len, sizeof(int));
        super::handleGcryError(err);
    }


    err = gcry_cipher_final(handle);
    super::handleGcryError(err);

    recovered_text_len = cipher_text_len - AEAD_IV_LEN - AEAD_TAG_LEN;
    err = gcry_cipher_decrypt(handle, recovered_text, recovered_text_len
                              , cipher_text, cipher_text_len - AEAD_IV_LEN - AEAD_TAG_LEN);
    super::handleGcryError(err);

    err = gcry_cipher_checktag(handle, tag.get(), AEAD_TAG_LEN);
    super::handleGcryError(err);

    gcry_cipher_close(handle);
}


template<int KEY_LEN, int BLOCK_LEN>
void LibgcryptCipher<KEY_LEN, BLOCK_LEN>::encrypt(const byte key[KEY_LEN],  const byte * plain_text, byte_len plain_text_len
                                                  , byte * cipher_text, byte_len & cipher_text_len)
{
    byte_len padded_plain_text_len = plain_text_len + BLOCK_LEN - (plain_text_len % BLOCK_LEN);
    if (cipher_text_len < padded_plain_text_len)
    {
        throw LibgcryptException("Libgcrypt Error: Invalid cipher text length. Must be at least: " + std::to_string(padded_plain_text_len));
    }

    gcry_cipher_hd_t handle;
    gcry_error_t err = 0;

    err = gcry_cipher_open(&handle, alg, mode, 0);
    handleGcryError(err);

    err = gcry_cipher_setkey(handle, key, KEY_LEN);
    handleGcryError(err);

    auto iv = std::shared_ptr<byte>(new byte[BLOCK_LEN], std::default_delete<byte[]>());
    random_bytes.generateRandomBytes(iv.get(), BLOCK_LEN);
    err = gcry_cipher_setiv(handle, iv.get(), BLOCK_LEN);
    handleGcryError(err);

    auto padded_plain_text = std::shared_ptr<byte>(new byte[padded_plain_text_len], std::default_delete<byte[]>());
    memcpy(padded_plain_text.get(), plain_text, plain_text_len);

    err = gcry_cipher_encrypt(handle, cipher_text, cipher_text_len, padded_plain_text.get(), padded_plain_text_len);
    handleGcryError(err);

    cipher_text_len = padded_plain_text_len;

    gcry_cipher_close(handle);

    memcpy(cipher_text + cipher_text_len, iv.get(), BLOCK_LEN);
    cipher_text_len += BLOCK_LEN;
}

template<int KEY_LEN, int BLOCK_LEN>
void LibgcryptCipher<KEY_LEN, BLOCK_LEN>::decrypt(const byte key[KEY_LEN], const byte * cipher_text, byte_len cipher_text_len
                                                  , byte * recovered_text, byte_len & recovered_text_len)
{
    auto req_len = BLOCK_LEN;
    if (recovered_text_len < req_len)
    {
        throw LibgcryptException("Libgcrypt Error: Invalid recovered text length. Must be at least: " + std::to_string(req_len));
    }

    gcry_cipher_hd_t handle;
    gcry_error_t err = 0;

    err = gcry_cipher_open(&handle, alg, mode, 0);
    handleGcryError(err);

    err = gcry_cipher_setkey(handle, key, KEY_LEN);
    handleGcryError(err);

    auto iv = std::shared_ptr<byte>(new byte[BLOCK_LEN], std::default_delete<byte[]>());
    memcpy(iv.get(), cipher_text + cipher_text_len - BLOCK_LEN, BLOCK_LEN);

    err = gcry_cipher_setiv(handle, iv.get(), BLOCK_LEN);
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
        throw LibgcryptException(std::string(gcry_strsource(err)) + " " + std::string(gcry_strerror(err)));
    }
}

CipherPtr LibgcryptCipherFactory::getCipher(Cipher cipher)
{
    switch (cipher)
    {
        case Cipher::AES_256_ECB:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB);
        case Cipher::AES_256_CBC:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC);
        case Cipher::AES_256_CFB:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB);
        case Cipher::AES_256_OFB:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB);
        case Cipher::AES_256_CTR:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR);
        case Cipher::AES_256_GCM:
            return CIPHER_AUTH(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM);
        case Cipher::AES_256_XTS:
            return CIPHER(KEY_512, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_XTS);
        case Cipher::AES_256_CCM:
            return CIPHER_AUTH(KEY_256, BLK_128, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CCM);
        case Cipher::AES_256_EAX:
            throw UnsupportedCipherException();
        case Cipher::AES_256_OCB:
            return CIPHER_AUTH(KEY_256, BLK_96, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OCB);
        case Cipher::AES_256_SIV:
            throw UnsupportedCipherException();

        case Cipher::AES_192_ECB:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB);
        case Cipher::AES_192_CBC:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC);
        case Cipher::AES_192_CFB:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CFB);
        case Cipher::AES_192_OFB:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OFB);
        case Cipher::AES_192_CTR:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CTR);
        case Cipher::AES_192_GCM:
            return CIPHER_AUTH(KEY_192, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_GCM);
        case Cipher::AES_192_XTS:
            return CIPHER(KEY_384, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_XTS);
        case Cipher::AES_192_CCM:
            return CIPHER_AUTH(KEY_192, BLK_128, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CCM);
        case Cipher::AES_192_EAX:
            throw UnsupportedCipherException();
        case Cipher::AES_192_OCB:
            return CIPHER_AUTH(KEY_192, BLK_96, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OCB);
        case Cipher::AES_192_SIV:
            throw UnsupportedCipherException();

        case Cipher::AES_128_ECB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB);
        case Cipher::AES_128_CBC:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC);
        case Cipher::AES_128_CFB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CFB);
        case Cipher::AES_128_OFB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_OFB);
        case Cipher::AES_128_CTR:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR);
        case Cipher::AES_128_GCM:
            return CIPHER_AUTH(KEY_128, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM);
        case Cipher::AES_128_XTS:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_XTS);
        case Cipher::AES_128_CCM:
            return CIPHER_AUTH(KEY_128, BLK_128, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM);
        case Cipher::AES_128_EAX:
            throw UnsupportedCipherException();
        case Cipher::AES_128_OCB:
            return CIPHER_AUTH(KEY_128, BLK_96, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_OCB);
        case Cipher::AES_128_SIV:
            throw UnsupportedCipherException();

        case Cipher::ARIA_256_ECB:
        case Cipher::ARIA_256_CBC:
        case Cipher::ARIA_256_CFB:
        case Cipher::ARIA_256_OFB:
        case Cipher::ARIA_256_CTR:
        case Cipher::ARIA_256_GCM:
        case Cipher::ARIA_256_XTS:
        case Cipher::ARIA_256_CCM:
        case Cipher::ARIA_256_EAX:
        case Cipher::ARIA_256_OCB:
        case Cipher::ARIA_256_SIV:
        case Cipher::ARIA_192_ECB:
        case Cipher::ARIA_192_CBC:
        case Cipher::ARIA_192_CFB:
        case Cipher::ARIA_192_OFB:
        case Cipher::ARIA_192_CTR:
        case Cipher::ARIA_192_GCM:
        case Cipher::ARIA_192_XTS:
        case Cipher::ARIA_192_CCM:
        case Cipher::ARIA_192_EAX:
        case Cipher::ARIA_192_OCB:
        case Cipher::ARIA_192_SIV:
        case Cipher::ARIA_128_ECB:
        case Cipher::ARIA_128_CBC:
        case Cipher::ARIA_128_CFB:
        case Cipher::ARIA_128_OFB:
        case Cipher::ARIA_128_CTR:
        case Cipher::ARIA_128_GCM:
        case Cipher::ARIA_128_XTS:
        case Cipher::ARIA_128_CCM:
        case Cipher::ARIA_128_EAX:
        case Cipher::ARIA_128_OCB:
        case Cipher::ARIA_128_SIV:
            throw UnsupportedCipherException();

        case Cipher::CAMELLIA_256_ECB:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_ECB);
        case Cipher::CAMELLIA_256_CBC:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_CBC);
        case Cipher::CAMELLIA_256_CFB:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_CFB);
        case Cipher::CAMELLIA_256_OFB:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_OFB);
        case Cipher::CAMELLIA_256_CTR:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_CTR);
        case Cipher::CAMELLIA_256_GCM:
            return CIPHER_AUTH(KEY_256, BLK_128, GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_GCM);
        case Cipher::CAMELLIA_256_XTS:
            return CIPHER(KEY_512, BLK_128, GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_XTS);
        case Cipher::CAMELLIA_256_CCM:
            return CIPHER_AUTH(KEY_256, BLK_128, GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_CCM);
        case Cipher::CAMELLIA_256_EAX:
            throw UnsupportedCipherException();
        case Cipher::CAMELLIA_256_OCB:
            return CIPHER_AUTH(KEY_256, BLK_96, GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_OCB);
        case Cipher::CAMELLIA_256_SIV:
            throw UnsupportedCipherException();

        case Cipher::CAMELLIA_192_ECB:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_ECB);
        case Cipher::CAMELLIA_192_CBC:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_CBC);
        case Cipher::CAMELLIA_192_CFB:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_CFB);
        case Cipher::CAMELLIA_192_OFB:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_OFB);
        case Cipher::CAMELLIA_192_CTR:
            return CIPHER(KEY_192, BLK_128, GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_CTR);
        case Cipher::CAMELLIA_192_GCM:
            return CIPHER_AUTH(KEY_192, BLK_128, GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_GCM);
        case Cipher::CAMELLIA_192_XTS:
            return CIPHER(KEY_384, BLK_128, GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_XTS);
        case Cipher::CAMELLIA_192_CCM:
            return CIPHER_AUTH(KEY_192, BLK_128, GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_CCM);
        case Cipher::CAMELLIA_192_EAX:
            throw UnsupportedCipherException();
        case Cipher::CAMELLIA_192_OCB:
            return CIPHER_AUTH(KEY_192, BLK_96, GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_OCB);
        case Cipher::CAMELLIA_192_SIV:
            throw UnsupportedCipherException();

        case Cipher::CAMELLIA_128_ECB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_ECB);
        case Cipher::CAMELLIA_128_CBC:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_CBC);
        case Cipher::CAMELLIA_128_CFB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_CFB);
        case Cipher::CAMELLIA_128_OFB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_OFB);
        case Cipher::CAMELLIA_128_CTR:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_CTR);
        case Cipher::CAMELLIA_128_GCM:
            return CIPHER_AUTH(KEY_128, BLK_128, GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_GCM);
        case Cipher::CAMELLIA_128_XTS:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_XTS);
        case Cipher::CAMELLIA_128_CCM:
            return CIPHER_AUTH(KEY_128, BLK_128, GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_CCM);
        case Cipher::CAMELLIA_128_EAX:
            throw UnsupportedCipherException();
        case Cipher::CAMELLIA_128_OCB:
            return CIPHER_AUTH(KEY_128, BLK_96, GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_OCB);
        case Cipher::CAMELLIA_128_SIV:
            throw UnsupportedCipherException();

        case Cipher::SM4_ECB:
        case Cipher::SM4_CBC:
        case Cipher::SM4_CFB:
        case Cipher::SM4_OFB:
        case Cipher::SM4_CTR:
        case Cipher::SM4_GCM:
        case Cipher::SM4_XTS:
        case Cipher::SM4_CCM:
        case Cipher::SM4_EAX:
        case Cipher::SM4_OCB:
        case Cipher::SM4_SIV:
            throw UnsupportedCipherException();

        case Cipher::SEED_ECB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_ECB);
        case Cipher::SEED_CBC:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_CBC);
        case Cipher::SEED_CFB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_CFB);
        case Cipher::SEED_OFB:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_OFB);
        case Cipher::SEED_CTR:
            return CIPHER(KEY_128, BLK_128, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_CTR);
        case Cipher::SEED_GCM:
            return CIPHER_AUTH(KEY_128, BLK_128, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_GCM);
        case Cipher::SEED_XTS:
            return CIPHER(KEY_256, BLK_128, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_XTS);
        case Cipher::SEED_CCM:
            return CIPHER_AUTH(KEY_128, BLK_128, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_CCM);
        case Cipher::SEED_EAX:
            throw UnsupportedCipherException();
        case Cipher::SEED_OCB:
            return CIPHER_AUTH(KEY_128, BLK_96, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_OCB);
        case Cipher::SEED_SIV:
            throw UnsupportedCipherException();

        case Cipher::BLOWFISH_ECB:
            return CIPHER(KEY_448, BLK_64, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB);
        case Cipher::BLOWFISH_CBC:
            return CIPHER(KEY_448, BLK_64, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CBC);
        case Cipher::BLOWFISH_CFB:
            return CIPHER(KEY_448, BLK_64, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CFB);
        case Cipher::BLOWFISH_OFB:
            return CIPHER(KEY_448, BLK_64, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_OFB);
        case Cipher::BLOWFISH_CTR:
            return CIPHER(KEY_448, BLK_64, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CTR);
        case Cipher::BLOWFISH_GCM:
            return CIPHER_AUTH(KEY_448, BLK_64, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_GCM);
        case Cipher::BLOWFISH_XTS:
            return CIPHER(KEY_448, BLK_64, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_XTS);
        case Cipher::BLOWFISH_CCM:
            return CIPHER_AUTH(KEY_448, BLK_64, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CCM);
        case Cipher::BLOWFISH_EAX:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_OCB:
            return CIPHER_AUTH(KEY_448, BLK_64, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_OCB);
        case Cipher::BLOWFISH_SIV:
            throw UnsupportedCipherException();
    }
}
