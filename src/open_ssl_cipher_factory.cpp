//
// Created by ISU on 09/02/2020.
//

#include "CryptoBench/open_ssl_cipher_factory.hpp"

#include <cstring>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/camellia.h>
#include <CryptoBench/cipher_exception.hpp>

#include "CryptoBench/random_bytes.hpp"

#define CIPHER(key_len, block_len, iv_len, cipher) (CipherPtr(new OpenSSLCipher<key_len, block_len, iv_len>(cipher)))
#define CIPHER_AUTH(key_len, block_len, iv_len, tag_len, cipher) (CipherPtr(new OpenSSLAuthCipher<key_len, block_len, iv_len, tag_len>(cipher)))
#define CIPHER_CCM(key_len, block_len, iv_len, tag_len, cipher) (CipherPtr(new OpenSSLCCMCipher<key_len, block_len, iv_len, tag_len>(cipher)))

#define KEY_512 64
#define KEY_448 56
#define KEY_256 32
#define KEY_192 24
#define KEY_128 16

#define BLK_128 16
#define BLK_64 8

#define IV_128 16
#define IV_96 12
#define IV_64 8

#define TAG_128 16

template <int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE>
class OpenSSLCipher : public SymmetricCipher
{
public:

    explicit inline OpenSSLCipher(const EVP_CIPHER * cipher_mode) : cipher_mode(cipher_mode), random_bytes()
    {}

    virtual void encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
                         , byte * cipher_text, byte_len & cipher_text_len) override;

    virtual void decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                         , byte * recovered_text, byte_len & recovered_text_len) override;

    inline int getBlockLen() override
    {
        return BLOCK_SIZE;
    }

    inline int getKeyLen() override
    {
        return KEY_SIZE;
    }

protected:

    RandomBytes random_bytes;
    const EVP_CIPHER* cipher_mode;

};


template <int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, int TAG_SIZE>
class OpenSSLAuthCipher : public OpenSSLCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>
{
public:

    explicit inline OpenSSLAuthCipher(const EVP_CIPHER* cipher_mode) : OpenSSLCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>(cipher_mode) {}

    void encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
                 , byte * cipher_text, byte_len & cipher_text_len) override;

    void decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                 , byte * recovered_text, byte_len & recovered_text_len) override;

};

template <int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, int TAG_SIZE>
class OpenSSLCCMCipher : public OpenSSLCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>
{
public:

    explicit inline OpenSSLCCMCipher(const EVP_CIPHER* cipher_mode) : OpenSSLCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>(cipher_mode) {}

    void encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
                 , byte * cipher_text, byte_len & cipher_text_len) override;

    void decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                 , byte * recovered_text, byte_len & recovered_text_len) override;

};

using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, int TAG_SIZE>
void OpenSSLCCMCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE, TAG_SIZE>::encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
                                                      , byte * cipher_text, byte_len & cipher_text_len)
{
    using super = OpenSSLCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>;

    auto req_len = plain_text_len + BLOCK_SIZE - (plain_text_len % BLOCK_SIZE) + BLOCK_SIZE + TAG_SIZE;
    if (cipher_text_len < req_len)
    {
        throw OpenSSLException("Invalid cipher text length. Must be at least: " + std::to_string(req_len));
    }

    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    auto &cipher_mode = super::cipher_mode;
    if (1 != EVP_EncryptInit_ex(ctx.get(), cipher_mode, nullptr, nullptr, nullptr))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_IVLEN, IV_SIZE, nullptr))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_TAG, TAG_SIZE, nullptr);

    auto iv = std::shared_ptr<byte>(new byte[IV_SIZE], std::default_delete<byte[]>());
    super::random_bytes.generateRandomBytes(iv.get(), IV_SIZE);
    if (1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, iv.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    int out_len1 = cipher_text_len;
    /*if (1 != EVP_EncryptUpdate(ctx.get(), nullptr, &out_len1, nullptr, plain_text_len))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }*/

    if (1 != EVP_EncryptUpdate(ctx.get(), cipher_text, &out_len1, plain_text, plain_text_len))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    int out_len2 = cipher_text_len - out_len1;
    if (1 != EVP_EncryptFinal_ex(ctx.get(), cipher_text + out_len1, &out_len2))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    auto tag = std::shared_ptr<byte>(new byte[TAG_SIZE], std::default_delete<byte[]>());
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_GET_TAG, TAG_SIZE, tag.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    cipher_text_len = out_len1 + out_len2;
    memcpy(cipher_text + cipher_text_len, tag.get(), TAG_SIZE);
    cipher_text_len += TAG_SIZE;
    memcpy(cipher_text + cipher_text_len, iv.get(), IV_SIZE);
    cipher_text_len += IV_SIZE;

}

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, int TAG_SIZE>
void OpenSSLCCMCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE, TAG_SIZE>::decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                                                      , byte * recovered_text, byte_len & recovered_text_len)
{
    using super = OpenSSLCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>;

    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    auto &cipher_mode = super::cipher_mode;
    if (1 != EVP_DecryptInit_ex(ctx.get(), cipher_mode, nullptr, nullptr, nullptr))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    auto tag = std::shared_ptr<byte>(new byte[TAG_SIZE], std::default_delete<byte[]>());
    memcpy(tag.get(), cipher_text + cipher_text_len - TAG_SIZE - IV_SIZE, TAG_SIZE);

    auto iv = std::shared_ptr<byte>(new byte[IV_SIZE], std::default_delete<byte[]>());
    memcpy(iv.get(), cipher_text + cipher_text_len - IV_SIZE, IV_SIZE);


    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_IVLEN, IV_SIZE, nullptr))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_TAG, TAG_SIZE, tag.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (1 != EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key, iv.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    int out_len1 = recovered_text_len;
    /*if (1 != EVP_DecryptUpdate(ctx.get(), nullptr, &out_len1, nullptr, cipher_text_len))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }*/

    if (0 >= EVP_DecryptUpdate(ctx.get(), recovered_text, &out_len1, cipher_text, cipher_text_len - TAG_SIZE - IV_SIZE))
    {
        throw OpenSSLException("Verification failed");
    }

    recovered_text_len = out_len1;
}

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, int TAG_SIZE>
void OpenSSLAuthCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE, TAG_SIZE>::encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
                                                      , byte * cipher_text, byte_len & cipher_text_len)
{
    using super = OpenSSLCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>;

    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    auto &cipher_mode = super::cipher_mode;
    if (1 != EVP_EncryptInit_ex(ctx.get(), cipher_mode, nullptr, nullptr, nullptr))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, nullptr);

    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, IV_SIZE, nullptr);

    auto iv = std::shared_ptr<byte>(new byte[IV_SIZE], std::default_delete<byte[]>());
    super::random_bytes.generateRandomBytes(iv.get(), IV_SIZE);
    if (1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, iv.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }


    int out_len1 = cipher_text_len;
    if (1 != EVP_EncryptUpdate(ctx.get(), cipher_text, &out_len1, plain_text, plain_text_len))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    int out_len2 = cipher_text_len - out_len1;
    if (1 != EVP_EncryptFinal_ex(ctx.get(), cipher_text, &out_len2))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    auto tag = std::shared_ptr<byte>(new byte[TAG_SIZE], std::default_delete<byte[]>());
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    cipher_text_len = out_len1 + out_len2;
    memcpy(cipher_text + cipher_text_len, tag.get(), TAG_SIZE);
    cipher_text_len += TAG_SIZE;
    memcpy(cipher_text + cipher_text_len, iv.get(), IV_SIZE);
    cipher_text_len += IV_SIZE;

}

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, int TAG_SIZE>
void OpenSSLAuthCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE, TAG_SIZE>::decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                                                      , byte * recovered_text, byte_len & recovered_text_len)
{
    using super = OpenSSLCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>;

    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    auto &cipher_mode = super::cipher_mode;
    if (1 != EVP_DecryptInit_ex(ctx.get(), cipher_mode, nullptr, nullptr, nullptr))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    auto tag = std::shared_ptr<byte>(new byte[TAG_SIZE], std::default_delete<byte[]>());
    memcpy(tag.get(), cipher_text + cipher_text_len - TAG_SIZE - IV_SIZE, TAG_SIZE);

    auto iv = std::shared_ptr<byte>(new byte[IV_SIZE], std::default_delete<byte[]>());
    memcpy(iv.get(), cipher_text + cipher_text_len - IV_SIZE, IV_SIZE);



    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, IV_SIZE, nullptr);

    if (1 != EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key, iv.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    int out_len1 = recovered_text_len;
    if (1 != EVP_DecryptUpdate(ctx.get(), recovered_text, &out_len1, cipher_text, cipher_text_len - TAG_SIZE - IV_SIZE))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, tag.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    int out_len2 = recovered_text_len - out_len1;
    if (0 >= EVP_DecryptFinal_ex(ctx.get(), recovered_text + out_len1, &out_len2))
    {
        throw OpenSSLException("Verification failed");
    }

    recovered_text_len = out_len1 + out_len2;
}

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE>
void OpenSSLCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>::encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
                                                  , byte * cipher_text, byte_len & cipher_text_len)
{
    auto req_len = plain_text_len + BLOCK_SIZE - (plain_text_len % BLOCK_SIZE) + BLOCK_SIZE;
    if (cipher_text_len < req_len)
    {
        throw OpenSSLException("Invalid cipher text length. Must be at least: " + std::to_string(req_len));
    }

    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    auto iv = std::shared_ptr<byte>(new byte[BLOCK_SIZE], std::default_delete<byte[]>());
    random_bytes.generateRandomBytes(iv.get(), BLOCK_SIZE);

    if (1 != EVP_EncryptInit_ex(ctx.get(), cipher_mode, nullptr, nullptr, nullptr))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (1 != EVP_CIPHER_CTX_set_key_length(ctx.get(), KEY_SIZE))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, iv.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    int out_len1 = cipher_text_len;
    if (1 != EVP_EncryptUpdate(ctx.get(), cipher_text, &out_len1, plain_text, plain_text_len))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    int out_len2 = cipher_text_len - out_len1;
    if (1 != EVP_EncryptFinal_ex(ctx.get(), cipher_text + out_len1, &out_len2))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    cipher_text_len = out_len1 + out_len2 + BLOCK_SIZE;
    memcpy(cipher_text + cipher_text_len - BLOCK_SIZE, iv.get(), BLOCK_SIZE);
}

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE>
void OpenSSLCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>::decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                                                  , byte * recovered_text, byte_len & recovered_text_len)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    auto iv = std::shared_ptr<byte>(new byte[BLOCK_SIZE], std::default_delete<byte[]>());
    memcpy(iv.get(), cipher_text + cipher_text_len - BLOCK_SIZE, BLOCK_SIZE);

    if (1 != EVP_DecryptInit_ex(ctx.get(), cipher_mode, nullptr, nullptr, nullptr))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (1 != EVP_CIPHER_CTX_set_key_length(ctx.get(), KEY_SIZE))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (1 != EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key, iv.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    //recovered_text_len = cipher_text_len - BLOCK_SIZE;
    int out_len1 = recovered_text_len;

    if (1 != EVP_DecryptUpdate(ctx.get(), recovered_text, &out_len1, cipher_text, cipher_text_len - BLOCK_SIZE))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    int out_len2 = recovered_text_len - out_len1;
    if (1 != EVP_DecryptFinal_ex(ctx.get(), recovered_text + out_len1, &out_len2))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    recovered_text_len = out_len1 + out_len2;
}

OpenSSLCipherFactory::OpenSSLCipherFactory()
{
    /*
    ERR_load_CRYPTO_strings();
    ERR_load_EVP_strings();
    ERR_load_ERR_strings();
    ERR_load_ASN1_strings();
    ERR_load_BIO_strings();
    ERR_load_OBJ_strings();*/
}

CipherPtr OpenSSLCipherFactory::getCipher(Cipher cipher)
{
    switch (cipher)
    {
        case Cipher::AES_256_ECB:
            return CIPHER(KEY_256, BLK_128, IV_128, EVP_aes_256_ecb());
        case Cipher::AES_256_CBC:
            return CIPHER(KEY_256, BLK_128, IV_128, EVP_aes_256_cbc());
        case Cipher::AES_256_CFB:
            return CIPHER(KEY_256, BLK_128, IV_128, EVP_aes_256_cfb());
        case Cipher::AES_256_OFB:
            return CIPHER(KEY_256, BLK_128, IV_128, EVP_aes_256_ofb());
        case Cipher::AES_256_CTR:
            return CIPHER(KEY_256, BLK_128, IV_128, EVP_aes_256_ctr());
        case Cipher::AES_256_GCM:
            return CIPHER_AUTH(KEY_256, BLK_128, IV_96, TAG_128, EVP_aes_256_gcm());
        case Cipher::AES_256_XTS:
            return CIPHER(KEY_512, BLK_128, IV_128, EVP_aes_256_xts()); // XTS mode expects key doubled
        case Cipher::AES_256_CCM:
            return CIPHER_CCM(KEY_256, BLK_128, IV_96, TAG_128, EVP_aes_256_ccm());
        case Cipher::AES_256_EAX:
            throw UnsupportedCipherException();
        case Cipher::AES_256_OCB:
            throw UnsupportedCipherException();
            //return CIPHER_AUTH(KEY_256, BLK_128, IV_96, TAG_128, EVP_aes_256_ocb());
        case Cipher::AES_256_SIV:
            throw UnsupportedCipherException();

        case Cipher::AES_192_ECB:
            return CIPHER(KEY_192, BLK_128, IV_128, EVP_aes_192_ecb());
        case Cipher::AES_192_CBC:
            return CIPHER(KEY_192, BLK_128, IV_128, EVP_aes_192_cbc());
        case Cipher::AES_192_CFB:
            return CIPHER(KEY_192, BLK_128, IV_128, EVP_aes_192_cfb());
        case Cipher::AES_192_OFB:
            return CIPHER(KEY_192, BLK_128, IV_128, EVP_aes_192_ofb());
        case Cipher::AES_192_CTR:
            return CIPHER(KEY_192, BLK_128, IV_128, EVP_aes_192_ctr());
        case Cipher::AES_192_GCM:
            return CIPHER_AUTH(KEY_192, BLK_128, IV_96, TAG_128, EVP_aes_192_gcm());
        case Cipher::AES_192_XTS:
            throw UnsupportedCipherException();
        case Cipher::AES_192_CCM:
            return CIPHER_CCM(KEY_192, BLK_128, IV_96, TAG_128, EVP_aes_192_ccm());
        case Cipher::AES_192_EAX:
            throw UnsupportedCipherException();
        case Cipher::AES_192_OCB:
            throw UnsupportedCipherException();
            //return CIPHER_AUTH(KEY_192, BLK_128, IV_96, TAG_128,EVP_aes_192_ocb());
        case Cipher::AES_192_SIV:
            throw UnsupportedCipherException();


        case Cipher::AES_128_ECB:
            return CIPHER(KEY_128, BLK_128, IV_128,EVP_aes_128_ecb());
        case Cipher::AES_128_CBC:
            return CIPHER(KEY_128, BLK_128, IV_128,EVP_aes_128_cbc());
        case Cipher::AES_128_CFB:
            return CIPHER(KEY_128, BLK_128, IV_128,EVP_aes_128_cfb());
        case Cipher::AES_128_OFB:
            return CIPHER(KEY_128, BLK_128, IV_128,EVP_aes_128_ofb());
        case Cipher::AES_128_CTR:
            return CIPHER(KEY_128, BLK_128, IV_128,EVP_aes_128_ctr());
        case Cipher::AES_128_GCM:
            return CIPHER_AUTH(KEY_128, BLK_128, IV_96, TAG_128, EVP_aes_128_gcm());
        case Cipher::AES_128_XTS:
            return CIPHER(KEY_256, BLK_128, IV_128, EVP_aes_128_xts()); // XTS mode expects key doubled
        case Cipher::AES_128_CCM:
            return CIPHER_CCM(KEY_128, BLK_128, IV_96, TAG_128, EVP_aes_128_ccm());
        case Cipher::AES_128_EAX:
            throw UnsupportedCipherException();
        case Cipher::AES_128_OCB:
            throw UnsupportedCipherException();
            //return CIPHER_AUTH(KEY_128, BLK_128, IV_96, TAG_128, EVP_aes_128_ocb());
        case Cipher::AES_128_SIV:
            throw UnsupportedCipherException();


        case Cipher::ARIA_256_ECB:
            return CIPHER(KEY_256, BLK_128, IV_128, EVP_aria_256_ecb());
        case Cipher::ARIA_256_CBC:
            return CIPHER(KEY_256, BLK_128, IV_128, EVP_aria_256_cbc());
        case Cipher::ARIA_256_CFB:
            return CIPHER(KEY_256, BLK_128, IV_128, EVP_aria_256_cfb());
        case Cipher::ARIA_256_OFB:
            return CIPHER(KEY_256, BLK_128, IV_128, EVP_aria_256_ofb());
        case Cipher::ARIA_256_CTR:
            return CIPHER(KEY_256, BLK_128, IV_128, EVP_aria_256_ctr());
        case Cipher::ARIA_256_GCM:
            return CIPHER_AUTH(KEY_256, BLK_128, IV_96, TAG_128, EVP_aria_256_gcm());
        case Cipher::ARIA_256_XTS:
            throw UnsupportedCipherException();
        case Cipher::ARIA_256_CCM:
            return CIPHER_CCM(KEY_256, BLK_128, IV_96, TAG_128, EVP_aria_256_ccm());
        case Cipher::ARIA_256_EAX:
            throw UnsupportedCipherException();
        case Cipher::ARIA_256_OCB:
            throw UnsupportedCipherException();
        case Cipher::ARIA_256_SIV:
            throw UnsupportedCipherException();

        case Cipher::ARIA_192_ECB:
            return CIPHER(KEY_192, BLK_128, IV_128, EVP_aria_192_ecb());
        case Cipher::ARIA_192_CBC:
            return CIPHER(KEY_192, BLK_128, IV_128, EVP_aria_192_cbc());
        case Cipher::ARIA_192_CFB:
            return CIPHER(KEY_192, BLK_128, IV_128, EVP_aria_192_cfb());
        case Cipher::ARIA_192_OFB:
            return CIPHER(KEY_192, BLK_128, IV_128, EVP_aria_192_ofb());
        case Cipher::ARIA_192_CTR:
            return CIPHER(KEY_192, BLK_128, IV_128, EVP_aria_192_ctr());
        case Cipher::ARIA_192_GCM:
            return CIPHER_AUTH(KEY_192, BLK_128, IV_96, TAG_128,EVP_aria_192_gcm());
        case Cipher::ARIA_192_XTS:
            throw UnsupportedCipherException();
        case Cipher::ARIA_192_CCM:
            return CIPHER_CCM(KEY_192, BLK_128, IV_96, TAG_128, EVP_aria_192_ccm());
        case Cipher::ARIA_192_EAX:
            throw UnsupportedCipherException();
        case Cipher::ARIA_192_OCB:
            throw UnsupportedCipherException();
        case Cipher::ARIA_192_SIV:
            throw UnsupportedCipherException();

        case Cipher::ARIA_128_ECB:
            return CIPHER(KEY_128, BLK_128, IV_128, EVP_aria_128_ecb());
        case Cipher::ARIA_128_CBC:
            return CIPHER(KEY_128, BLK_128, IV_128, EVP_aria_128_cbc());
        case Cipher::ARIA_128_CFB:
            return CIPHER(KEY_128, BLK_128, IV_128, EVP_aria_128_cfb());
        case Cipher::ARIA_128_OFB:
            return CIPHER(KEY_128, BLK_128, IV_128, EVP_aria_128_ofb());
        case Cipher::ARIA_128_CTR:
            return CIPHER(KEY_128, BLK_128, IV_128, EVP_aria_128_ctr());
        case Cipher::ARIA_128_GCM:
            return CIPHER_AUTH(KEY_128, BLK_128, IV_96, TAG_128, EVP_aria_128_gcm());
        case Cipher::ARIA_128_XTS:
            throw UnsupportedCipherException();
        case Cipher::ARIA_128_CCM:
            return CIPHER_CCM(KEY_128, BLK_128, IV_96, TAG_128, EVP_aria_128_ccm());
        case Cipher::ARIA_128_EAX:
            throw UnsupportedCipherException();
        case Cipher::ARIA_128_OCB:
            throw UnsupportedCipherException();
        case Cipher::ARIA_128_SIV:
            throw UnsupportedCipherException();


        case Cipher::CAMELLIA_256_ECB:
        case Cipher::CAMELLIA_256_CBC:
        case Cipher::CAMELLIA_256_CFB:
        case Cipher::CAMELLIA_256_OFB:
        case Cipher::CAMELLIA_256_CTR:
        case Cipher::CAMELLIA_256_GCM:
        case Cipher::CAMELLIA_256_XTS:
        case Cipher::CAMELLIA_256_CCM:
        case Cipher::CAMELLIA_256_EAX:
        case Cipher::CAMELLIA_256_OCB:
        case Cipher::CAMELLIA_256_SIV:
            throw UnsupportedCipherException();

        case Cipher::CAMELLIA_192_ECB:
        case Cipher::CAMELLIA_192_CBC:
        case Cipher::CAMELLIA_192_CFB:
        case Cipher::CAMELLIA_192_OFB:
        case Cipher::CAMELLIA_192_CTR:
        case Cipher::CAMELLIA_192_GCM:
        case Cipher::CAMELLIA_192_XTS:
        case Cipher::CAMELLIA_192_CCM:
        case Cipher::CAMELLIA_192_EAX:
        case Cipher::CAMELLIA_192_OCB:
        case Cipher::CAMELLIA_192_SIV:
            throw UnsupportedCipherException();

        case Cipher::CAMELLIA_128_ECB:
        case Cipher::CAMELLIA_128_CBC:
        case Cipher::CAMELLIA_128_CFB:
        case Cipher::CAMELLIA_128_OFB:
        case Cipher::CAMELLIA_128_CTR:
        case Cipher::CAMELLIA_128_GCM:
        case Cipher::CAMELLIA_128_XTS:
        case Cipher::CAMELLIA_128_CCM:
        case Cipher::CAMELLIA_128_EAX:
        case Cipher::CAMELLIA_128_OCB:
        case Cipher::CAMELLIA_128_SIV:
            throw UnsupportedCipherException();

        case Cipher::SEED_ECB:
            return CIPHER(KEY_128, BLK_128, IV_128, EVP_seed_ecb());
        case Cipher::SEED_CBC:
            return CIPHER(KEY_128, BLK_128, IV_128, EVP_seed_cbc());
        case Cipher::SEED_CFB:
            return CIPHER(KEY_128, BLK_128, IV_128, EVP_seed_cfb());
        case Cipher::SEED_OFB:
            return CIPHER(KEY_128, BLK_128, IV_128, EVP_seed_ofb());
        case Cipher::SEED_CTR:
            throw UnsupportedCipherException();
        case Cipher::SEED_GCM:
            throw UnsupportedCipherException();
        case Cipher::SEED_XTS:
            throw UnsupportedCipherException();
        case Cipher::SEED_CCM:
            throw UnsupportedCipherException();
        case Cipher::SEED_EAX:
            throw UnsupportedCipherException();
        case Cipher::SEED_OCB:
            throw UnsupportedCipherException();
        case Cipher::SEED_SIV:
            throw UnsupportedCipherException();

        case Cipher::BLOWFISH_ECB:
            return CIPHER(KEY_448, BLK_64, IV_64, EVP_bf_ecb());
        case Cipher::BLOWFISH_CBC:
            return CIPHER(KEY_448, BLK_64, IV_64, EVP_bf_cbc());
        case Cipher::BLOWFISH_CFB:
            return CIPHER(KEY_448, BLK_64, IV_64, EVP_bf_cfb());
        case Cipher::BLOWFISH_OFB:
            return CIPHER(KEY_448, BLK_64, IV_64, EVP_bf_ofb());
        case Cipher::BLOWFISH_CTR:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_GCM:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_XTS:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_CCM:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_EAX:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_OCB:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_SIV:
            throw UnsupportedCipherException();

        case Cipher::BLOWFISH_256_ECB:
            return CIPHER(KEY_256, BLK_64, IV_64, EVP_bf_ecb());
        case Cipher::BLOWFISH_256_CBC:
            return CIPHER(KEY_256, BLK_64, IV_64, EVP_bf_cbc());
        case Cipher::BLOWFISH_256_CFB:
            return CIPHER(KEY_256, BLK_64, IV_64, EVP_bf_cfb());
        case Cipher::BLOWFISH_256_OFB:
            return CIPHER(KEY_256, BLK_64, IV_64, EVP_bf_ofb());
        case Cipher::BLOWFISH_256_CTR:
        case Cipher::BLOWFISH_256_GCM:
        case Cipher::BLOWFISH_256_XTS:
        case Cipher::BLOWFISH_256_CCM:
        case Cipher::BLOWFISH_256_EAX:
        case Cipher::BLOWFISH_256_OCB:
        case Cipher::BLOWFISH_256_SIV:
            throw UnsupportedCipherException();

        case Cipher::BLOWFISH_192_ECB:
            return CIPHER(KEY_192, BLK_64, IV_64, EVP_bf_ecb());
        case Cipher::BLOWFISH_192_CBC:
            return CIPHER(KEY_192, BLK_64, IV_64, EVP_bf_cbc());
        case Cipher::BLOWFISH_192_CFB:
            return CIPHER(KEY_192, BLK_64, IV_64, EVP_bf_cfb());
        case Cipher::BLOWFISH_192_OFB:
            return CIPHER(KEY_192, BLK_64, IV_64, EVP_bf_ofb());
        case Cipher::BLOWFISH_192_CTR:
        case Cipher::BLOWFISH_192_GCM:
        case Cipher::BLOWFISH_192_XTS:
        case Cipher::BLOWFISH_192_CCM:
        case Cipher::BLOWFISH_192_EAX:
        case Cipher::BLOWFISH_192_OCB:
        case Cipher::BLOWFISH_192_SIV:
            throw UnsupportedCipherException();

        case Cipher::BLOWFISH_128_ECB:
            return CIPHER(KEY_128, BLK_64, IV_64, EVP_bf_ecb());
        case Cipher::BLOWFISH_128_CBC:
            return CIPHER(KEY_128, BLK_64, IV_64, EVP_bf_cbc());
        case Cipher::BLOWFISH_128_CFB:
            return CIPHER(KEY_128, BLK_64, IV_64, EVP_bf_cfb());
        case Cipher::BLOWFISH_128_OFB:
            return CIPHER(KEY_128, BLK_64, IV_64, EVP_bf_ofb());
        case Cipher::BLOWFISH_128_CTR:
        case Cipher::BLOWFISH_128_GCM:
        case Cipher::BLOWFISH_128_XTS:
        case Cipher::BLOWFISH_128_CCM:
        case Cipher::BLOWFISH_128_EAX:
        case Cipher::BLOWFISH_128_OCB:
        case Cipher::BLOWFISH_128_SIV:
            throw UnsupportedCipherException();
    }
}