//
// Created by ISU on 09/02/2020.
//

#include "CryptoBench/open_ssl_cipher_factory.hpp"

#include <cstring>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <CryptoBench/cipher_exception.hpp>

#include "CryptoBench/random_bytes.hpp"

#define CIPHER(key_len, block_len, cipher) (CipherPtr(new OpenSSLCipher<key_len, block_len>(cipher)))
#define CIPHER_AUTH(key_len, block_len, cipher) (CipherPtr(new OpenSSLAuthCipher<key_len, block_len>(cipher)))
#define CIPHER_CCM(key_len, block_len, cipher) (CipherPtr(new OpenSSLCCMCipher<key_len, block_len>(cipher)))

#define KEY_128 16
#define KEY_192 24
#define KEY_256 32
#define KEY_512 64
#define KEY_448 56

#define BLK_128 16
#define BLK_64 8

#define AEAD_TAG_LEN 16
#define AEAD_IV_LEN 12

#define CCM_TAG_LEN 12
#define CCM_IV_LEN 8

#define CIPHER_128_BLOCK(key_len, cipher) (CIPHER(key_len, BLK_128, cipher))

template <int KEY_SIZE, int BLOCK_SIZE>
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


template <int KEY_SIZE, int BLOCK_SIZE>
class OpenSSLAuthCipher : public OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>
{
public:

    explicit inline OpenSSLAuthCipher(const EVP_CIPHER* cipher_mode) : OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>(cipher_mode) {}

    void encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
                 , byte * cipher_text, byte_len & cipher_text_len) override;

    void decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                 , byte * recovered_text, byte_len & recovered_text_len) override;

};

template <int KEY_SIZE, int BLOCK_SIZE>
class OpenSSLCCMCipher : public OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>
{
public:

    explicit inline OpenSSLCCMCipher(const EVP_CIPHER* cipher_mode) : OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>(cipher_mode) {}

    void encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
                 , byte * cipher_text, byte_len & cipher_text_len) override;

    void decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                 , byte * recovered_text, byte_len & recovered_text_len) override;

};

using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

template<int KEY_SIZE, int BLOCK_SIZE>
void OpenSSLCCMCipher<KEY_SIZE, BLOCK_SIZE>::encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
                                                      , byte * cipher_text, byte_len & cipher_text_len)
{
    auto req_len = plain_text_len + BLOCK_SIZE - (plain_text_len % BLOCK_SIZE) + BLOCK_SIZE + AEAD_TAG_LEN;
    if (cipher_text_len < req_len)
    {
        throw OpenSSLException("Invalid cipher text length. Must be at least: " + std::to_string(req_len));
    }

    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    auto iv = std::shared_ptr<byte>(new byte[CCM_IV_LEN], std::default_delete<byte[]>());
    OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>::random_bytes.generateRandomBytes(iv.get(), CCM_IV_LEN);

    auto &cipher_mode = OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>::cipher_mode;
    if (1 != EVP_EncryptInit_ex(ctx.get(), cipher_mode, nullptr, key, iv.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_IVLEN, CCM_IV_LEN, nullptr))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_TAG, CCM_TAG_LEN, nullptr);

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

    auto tag = std::shared_ptr<byte>(new byte[CCM_TAG_LEN], std::default_delete<byte[]>());
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_GET_TAG, CCM_TAG_LEN, tag.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    cipher_text_len = out_len1 + out_len2;
    memcpy(cipher_text + cipher_text_len, iv.get(), CCM_IV_LEN);
    cipher_text_len += CCM_IV_LEN;
    memcpy(cipher_text + cipher_text_len, tag.get(), CCM_TAG_LEN);
    cipher_text_len += CCM_TAG_LEN;

}

template<int KEY_SIZE, int BLOCK_SIZE>
void OpenSSLCCMCipher<KEY_SIZE, BLOCK_SIZE>::decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                                                      , byte * recovered_text, byte_len & recovered_text_len)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    auto tag = std::shared_ptr<byte>(new byte[CCM_TAG_LEN], std::default_delete<byte[]>());
    memcpy(tag.get(), cipher_text + cipher_text_len - CCM_TAG_LEN, CCM_TAG_LEN);

    auto iv = std::shared_ptr<byte>(new byte[CCM_IV_LEN], std::default_delete<byte[]>());
    memcpy(iv.get(), cipher_text + cipher_text_len - CCM_TAG_LEN - CCM_IV_LEN, CCM_IV_LEN);

    auto &cipher_mode = OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>::cipher_mode;
    if (1 != EVP_DecryptInit_ex(ctx.get(), cipher_mode, nullptr, key, iv.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_IVLEN, CCM_IV_LEN, nullptr))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_TAG, CCM_TAG_LEN, tag.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    int out_len1 = recovered_text_len;
    /*if (1 != EVP_DecryptUpdate(ctx.get(), nullptr, &out_len1, nullptr, cipher_text_len))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }*/

    if (1 != EVP_DecryptUpdate(ctx.get(), recovered_text, &out_len1, cipher_text, cipher_text_len - CCM_TAG_LEN - CCM_IV_LEN))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    int out_len2 = recovered_text_len - out_len1;
    if (1 >= EVP_DecryptFinal_ex(ctx.get(), recovered_text + out_len1, &out_len2))
    {
        throw OpenSSLException("Verification failed");
    }

    recovered_text_len = out_len1 + out_len2;
}

template<int KEY_SIZE, int BLOCK_SIZE>
void OpenSSLAuthCipher<KEY_SIZE, BLOCK_SIZE>::encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
                                                      , byte * cipher_text, byte_len & cipher_text_len)
{
    auto req_len = plain_text_len + BLOCK_SIZE - (plain_text_len % BLOCK_SIZE) + BLOCK_SIZE + AEAD_TAG_LEN;
    if (cipher_text_len < req_len)
    {
        throw OpenSSLException("Invalid cipher text length. Must be at least: " + std::to_string(req_len));
    }

    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    auto iv = std::shared_ptr<byte>(new byte[AEAD_IV_LEN], std::default_delete<byte[]>());
    OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>::random_bytes.generateRandomBytes(iv.get(), AEAD_IV_LEN);

    auto &cipher_mode = OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>::cipher_mode;
    if (1 != EVP_EncryptInit_ex(ctx.get(), cipher_mode, nullptr, key, iv.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, AEAD_IV_LEN, nullptr))
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

    auto tag = std::shared_ptr<byte>(new byte[AEAD_TAG_LEN], std::default_delete<byte[]>());
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_LEN, tag.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    cipher_text_len = out_len1 + out_len2;
    memcpy(cipher_text + cipher_text_len, iv.get(), AEAD_IV_LEN);
    cipher_text_len += AEAD_IV_LEN;
    memcpy(cipher_text + cipher_text_len, tag.get(), AEAD_TAG_LEN);
    cipher_text_len += AEAD_TAG_LEN;

}

template<int KEY_SIZE, int BLOCK_SIZE>
void OpenSSLAuthCipher<KEY_SIZE, BLOCK_SIZE>::decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                                                      , byte * recovered_text, byte_len & recovered_text_len)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    auto tag = std::shared_ptr<byte>(new byte[AEAD_TAG_LEN], std::default_delete<byte[]>());
    memcpy(tag.get(), cipher_text + cipher_text_len - AEAD_TAG_LEN, AEAD_TAG_LEN);

    auto iv = std::shared_ptr<byte>(new byte[AEAD_IV_LEN], std::default_delete<byte[]>());
    memcpy(iv.get(), cipher_text + cipher_text_len - AEAD_TAG_LEN - AEAD_IV_LEN, AEAD_IV_LEN);

    auto &cipher_mode = OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>::cipher_mode;
    if (1 != EVP_DecryptInit_ex(ctx.get(), cipher_mode, nullptr, key, iv.get()))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, AEAD_IV_LEN, nullptr))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    int out_len1 = recovered_text_len;
    if (1 != EVP_DecryptUpdate(ctx.get(), recovered_text, &out_len1, cipher_text, cipher_text_len - AEAD_TAG_LEN - AEAD_IV_LEN))
    {
        throw OpenSSLException(std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, AEAD_TAG_LEN, tag.get()))
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

template<int KEY_SIZE, int BLOCK_SIZE>
void OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>::encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
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

    if (1 != EVP_EncryptInit_ex(ctx.get(), cipher_mode, nullptr, key, iv.get()))
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

template<int KEY_SIZE, int BLOCK_SIZE>
void OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>::decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                                                  , byte * recovered_text, byte_len & recovered_text_len)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    auto iv = std::shared_ptr<byte>(new byte[BLOCK_SIZE], std::default_delete<byte[]>());
    memcpy(iv.get(), cipher_text + cipher_text_len - BLOCK_SIZE, BLOCK_SIZE);

    if (1 != EVP_DecryptInit_ex(ctx.get(), cipher_mode, nullptr, key, iv.get()))
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
            return CIPHER_128_BLOCK(KEY_256, EVP_aes_256_ecb());
        case Cipher::AES_256_CBC:
            return CIPHER_128_BLOCK(KEY_256, EVP_aes_256_cbc());
        case Cipher::AES_256_CFB:
            return CIPHER_128_BLOCK(KEY_256, EVP_aes_256_cfb());
        case Cipher::AES_256_OFB:
            return CIPHER_128_BLOCK(KEY_256, EVP_aes_256_ofb());
        case Cipher::AES_256_CTR:
            return CIPHER_128_BLOCK(KEY_256, EVP_aes_256_ctr());
        case Cipher::AES_256_GCM:
            return CIPHER_AUTH(KEY_256, BLK_128, EVP_aes_256_gcm());
        case Cipher::AES_256_OCB:
            return CIPHER_AUTH(KEY_256, BLK_128, EVP_aes_256_ocb());
        case Cipher::AES_256_XTS:
            return CIPHER_128_BLOCK(KEY_512, EVP_aes_256_xts()); // XTS mode expects key doubled
        case Cipher::AES_256_CCM:
            return CIPHER_CCM(KEY_256, BLK_128, EVP_aes_256_ccm());
        case Cipher::AES_256_EAX:
        case Cipher::AES_256_SIV:
            throw UnsupportedCipherException();

        case Cipher::AES_192_ECB:
            return CIPHER_128_BLOCK(KEY_192, EVP_aes_192_ecb());
        case Cipher::AES_192_CBC:
            return CIPHER_128_BLOCK(KEY_192, EVP_aes_192_cbc());
        case Cipher::AES_192_CFB:
            return CIPHER_128_BLOCK(KEY_192, EVP_aes_192_cfb());
        case Cipher::AES_192_OFB:
            return CIPHER_128_BLOCK(KEY_192, EVP_aes_192_ofb());
        case Cipher::AES_192_CTR:
            return CIPHER_128_BLOCK(KEY_192, EVP_aes_192_ctr());
        case Cipher::AES_192_GCM:
            return CIPHER_AUTH(KEY_192, BLK_128, EVP_aes_192_gcm());
        case Cipher::AES_192_XTS:
            throw UnsupportedCipherException();
        case Cipher::AES_192_CCM:
            return CIPHER_CCM(KEY_192, BLK_128, EVP_aes_192_ccm());
        case Cipher::AES_192_EAX:
            throw UnsupportedCipherException();
        case Cipher::AES_192_OCB:
            return CIPHER_AUTH(KEY_192, BLK_128, EVP_aes_192_ocb());
        case Cipher::AES_192_SIV:
            throw UnsupportedCipherException();


        case Cipher::AES_128_ECB:
            return CIPHER_128_BLOCK(KEY_128, EVP_aes_128_ecb());
        case Cipher::AES_128_CBC:
            return CIPHER_128_BLOCK(KEY_128, EVP_aes_128_cbc());
        case Cipher::AES_128_CFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_aes_128_cfb());
        case Cipher::AES_128_OFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_aes_128_ofb());
        case Cipher::AES_128_CTR:
            return CIPHER_128_BLOCK(KEY_128, EVP_aes_128_ctr());
        case Cipher::AES_128_GCM:
            return CIPHER_AUTH(KEY_128, BLK_128, EVP_aes_128_gcm());
        case Cipher::AES_128_XTS:
            return CIPHER_128_BLOCK(KEY_256, EVP_aes_128_xts()); // XTS mode expects key doubled
        case Cipher::AES_128_CCM:
            return CIPHER_CCM(KEY_128, BLK_128, EVP_aes_128_ccm());
        case Cipher::AES_128_EAX:
            throw UnsupportedCipherException();
        case Cipher::AES_128_OCB:
            return CIPHER_AUTH(KEY_128, BLK_128, EVP_aes_128_ocb());
        case Cipher::AES_128_SIV:
            throw UnsupportedCipherException();


            //XTS & OCB not available for ARIA. CHECK OTHER LIBRARIES
        case Cipher::ARIA_256_ECB:
            return CIPHER_128_BLOCK(KEY_256, EVP_aria_256_ecb());
        case Cipher::ARIA_256_CBC:
            return CIPHER_128_BLOCK(KEY_256, EVP_aria_256_cbc());
        case Cipher::ARIA_256_CFB:
            return CIPHER_128_BLOCK(KEY_256, EVP_aria_256_cfb());
        case Cipher::ARIA_256_OFB:
            return CIPHER_128_BLOCK(KEY_256, EVP_aria_256_ofb());
        case Cipher::ARIA_256_CTR:
            return CIPHER_128_BLOCK(KEY_256, EVP_aria_256_ctr());
        case Cipher::ARIA_256_GCM:
            return CIPHER_AUTH(KEY_256, BLK_128, EVP_aria_256_gcm());
        case Cipher::ARIA_256_XTS:
            throw UnsupportedCipherException();
        case Cipher::ARIA_256_CCM:
            return CIPHER_CCM(KEY_256, BLK_128, EVP_aria_256_ccm());
        case Cipher::ARIA_256_EAX:
            throw UnsupportedCipherException();
        case Cipher::ARIA_256_OCB:
            throw UnsupportedCipherException();
        case Cipher::ARIA_256_SIV:
            throw UnsupportedCipherException();

        case Cipher::ARIA_192_ECB:
            return CIPHER_128_BLOCK(KEY_192, EVP_aria_192_ecb());
        case Cipher::ARIA_192_CBC:
            return CIPHER_128_BLOCK(KEY_192, EVP_aria_192_cbc());
        case Cipher::ARIA_192_CFB:
            return CIPHER_128_BLOCK(KEY_192, EVP_aria_192_cfb());
        case Cipher::ARIA_192_OFB:
            return CIPHER_128_BLOCK(KEY_192, EVP_aria_192_ofb());
        case Cipher::ARIA_192_CTR:
            return CIPHER_128_BLOCK(KEY_192, EVP_aria_192_ctr());
        case Cipher::ARIA_192_GCM:
            return CIPHER_AUTH(KEY_192, BLK_128, EVP_aria_192_gcm());
        case Cipher::ARIA_192_XTS:
            throw UnsupportedCipherException();
        case Cipher::ARIA_192_CCM:
            return CIPHER_AUTH(KEY_192, BLK_128, EVP_aria_192_ccm());
        case Cipher::ARIA_192_EAX:
            throw UnsupportedCipherException();
        case Cipher::ARIA_192_OCB:
            throw UnsupportedCipherException();
        case Cipher::ARIA_192_SIV:
            throw UnsupportedCipherException();

        case Cipher::ARIA_128_ECB:
            return CIPHER_128_BLOCK(KEY_128, EVP_aria_128_ecb());
        case Cipher::ARIA_128_CBC:
            return CIPHER_128_BLOCK(KEY_128, EVP_aria_128_cbc());
        case Cipher::ARIA_128_CFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_aria_128_cfb());
        case Cipher::ARIA_128_OFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_aria_128_ofb());
        case Cipher::ARIA_128_CTR:
            return CIPHER_128_BLOCK(KEY_128, EVP_aria_128_ctr());
        case Cipher::ARIA_128_GCM:
            return CIPHER_AUTH(KEY_128, BLK_128, EVP_aria_128_gcm());
        case Cipher::ARIA_128_XTS:
            throw UnsupportedCipherException();
        case Cipher::ARIA_128_CCM:
            return CIPHER_AUTH(KEY_128, BLK_128, EVP_aria_128_ccm());
        case Cipher::ARIA_128_EAX:
            throw UnsupportedCipherException();
        case Cipher::ARIA_128_OCB:
            throw UnsupportedCipherException();
        case Cipher::ARIA_128_SIV:
            throw UnsupportedCipherException();


        case Cipher::SM4_ECB:
            return CIPHER_128_BLOCK(KEY_128, EVP_sm4_ecb());
        case Cipher::SM4_CBC:
            return CIPHER_128_BLOCK(KEY_128, EVP_sm4_cbc());
        case Cipher::SM4_CFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_sm4_cfb());
        case Cipher::SM4_OFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_sm4_ofb());
        case Cipher::SM4_CTR:
            return CIPHER_128_BLOCK(KEY_128, EVP_sm4_ctr());
        case Cipher::SM4_GCM:
            throw UnsupportedCipherException();
        case Cipher::SM4_XTS:
            throw UnsupportedCipherException();
        case Cipher::SM4_CCM:
            throw UnsupportedCipherException();
        case Cipher::SM4_EAX:
            throw UnsupportedCipherException();
        case Cipher::SM4_OCB:
            throw UnsupportedCipherException();
        case Cipher::SM4_SIV:
            throw UnsupportedCipherException();


        case Cipher::SEED_ECB:
            return CIPHER_128_BLOCK(KEY_128, EVP_seed_ecb());
        case Cipher::SEED_CBC:
            return CIPHER_128_BLOCK(KEY_128, EVP_seed_cbc());
        case Cipher::SEED_CFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_seed_cfb());
        case Cipher::SEED_OFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_seed_ofb());
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
            return CIPHER(KEY_448, BLK_64, EVP_bf_ecb());
        case Cipher::BLOWFISH_CBC:
            return CIPHER(KEY_448, BLK_64, EVP_bf_cbc());
        case Cipher::BLOWFISH_CFB:
            return CIPHER(KEY_448, BLK_64, EVP_bf_cfb());
        case Cipher::BLOWFISH_OFB:
            return CIPHER(KEY_448, BLK_64, EVP_bf_ofb());
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

        default:
            return nullptr;
    }
}