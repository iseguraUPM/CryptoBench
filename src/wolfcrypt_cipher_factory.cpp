//
// Created by ISU on 08/03/2020.
//

#include "CryptoBench/wolfcrypt_cipher_factory.hpp"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/camellia.h>
#include <wolfssl/wolfcrypt/des3.h>

#include <CryptoBench/random_bytes.hpp>
#include <CryptoBench/cipher_exception.hpp>


#define KEY_512 64
#define KEY_448 56
#define KEY_256 32
#define KEY_192 24
#define KEY_128 16

#define BLK_128 16
#define BLK_64 8

#define IV_128 16
#define IV_96 12

#define TAG_128 16

#define CIPHER(key_len, block_len, iv_len, algo_t, enc_dir, dec_dir, set_key_func, enc_func, dec_func)(CipherPtr(\
    new WolfcryptCipher<key_len, block_len, iv_len, algo_t> \
        (set_key_func, enc_func, dec_func, enc_dir, dec_dir, true)))

#define CIPHER_CTR(key_len, block_len, iv_len, algo_t, enc_dir, dec_dir, set_key_func, enc_func, dec_func)(CipherPtr(\
    new WolfcryptCipher<key_len, block_len, iv_len, algo_t> \
        (set_key_func, enc_func, dec_func, enc_dir, dec_dir, false)))

#define CIPHER_AUTH(key_len, block_len, iv_len, tag_len, algo_t, enc_dir, dec_dir, set_key_func, enc_func, dec_func)(CipherPtr(\
    new WolfcryptAuthCipher<key_len, block_len, iv_len, tag_len, algo_t> \
        (set_key_func, enc_func, dec_func, enc_dir, dec_dir)))

template <int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, typename ALGO>
class WolfcryptCipher : public SymmetricCipher
{
public:
    using set_key_func = int (&)(ALGO*, const byte*, word32, const byte*, int);
    using cipher_func = int (&)(ALGO*, byte *, const byte *, word32);

    explicit inline WolfcryptCipher(set_key_func &set_key, cipher_func &enc, cipher_func &dec, int encrypt_dir, int decrypt_dir, bool padded)
            : set_key(set_key), enc(enc), dec(dec)
            , encrypt_dir(encrypt_dir), decrypt_dir(decrypt_dir), random_bytes(), padded(padded) {};

    void encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
                         , byte * cipher_text, byte_len & cipher_text_len) override;

    void decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
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

    set_key_func &set_key;
    cipher_func &enc;
    cipher_func &dec;
    const int encrypt_dir;
    const int decrypt_dir;
    bool padded;
};

template <int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, int TAG_SIZE, typename ALGO>
class WolfcryptAuthCipher : public SymmetricCipher
{
public:
    using set_key_func = int (&)(ALGO*, const byte*, word32);
    using cipher_enc_func = int (&)(ALGO*, byte*, const byte*, word32,
            const byte*, word32, byte*, word32, const byte*, word32);
    using cipher_dec_func = int (&)(ALGO*, byte*, const byte*, word32,
            const byte*, word32, const byte*, word32, const byte*, word32);

    explicit inline WolfcryptAuthCipher(set_key_func &set_key, cipher_enc_func &enc, cipher_dec_func &dec
                                        , int encrypt_dir, int decrypt_dir)
            : set_key(set_key), enc(enc), dec(dec)
            , encrypt_dir(encrypt_dir), decrypt_dir(decrypt_dir), random_bytes() {};

    void encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
                 , byte * cipher_text, byte_len & cipher_text_len) override;

    void decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
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

    set_key_func &set_key;
    cipher_enc_func &enc;
    cipher_dec_func &dec;
    const int encrypt_dir;
    const int decrypt_dir;
};

template <int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, int TAG_SIZE, typename ALGO>
void WolfcryptAuthCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE, TAG_SIZE, ALGO>::encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
                                                              , byte * cipher_text, byte_len & cipher_text_len)
{
    auto iv = std::shared_ptr<byte>(new byte[IV_SIZE], std::default_delete<byte[]>());
    random_bytes.generateRandomBytes(iv.get(), IV_SIZE);

    ALGO algo;
    if (0 != set_key(&algo, key, KEY_SIZE))
        throw WolfCryptException("Encrypt set key failure");


    auto tag = std::shared_ptr<byte>(new byte[TAG_SIZE], std::default_delete<byte[]>());
    if (0 != enc(&algo, cipher_text, plain_text, plain_text_len, iv.get()
                 , IV_SIZE, tag.get(), TAG_SIZE, nullptr, 0))
        throw WolfCryptException("Encrypt failure");

    cipher_text_len = plain_text_len;
    memcpy(cipher_text + cipher_text_len, tag.get(), TAG_SIZE);
    cipher_text_len += TAG_SIZE;
    memcpy(cipher_text + cipher_text_len, iv.get(), IV_SIZE);
    cipher_text_len += IV_SIZE;
}

template <int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, int TAG_SIZE, typename ALGO>
void WolfcryptAuthCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE, TAG_SIZE, ALGO>::decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                                                              , byte * recovered_text, byte_len & recovered_text_len)
{
    auto tag = std::shared_ptr<byte>(new byte[TAG_SIZE], std::default_delete<byte[]>());
    memcpy(tag.get(), cipher_text + cipher_text_len - TAG_SIZE - IV_SIZE, TAG_SIZE);
    auto iv = std::shared_ptr<byte>(new byte[IV_SIZE], std::default_delete<byte[]>());
    memcpy(iv.get(), cipher_text + cipher_text_len - IV_SIZE, IV_SIZE);

    ALGO algo;
    if (0 != set_key(&algo, key, KEY_SIZE))
        throw WolfCryptException("Encrypt set key failure");

    if (0 != dec(&algo, recovered_text, cipher_text, cipher_text_len - IV_SIZE - TAG_SIZE, iv.get()
                 , IV_SIZE, tag.get(), TAG_SIZE, nullptr, 0))
        throw WolfCryptException("Encrypt failure");

    recovered_text_len = cipher_text_len;
}

template <int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, typename ALGO>
void WolfcryptCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE, ALGO>::encrypt(const byte key[KEY_SIZE],  const byte * plain_text, byte_len plain_text_len
                                                          , byte * cipher_text, byte_len & cipher_text_len)
{
    if (plain_text_len % BLOCK_SIZE != 0 && padded)
        throw PaddingException();

    auto iv = std::shared_ptr<byte>(new byte[BLOCK_SIZE], std::default_delete<byte[]>());
    random_bytes.generateRandomBytes(iv.get(), BLOCK_SIZE);

    ALGO algo;
    if (0 != set_key(&algo, key, KEY_SIZE, iv.get(), encrypt_dir))
        throw WolfCryptException("Encrypt set key failure");

    if (0 != enc(&algo, cipher_text, plain_text, plain_text_len))
        throw WolfCryptException("Encrypt failure");

    cipher_text_len = plain_text_len;
    memcpy(cipher_text + cipher_text_len, iv.get(), BLOCK_SIZE);
    cipher_text_len += BLOCK_SIZE;
}

template <int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, typename ALGO>
void WolfcryptCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE, ALGO>::decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                                                          , byte * recovered_text, byte_len & recovered_text_len)
{
    auto iv = std::shared_ptr<byte>(new byte[BLOCK_SIZE], std::default_delete<byte[]>());
    memcpy(iv.get(), cipher_text + cipher_text_len - BLOCK_SIZE, BLOCK_SIZE);

    ALGO algo;
    if (0 != set_key(&algo, key, KEY_SIZE, iv.get(), decrypt_dir))
        throw WolfCryptException("Decrypt set key failure");

    if (0 != dec(&algo, recovered_text, cipher_text, cipher_text_len - BLOCK_SIZE))
        throw WolfCryptException("Decrypt failure");

    recovered_text_len = cipher_text_len;
}

CipherPtr WolfCryptCipherFactory::getCipher(Cipher cipher)
{
    switch (cipher) {
        case Cipher::AES_256_ECB:
            throw UnsupportedCipherException();
        case Cipher::AES_256_CBC:
            throw UnsupportedCipherException();
            //return CIPHER(KEY_256, BLK_128, IV_128, ::Aes, AES_ENCRYPTION, AES_DECRYPTION, wc_AesSetKey, wc_AesCbcEncrypt, wc_AesCbcDecrypt);
        case Cipher::AES_256_CFB:
        case Cipher::AES_256_OFB:
            throw UnsupportedCipherException();
        case Cipher::AES_256_CTR:
            return CIPHER_CTR(KEY_256, BLK_128, IV_128, ::Aes, AES_ENCRYPTION, AES_ENCRYPTION, wc_AesSetKey, wc_AesCtrEncrypt, wc_AesCtrEncrypt);
        case Cipher::AES_256_GCM:
            return CIPHER_AUTH(KEY_256, BLK_128, IV_96, TAG_128, ::Aes, AES_ENCRYPTION, AES_DECRYPTION, wc_AesGcmSetKey, wc_AesGcmEncrypt, wc_AesGcmDecrypt);
        case Cipher::AES_256_XTS:
            throw UnsupportedCipherException();
        case Cipher::AES_256_CCM:
            return CIPHER_AUTH(KEY_256, BLK_128, IV_96, TAG_128, ::Aes, AES_ENCRYPTION, AES_DECRYPTION, wc_AesCcmSetKey, wc_AesCcmEncrypt, wc_AesCcmDecrypt);
        case Cipher::AES_256_EAX:
        case Cipher::AES_256_OCB:
        case Cipher::AES_256_SIV:

        case Cipher::AES_192_ECB:
            throw UnsupportedCipherException();
        case Cipher::AES_192_CBC:
            throw UnsupportedCipherException();
            //return CIPHER(KEY_192, BLK_128, IV_128, ::Aes, AES_ENCRYPTION, AES_DECRYPTION, wc_AesSetKey, wc_AesCbcEncrypt, wc_AesCbcDecrypt);
        case Cipher::AES_192_CFB:
        case Cipher::AES_192_OFB:
            throw UnsupportedCipherException();
        case Cipher::AES_192_CTR:
            return CIPHER_CTR(KEY_192, BLK_128, IV_128, ::Aes, AES_ENCRYPTION, AES_ENCRYPTION, wc_AesSetKey, wc_AesCtrEncrypt, wc_AesCtrEncrypt);
        case Cipher::AES_192_GCM:
            return CIPHER_AUTH(KEY_192, BLK_128, IV_96, TAG_128, ::Aes, AES_ENCRYPTION, AES_DECRYPTION, wc_AesGcmSetKey, wc_AesGcmEncrypt, wc_AesGcmDecrypt);
        case Cipher::AES_192_XTS:
            throw UnsupportedCipherException();
        case Cipher::AES_192_CCM:
            return CIPHER_AUTH(KEY_192, BLK_128, IV_96, TAG_128, ::Aes, AES_ENCRYPTION, AES_DECRYPTION, wc_AesCcmSetKey, wc_AesCcmEncrypt, wc_AesCcmDecrypt);
        case Cipher::AES_192_EAX:
        case Cipher::AES_192_OCB:
        case Cipher::AES_192_SIV:

        case Cipher::AES_128_ECB:
            throw UnsupportedCipherException();
        case Cipher::AES_128_CBC:
            throw UnsupportedCipherException();
            //return CIPHER(KEY_128, BLK_128, IV_128, ::Aes, AES_ENCRYPTION, AES_DECRYPTION, wc_AesSetKey, wc_AesCbcEncrypt, wc_AesCbcDecrypt);
        case Cipher::AES_128_CFB:
        case Cipher::AES_128_OFB:
            throw UnsupportedCipherException();
        case Cipher::AES_128_CTR:
            return CIPHER_CTR(KEY_128, BLK_128, IV_128, ::Aes, AES_ENCRYPTION, AES_ENCRYPTION, wc_AesSetKey, wc_AesCtrEncrypt, wc_AesCtrEncrypt);
        case Cipher::AES_128_GCM:
            return CIPHER_AUTH(KEY_128, BLK_128, IV_96, TAG_128, ::Aes, AES_ENCRYPTION, AES_DECRYPTION, wc_AesGcmSetKey, wc_AesGcmEncrypt, wc_AesGcmDecrypt);
        case Cipher::AES_128_XTS:
            throw UnsupportedCipherException();
        case Cipher::AES_128_CCM:
            return CIPHER_AUTH(KEY_128, BLK_128, IV_96, TAG_128,  ::Aes, AES_ENCRYPTION, AES_DECRYPTION, wc_AesCcmSetKey, wc_AesCcmEncrypt, wc_AesCcmDecrypt);
        case Cipher::AES_128_EAX:
        case Cipher::AES_128_OCB:
        case Cipher::AES_128_SIV:

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

        case Cipher::SEED_ECB:
        case Cipher::SEED_CBC:
        case Cipher::SEED_CFB:
        case Cipher::SEED_OFB:
        case Cipher::SEED_CTR:
        case Cipher::SEED_GCM:
        case Cipher::SEED_XTS:
        case Cipher::SEED_CCM:
        case Cipher::SEED_EAX:
        case Cipher::SEED_OCB:
        case Cipher::SEED_SIV:

        case Cipher::BLOWFISH_ECB:
        case Cipher::BLOWFISH_CBC:
        case Cipher::BLOWFISH_CFB:
        case Cipher::BLOWFISH_OFB:
        case Cipher::BLOWFISH_CTR:
        case Cipher::BLOWFISH_GCM:
        case Cipher::BLOWFISH_XTS:
        case Cipher::BLOWFISH_CCM:
        case Cipher::BLOWFISH_EAX:
        case Cipher::BLOWFISH_OCB:
        case Cipher::BLOWFISH_SIV:

        case Cipher::BLOWFISH_256_ECB:
        case Cipher::BLOWFISH_256_CBC:
        case Cipher::BLOWFISH_256_CFB:
        case Cipher::BLOWFISH_256_OFB:
        case Cipher::BLOWFISH_256_CTR:
        case Cipher::BLOWFISH_256_GCM:
        case Cipher::BLOWFISH_256_XTS:
        case Cipher::BLOWFISH_256_CCM:
        case Cipher::BLOWFISH_256_EAX:
        case Cipher::BLOWFISH_256_OCB:
        case Cipher::BLOWFISH_256_SIV:

        case Cipher::BLOWFISH_192_ECB:
        case Cipher::BLOWFISH_192_CBC:
        case Cipher::BLOWFISH_192_CFB:
        case Cipher::BLOWFISH_192_OFB:
        case Cipher::BLOWFISH_192_CTR:
        case Cipher::BLOWFISH_192_GCM:
        case Cipher::BLOWFISH_192_XTS:
        case Cipher::BLOWFISH_192_CCM:
        case Cipher::BLOWFISH_192_EAX:
        case Cipher::BLOWFISH_192_OCB:
        case Cipher::BLOWFISH_192_SIV:

        case Cipher::BLOWFISH_128_ECB:
        case Cipher::BLOWFISH_128_CBC:
        case Cipher::BLOWFISH_128_CFB:
        case Cipher::BLOWFISH_128_OFB:
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
