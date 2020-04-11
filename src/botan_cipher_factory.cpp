//
// Created by Juan Pablo Melgarejo on 3/30/20.
//

#include <CryptoBench/cipher_exception.hpp>
#include "CryptoBench/botan_cipher_factory.hpp"


#define KEY_128 16
#define KEY_192 24
#define KEY_256 32
#define KEY_384 48
#define KEY_448 56
#define KEY_512 64

#define BOTAN_CIPHER(key_len, block_len, iv_len, cipher) (CipherPtr(new BotanCipher<key_len, block_len, iv_len>(cipher)))

template <int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE>
class BotanCipher : public SymmetricCipher
{
public:
    const char * cipherDescription;

    explicit BotanCipher(const char* cipherInfo);

    virtual void encrypt(const byte key[KEY_SIZE], const byte * plain_text, byte_len plain_text_len
                         , byte * cipher_text, byte_len & cipher_text_len) override;

    virtual void decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                         , byte * recovered_text, byte_len & recovered_text_len) override;

    int getBlockLen() override;

    int getKeyLen() override;

protected:
    RandomBytes random_bytes;

};

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE>
BotanCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>::BotanCipher(const char *cipherDescription)
{
    this->cipherDescription = cipherDescription;
    random_bytes = RandomBytes();
}


template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE>
int BotanCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>::getBlockLen()
{
    return BLOCK_SIZE;
}

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE>
int BotanCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>::getKeyLen()
{
    return KEY_SIZE;
}



template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE>
void BotanCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>::decrypt(const byte key[KEY_SIZE], const byte *cipher_text, byte_len cipher_text_len
                                                         , byte *recovered_text, byte_len &recovered_text_len)
{
    try{
        auto iv = std::shared_ptr<byte>(new byte[IV_SIZE], std::default_delete<byte[]>());
        memcpy(iv.get(), cipher_text + cipher_text_len - IV_SIZE, IV_SIZE);
        cipher_text_len -= IV_SIZE;

        std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create(cipherDescription, Botan::DECRYPTION);
        dec->set_key(key, KEY_SIZE);
        dec->start(iv.get(), IV_SIZE);

        Botan::secure_vector<uint8_t> ct((const char *)&cipher_text[0], (const char *)&cipher_text[0] + cipher_text_len);

        dec->finish(ct);

        memcpy(recovered_text, ct.data(), ct.size());
        recovered_text_len = ct.size();
    }catch(Botan::Exception ex){
        throw BotanException(ex.what());
    }
}

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE>
void BotanCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>::encrypt(const byte key[KEY_SIZE], const byte *plain_text, byte_len plain_text_len
                                                         , byte * cipher_text, byte_len &cipher_text_len)
{
    try{
        auto iv = std::shared_ptr<byte>(new byte[IV_SIZE], std::default_delete<byte[]>());
        random_bytes.generateRandomBytes(iv.get(), IV_SIZE);

        std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create(cipherDescription, Botan::ENCRYPTION);
        enc->set_key(key, KEY_SIZE);
        enc->start(iv.get(), IV_SIZE);

        // Copy input data to a buffer that will be encrypted
        Botan::secure_vector<uint8_t> pt((const char *)&plain_text[0], (const char *)&plain_text[0] + plain_text_len);
        enc->finish(pt);

        memcpy(cipher_text, pt.data(), pt.size());
        cipher_text_len = pt.size();

        memcpy(cipher_text + cipher_text_len, iv.get(), IV_SIZE);
        cipher_text_len += IV_SIZE;
    }catch(Botan::Exception ex){
        throw BotanException(ex.what());
    }
}


CipherPtr BotanCipherFactory::getCipher(Cipher cipher)
{
    switch(cipher)
    {
        case Cipher::AES_256_ECB:
            throw UnsupportedCipherException();
        case Cipher::AES_256_CBC:
            return BOTAN_CIPHER(KEY_256, 16,16, "AES-256/CBC");
        case Cipher::AES_256_CFB:
            return BOTAN_CIPHER(KEY_256, 16,16, "AES-256/CFB");
        case Cipher::AES_256_OFB:
            return BOTAN_CIPHER(KEY_256, 16,16, "AES-256/OFB");
        case Cipher::AES_256_CTR:
            return BOTAN_CIPHER(KEY_256, 16,16, "AES-256/CTR");
        case Cipher::AES_256_GCM:
            return BOTAN_CIPHER(KEY_256, 16,16, "AES-256/GCM");
        case Cipher::AES_256_XTS:
            return BOTAN_CIPHER(KEY_512, 16,16, "AES-256/XTS");
        case Cipher::AES_256_CCM:
            return BOTAN_CIPHER(KEY_256, 16,12, "AES-256/CCM");
        case Cipher::AES_256_EAX:
            return BOTAN_CIPHER(KEY_256, 16,16, "AES-256/EAX");
        case Cipher::AES_256_OCB:
            return BOTAN_CIPHER(KEY_256, 16,12, "AES-256/OCB");
        case Cipher::AES_256_SIV:
            return BOTAN_CIPHER(KEY_512, 16,16, "AES-256/SIV");

        case Cipher::AES_192_ECB:
            throw UnsupportedCipherException();
        case Cipher::AES_192_CBC:
            return BOTAN_CIPHER(KEY_192, 16,16, "AES-192/CBC");
        case Cipher::AES_192_CFB:
            return BOTAN_CIPHER(KEY_192, 16,16, "AES-192/CFB");
        case Cipher::AES_192_OFB:
            return BOTAN_CIPHER(KEY_192, 16,16, "AES-192/OFB");
        case Cipher::AES_192_CTR:
            return BOTAN_CIPHER(KEY_192, 16,16, "AES-192/CTR");
        case Cipher::AES_192_GCM:
            return BOTAN_CIPHER(KEY_192, 16,16, "AES-192/GCM");
        case Cipher::AES_192_XTS:
            return BOTAN_CIPHER(KEY_384, 16,16, "AES-192/XTS");
        case Cipher::AES_192_CCM:
            return BOTAN_CIPHER(KEY_192, 16,12, "AES-192/CCM");
        case Cipher::AES_192_EAX:
            return BOTAN_CIPHER(KEY_192, 16,16, "AES-192/EAX");
        case Cipher::AES_192_OCB:
            return BOTAN_CIPHER(KEY_192, 16,12, "AES-192/OCB");
        case Cipher::AES_192_SIV:
            return BOTAN_CIPHER(KEY_384, 16,16, "AES-192/SIV");

        case Cipher::AES_128_ECB:
            throw UnsupportedCipherException();
        case Cipher::AES_128_CBC:
            return BOTAN_CIPHER(KEY_128, 16,16, "AES-128/CBC");
        case Cipher::AES_128_CFB:
            return BOTAN_CIPHER(KEY_128, 16,16, "AES-128/CFB");
        case Cipher::AES_128_OFB:
            return BOTAN_CIPHER(KEY_128, 16,16, "AES-128/OFB");
        case Cipher::AES_128_CTR:
            return BOTAN_CIPHER(KEY_128, 16,16, "AES-128/CTR");
        case Cipher::AES_128_GCM:
            return BOTAN_CIPHER(KEY_128, 16,16, "AES-128/GCM");
        case Cipher::AES_128_XTS:
            return BOTAN_CIPHER(KEY_256, 16,16, "AES-128/XTS");
        case Cipher::AES_128_CCM:
            return BOTAN_CIPHER(KEY_128, 16,12, "AES-128/CCM");
        case Cipher::AES_128_EAX:
            return BOTAN_CIPHER(KEY_128, 16,16, "AES-128/EAX");
        case Cipher::AES_128_OCB:
            return BOTAN_CIPHER(KEY_128, 16,12, "AES-128/OCB");
        case Cipher::AES_128_SIV:
            return BOTAN_CIPHER(KEY_256, 16,16, "AES-128/SIV");

        case Cipher::ARIA_256_ECB:
            throw UnsupportedCipherException();
        case Cipher::ARIA_256_CBC:
            return BOTAN_CIPHER(KEY_256, 16,16, "ARIA-256/CBC");
        case Cipher::ARIA_256_CFB:
            return BOTAN_CIPHER(KEY_256, 16,16, "ARIA-256/CFB");
        case Cipher::ARIA_256_OFB:
            return BOTAN_CIPHER(KEY_256, 16,16, "ARIA-256/OFB");
        case Cipher::ARIA_256_CTR:
            return BOTAN_CIPHER(KEY_256, 16,16, "ARIA-256/CTR");
        case Cipher::ARIA_256_GCM:
            return BOTAN_CIPHER(KEY_256, 16,16, "ARIA-256/GCM");
        case Cipher::ARIA_256_XTS:
            return BOTAN_CIPHER(KEY_512, 16,16, "ARIA-256/XTS");
        case Cipher::ARIA_256_CCM:
            return BOTAN_CIPHER(KEY_256, 16,12, "ARIA-256/CCM");
        case Cipher::ARIA_256_EAX:
            return BOTAN_CIPHER(KEY_256, 16,16, "ARIA-256/EAX");
        case Cipher::ARIA_256_OCB:
            return BOTAN_CIPHER(KEY_256, 16,12, "ARIA-256/OCB");
        case Cipher::ARIA_256_SIV:
            return BOTAN_CIPHER(KEY_512, 16,16, "ARIA-256/SIV");

        case Cipher::ARIA_192_ECB:
            throw UnsupportedCipherException();
        case Cipher::ARIA_192_CBC:
            return BOTAN_CIPHER(KEY_192, 16,16, "ARIA-192/CBC");
        case Cipher::ARIA_192_CFB:
            return BOTAN_CIPHER(KEY_192, 16,16, "ARIA-192/CFB");
        case Cipher::ARIA_192_OFB:
            return BOTAN_CIPHER(KEY_192, 16,16, "ARIA-192/OFB");
        case Cipher::ARIA_192_CTR:
            return BOTAN_CIPHER(KEY_192, 16,16, "ARIA-192/CTR");
        case Cipher::ARIA_192_GCM:
            return BOTAN_CIPHER(KEY_192, 16,16, "ARIA-192/GCM");
        case Cipher::ARIA_192_XTS:
            return BOTAN_CIPHER(KEY_384, 16,16, "ARIA-192/XTS");
        case Cipher::ARIA_192_CCM:
            return BOTAN_CIPHER(KEY_192, 16,12, "ARIA-192/CCM");
        case Cipher::ARIA_192_EAX:
            return BOTAN_CIPHER(KEY_192, 16,16, "ARIA-192/EAX");
        case Cipher::ARIA_192_OCB:
            return BOTAN_CIPHER(KEY_192, 16,12, "ARIA-192/OCB");
        case Cipher::ARIA_192_SIV:
            return BOTAN_CIPHER(KEY_384, 16,16, "ARIA-192/SIV");

        case Cipher::ARIA_128_ECB:
            throw UnsupportedCipherException();
        case Cipher::ARIA_128_CBC:
            return BOTAN_CIPHER(KEY_128, 16,16, "ARIA-128/CBC");
        case Cipher::ARIA_128_CFB:
            return BOTAN_CIPHER(KEY_128, 16,16, "ARIA-128/CFB");
        case Cipher::ARIA_128_OFB:
            return BOTAN_CIPHER(KEY_128, 16,16, "ARIA-128/OFB");
        case Cipher::ARIA_128_CTR:
            return BOTAN_CIPHER(KEY_128, 16,16, "ARIA-128/CTR");
        case Cipher::ARIA_128_GCM:
            return BOTAN_CIPHER(KEY_128, 16,16, "ARIA-128/GCM");
        case Cipher::ARIA_128_XTS:
            return BOTAN_CIPHER(KEY_256, 16,16, "ARIA-128/XTS");
        case Cipher::ARIA_128_CCM:
            return BOTAN_CIPHER(KEY_128, 16,12, "ARIA-128/CCM");
        case Cipher::ARIA_128_EAX:
            return BOTAN_CIPHER(KEY_128, 16,16, "ARIA-128/EAX");
        case Cipher::ARIA_128_OCB:
            return BOTAN_CIPHER(KEY_128, 16,12, "ARIA-128/OCB");
        case Cipher::ARIA_128_SIV:
            return BOTAN_CIPHER(KEY_256, 16,16, "ARIA-128/SIV");

        case Cipher::CAMELLIA_256_ECB:
            throw UnsupportedCipherException();
        case Cipher::CAMELLIA_256_CBC:
            return BOTAN_CIPHER(KEY_256, 16,16, "Camellia-256/CBC");
        case Cipher::CAMELLIA_256_CFB:
            return BOTAN_CIPHER(KEY_256, 16,16, "Camellia-256/CFB");
        case Cipher::CAMELLIA_256_OFB:
            return BOTAN_CIPHER(KEY_256, 16,16, "Camellia-256/OFB");
        case Cipher::CAMELLIA_256_CTR:
            return BOTAN_CIPHER(KEY_256, 16,16, "Camellia-256/CTR");
        case Cipher::CAMELLIA_256_GCM:
            return BOTAN_CIPHER(KEY_256, 16,16, "Camellia-256/GCM");
        case Cipher::CAMELLIA_256_XTS:
            return BOTAN_CIPHER(KEY_512, 16,16, "Camellia-256/XTS");
        case Cipher::CAMELLIA_256_CCM:
            return BOTAN_CIPHER(KEY_256, 16,12, "Camellia-256/CCM");
        case Cipher::CAMELLIA_256_EAX:
            return BOTAN_CIPHER(KEY_256, 16,16, "Camellia-256/EAX");
        case Cipher::CAMELLIA_256_OCB:
            return BOTAN_CIPHER(KEY_256, 16,12, "Camellia-256/OCB");
        case Cipher::CAMELLIA_256_SIV:
            return BOTAN_CIPHER(KEY_512, 16, 16, "Camellia-256/SIV");

        case Cipher::CAMELLIA_192_ECB:
            throw UnsupportedCipherException();
        case Cipher::CAMELLIA_192_CBC:
            return BOTAN_CIPHER(KEY_192, 16,16, "Camellia-192/CBC");
        case Cipher::CAMELLIA_192_CFB:
            return BOTAN_CIPHER(KEY_192, 16,16, "Camellia-192/CFB");
        case Cipher::CAMELLIA_192_OFB:
            return BOTAN_CIPHER(KEY_192, 16,16, "Camellia-192/OFB");
        case Cipher::CAMELLIA_192_CTR:
            return BOTAN_CIPHER(KEY_192, 16,16, "Camellia-192/CTR");
        case Cipher::CAMELLIA_192_GCM:
            return BOTAN_CIPHER(KEY_192, 16,16, "Camellia-192/GCM");
        case Cipher::CAMELLIA_192_XTS:
            return BOTAN_CIPHER(KEY_384, 16,16, "Camellia-192/XTS");
        case Cipher::CAMELLIA_192_CCM:
            return BOTAN_CIPHER(KEY_192, 16,12, "Camellia-192/CCM");
        case Cipher::CAMELLIA_192_EAX:
            return BOTAN_CIPHER(KEY_192, 16,16, "Camellia-192/EAX");
        case Cipher::CAMELLIA_192_OCB:
            return BOTAN_CIPHER(KEY_192, 16,12, "Camellia-192/OCB");
        case Cipher::CAMELLIA_192_SIV:
            return BOTAN_CIPHER(KEY_384, 16,16, "Camellia-192/SIV");

        case Cipher::CAMELLIA_128_ECB:
            throw UnsupportedCipherException();
        case Cipher::CAMELLIA_128_CBC:
            return BOTAN_CIPHER(KEY_128, 16,16, "Camellia-128/CBC");
        case Cipher::CAMELLIA_128_CFB:
            return BOTAN_CIPHER(KEY_128, 16,16, "Camellia-128/CFB");
        case Cipher::CAMELLIA_128_OFB:
            return BOTAN_CIPHER(KEY_128, 16,16, "Camellia-128/OFB");
        case Cipher::CAMELLIA_128_CTR:
            return BOTAN_CIPHER(KEY_128, 16,16, "Camellia-128/CTR");
        case Cipher::CAMELLIA_128_GCM:
            return BOTAN_CIPHER(KEY_128, 16,16, "Camellia-128/GCM");
        case Cipher::CAMELLIA_128_XTS:
            return BOTAN_CIPHER(KEY_256, 16,16, "Camellia-128/XTS");
        case Cipher::CAMELLIA_128_CCM:
            return BOTAN_CIPHER(KEY_128, 16,12, "Camellia-128/CCM");
        case Cipher::CAMELLIA_128_EAX:
            return BOTAN_CIPHER(KEY_128, 16,16, "Camellia-128/EAX");
        case Cipher::CAMELLIA_128_OCB:
            return BOTAN_CIPHER(KEY_128, 16,12, "Camellia-128/OCB");
        case Cipher::CAMELLIA_128_SIV:
            return BOTAN_CIPHER(KEY_256, 16,16, "Camellia-128/SIV");

        case Cipher::SM4_ECB:
            throw UnsupportedCipherException();
        case Cipher::SM4_CBC:
            return BOTAN_CIPHER(KEY_128, 16,16, "SM4/CBC");
        case Cipher::SM4_CFB:
            return BOTAN_CIPHER(KEY_128, 16,16, "SM4/CFB");
        case Cipher::SM4_OFB:
            return BOTAN_CIPHER(KEY_128, 16,16, "SM4/OFB");
        case Cipher::SM4_CTR:
            return BOTAN_CIPHER(KEY_128, 16,16, "SM4/CTR");
        case Cipher::SM4_GCM:
            return BOTAN_CIPHER(KEY_128, 16,16, "SM4/GCM");
        case Cipher::SM4_XTS:
            return BOTAN_CIPHER(KEY_256, 16,16, "SM4/XTS");
        case Cipher::SM4_CCM:
            return BOTAN_CIPHER(KEY_128, 16,12, "SM4/CCM");
        case Cipher::SM4_EAX:
            return BOTAN_CIPHER(KEY_128, 16,16, "SM4/EAX");
        case Cipher::SM4_OCB:
            return BOTAN_CIPHER(KEY_128, 16,12, "SM4/OCB");
        case Cipher::SM4_SIV:
            return BOTAN_CIPHER(KEY_256, 16,16, "SM4/SIV");


        case Cipher::SEED_ECB:
            throw UnsupportedCipherException();
        case Cipher::SEED_CBC:
            return BOTAN_CIPHER(KEY_128, 16,16, "SEED/CBC");
        case Cipher::SEED_CFB:
            return BOTAN_CIPHER(KEY_128, 16,16, "SEED/CFB");
        case Cipher::SEED_OFB:
            return BOTAN_CIPHER(KEY_128, 16,16, "SEED/OFB");
        case Cipher::SEED_CTR:
            return BOTAN_CIPHER(KEY_128, 16,16, "SEED/CTR");
        case Cipher::SEED_GCM:
            return BOTAN_CIPHER(KEY_128, 16,16, "SEED/GCM");
        case Cipher::SEED_XTS:
            return BOTAN_CIPHER(KEY_256, 16,16, "SEED/XTS");
        case Cipher::SEED_CCM:
            return BOTAN_CIPHER(KEY_128, 16,12, "SEED/CCM");
        case Cipher::SEED_EAX:
            return BOTAN_CIPHER(KEY_128, 16,16, "SEED/EAX");
        case Cipher::SEED_OCB:
            return BOTAN_CIPHER(KEY_128, 16,12, "SEED/OCB");
        case Cipher::SEED_SIV:
            return BOTAN_CIPHER(KEY_256, 16,16, "SEED/SIV");


        case Cipher::BLOWFISH_ECB:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_CBC:
            return BOTAN_CIPHER(KEY_448, 8, 8, "Blowfish/CBC");
        case Cipher::BLOWFISH_CFB:
            return BOTAN_CIPHER(KEY_448, 8, 8, "Blowfish/CFB");
        case Cipher::BLOWFISH_OFB:
            return BOTAN_CIPHER(KEY_448, 8, 8, "Blowfish/OFB");
        case Cipher::BLOWFISH_CTR:
            return BOTAN_CIPHER(KEY_448, 8, 8, "Blowfish/CTR");
        case Cipher::BLOWFISH_GCM:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_XTS:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_CCM:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_EAX:
            return BOTAN_CIPHER(KEY_448, 8, 8, "Blowfish/EAX");
        case Cipher::BLOWFISH_OCB:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_SIV:
            throw UnsupportedCipherException();

        case Cipher::BLOWFISH_256_ECB:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_256_CBC:
            return BOTAN_CIPHER(KEY_256, 8,8, "Blowfish/CBC");
        case Cipher::BLOWFISH_256_CFB:
            return BOTAN_CIPHER(KEY_256, 8,8, "Blowfish/CFB");
        case Cipher::BLOWFISH_256_OFB:
            return BOTAN_CIPHER(KEY_256, 8,8, "Blowfish/OFB");
        case Cipher::BLOWFISH_256_CTR:
            return BOTAN_CIPHER(KEY_256, 8,8, "Blowfish/CTR");
        case Cipher::BLOWFISH_256_GCM:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_256_XTS:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_256_CCM:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_256_EAX:
            return BOTAN_CIPHER(KEY_256, 8,8, "Blowfish/EAX");
        case Cipher::BLOWFISH_256_OCB:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_256_SIV:
            throw UnsupportedCipherException();

        case Cipher::BLOWFISH_192_ECB:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_192_CBC:
            return BOTAN_CIPHER(KEY_192, 8,8, "Blowfish/CBC");
        case Cipher::BLOWFISH_192_CFB:
            return BOTAN_CIPHER(KEY_192, 8,8, "Blowfish/CFB");
        case Cipher::BLOWFISH_192_OFB:
            return BOTAN_CIPHER(KEY_192, 8,8, "Blowfish/OFB");
        case Cipher::BLOWFISH_192_CTR:
            return BOTAN_CIPHER(KEY_192, 8,8, "Blowfish/CTR");
        case Cipher::BLOWFISH_192_GCM:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_192_XTS:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_192_CCM:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_192_EAX:
            return BOTAN_CIPHER(KEY_192, 8,8, "Blowfish/EAX");
        case Cipher::BLOWFISH_192_OCB:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_192_SIV:
            throw UnsupportedCipherException();

        case Cipher::BLOWFISH_128_ECB:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_128_CBC:
            return BOTAN_CIPHER(KEY_128, 8,8, "Blowfish/CBC");
        case Cipher::BLOWFISH_128_CFB:
            return BOTAN_CIPHER(KEY_128, 8,8, "Blowfish/CFB");
        case Cipher::BLOWFISH_128_OFB:
            return BOTAN_CIPHER(KEY_128, 8,8, "Blowfish/OFB");
        case Cipher::BLOWFISH_128_CTR:
            return BOTAN_CIPHER(KEY_128, 8,8, "Blowfish/CTR");
        case Cipher::BLOWFISH_128_GCM:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_128_XTS:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_128_CCM:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_128_EAX:
            return BOTAN_CIPHER(KEY_128, 8,8, "Blowfish/EAX");
        case Cipher::BLOWFISH_128_OCB:
            throw UnsupportedCipherException();
        case Cipher::BLOWFISH_128_SIV:
            throw UnsupportedCipherException();
    }
}