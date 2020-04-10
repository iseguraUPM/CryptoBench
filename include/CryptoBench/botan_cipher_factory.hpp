//
// Created by Juan Pablo Melgarejo on 3/30/20.
//

#ifndef CRYPTOBENCH_BOTAN_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_BOTAN_CIPHER_FACTORY_HPP

#include <botan/cipher_mode.h>
#include "cipher_factory.hpp"
#include "random_bytes.hpp"

class BotanCipherFactory : public CipherFactory
{

public:

    CipherPtr getCipher(Cipher cipher) override;

};

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
}

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE>
void BotanCipher<KEY_SIZE, BLOCK_SIZE, IV_SIZE>::encrypt(const byte key[KEY_SIZE], const byte *plain_text, byte_len plain_text_len
                                                   , byte * cipher_text, byte_len &cipher_text_len)
{
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
}

#endif //CRYPTOBENCH_BOTAN_CIPHER_FACTORY_HPP
