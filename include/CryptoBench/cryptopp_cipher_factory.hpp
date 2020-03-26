//
// Created by Juan Pablo Melgarejo on 3/24/20.
//

#ifndef CRYPTOBENCH_CRYPTOPP_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_CRYPTOPP_CIPHER_FACTORY_HPP

#include "cipher_factory.hpp"
#include "random_bytes.hpp"
#include <cryptopp/hex.h>
#include <cryptopp/default.h>
#include <cryptopp/aria.h>

class CryptoppCipherFactory : public CipherFactory
{

public:

    CipherPtr getCipher(Cipher cipher) override;

};

template <int KEY_SIZE, int BLOCK_SIZE, typename T>
class CryptoppCipher : public SymmetricCipher
{
public:

    explicit CryptoppCipher();

    virtual void encrypt(const byte key[KEY_SIZE], const security::secure_string& plain_text
                         , security::secure_string& cipher_text) override;

    virtual void decrypt(const byte key[KEY_SIZE], const security::secure_string &cipher_text
                         , security::secure_string &recovered_text) override;

    int getBlockLen() override;

    int getKeyLen() override;

protected:
    RandomBytes random_bytes;

};

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
CryptoppCipher<KEY_SIZE, BLOCK_SIZE, T>::CryptoppCipher()
{
    random_bytes = RandomBytes();
}

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
int CryptoppCipher<KEY_SIZE, BLOCK_SIZE, T>::getBlockLen()
{
    return BLOCK_SIZE;
}

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
int CryptoppCipher<KEY_SIZE, BLOCK_SIZE, T>::getKeyLen()
{
    return KEY_SIZE;
}

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
void CryptoppCipher<KEY_SIZE, BLOCK_SIZE, T>::decrypt(const byte key[KEY_SIZE], const security::secure_string &cipher_text
                                                   , security::secure_string &recovered_text)
{
    byte iv[BLOCK_SIZE];
    cipher_text.copy((char *) iv, BLOCK_SIZE, cipher_text.size() - BLOCK_SIZE);

    recovered_text.resize(cipher_text.size() - BLOCK_SIZE);

    typename T::Decryption cfbDecryption(key, CryptoPP::ARIA::DEFAULT_KEYLENGTH, iv);
    cfbDecryption.ProcessData((byte *) &recovered_text[0], (byte *) &cipher_text[0]
                              , cipher_text.size() - BLOCK_SIZE);

}

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
void CryptoppCipher<KEY_SIZE, BLOCK_SIZE, T>::encrypt(const byte key[KEY_SIZE], const security::secure_string &plain_text
                                                   , security::secure_string &cipher_text)
{
    byte iv[BLOCK_SIZE];
    random_bytes.generateRandomBytes(iv, BLOCK_SIZE);

    cipher_text.resize(plain_text.size());

    typename T::Encryption encryption(key, CryptoPP::ARIA::DEFAULT_KEYLENGTH, iv);
    encryption.ProcessData((byte *) &cipher_text[0], (byte *) &plain_text[0], plain_text.size());

    cipher_text.append((char *) iv, BLOCK_SIZE);
}


#endif //CRYPTOBENCH_CRYPTOPP_CIPHER_FACTORY_HPP
