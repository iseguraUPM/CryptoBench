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
#include <math.h>

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

    typename T::Decryption cfbDecryption(key, KEY_SIZE, iv);
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

    typename T::Encryption encryption(key, KEY_SIZE, iv);
    encryption.ProcessData((byte *) &cipher_text[0], (byte *) &plain_text[0], plain_text.size());

    cipher_text.append((char *) iv, BLOCK_SIZE);
}


template <int KEY_SIZE, int BLOCK_SIZE, typename T>
class CryptoppCipherECB : public SymmetricCipher
{
public:

    explicit CryptoppCipherECB();

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
CryptoppCipherECB<KEY_SIZE, BLOCK_SIZE, T>::CryptoppCipherECB()
{
    random_bytes = RandomBytes();
}

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
int CryptoppCipherECB<KEY_SIZE, BLOCK_SIZE, T>::getBlockLen()
{
    return BLOCK_SIZE;
}

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
int CryptoppCipherECB<KEY_SIZE, BLOCK_SIZE, T>::getKeyLen()
{
    return KEY_SIZE;
}

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
void CryptoppCipherECB<KEY_SIZE, BLOCK_SIZE, T>::decrypt(const byte key[KEY_SIZE], const security::secure_string &cipher_text
                                                      , security::secure_string &recovered_text)
{
    recovered_text.resize(cipher_text.size());

    typename T::Decryption cfbDecryption(key, KEY_SIZE);
    cfbDecryption.ProcessData((byte *) &recovered_text[0], (byte *) &cipher_text[0]
                              , cipher_text.size());

}

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
void CryptoppCipherECB<KEY_SIZE, BLOCK_SIZE, T>::encrypt(const byte key[KEY_SIZE], const security::secure_string &plain_text
                                                      , security::secure_string &cipher_text)
{

    float length = ceil((float)plain_text.size() / (float)BLOCK_SIZE) * BLOCK_SIZE;

    cipher_text.resize(length);

    typename T::Encryption encryption(key, KEY_SIZE);
    encryption.ProcessData((byte *) &cipher_text[0], (byte *) &plain_text[0], length);
}

template <int KEY_SIZE, int BLOCK_SIZE, typename T>
class CryptoppCipherCBC : public SymmetricCipher
{
public:

    explicit CryptoppCipherCBC();

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
CryptoppCipherCBC<KEY_SIZE, BLOCK_SIZE, T>::CryptoppCipherCBC()
{

}

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
int CryptoppCipherCBC<KEY_SIZE, BLOCK_SIZE, T>::getBlockLen()
{
    return BLOCK_SIZE;
}

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
int CryptoppCipherCBC<KEY_SIZE, BLOCK_SIZE, T>::getKeyLen()
{
    return KEY_SIZE;
}

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
void CryptoppCipherCBC<KEY_SIZE, BLOCK_SIZE, T>::decrypt(const byte key[KEY_SIZE], const security::secure_string &cipher_text
                                                         , security::secure_string &recovered_text)
{
    byte iv[BLOCK_SIZE];
    cipher_text.copy((char *) iv, BLOCK_SIZE, cipher_text.size() - BLOCK_SIZE);

    recovered_text.resize(cipher_text.size() - BLOCK_SIZE);

    typename T::Decryption cfbDecryption(key, KEY_SIZE, iv);
    cfbDecryption.ProcessData((byte *) &recovered_text[0], (byte *) &cipher_text[0]
                              , cipher_text.size() - BLOCK_SIZE);
}

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
void CryptoppCipherCBC<KEY_SIZE, BLOCK_SIZE, T>::encrypt(const byte key[KEY_SIZE], const security::secure_string &plain_text
                                                         , security::secure_string &cipher_text)
{
    byte iv[BLOCK_SIZE];
    random_bytes.generateRandomBytes(iv, BLOCK_SIZE);
    float length = ceil((float)plain_text.size() / (float)BLOCK_SIZE) * BLOCK_SIZE;

    cipher_text.resize(length);

    typename T::Encryption encryption(key, KEY_SIZE, iv);
    encryption.ProcessData((byte *) &cipher_text[0], (byte *) &plain_text[0], length);

    cipher_text.append((char *) iv, BLOCK_SIZE);
}

#endif //CRYPTOBENCH_CRYPTOPP_CIPHER_FACTORY_HPP
