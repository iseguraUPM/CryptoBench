//
// Created by Juan Pablo Melgarejo on 3/24/20.
//

#ifndef CRYPTOBENCH_CRYPTOPP_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_CRYPTOPP_CIPHER_FACTORY_HPP

#include "cipher_factory.hpp"

#include <cmath>

#include <cryptopp/hex.h>
#include <cryptopp/default.h>
#include <cryptopp/aria.h>


#include "random_bytes.hpp"

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

    virtual void encrypt(const byte key[KEY_SIZE], const byte * plain_text, byte_len plain_text_len
            , byte * cipher_text, byte_len & cipher_text_len) override;

    virtual void decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                         , byte * recovered_text, byte_len & recovered_text_len) override;

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
void CryptoppCipher<KEY_SIZE, BLOCK_SIZE, T>::decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                                                      , byte * recovered_text, byte_len & recovered_text_len)
{
    byte * iv = new byte[BLOCK_SIZE];
    memcpy(iv, cipher_text + cipher_text_len, BLOCK_SIZE);

    recovered_text_len = cipher_text_len;

    typename T::Decryption decryption;
    decryption.SetKeyWithIV(key, KEY_SIZE, iv, BLOCK_SIZE);

    auto sink = CryptoPP::ArraySink(recovered_text, recovered_text_len);
    CryptoPP::ArraySource(cipher_text, cipher_text_len, true
                          ,new CryptoPP::StreamTransformationFilter(decryption, new CryptoPP::Redirector(sink)));

    recovered_text_len = sink.TotalPutLength();

    delete[] iv;
}

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
void CryptoppCipher<KEY_SIZE, BLOCK_SIZE, T>::encrypt(const byte key[KEY_SIZE], const byte * plain_text, byte_len plain_text_len
                                                      , byte * cipher_text, byte_len & cipher_text_len)
{
    byte * iv = new byte[BLOCK_SIZE];
    random_bytes.generateRandomBytes(iv, BLOCK_SIZE);

    typename T::Encryption encryption;
    encryption.SetKeyWithIV(key, KEY_SIZE, iv, BLOCK_SIZE);

    auto sink = CryptoPP::ArraySink(cipher_text, cipher_text_len);
    CryptoPP::ArraySource(plain_text, plain_text_len, true
                          ,new CryptoPP::StreamTransformationFilter(encryption, new CryptoPP::Redirector(sink)));

    cipher_text_len = sink.TotalPutLength();
    memcpy(cipher_text + cipher_text_len, iv, BLOCK_SIZE);
    delete[] iv;
}


template <int KEY_SIZE, int BLOCK_SIZE, typename T>
class CryptoppCipherECB : public SymmetricCipher
{
public:

    explicit CryptoppCipherECB();

    virtual void encrypt(const byte key[KEY_SIZE], const byte * plain_text, byte_len plain_text_len
                         , byte * cipher_text, byte_len & cipher_text_len) override;

    virtual void decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                         , byte * recovered_text, byte_len & recovered_text_len) override;

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
void CryptoppCipherECB<KEY_SIZE, BLOCK_SIZE, T>::decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                                                         , byte * recovered_text, byte_len & recovered_text_len)
{
    recovered_text_len = cipher_text_len;

    typename T::Decryption cfbDecryption(key, KEY_SIZE);
    cfbDecryption.ProcessData(recovered_text, cipher_text, cipher_text_len);
}

template<int KEY_SIZE, int BLOCK_SIZE, typename T>
void CryptoppCipherECB<KEY_SIZE, BLOCK_SIZE, T>::encrypt(const byte key[KEY_SIZE], const byte * plain_text, byte_len plain_text_len
                                                         , byte * cipher_text, byte_len & cipher_text_len)
{

    float length = ceil(plain_text_len / (float)BLOCK_SIZE) * BLOCK_SIZE;

    cipher_text_len = length;

    typename T::Encryption encryption(key, KEY_SIZE);
    encryption.ProcessData(cipher_text, plain_text, cipher_text_len);

}

template <int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, typename T>
class CryptoppCipherAuth : public SymmetricCipher
{
public:

    explicit CryptoppCipherAuth();

    virtual void encrypt(const byte key[KEY_SIZE], const byte * plain_text, byte_len plain_text_len
                         , byte * cipher_text, byte_len & cipher_text_len) override;

    virtual void decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                         , byte * recovered_text, byte_len & recovered_text_len) override;

    int getBlockLen() override;

    int getKeyLen() override;

protected:
    RandomBytes random_bytes;

};

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, typename T>
CryptoppCipherAuth<KEY_SIZE, BLOCK_SIZE, IV_SIZE, T>::CryptoppCipherAuth()
{
    random_bytes = RandomBytes();
}

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, typename T>
int CryptoppCipherAuth<KEY_SIZE, BLOCK_SIZE, IV_SIZE, T>::getBlockLen()
{
    return BLOCK_SIZE;
}

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, typename T>
int CryptoppCipherAuth<KEY_SIZE, BLOCK_SIZE, IV_SIZE, T>::getKeyLen()
{
    return KEY_SIZE;
}

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, typename T>
void CryptoppCipherAuth<KEY_SIZE, BLOCK_SIZE, IV_SIZE, T>::decrypt(const byte key[KEY_SIZE], const byte * cipher_text, byte_len cipher_text_len
                                                          , byte * recovered_text, byte_len & recovered_text_len)
{
    byte * iv = new byte[IV_SIZE];
    memcpy(iv, cipher_text + cipher_text_len, IV_SIZE);

    recovered_text_len = cipher_text_len;

    typename T::Decryption decryption;
    decryption.SetKeyWithIV(key, KEY_SIZE, iv, IV_SIZE);

    auto sink = CryptoPP::ArraySink(recovered_text, recovered_text_len);
    CryptoPP::ArraySource(cipher_text, cipher_text_len, true
                          ,new CryptoPP::AuthenticatedDecryptionFilter(decryption, new CryptoPP::Redirector(sink)));

    recovered_text_len = sink.TotalPutLength();

    delete[] iv;
}

template<int KEY_SIZE, int BLOCK_SIZE, int IV_SIZE, typename T>
void CryptoppCipherAuth<KEY_SIZE, BLOCK_SIZE, IV_SIZE, T>::encrypt(const byte key[KEY_SIZE], const byte * plain_text, byte_len plain_text_len
                                                          , byte * cipher_text, byte_len & cipher_text_len)
{
    byte * iv = new byte[IV_SIZE];
    random_bytes.generateRandomBytes(iv, IV_SIZE);

    typename T::Encryption encryption;
    encryption.SetKeyWithIV(key, KEY_SIZE, iv, IV_SIZE);

    auto sink = CryptoPP::ArraySink(cipher_text, cipher_text_len);
    CryptoPP::ArraySource(plain_text, plain_text_len, true
            ,new CryptoPP::AuthenticatedEncryptionFilter(encryption, new CryptoPP::Redirector(sink)));

    cipher_text_len = sink.TotalPutLength();
    memcpy(cipher_text + cipher_text_len, iv, IV_SIZE);
    delete[] iv;
}

#endif //CRYPTOBENCH_CRYPTOPP_CIPHER_FACTORY_HPP
