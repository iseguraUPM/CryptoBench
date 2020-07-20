//
// Created by Juan Pablo Melgarejo on 7/17/20.
//

#ifndef CRYPTOBENCH_HENCRYPT_HPP
#define CRYPTOBENCH_HENCRYPT_HPP

#include "engine.hpp"
#include "key_manager.hpp"
#include "ciphertext_codec.hpp"
#include "cipher/open_ssl_cipher_factory.hpp"
#include "cipher/libsodium_cipher_factory.hpp"
#include "cipher/cryptopp_cipher_factory.hpp"
#include "cipher/cipher_exception.hpp"
#include "cipher/libgcrypt_cipher_factory.hpp"
#include "cipher/botan_cipher_factory.hpp"
#include "cipher/wolfcrypt_cipher_factory.hpp"

using byte_ptr = std::shared_ptr<byte>;

class Hencrypt
{
public:
    explicit Hencrypt(Engine &engine, KeyManager &key_manager, CiphertextCodec &codec);

    std::string encryptMinTime(int sec_level, double eval_time, const std::string &plaintext_filename);
    std::string encryptMaxSec(int64_t max_time, double eval_time, const std::string &plaintext_filename);

    void decrypt(const std::string &ciphertext_filename, const std::string &plaintext_filename);

private:

    void writeFragment(CiphertextFragment &fragment, const std::string &path);

    bool readFragment(CiphertextFragment &fragment, const std::string &path);

private:

    KeyManager &key_manager;
    Engine &engine;
    CiphertextCodec &codec;

    OpenSSLCipherFactory open_ssl_cipher_factory;
    LibsodiumCipherFactory libsodium_cipher_factory;
    LibgcryptCipherFactory libgcrypt_cipher_factory;
    CryptoppCipherFactory cryptopp_cipher_factory;
    BotanCipherFactory botan_cipher_factory;
    WolfCryptCipherFactory wolf_crypt_cipher_factory;

    const CipherFactory & toFactory(const std::string &lib_name);

};


#endif //CRYPTOBENCH_HENCRYPT_HPP
