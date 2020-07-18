//
// Created by Juan Pablo Melgarejo on 7/17/20.
//

#ifndef CRYPTOBENCH_HENCRYPT_HPP
#define CRYPTOBENCH_HENCRYPT_HPP

#include <CryptoBench/engine.hpp>
#include <CryptoBench/cipher/open_ssl_cipher_factory.hpp>
#include <CryptoBench/cipher/libsodium_cipher_factory.hpp>
#include <CryptoBench/cipher/cryptopp_cipher_factory.hpp>
#include <CryptoBench/cipher/cipher_exception.hpp>
#include <CryptoBench/cipher/libgcrypt_cipher_factory.hpp>
#include <CryptoBench/cipher/botan_cipher_factory.hpp>
#include <CryptoBench/cipher/wolfcrypt_cipher_factory.hpp>
#include <CryptoBench/file_utilities.hpp>
#include <CryptoBench/key_manager.hpp>

using byte_ptr = std::shared_ptr<byte>;

class Hencrypt
{
public:
    explicit Hencrypt(std::string plaintext_filename, std::string key_filename);

    void set_system_profile(std::string system_profile_file_name);
    void set_cipher_seed(std::string cipher_seed_file_name);
    void set_eval_time(double eval_time);

    int encrypt_min_time(int sec_level);
    bool encrypt_max_sec(int64_t max_time);


private:
    std::string plaintext_filename;
    byte_len plaintext_size;
    std::string key_filename;
    byte key;
    KeyManager key_manager;

    std::string system_profile_file_name;
    std::string cipher_seed_file_name;
    double eval_time;

    OpenSSLCipherFactory open_ssl_cipher_factory;
    LibsodiumCipherFactory libsodium_cipher_factory;
    LibgcryptCipherFactory libgcrypt_cipher_factory;
    CryptoppCipherFactory cryptopp_cipher_factory;
    BotanCipherFactory botan_cipher_factory;
    WolfCryptCipherFactory wolf_crypt_cipher_factory;

    const CipherFactory* toFactory(const std::string &lib_name);

};


#endif //CRYPTOBENCH_HENCRYPT_HPP
