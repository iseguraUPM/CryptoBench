//
// Created by Juan Pablo Melgarejo on 7/16/20.
//
#include <gtest/gtest.h>

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

class LibraryFixture : public ::testing::Test
{
protected:

    void SetUp() override
    {
        plaintext_filename = "testfile.bin";
        key_filename = "key.bin";

        system_profile_file_name = "system_profile.dat";
        cipher_seed_file_name = "cipher_seed_time.dat";

        sec_level = 3;

    }

    void TearDown() override
    {
    }

    const CipherFactory* toFactory(const std::string &lib_name);


protected:
    std::string plaintext_filename;
    byte_len plaintext_size;
    std::string key_filename;
    byte key;

    std::string system_profile_file_name;
    std::string cipher_seed_file_name;
    int sec_level;

    OpenSSLCipherFactory open_ssl_cipher_factory;
    LibsodiumCipherFactory libsodium_cipher_factory;
    LibgcryptCipherFactory libgcrypt_cipher_factory;
    CryptoppCipherFactory cryptopp_cipher_factory;
    BotanCipherFactory botan_cipher_factory;
    WolfCryptCipherFactory wolf_crypt_cipher_factory;

};

const CipherFactory* LibraryFixture::toFactory(const std::string &lib_name)
{

    if (lib_name == "openssl")
    {
        return &open_ssl_cipher_factory;
    } else if (lib_name == "libsodium")
    {
        return &libsodium_cipher_factory;
    } else if (lib_name == "gcrypt")
    {
        return &libgcrypt_cipher_factory;
    } else if (lib_name == "cryptopp")
    {
        return &cryptopp_cipher_factory;
    } else if (lib_name == "botan")
    {
        return &botan_cipher_factory;
    } else if (lib_name == "wolfcrypt")
    {
        return &wolf_crypt_cipher_factory;
    } else
    {
        throw std::runtime_error("Unknown library: " + lib_name);
    }
}


TEST_F(LibraryFixture, MinTime)
{
}