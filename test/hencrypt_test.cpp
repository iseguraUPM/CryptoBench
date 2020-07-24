//
// Created by Juan Pablo Melgarejo on 7/17/20.
//

#include <gtest/gtest.h>

#include <hencrypt/hencrypt.hpp>

class HencryptFixture : public ::testing::Test
{
protected:

    void SetUp() override
    {
        std::string system_profile_file_name = "test_system_profile.dat";
        std::string cipher_seed_file_name = "test_cipher_seed.dat";
        test_plaintext_filename = "test_plaintext.txt";
        std::string key_filename = "test_key.bin";

        system_info = SystemInfo::getInstance(system_profile_file_name);
        cipher_database = CipherDatabase::getInstance(cipher_seed_file_name);


        generateKeyFile(key_filename);
        key_manager = KeyManager(key_filename);
        codec = CiphertextCodec();

        generatePlaintext();
    }

    void generateKeyFile(const std::string &key_filename) const
    {
        RandomBytes random_bytes;
        byte keys[64];
        random_bytes.generateRandomBytes(keys, 64);
        std::ofstream key_file(key_filename);
        key_file.write(reinterpret_cast<const char *>(keys), 64);
        key_file.close();
    }

    void generatePlaintext() const
    {
        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
        std::default_random_engine random_engine(seed);
        std::uniform_int_distribution<byte_len > dist(0, std::pow(2, 15));
        byte_len random_len = dist(random_engine);
        byte *random_data = new byte[random_len];
        RandomBytes random_bytes;
        random_bytes.generateRandomBytes(random_data, random_len);
        std::ofstream plaintext;
        plaintext.open(test_plaintext_filename);
        plaintext.write(reinterpret_cast<const char *>(random_data), random_len);
        plaintext.close();
        delete[] random_data;
    }

    void TearDown() override
    {
    }

protected:

    SystemInfo system_info;
    CipherDatabase cipher_database;
    KeyManager key_manager;
    CiphertextCodec codec;

    std::string test_plaintext_filename;


};

static void compareFiles(std::string filename_a, std::string filename_b)
{
    std::ifstream file_a(filename_a, std::ios::binary);
    std::ifstream file_b(filename_b, std::ios::binary);

    byte_len len = obtainFileSize(file_a);
    ASSERT_EQ(len, obtainFileSize(file_b));

    byte buffer[2048];
    byte_len read_bytes = 0;
    while (read_bytes < len)
    {
        file_a.read(reinterpret_cast<char *>(buffer), 1024);
        file_b.read(reinterpret_cast<char *>(buffer + 1024), 1024);

        byte_len read = file_a.gcount();
        for (int i = 0; i < read; i++)
        {
            EXPECT_EQ(buffer[i], buffer[i + 1024]);
        }

        read_bytes += read;
    }

    file_a.close();
    file_b.close();
}

TEST_F(HencryptFixture, EncryptTest)
{
    Engine engine(system_info, cipher_database);
    Hencrypt hencrypt(engine, key_manager, codec);

    std::string ciphertext_filename = hencrypt.encryptMinTime(2, 7, test_plaintext_filename);
    EXPECT_FALSE(ciphertext_filename.empty());
}

TEST_F(HencryptFixture, EncryptDecryptTest)
{
    Engine engine(system_info, cipher_database);
    Hencrypt hencrypt(engine, key_manager, codec);

    std::string ciphertext_filename = hencrypt.encryptMinTime(2, 7, test_plaintext_filename);
    ASSERT_FALSE(ciphertext_filename.empty());

    std::string decrypted_filename = "dec_" + test_plaintext_filename;
    hencrypt.decrypt(ciphertext_filename, decrypted_filename);

    compareFiles(test_plaintext_filename, decrypted_filename);
}

