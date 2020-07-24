//
// Created by ISU on 18/07/2020.
//

#include <gtest/gtest.h>

#include <fstream>

#include <hencrypt/ciphertext_codec.hpp>
#include <hencrypt/random_bytes.hpp>



class CodecFixture : public ::testing::Test
{
protected:

    void SetUp() override
    {
        RandomBytes random;
        data = std::shared_ptr<byte>(new byte[1024], std::default_delete<byte[]>());
        random.generateRandomBytes(data.get(), 1024);

        test_filename = "codec_test_file.bin";

        // Random engine
        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
        random_engine = std::default_random_engine(seed);

    }

    void TearDown() override
    {
    }

    CiphertextFragment generateRandomFragment()
    {
        CiphertextFragment fragment;
        int num_ciphers = sizeof(CIPHER_LIST) / sizeof(Cipher);
        std::uniform_int_distribution<int> int_uniform_dist(0, num_ciphers - 1);
        fragment.cipher = CIPHER_LIST[int_uniform_dist(random_engine)];

        int_uniform_dist = std::uniform_int_distribution<int>(0, 4);
        fragment.lib = LIB_LIST[int_uniform_dist(random_engine)];

        int_uniform_dist = std::uniform_int_distribution<int>(0, 4096);
        fragment.len = int_uniform_dist(random_engine);
        fragment.bytes = std::shared_ptr<byte>(new byte[fragment.len], std::default_delete<byte[]>());
        RandomBytes random_bytes;
        random_bytes.generateRandomBytes(fragment.bytes.get(), fragment.len);

        char cstr[128];
        random_bytes.generateRandomBytes(reinterpret_cast<unsigned char *>(cstr), 128);
        for (int i = 0; i < sizeof(cstr); i++)
        {
            fragment.next_fragment_path.push_back(cstr[i]);
        }

        return fragment;
    }

protected:

    CiphertextCodec codec;
    std::shared_ptr<byte> data;
    std::string test_filename;

    std::default_random_engine random_engine;
    static std::string LIB_LIST[];
};

std::string CodecFixture::LIB_LIST[] = {"openssl", "wolfcrypt", "botan", "libsodium", "cryptopp"};

TEST_F(CodecFixture, EncodeDecodeMultipleTest)
{
    const int num_fragments = 5;
    CiphertextFragment fragments[num_fragments];
    for (int i = 0; i < num_fragments; i++)
    {
        fragments[i] = generateRandomFragment();
        if (i == num_fragments - 1)
        {
            fragments[i].next_fragment_path = "";
        }
    }

    std::ofstream ofs;
    ofs.open(test_filename, std::ios::binary);
    for (int i = 0; i < num_fragments; i++)
    {
        codec.encode(ofs,  fragments[i]);
    }
    ofs.close();


    CiphertextFragment decoded[num_fragments];
    std::ifstream ifs;
    ifs.open(test_filename, std::ios::binary);
    for (int i = 0; i < num_fragments; i++)
    {
        codec.decode(ifs,  decoded[i]);
    }

    EXPECT_FALSE(codec.decode(ifs, decoded[num_fragments - 1]));

    ofs.close();

    for (int i = 0; i < num_fragments; i++)
    {
        EXPECT_EQ(fragments[i].cipher, decoded[i].cipher);
        EXPECT_EQ(fragments[i].lib, decoded[i].lib);
        EXPECT_EQ(fragments[i].len, decoded[i].len);
        for (int j = 0; j < fragments[j].len; j++)
        {
            EXPECT_EQ(fragments[i].bytes.get()[j], decoded[i].bytes.get()[j]);
        }
        EXPECT_EQ(fragments[i].next_fragment_path, decoded[i].next_fragment_path);
    }
}

TEST_F(CodecFixture, EncodeDecodeTest)
{
    CiphertextFragment fragment;
    fragment = generateRandomFragment();

    std::ofstream ofs;
    ofs.open(test_filename, std::ios::binary);

    codec.encode(ofs, fragment);
    ofs.close();

    std::ifstream ifs;
    ifs.open(test_filename, std::ios::binary);

    CiphertextFragment decoded;
    codec.decode(ifs, decoded);

    ifs.close();

    EXPECT_EQ(fragment.cipher, decoded.cipher);
    EXPECT_EQ(fragment.lib, decoded.lib);
    EXPECT_EQ(fragment.len, decoded.len);
    for (int i = 0; i < fragment.len; i++)
    {
        EXPECT_EQ(fragment.bytes.get()[i], decoded.bytes.get()[i]);
    }
    EXPECT_EQ(fragment.next_fragment_path, decoded.next_fragment_path);
}