//
// Created by ISU on 18/07/2020.
//

#include <gtest/gtest.h>

#include <fstream>

#include <CryptoBench/ciphertext_codec.hpp>
#include <CryptoBench/random_bytes.hpp>

class CodecFixture : public ::testing::Test
{
protected:

    void SetUp() override
    {
        RandomBytes random;
        data = std::shared_ptr<byte[]>(new byte[1024], std::default_delete<byte[]>());
        random.generateRandomBytes(data.get(), 1024);

        test_filename = "codec_test_file.bin";

    }

    void TearDown() override
    {
    }

protected:

    CiphertextCodec codec;
    std::shared_ptr<byte[]> data;
    std::string test_filename;

};

TEST_F(CodecFixture, EncodeDecodeTest)
{
    CiphertextFragment fragment;

    fragment.cipher = Cipher::BLOWFISH_128_OFB;
    fragment.lib = "wolfcrypt";
    fragment.len = 1024ull;
    fragment.bytes = data;

    std::ofstream ofs;
    ofs.open(test_filename);

    codec.encode(ofs, fragment);
    ofs.close();

    std::ifstream ifs;
    ifs.open(test_filename);

    CiphertextFragment decoded;
    codec.decode(ifs, decoded);

    EXPECT_EQ(fragment.cipher, decoded.cipher);
    EXPECT_EQ(fragment.lib, decoded.lib);
    EXPECT_EQ(fragment.len, decoded.len);
    for (int i = 0; i < fragment.len; i++)
    {
        EXPECT_EQ(fragment.bytes[i], decoded.bytes[i]);
    }
}