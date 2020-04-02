//
// Created by ISU on 02/04/2020.
//

#include "cipher_factory_test.hpp"

class CipherConsistencyFixture : public CipherFactoryFixture
{
protected:
    void SetUp() override
    {
        input = (byte *) "The quick brown fox jumps over the lazy dog";
        input_len = std::strlen(reinterpret_cast<const char *>(input));
        RandomBytes random_bytes;
        random_bytes.generateRandomBytes(key256, 32);
        random_bytes.generateRandomBytes(key384, 48);
        random_bytes.generateRandomBytes(key192, 24);
        random_bytes.generateRandomBytes(key128, 16);


    }

    void TearDown() override
    {
    }
};

TEST_P(CipherConsistencyFixture, CiphertextChecksum)
{

}