//
// Created by ISU on 09/02/2020.
//

#include <fstream>
#include <chrono>
#include <utility>

#include <CryptoBench/open_ssl_cipher_factory.hpp>

struct BenchmarkResult
{
    unsigned long encrypt_time_micro;
    unsigned long decrypt_time_micro;
    int key_bits;
    int block_bits;
    std::string cipher_alg;
    std::string block_mode;

    BenchmarkResult(int key_len, int block_len, std::string cipher, std::string mode)
    : key_bits(key_len), block_bits(block_len), cipher_alg(std::move(cipher)), block_mode(std::move(mode))
    {}
};

void generateRandomBytes(byte *arr, int len)
{
    if (len <= 0)
        throw std::runtime_error("Random bytes length must be greater than 0");
    for (int i = 0; i < len; i++)
    {
        arr[i] = rand() % 0xFF;
    }
}

void benchmarkCipher(const byte* key, const byte* iv, const security::secure_string &input_text, CipherPtr &cipher, BenchmarkResult &result)
{
    using namespace std::chrono;

    security::secure_string output_text;

    high_resolution_clock::time_point t1 = high_resolution_clock::now();
    cipher->encrypt(key, iv, input_text, output_text);
    high_resolution_clock::time_point t2 = high_resolution_clock::now();

    result.encrypt_time_micro = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();

    security::secure_string recovered_text;

    t1 = high_resolution_clock::now();
    cipher->encrypt(key, iv, output_text, recovered_text);
    t2 = high_resolution_clock::now();

    result.decrypt_time_micro = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
}

void recordResult(BenchmarkResult &result, std::ofstream &file_stream)
{
    file_stream << result.cipher_alg << "," << result.key_bits
    << "," << result.block_mode << "," << result.block_bits << "," << result.encrypt_time_micro << ","
    << result.decrypt_time_micro << "\n";
}

int main(int argc, char** arv)
{
    std::ofstream resultsFile;
    resultsFile.open("benchmark.csv");

    resultsFile << "ALG,KEY_BITS,BLOCK_MODE,BLOCK_BITS,ENCRYPT_T,DECRYPT_T\n";

    security::secure_string input_text = "The quick fox jumps over the lazy dog";

    OpenSSLCipherFactory factory;
    CipherPtr cipher;

    byte key256[32];
    generateRandomBytes(key256, 32);
    byte key128[16];
    generateRandomBytes(key128, 16);

    byte iv128[16];
    generateRandomBytes(iv128, 16);

    cipher = factory.getCipher(Cipher::AES_256_CBC);
    BenchmarkResult result(256, 128, "AES", "CBC");
    benchmarkCipher(key256, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    resultsFile.close();

    return 0;
}



