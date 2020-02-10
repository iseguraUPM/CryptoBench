//
// Created by ISU on 09/02/2020.
//

#include <fstream>
#include <chrono>
#include <utility>
#include <iostream>

#include <CryptoBench/open_ssl_cipher_factory.hpp>

struct BenchmarkResult
{
    unsigned long encrypt_time_micro;
    unsigned long decrypt_time_micro;
    int key_bits;
    int block_bits;
    unsigned int input_size;
    std::string cipher_alg;
    std::string block_mode;

    BenchmarkResult() {}

    BenchmarkResult(int key_len, int block_len, unsigned int input_size, std::string cipher, std::string mode)
    : key_bits(key_len), block_bits(block_len), input_size(input_size), cipher_alg(std::move(cipher)), block_mode(std::move(mode))
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
    cipher->decrypt(key, iv, output_text, recovered_text);
    t2 = high_resolution_clock::now();

    result.decrypt_time_micro = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
}

void recordResult(BenchmarkResult &result, std::ofstream &file_stream)
{
    file_stream << result.cipher_alg << ","
    << result.key_bits << ","
    << result.block_mode << ","
    << result.block_bits << ","
    << result.input_size << ","
    << result.encrypt_time_micro << ","
    << result.decrypt_time_micro << "\n";
}


void generateInputFile(const std::string& filename, int line_count)
{
    const std::string foxStr = "The Quick Brown Fox Jumps Over The Lazy Dog";

    std::ofstream textFile;
    textFile.open(filename);

    for (int i = 0; i < line_count; i++)
    {
        textFile << i << ". " << foxStr << "\n";
    }

    textFile.close();
}

int readInputFile(std::ifstream &t, security::secure_string &input_text)
{
    t.seekg(0, std::ios::end);
    int len = t.tellg();
    input_text.reserve(len);
    t.seekg(0, std::ios::beg);
    input_text.assign((std::istreambuf_iterator<char>(t)),
            std::istreambuf_iterator<char>());
    return len;
}

int main(int argc, char** arv)
{
    generateInputFile("fox.txt", 100000);

    std::ifstream input_file("fox.txt", std::ios::binary | std::ios::ate);
    security::secure_string input_text;

    int input_size = readInputFile(input_file, input_text);

    std::ofstream resultsFile;
    resultsFile.open("benchmark.csv");

    resultsFile << "ALG,KEY_BITS,BLOCK_MODE,BLOCK_BITS,FILE_BYTES,ENCRYPT_T,DECRYPT_T\n";

    //security::secure_string input_text = "The quick fox jumps over the lazy dog";

    OpenSSLCipherFactory factory;
    CipherPtr cipher;
    BenchmarkResult result;

    byte key256[32];
    generateRandomBytes(key256, 32);
    byte key128[16];
    generateRandomBytes(key128, 16);

    byte iv128[16];
    generateRandomBytes(iv128, 16);

    cipher = factory.getCipher(Cipher::AES_128_ECB);
    result = BenchmarkResult(128, 128, input_size, "AES", "ECB");
    benchmarkCipher(key128, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::AES_128_CBC);
    result = BenchmarkResult(128, 128, input_size, "AES", "CBC");
    benchmarkCipher(key128, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::AES_128_CFB);
    result = BenchmarkResult(128, 128, input_size, "AES", "CFB");
    benchmarkCipher(key128, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::AES_256_ECB);
    result = BenchmarkResult(256, 128, input_size, "AES", "ECB");
    benchmarkCipher(key256, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::AES_256_CBC);
    result = BenchmarkResult(256, 128, input_size, "AES", "CBC");
    benchmarkCipher(key256, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::AES_256_CFB);
    result = BenchmarkResult(256, 128, input_size, "AES", "CFB");
    benchmarkCipher(key256, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::ARIA_256_ECB);
    result = BenchmarkResult(256, 128, input_size, "ARIA", "ECB");
    benchmarkCipher(key256, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::ARIA_256_CBC);
    result = BenchmarkResult(256, 128, input_size, "ARIA", "CBC");
    benchmarkCipher(key256, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::ARIA_256_CFB);
    result = BenchmarkResult(256, 128, input_size, "ARIA", "CFB");
    benchmarkCipher(key256, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::ARIA_128_ECB);
    result = BenchmarkResult(128, 128, input_size, "ARIA", "ECB");
    benchmarkCipher(key128, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::ARIA_128_CBC);
    result = BenchmarkResult(128, 128, input_size, "ARIA", "CBC");
    benchmarkCipher(key128, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::ARIA_128_CFB);
    result = BenchmarkResult(128, 128, input_size, "ARIA", "CFB");
    benchmarkCipher(key128, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::CAMELLIA_256_ECB);
    result = BenchmarkResult(256, 128, input_size, "Camellia", "ECB");
    benchmarkCipher(key256, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::CAMELLIA_256_CBC);
    result = BenchmarkResult(256, 128, input_size, "Camellia", "CBC");
    benchmarkCipher(key256, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::CAMELLIA_256_CFB);
    result = BenchmarkResult(256, 128, input_size, "Camellia", "CFB");
    benchmarkCipher(key256, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::CAMELLIA_128_ECB);
    result = BenchmarkResult(128, 128, input_size, "Camellia", "ECB");
    benchmarkCipher(key128, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::CAMELLIA_128_CBC);
    result = BenchmarkResult(128, 128, input_size, "Camellia", "CBC");
    benchmarkCipher(key128, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::CAMELLIA_128_CFB);
    result = BenchmarkResult(128, 128, input_size, "Camellia", "CFB");
    benchmarkCipher(key128, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    byte iv64[8];
    generateRandomBytes(iv64, 8);

    cipher = factory.getCipher(Cipher::CAST5_ECB);
    result = BenchmarkResult(128, 64, input_size, "CAST5", "ECB");
    benchmarkCipher(key128, iv64, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::CAST5_CBC);
    result = BenchmarkResult(128, 64, input_size, "CAST5", "CBC");
    benchmarkCipher(key128, iv64, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::CAST5_CFB);
    result = BenchmarkResult(128, 64, input_size, "CAST5", "CFB");
    benchmarkCipher(key128, iv64, input_text, cipher, result);
    recordResult(result, resultsFile);

    byte key448[56];
    generateRandomBytes(key448, 56);

    cipher = factory.getCipher(Cipher::BLOWFISH_ECB);
    result = BenchmarkResult(448, 64, input_size, "Blowfish", "ECB");
    benchmarkCipher(key448, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::BLOWFISH_CBC);
    result = BenchmarkResult(448, 64, input_size, "Blowfish", "CBC");
    benchmarkCipher(key448, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    cipher = factory.getCipher(Cipher::BLOWFISH_CFB);
    result = BenchmarkResult(448, 64, input_size, "Blowfish", "CFB");
    benchmarkCipher(key448, iv128, input_text, cipher, result);
    recordResult(result, resultsFile);

    input_file.close();
    resultsFile.close();

    return 0;
}



