//
// Created by ISU on 09/02/2020.
//

#include <fstream>
#include <chrono>
#include <utility>
#include <iostream>
#include <vector>
#include <random>
#include <climits>
#include <algorithm>
#include <sstream>
#include <iomanip>

#include <CryptoBench/open_ssl_cipher_factory.hpp>

struct BenchmarkResult
{
    unsigned long encrypt_time_micro{};
    unsigned long decrypt_time_micro{};
    int key_bits{};
    int block_bits{};
    unsigned int input_size{};
    std::string cipher_alg;
    std::string block_mode;

    BenchmarkResult() = default;

    BenchmarkResult(int key_len, int block_len, unsigned int input_size, std::string cipher, std::string mode)
    : key_bits(key_len), block_bits(block_len), input_size(input_size), cipher_alg(std::move(cipher)), block_mode(std::move(mode))
    {
        encrypt_time_micro = 0;
        decrypt_time_micro = 0;
    }
};


void generateRandomBytes(byte *arr, int len) noexcept (false)
{
    if (len <= 0)
        throw std::runtime_error("Random bytes length must be greater than 0");
    for (int i = 0; i < len; i++)
    {
        arr[i] = rand() % 0xFF;
    }
}


void benchmarkCipher(const byte* key, const security::secure_string &input_text, CipherPtr &cipher, BenchmarkResult &result)
{
    using namespace std::chrono;

    security::secure_string output_text;

    high_resolution_clock::time_point t1 = high_resolution_clock::now();
    cipher->encrypt(key, input_text, output_text);
    high_resolution_clock::time_point t2 = high_resolution_clock::now();

    result.encrypt_time_micro = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();

    security::secure_string recovered_text;

    t1 = high_resolution_clock::now();
    cipher->decrypt(key, output_text, recovered_text);
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

int min(std::size_t x, std::size_t y)
{
    return x > y ? y : x;
}

void generateInputBinaryFile(const std::string& filename, std::size_t target_size)
{
    std::independent_bits_engine<std::default_random_engine, CHAR_BIT, unsigned char> rbe;
    std::ofstream binaryFile(filename, std::ios::binary);
    std::size_t file_size = 0;

    const int buffer_size = 1024;
    unsigned char buffer[buffer_size];
    while (file_size < target_size)
    {
        std::generate(std::begin(buffer), std::end(buffer), std::ref(rbe));
        std::size_t to_write = min(buffer_size, target_size - file_size);
        binaryFile.write((char *) &buffer[0], min(buffer_size, target_size - file_size));
        file_size += to_write;
    }
}


void generateInputTextFile(const std::string& filename, int line_count)
{
    const std::string foxStr = "The Quick Brown Fox Jumps Over The Lazy Dog";

    std::ofstream textFile;
    textFile.open(filename);

    std::random_device engine;
    unsigned char x = engine();

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

void runSingleBenchmark(Cipher cipher, OpenSSLCipherFactory &factory, const security::secure_string &input_text, int input_size, std::ofstream &resultsFile)
{
    CipherPtr cipherptr = factory.getCipher(cipher);

    byte key [cipherptr->getKeyLen()];
    generateRandomBytes(key, cipherptr->getKeyLen());

    auto infoPair = cipherDescription(cipher);
    BenchmarkResult result = BenchmarkResult(cipherptr->getKeyLen()*8, cipherptr->getBlockLen()*8, input_size, infoPair.first, infoPair.second);

    benchmarkCipher(key, input_text, cipherptr, result);
    recordResult(result, resultsFile);
}

void runFullBenchmark(const security::secure_string &input_text, int input_size, std::ofstream &resultsFile)
{
    OpenSSLCipherFactory factory;

    const int rounds = 3;
    for(Cipher cipher : CIPHER_LIST)
    {
        auto info_pair = cipherDescription(cipher);
        for(int i = 0; i < rounds; i++)
        {
            runSingleBenchmark(cipher, factory, input_text, input_size, resultsFile);
        }
    }
}

void runBenchmarkWSize(int bytes, std::ofstream &results_file)
{
    security::secure_string input_text;
    std::ifstream input_file;

    generateInputBinaryFile("input.bin", bytes);
    input_file.open("input.bin", std::ios::binary);
    int input_size = readInputFile(input_file, input_text);

    std::cout << "Running " << input_size << " bytes random file benchmark\n";
    runFullBenchmark(input_text, input_size, results_file);

    input_file.close();
}

int main(int argc, char** arv)
{
    //generateInputTextFile("fox.txt", 100000);
    //std::ifstream input_file("fox.txt", std::ios::binary);

    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d-%H-%M-%S");

    std::ofstream resultsFile;
    resultsFile.open("benchmark_" + ss.str() + ".csv");
    resultsFile << "ALGORITHM,KEY_BITS,BLOCK_MODE,BLOCK_BITS,FILE_BYTES,ENCRYPT_T,DECRYPT_T\n";

    //security::secure_string input_text;
    //input_text = "The quick fox jumps over the lazy dog";

    // From 2^10 to 2^25
    /*int sizes[] = {
            1024,
            2048,
            4096,
            8192,
            16384,
            32768,
            65536,
            131072,
            262144,
            524288,
            1048576,
            2097152,
            4194304,
            8388608,
            16777216,
            33554432,
            67108864,
            134217728//,
            //268435456,
            //536870912,
            //1073741824
    };*/

    std::cout << "Starting...\n";

    generateInputTextFile("fox.txt", 10000);
    std::ifstream input_file("fox.txt", std::ios::binary);
    security::secure_string plaintext;
    int text_size = readInputFile(input_file, plaintext);
    OpenSSLCipherFactory cipherFactory;
    runSingleBenchmark(Cipher::AES_192_CBC, cipherFactory, plaintext, text_size, resultsFile);
    input_file.close();

    generateInputBinaryFile("input.bin", text_size);
    input_file.open("input.bin", std::ios::binary);
    text_size = readInputFile(input_file, plaintext);
    runSingleBenchmark(Cipher::AES_192_CBC, cipherFactory, plaintext, text_size, resultsFile);
    input_file.close();

    /*for (int b : sizes)
    {

        runBenchmarkWSize(b, resultsFile);
    }*/

    std::cout << "Done!\n";

    resultsFile.close();

    return 0;
}



