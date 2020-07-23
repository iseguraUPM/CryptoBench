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

struct PerfListener
{
    std::vector<std::string> cipher_list;
    unsigned long decision_time_nano{};
    unsigned long enc_processing_time_nano{};
    unsigned long enc_io_time_nano{};
    unsigned long dec_processing_time_nano{};
    unsigned long dec_io_time_nano{};
    std::mutex io_lock;
    std::string fragments_info;
};

struct Chrono;
struct OutputFile;
enum class Strategy;

using byte_ptr = std::shared_ptr<byte>;

class Hencrypt
{
public:
    explicit Hencrypt(Engine &engine, KeyManager &key_manager, CiphertextCodec &codec);

    void setPerformanceListener(PerfListener *listener);

    std::string encryptMinTime(int sec_level, double eval_time, const std::string &plaintext_filename);
    std::string encryptMaxSec(int64_t max_time, double eval_time, const std::string &plaintext_filename);

    void decrypt(const std::string &ciphertext_filename, const std::string &plaintext_filename);

private:

    std::string encrypt(Strategy strategy, double max_time_available, int sec_level, double eval_time, const std::string &plaintext_filename);

    void writeFragment(CiphertextFragment fragment, std::string path, const OutputFile &outputFile);

    bool readFragment(CiphertextFragment &fragment, const std::string &path, byte_len &position);

    const CipherFactory & toFactory(const std::string &lib_name);

    void recordProcessingMeasurement(Chrono &chrono, bool is_encrypt);
    void recordIOMeasurement(Chrono &chrono, bool is_encrypt);
    void recordDecisionMeasurement(Chrono &chrono);

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

    PerfListener *listener;
};


#endif //CRYPTOBENCH_HENCRYPT_HPP
