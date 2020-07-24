//
// Created by Juan Pablo Melgarejo on 7/17/20.
//

#include "hencrypt/hencrypt.hpp"

#include <chrono>
#include <thread>

#include "hencrypt/byte_conversions.hpp"
#include "hencrypt/file_utilities.hpp"

struct Chrono
{
    std::chrono::steady_clock::time_point t1;
    std::chrono::steady_clock::time_point t2;
};

enum class Strategy
{
    min_time, max_sec
};

struct OutputFile
{
    explicit OutputFile(std::string filename) : ofs(new std::ofstream(filename, std::ios::binary)), mutex(new std::mutex())
    {
    }
    std::unique_ptr<std::ofstream> ofs;
    std::unique_ptr<std::mutex> mutex;
};

Hencrypt::Hencrypt(Engine &engine, KeyManager &key_manager, CiphertextCodec &codec) : engine(engine), key_manager(key_manager), codec(codec), listener(
        nullptr)
{}

void Hencrypt::recordProcessingMeasurement(Chrono &chrono, bool is_encrypt)
{
    if (listener == nullptr)
        return;
    if (is_encrypt)
        listener->enc_processing_time_nano += std::chrono::duration_cast<std::chrono::nanoseconds>(chrono.t2 - chrono.t1).count();
    else
        listener->dec_processing_time_nano += std::chrono::duration_cast<std::chrono::nanoseconds>(chrono.t2 - chrono.t1).count();
}

void Hencrypt::recordIOMeasurement(Chrono &chrono, bool is_encrypt)
{
    if (listener == nullptr)
        return;
    std::lock_guard<std::mutex> guard(listener->io_lock);
    if (is_encrypt)
        listener->enc_io_time_nano += std::chrono::duration_cast<std::chrono::nanoseconds>(chrono.t2 - chrono.t1).count();
    else
        listener->dec_io_time_nano += std::chrono::duration_cast<std::chrono::nanoseconds>(chrono.t2 - chrono.t1).count();
}

void Hencrypt::recordDecisionMeasurement(Chrono &chrono)
{
    if (listener == nullptr)
        return;
    listener->decision_time_nano += std::chrono::duration_cast<std::chrono::nanoseconds>(chrono.t2 - chrono.t1).count();
}

std::string Hencrypt::encrypt(Strategy strategy, double max_time_available, int sec_level, double eval_time, const std::string &plaintext_filename)
{
    std::ifstream plaintext_file;
    plaintext_file.open(plaintext_filename, std::ios::binary);

    std::set<char> delims{'/'};
    std::vector<std::string> path = splitPath(plaintext_filename, delims);
    const std::string plaintext_name_only = path.back();
    std::string ciphertext_filename;

    byte_len plaintext_size = obtainFileSize(plaintext_file);

    // TODO: consider eval_time into the max-time-available
    int64_t max_time_us = max_time_available * 1000000; // sec to microsec

    std::vector<EncryptTask> scheduling;
    {
        Chrono chrono;
        chrono.t1 = std::chrono::steady_clock::now();
        if (strategy == Strategy::min_time)
            scheduling = engine.minimizeTime(eval_time, plaintext_size, sec_level);
        else
            scheduling = engine.maximizeSecurity(eval_time, plaintext_size, max_time_us);
        chrono.t2 = std::chrono::steady_clock::now();
        recordDecisionMeasurement(chrono);
    }

    std::map<std::string, OutputFile> device_files;
    std::vector<std::thread> io_threads;
    byte_len position = 0;
    for (int i = 0; i < scheduling.size(); i++)
    {
        auto &task = scheduling[i];
        byte_ptr input_buffer = byte_ptr(new byte[task.block_len + 1024], std::default_delete<byte[]>());

        Cipher cipher = toCipher(task.alg_name, task.key_len, task.mode_name);
        const CipherFactory &factory = toFactory(task.lib_name);

        byte_len block_len = remainingFileLen(plaintext_size, position, task.block_len);
        Chrono chrono;
        chrono.t1 = std::chrono::steady_clock::now();
        readInputFile(plaintext_file, input_buffer.get(), position, block_len);
        chrono.t2 = std::chrono::steady_clock::now();
        recordProcessingMeasurement(chrono, true);

        CipherPtr cipher_ptr;
        try
        {
            cipher_ptr = factory.getCipher(cipher);
        } catch (UnsupportedCipherException &ex)
        {
            // TODO: hecrypt exception
            throw ex;
        }

        byte_ptr output_buffer = byte_ptr(new byte[task.block_len + 1024], std::default_delete<byte[]>());
        const byte *key = key_manager.getKeyBySize(cipher_ptr->getKeyLen());
        byte_len output_size = block_len + 1024;

        chrono.t1 = std::chrono::steady_clock::now();
        cipher_ptr->encrypt(key, input_buffer.get(), block_len, output_buffer.get(), output_size);
        chrono.t2 = std::chrono::steady_clock::now();
        recordProcessingMeasurement(chrono, true);

        // Peek next fragment
        std::string next_fragment_filename;
        if (i < scheduling.size() - 1)
        {
            next_fragment_filename = scheduling[i + 1].device_path + plaintext_name_only;
        }

        const std::string fragment_filename = task.device_path + plaintext_name_only;
        auto found = device_files.find(fragment_filename);
        if (found == device_files.end())
        {
            found = device_files.emplace(fragment_filename, fragment_filename).first;
        }

        CiphertextFragment fragment = {task.lib_name, cipher, output_buffer, output_size, next_fragment_filename};
        io_threads.emplace_back(&Hencrypt::writeFragment, this, fragment, fragment_filename, std::ref(found->second));

        if (ciphertext_filename.empty())
        {
            ciphertext_filename = fragment_filename;
        }
        position += block_len;
        if (listener != nullptr)
            listener->fragments_info += std::to_string(block_len) + "-" + task.lib_name + "-" + task.alg_name + "-" + std::to_string(task.key_len) + "-" + task.mode_name + ":";
    }

    for (auto &worker : io_threads)
        worker.join();

    for (auto &open_files : device_files)
    {
        open_files.second.ofs->close();
    }

    plaintext_file.sync();
    plaintext_file.close();
    return ciphertext_filename;
}

std::string Hencrypt::encryptMinTime(int sec_level, double eval_time, const std::string &plaintext_filename)
{
    return encrypt(Strategy::min_time, -1, sec_level, eval_time, plaintext_filename);
}

std::string Hencrypt::encryptMaxSec(int64_t max_time, double eval_time, const std::string &plaintext_filename)
{
    return encrypt(Strategy::max_sec, max_time, -1, eval_time, plaintext_filename);
}

void
Hencrypt::writeFragment(CiphertextFragment fragment, std::string path, const OutputFile &outputFile)
{
    std::lock_guard<std::mutex> guard(*outputFile.mutex);
    Chrono chrono;

    chrono.t1 = std::chrono::steady_clock::now();
    codec.encode(*outputFile.ofs, fragment);
    chrono.t2 = std::chrono::steady_clock::now();
    recordIOMeasurement(chrono, true);
}

void Hencrypt::decrypt(const std::string &ciphertext_filename, const std::string &plaintext_filename)
{
    std::ofstream plaintext_file;
    plaintext_file.open(plaintext_filename, std::ios::binary);

    std::string fragment_filename = ciphertext_filename;

    std::map<std::string, byte_len> last_position;
    while (true)
    {
        CiphertextFragment fragment;
        auto found = last_position.find(fragment_filename);
        if (found == last_position.end())
        {
            found = last_position.emplace(fragment_filename, 0).first;
        }

        if (!readFragment(fragment, fragment_filename, found->second))
        {
            throw std::runtime_error("Corrupt cipher text fragment chain");
        }

        const CipherFactory &factory = toFactory(fragment.lib);
        CipherPtr cipher_ptr;
        try
        {
            cipher_ptr = factory.getCipher(fragment.cipher);
        } catch (UnsupportedCipherException &ex)
        {
            // TODO: hecrypt exception
            throw ex;
        }

        byte_ptr output_buffer = byte_ptr(new byte[fragment.len + 1024], std::default_delete<byte[]>());
        const byte *key = key_manager.getKeyBySize(cipher_ptr->getKeyLen());
        byte_len output_size = fragment.len + 1024;
        Chrono chrono;
        chrono.t1 = std::chrono::steady_clock::now();
        cipher_ptr->decrypt(key, fragment.bytes.get(), fragment.len, output_buffer.get(), output_size);
        chrono.t2 = std::chrono::steady_clock::now();
        recordProcessingMeasurement(chrono, false);

        chrono.t1 = std::chrono::steady_clock::now();
        writeOutputFile(plaintext_file, output_buffer.get(), output_size);
        chrono.t2 = std::chrono::steady_clock::now();
        recordIOMeasurement(chrono, false);

        fragment_filename = fragment.next_fragment_path;
        if (fragment_filename.empty())
        {
            break;
        }
    }

    plaintext_file.flush();
    plaintext_file.close();
}

bool Hencrypt::readFragment(CiphertextFragment &fragment, const std::string &path, byte_len &position)
{
    Chrono chrono;
    std::ifstream ifs;
    ifs.open(path, std::ios::binary);
    if (position != 0)
        ifs.seekg(position);

    chrono.t1 = std::chrono::steady_clock::now();
    if (!codec.decode(ifs, fragment))
        return false;
    chrono.t2 = std::chrono::steady_clock::now();
    recordIOMeasurement(chrono, false);

    byte_len p = ifs.tellg();
    position += p - position;

    ifs.close();
    return true;
}

const CipherFactory& Hencrypt::toFactory(const std::string &lib_name)
{

    if (lib_name == "openssl")
    {
        return open_ssl_cipher_factory;
    } else if (lib_name == "libsodium")
    {
        return libsodium_cipher_factory;
    } else if (lib_name == "gcrypt")
    {
        return libgcrypt_cipher_factory;
    } else if (lib_name == "cryptopp")
    {
        return cryptopp_cipher_factory;
    } else if (lib_name == "botan")
    {
        return botan_cipher_factory;
    } else if (lib_name == "wolfcrypt")
    {
        return wolf_crypt_cipher_factory;
    } else
    {
        throw std::runtime_error("Unknown library: " + lib_name);
    }
}

void Hencrypt::setPerformanceListener(PerfListener *listener)
{
    this->listener = listener;
    this->listener->decision_time_nano = 0;
    this->listener->enc_io_time_nano = 0;
    this->listener->enc_processing_time_nano = 0;
    this->listener->dec_io_time_nano = 0;
    this->listener->dec_processing_time_nano = 0;
}



