//
// Created by ISU on 22/07/2020.
//

#include <chrono>
#include <utility>
#include <iostream>
#include <iomanip>

#include <CryptoBench/hencrypt.hpp>

#define MAX_ENGINE_TIME_SEC 8

struct OutputSet
{
    OutputSet(std::ostream &perf, std::ostream &err) : perf_result(perf),
                                                       error_log(err)
    {
    }

    std::ostream &perf_result;
    std::ostream &error_log;
};

std::string timeStringNowFormat(const char *format)
{
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), format);
    return std::move(ss.str());
}

void recordError(std::string strategy, int sec_level, double eval_time, byte_len input_size, const std::string msg
                 , std::ostream &error_log)
{
    error_log << timeStringNowFormat("%Y-%m-%d %H:%M:%S ")
              << "strategy: " << strategy << " "
              << "sec: " << sec_level << " "
              << "time: " << eval_time << " ("
              << std::to_string(input_size) << " B): "
              << msg
              << "\n";
}

struct BenchmarkResult
{
    std::string strategy;
    unsigned long overall_time_nano{};
    unsigned long decision_time_nano{};
    unsigned long encrypt_time_nano{};
    unsigned long decrypt_time_nano{};
    unsigned long  encrypt_io_time_nano{};
    unsigned long  decrypt_io_time_nano{};
    int sec_level{};
    byte_len input_size{};
    std::vector<std::string> cipher_list;
    std::string fragmentsInfo;

    BenchmarkResult() = default;

    BenchmarkResult(std::string strategy, int sec_level, double eval_time, byte_len input_size, std::vector<std::string> cipher_list, std::string fragmentsInfo)
            : strategy(strategy), sec_level(sec_level), input_size(input_size), cipher_list(cipher_list), fragmentsInfo(fragmentsInfo)
    {
        overall_time_nano = 0;
        decision_time_nano = 0;
        encrypt_time_nano = 0;
        encrypt_io_time_nano = 0;
        decrypt_time_nano = 0;
        decrypt_io_time_nano = 0;
    }

};

void recordResult(BenchmarkResult &result, std::ostream &file_stream)
{
    std::stringstream result_line;
    result_line << HENCRYPT_SYS_ARCH << ","
                << result.fragmentsInfo << ","
                << result.strategy << ","
                << result.input_size << ","
                << result.sec_level << ","
                << result.overall_time_nano << ","
                << result.decision_time_nano << ","
                << result.encrypt_time_nano << ","
                << result.decrypt_time_nano << ","
                << result.encrypt_io_time_nano << ","
                << result.decrypt_io_time_nano << "\n";

    file_stream << result_line.str();
#ifdef CRYPTOBENCH_DEBUG
    std::cout << result_line.str();
#endif
}

void runEngineBenchmark(Hencrypt &hencrypt, int sec_level, double &eval_time, std::string input_filename, byte_len input_size, std::string strategy, OutputSet &output_set, bool &repeat)
{
    PerfListener listener;
    hencrypt.setPerformanceListener(&listener);
    using std::chrono::steady_clock;
    std::string fragmentsInfo;

    steady_clock::time_point t1 = steady_clock::now();
    fragmentsInfo = hencrypt.encryptMinTime(sec_level, eval_time, input_filename);
    steady_clock::time_point t2 = steady_clock::now();
    unsigned long overall_t = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
    // TODO: decrypt

    if (listener.cipher_list.empty() && eval_time < MAX_ENGINE_TIME_SEC)
    {
        repeat = true;
        eval_time += 1;
        return;
    } else
    {
        repeat = false;
    }

    BenchmarkResult result(strategy, sec_level, eval_time, input_size, listener.cipher_list, fragmentsInfo);
    result.overall_time_nano = overall_t;
    result.decision_time_nano = listener.decision_time_nano;
    result.encrypt_time_nano = listener.enc_processing_time_nano;
    result.encrypt_io_time_nano = listener.enc_io_time_nano;
    result.decrypt_time_nano = listener.dec_processing_time_nano;
    result.decrypt_io_time_nano = listener.dec_io_time_nano;
    result.cipher_list = listener.cipher_list;

    recordResult(result, output_set.perf_result);
}

void runBenchmark(std::string &input_filename, std::string &key_filename, std::string &system_profile, std::string &cipher_seed, std::string &results_filename, std::string &error_filename)
{
    std::ofstream results_file;
    results_file.open(results_filename, std::ios::app);
    std::ofstream error_file;
    error_file.open(error_filename, std::ios::app);
    OutputSet output_set = OutputSet(results_file, error_file);

    std::ifstream input_file(input_filename);
    byte_len input_size = obtainFileSize(input_file);
    input_file.close();

    std::string strategy = "min-time";
    int sec_levels[] = { 1, 2, 3, 4, 5 };
    for (int sec_level : sec_levels)
    {
        double eval_time = 1;
        bool repeat = false;
        do
        {
            try
            {
                SystemInfo system_info = SystemInfo::getInstance(system_profile);
                CipherDatabase cipher_database = CipherDatabase::getInstance(cipher_seed);

                Engine encryption_engine = Engine(system_info, cipher_database);

                CiphertextCodec codec;
                KeyManager key_manager = KeyManager(key_filename);
                Hencrypt hencrypt(encryption_engine, key_manager, codec);
                runEngineBenchmark(hencrypt, sec_level, eval_time, input_filename, input_size, strategy, output_set, repeat);
            } catch (std::exception &ex)
            {
                recordError(strategy, sec_level, eval_time, input_size, ex.what(), error_file);
            }
        } while (repeat);

    }

    error_file.close();
    results_file.close();
}

int arg_no = 1;
std::string nextArg(char **argv)
{
    return std::string(argv[arg_no++]);
}

int main(int argc, char** argv)
{
    if (argc == 7) {
        std::string input_file = nextArg(argv);
        std::string key_file = nextArg(argv);
        std::string system_profile = nextArg(argv);
        std::string cipher_seed = nextArg(argv);
        std::string results_filename = nextArg(argv);
        std::string error_filename = nextArg(argv);
        runBenchmark(input_file, key_file, system_profile, cipher_seed, results_filename, error_filename);
        return 0;
    }

    std::cerr << "Invalid arguments" << std::endl;
    std::cout << "Usage: " << argv[0] << " <input file> <key file> <system profile> <cipher seed> <results file> <error log file>" << std::endl;
    return 1;
}