//
// Created by Juan Pablo Melgarejo on 7/14/20.
//

#ifndef CRYPTOBENCH_ENGINE_HPP
#define CRYPTOBENCH_ENGINE_HPP

#include <vector>
#include <array>
#include <fstream>
#include <iterator>

#include <ortools/constraint_solver/constraint_solver.h>
#include <ortools/sat/cp_model.h>
#include <ortools/sat/integer_expr.h>

typedef struct
{
    int64 begin_at_ns;
    int64 block_len;
    std::string lib_name;
    std::string alg_name;
    int key_len;
    std::string mode_name;
    std::string device_name;
} EncryptTask;

struct OptimizeTask;

class Engine
{
public:

    static Engine loadEngine(std::string system_profile_file_name, std::string cipher_seed_file_name);

    std::vector<EncryptTask> minimizeTime(double eval_time_sec, int64_t file_size, int sec_level);
    std::vector<EncryptTask> maximizeSecurity(double eval_time_sec, int64_t file_size, int64_t time_available_us);

private:

    static void loadSystemProfile(const std::string &system_profile_file_name, Engine &instance);
    static void loadCipherData(const std::string &cipher_seed_file_name, Engine &instance);

    Engine() = default;

private:

    int64 int_scale;
    std::vector<int64_t> blocks;
    std::vector<int> devices;
    std::vector<std::string> device_names;
    std::vector<std::vector<int64_t>> processors;
    std::vector<std::string> cipher_names;
    std::vector<int> sec_levels;


    void saveResult(const operations_research::sat::CpSolverResponse &response, std::vector<EncryptTask> &result, int proc_id
               , int device_id, const OptimizeTask &task) const;
};


#endif //CRYPTOBENCH_ENGINE_HPP
