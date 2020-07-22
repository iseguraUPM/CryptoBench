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

#include "system_info.hpp"
#include "cipher_database.hpp"

struct EncryptTask
{
    int64 begin_at_ns;
    int64 block_len;
    std::string lib_name;
    std::string alg_name;
    int key_len;
    std::string mode_name;
    std::string device_name;
    std::string device_path;
};

struct OptimizeTask;

class Engine
{
public:

    explicit Engine(const SystemInfo &sys_info, CipherDatabase &cipher_database);

    std::vector<EncryptTask> minimizeTime(double eval_time_sec, int64_t file_size, int sec_level);
    std::vector<EncryptTask> maximizeSecurity(double eval_time_sec, int64_t file_size, int64_t time_available_us);

private:

    void saveResult(const operations_research::sat::CpSolverResponse &response, std::vector<EncryptTask> &result, int proc_id
                    , int device_id, const OptimizeTask &task) const;

private:

    const SystemInfo &sys_info;
    CipherDatabase &cipher_database;

};


#endif //CRYPTOBENCH_ENGINE_HPP
