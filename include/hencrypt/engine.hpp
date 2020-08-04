//
// Created by Juan Pablo Melgarejo on 7/14/20.
//

#ifndef HENCRYPT_ENGINE_HPP
#define HENCRYPT_ENGINE_HPP

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

    /**
     * Compute the encryption tasks necessary to minimize the encryption time of a file in keeping within the desired encryption
     * level.
     * @param eval_time_sec time to compute the algorithm in seconds
     * @param file_size input file size
     * @param sec_level desired security level
     * @return the encryption tasks in order of execution
     */
    std::vector<EncryptTask> minimizeTime(double eval_time_sec, int64_t file_size, int sec_level);

    /**
     * Compute the encryption tasks necessary to maximize the security level of an encryption in keeping within the desired
     * available time.
     * @param eval_time_sec time to compute the algorithm
     * @param file_size input file size
     * @param time_available_us available time in microseconds
     * @return the encryption tasks in order of execution
     */
    std::vector<EncryptTask> maximizeSecurity(double eval_time_sec, int64_t file_size, int64_t time_available_us);

private:

    void saveResult(const operations_research::sat::CpSolverResponse &response, std::vector<EncryptTask> &result, int proc_id
                    , int device_id, const OptimizeTask &task) const;

private:

    const SystemInfo &sys_info;
    CipherDatabase &cipher_database;

};


#endif //HENCRYPT_ENGINE_HPP
