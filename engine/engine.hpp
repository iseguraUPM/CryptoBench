//
// Created by Juan Pablo Melgarejo on 7/14/20.
//

#ifndef CRYPTOBENCH_ENGINE_HPP
#define CRYPTOBENCH_ENGINE_HPP

#include <vector>
#include <array>

#include <ortools/constraint_solver/constraint_solver.h>
#include <ortools/sat/cp_model.h>
#include <ortools/sat/integer_expr.h>

typedef struct {
    int64 begin_at_ns;
    int64 block_len;
    std::string cipher_name;
    std::string device_name;
} EncryptTask;

class Engine
{
public:
    Engine();
    std::vector<EncryptTask> minimizeTime(int64_t file_size, int sec_level);
    void maximizeSecurity(int64_t file_size, int64_t time_available);

private:
    std::vector<int64_t> blocks;
    std::vector<int> devices;
    std::vector<std::string> device_names;
    std::vector<std::vector<int64_t>> processors;
    std::vector<std::string> cipher_names;
    std::vector<int> sec_levels;

};


#endif //CRYPTOBENCH_ENGINE_HPP
