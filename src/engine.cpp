//
// Created by Juan Pablo Melgarejo on 7/14/20.
//

#include "CryptoBench/engine.hpp"

struct OptimizeTask
{
    operations_research::sat::IntervalVar p_interval;
    operations_research::sat::IntervalVar io_interval;
    int64_t block_len;
};

Engine Engine::loadEngine(std::string system_profile_file_name, std::string cipher_seed_file_name)
{
    Engine instance;

    loadSystemProfile(system_profile_file_name, instance);
    loadCipherData(cipher_seed_file_name, instance);

    return instance;
}

void Engine::loadSystemProfile(const std::string &system_profile_file_name, Engine &instance)
{
    std::ifstream f(system_profile_file_name);

    if(!f)
    {
        throw std::runtime_error("Error opening system profile: " + system_profile_file_name);
    }

    std::string line;
    while(std::getline(f,line)) {
        std::istringstream iss_device(line);
        std::string device;
        int64 pace;
        iss_device >> device;
        instance.device_names.push_back(device);
        iss_device >> pace;
        instance.devices.push_back(pace);
    }
}

void Engine::loadCipherData(const std::string &cipher_seed_file_name, Engine &instance)
{
    std::ifstream f(cipher_seed_file_name);

    if(!f)
    {
        throw std::runtime_error("Error opening cipher seed: " + cipher_seed_file_name);
    }

    std::string line;
    int64_t word;
    std::getline(f,line);
    std::istringstream iss_block(line);

    while (iss_block >> word) {
        instance.blocks.push_back(word);
    }

    std::getline(f, line);
    std::istringstream iss_scale(line);
    iss_scale >> instance.int_scale;

    while(std::getline(f,line)) {
        std::istringstream iss_cipher(line);
        std::string cipher;
        int64 security_level;
        iss_cipher >> cipher;
        instance.cipher_names.push_back(cipher);
        iss_cipher >> security_level;
        instance.sec_levels.push_back(security_level);

        std::vector<int64> cipher_paces;
        while (iss_cipher >> word) {
            cipher_paces.push_back(word);
        }
        instance.processors.push_back(cipher_paces);
    }
}

std::vector<EncryptTask> Engine::minimizeTime(double eval_time_sec, int64_t file_size, int sec_level)
{
    using namespace operations_research;

    // TODO: performance of INF horizon
    int64_t horizon = INT64_MAX - 1;

    std::vector<sat::IntervalVar> all_p_intervals;
    std::vector<sat::IntVar> all_io_ends;

    std::vector<std::vector<sat::IntervalVar>> per_device_intervals(devices.size());

    std::vector<std::vector<std::vector<OptimizeTask>>> all_tasks(processors.size());
    long task_count = 0;

    std::vector<sat::BoolVar> all_chosen;
    std::vector<int64_t> all_block_sizes;

    sat::CpModelBuilder cp_model;
    Domain domain(0, horizon);
    for (int proc_id = 0; proc_id < processors.size(); proc_id++)
    {
        if (sec_levels[proc_id] != sec_level)
            continue;

        all_tasks[proc_id] = std::vector<std::vector<OptimizeTask>>(blocks.size());
        for (int block_id = 0; block_id < blocks.size(); block_id++)
        {
            if (processors[proc_id][block_id] == 0 || blocks[block_id] > file_size)
                continue;
            all_tasks[proc_id][block_id] = std::vector<OptimizeTask>(devices.size());
            for (int device_id = 0; device_id < devices.size(); device_id++)
            {
                sat::BoolVar chosen = cp_model.NewBoolVar();
                all_chosen.push_back(chosen);
                all_block_sizes.push_back(blocks[block_id]);

                sat::IntVar p_time = cp_model.NewConstant(blocks[block_id] * processors[proc_id][block_id]);
                sat::IntVar p_start = cp_model.NewIntVar(domain);
                sat::IntVar p_end = cp_model.NewIntVar(domain);
                sat::IntervalVar p_interval = cp_model.NewOptionalIntervalVar(p_start, p_time, p_end, chosen);

                all_p_intervals.push_back(p_interval);

                sat::IntVar io_time = cp_model.NewConstant(blocks[block_id] * devices[device_id]);
                sat::IntVar io_end = cp_model.NewIntVar(domain);
                sat::IntervalVar io_interval = cp_model.NewOptionalIntervalVar(p_end, io_time, io_end, chosen);

                all_io_ends.push_back(io_end);
                per_device_intervals[device_id].push_back(io_interval);

                all_tasks[proc_id][block_id][device_id] = OptimizeTask{p_interval, io_interval, blocks[block_id]};
                task_count++;
            }
        }
    }

    /// Constraints
    cp_model.AddNoOverlap(all_p_intervals);
    for (int device_id = 0; device_id < devices.size(); device_id++)
    {
        cp_model.AddNoOverlap(per_device_intervals[device_id]);
    }

    sat::IntVar block_sum = cp_model.NewIntVar(domain);
    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_block_sizes), block_sum);
    cp_model.AddGreaterOrEqual(block_sum, file_size);

    /// Objective
    cp_model.Minimize(block_sum);

    sat::IntVar obj_var = cp_model.NewIntVar(domain);
    cp_model.AddMaxEquality(obj_var, all_io_ends);
    cp_model.Minimize(obj_var);

    cp_model.Minimize(sat::LinearExpr::BooleanSum(all_chosen));

    /// Add time limit constraint in order to find feasible solutions
    sat::Model model;
    sat::SatParameters parameters;
    parameters.set_max_time_in_seconds(eval_time_sec);
    model.Add(NewSatParameters(parameters));

    /// Solver
    sat::CpModelProto model_proto = cp_model.Build();
    sat::CpSolverResponse response = sat::SolveCpModel(model_proto, &model);

    std::vector<EncryptTask> result;
    if (response.status() == sat::CpSolverStatus::OPTIMAL || response.status() == sat::CpSolverStatus::FEASIBLE)
    {
        for (int proc_id = 0; proc_id < processors.size(); proc_id++)
        {
            if (sec_levels[proc_id] != sec_level)
                continue;

            for (int device_id = 0; device_id < devices.size(); device_id++)
            {
                for (int block_id = 0; block_id < blocks.size(); block_id++)
                {
                    if (processors[proc_id][block_id] == 0 || blocks[block_id] > file_size)
                        continue;

                    auto &task = all_tasks[proc_id][block_id][device_id];
                    if (!sat::SolutionBooleanValue(response, task.p_interval.PresenceBoolVar()))
                    {
                        continue;
                    }

                    saveResult(response, result, proc_id, device_id, task);
                }
            }
        }
        std::sort(result.begin(), result.end(),
                [](const EncryptTask& a, const EncryptTask& b) {
                    return a.begin_at_ns < b.begin_at_ns;
        });

    }
    return result;
}

std::vector<EncryptTask> Engine::maximizeSecurity(double eval_time_sec, int64_t file_size, int64_t time_available_us)
{
    using namespace operations_research;
    time_available_us *= 1000; // to ns

    // TODO: performance of INF horizon
    int64_t horizon = INT64_MAX - 1;

    std::vector<sat::IntervalVar> all_p_intervals;
    std::vector<sat::IntVar> all_io_ends;

    std::vector<std::vector<sat::IntervalVar>> per_device_intervals(devices.size());

    std::vector<std::vector<std::vector<OptimizeTask>>> all_tasks(processors.size());
    long task_count = 0;

    std::vector<sat::BoolVar> all_chosen;
    std::vector<int64_t> all_block_sizes;
    std::vector<int64_t> all_weighted_sec_levels;

    sat::CpModelBuilder cp_model;
    Domain domain(0, horizon);
    for (int proc_id = 0; proc_id < processors.size(); proc_id++)
    {
        all_tasks[proc_id] = std::vector<std::vector<OptimizeTask>>(blocks.size());
        for (int block_id = 0; block_id < blocks.size(); block_id++)
        {
            if (processors[proc_id][block_id] == 0 || blocks[block_id] > file_size)
                continue;
            all_tasks[proc_id][block_id] = std::vector<OptimizeTask>(devices.size());
            for (int device_id = 0; device_id < devices.size(); device_id++)
            {
                sat::BoolVar chosen = cp_model.NewBoolVar();
                all_chosen.push_back(chosen);
                all_block_sizes.push_back(blocks[block_id]);

                // This assumes descending block order
                ulong block_rank = blocks.size() - block_id;
                all_weighted_sec_levels.push_back((int64_t) std::pow(block_rank, sec_levels[proc_id]));

                sat::IntVar p_time = cp_model.NewConstant(blocks[block_id] * processors[proc_id][block_id]);
                sat::IntVar p_start = cp_model.NewIntVar(domain);
                sat::IntVar p_end = cp_model.NewIntVar(domain);
                sat::IntervalVar p_interval = cp_model.NewOptionalIntervalVar(p_start, p_time, p_end, chosen);

                all_p_intervals.push_back(p_interval);

                sat::IntVar io_time = cp_model.NewConstant(blocks[block_id] * devices[device_id]);
                sat::IntVar io_end = cp_model.NewIntVar(domain);
                sat::IntervalVar io_interval = cp_model.NewOptionalIntervalVar(p_end, io_time, io_end, chosen);

                all_io_ends.push_back(io_end);
                per_device_intervals[device_id].push_back(io_interval);

                all_tasks[proc_id][block_id][device_id] = OptimizeTask{p_interval, io_interval, blocks[block_id]};
                task_count++;
            }
        }
    }

    /// Constraints
    cp_model.AddNoOverlap(all_p_intervals);
    for (int device_id = 0; device_id < devices.size(); device_id++)
    {
        cp_model.AddNoOverlap(per_device_intervals[device_id]);
    }

    sat::IntVar block_sum = cp_model.NewIntVar(domain);
    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_block_sizes), block_sum);
    cp_model.AddGreaterOrEqual(block_sum, file_size);

    sat::IntVar makespan = cp_model.NewIntVar(domain);
    cp_model.AddMaxEquality(makespan, all_io_ends);
    cp_model.AddLessOrEqual(makespan, time_available_us * int_scale);

    /// Objective
    cp_model.Minimize(block_sum);

    cp_model.Maximize(makespan);

    sat::IntVar weighted_security = cp_model.NewIntVar(domain);
    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_weighted_sec_levels), weighted_security);
    cp_model.Maximize(weighted_security);

    cp_model.Minimize(sat::LinearExpr::BooleanSum(all_chosen));

    /// Add time limit constraint in order to find feasible solutions
    sat::Model model;
    sat::SatParameters parameters;
    parameters.set_max_time_in_seconds(eval_time_sec);
    model.Add(NewSatParameters(parameters));

    /// Solver
    sat::CpModelProto model_proto = cp_model.Build();
    sat::CpSolverResponse response = sat::SolveCpModel(model_proto, &model);

    std::vector<EncryptTask> result;
    if (response.status() == sat::CpSolverStatus::OPTIMAL || response.status() == sat::CpSolverStatus::FEASIBLE)
    {
        for (int proc_id = 0; proc_id < processors.size(); proc_id++)
        {
            for (int device_id = 0; device_id < devices.size(); device_id++)
            {
                for (int block_id = 0; block_id < blocks.size(); block_id++)
                {
                    if (processors[proc_id][block_id] == 0 || blocks[block_id] > file_size)
                        continue;

                    auto &task = all_tasks[proc_id][block_id][device_id];
                    if (!sat::SolutionBooleanValue(response, task.p_interval.PresenceBoolVar()))
                    {
                        continue;
                    }

                    saveResult(response, result, proc_id, device_id, task);
                }
            }
        }
        std::sort(result.begin(), result.end(),
                [](const EncryptTask& a, const EncryptTask& b) {
                    return a.begin_at_ns < b.begin_at_ns;
                });

    }
    return result;
}

void Engine::saveResult(const operations_research::sat::CpSolverResponse &response, std::vector<EncryptTask> &result
                        , int proc_id, int device_id, const OptimizeTask &task) const
{
    // start_p, bytes, encryption, device
    int64 begin = operations_research::sat::SolutionIntegerValue(response, task.p_interval.StartVar());
    int64 block_len = task.block_len;

    std::stringstream ss(cipher_names[proc_id]);

    std::string lib_name;
    std::getline(ss, lib_name, '-');

    std::string alg_name;
    std::getline(ss, alg_name, '-');

    std::string keylen_str;
    std::getline(ss, keylen_str, '-');
    int key_len = std::stoi(keylen_str);

    std::string mode_name;
    std::getline(ss, mode_name, '-');

    std::string device_name = device_names[device_id];
    result.push_back({begin, block_len, lib_name, alg_name, key_len, mode_name, device_name});
}
