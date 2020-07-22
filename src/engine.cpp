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

Engine::Engine(const SystemInfo &sys_info, CipherDatabase &cipher_database) : sys_info(sys_info), cipher_database(cipher_database)
{}

std::vector<EncryptTask> Engine::minimizeTime(double eval_time_sec, int64_t file_size, int sec_level)
{
    using namespace operations_research;

    // TODO: performance of INF horizon
    int64_t horizon = INT64_MAX - 1;

    auto &device_paces = sys_info.getDevicePaces();
    auto &cipher_times = cipher_database.getCipherTimesPerBlock();
    auto &sec_levels = cipher_database.getSecurityLevels();
    auto &block_sizes = cipher_database.getBlockSizes();

    std::vector<sat::IntervalVar> all_p_intervals;
    std::vector<sat::IntVar> all_io_ends;

    std::vector<std::vector<sat::IntervalVar>> per_device_intervals(device_paces.size());

    std::vector<std::vector<std::vector<OptimizeTask>>> all_tasks(cipher_times.size());
    long task_count = 0;

    std::vector<sat::BoolVar> all_chosen;
    std::vector<int64_t> all_block_sizes;

    sat::CpModelBuilder cp_model;
    Domain domain(0, horizon);
    for (int proc_id = 0; proc_id < cipher_times.size(); proc_id++)
    {
        if (sec_levels[proc_id] != sec_level)
            continue;

        all_tasks[proc_id] = std::vector<std::vector<OptimizeTask>>(block_sizes.size());
        for (int block_id = 0; block_id < block_sizes.size(); block_id++)
        {
            if (cipher_times[proc_id][block_id] == 0 || block_sizes[block_id] > file_size)
                continue;
            all_tasks[proc_id][block_id] = std::vector<OptimizeTask>(device_paces.size());
            for (int device_id = 0; device_id < device_paces.size(); device_id++)
            {
                sat::BoolVar chosen = cp_model.NewBoolVar();
                all_chosen.push_back(chosen);
                all_block_sizes.push_back(block_sizes[block_id]);

                sat::IntVar p_time = cp_model.NewConstant(cipher_times[proc_id][block_id]);
                sat::IntVar p_start = cp_model.NewIntVar(domain);
                sat::IntVar p_end = cp_model.NewIntVar(domain);
                sat::IntervalVar p_interval = cp_model.NewOptionalIntervalVar(p_start, p_time, p_end, chosen);

                all_p_intervals.push_back(p_interval);

                sat::IntVar io_time = cp_model.NewConstant(block_sizes[block_id] * device_paces[device_id]);
                sat::IntVar io_end = cp_model.NewIntVar(domain);
                sat::IntervalVar io_interval = cp_model.NewOptionalIntervalVar(p_end, io_time, io_end, chosen);

                all_io_ends.push_back(io_end);
                per_device_intervals[device_id].push_back(io_interval);

                all_tasks[proc_id][block_id][device_id] = OptimizeTask{p_interval, io_interval, block_sizes[block_id]};
                task_count++;
            }
        }
    }

    /// Constraints
    cp_model.AddNoOverlap(all_p_intervals);
    for (int device_id = 0; device_id < device_paces.size(); device_id++)
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
        for (int proc_id = 0; proc_id < cipher_times.size(); proc_id++)
        {
            if (sec_levels[proc_id] != sec_level)
                continue;

            for (int device_id = 0; device_id < device_paces.size(); device_id++)
            {
                for (int block_id = 0; block_id < block_sizes.size(); block_id++)
                {
                    if (cipher_times[proc_id][block_id] == 0 || block_sizes[block_id] > file_size)
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
    int64_t time_available_ns = time_available_us * 1000; // to ns

    // TODO: performance of INF horizon
    int64_t horizon = INT64_MAX - 1;

    auto &device_paces = sys_info.getDevicePaces();
    auto &cipher_times = cipher_database.getCipherTimesPerBlock();
    auto &sec_levels = cipher_database.getSecurityLevels();
    auto &block_sizes = cipher_database.getBlockSizes();

    std::vector<sat::IntervalVar> all_p_intervals;
    std::vector<sat::IntVar> all_io_ends;

    std::vector<std::vector<sat::IntervalVar>> per_device_intervals(device_paces.size());

    std::vector<std::vector<std::vector<OptimizeTask>>> all_tasks(cipher_times.size());
    long task_count = 0;

    std::vector<sat::BoolVar> all_chosen;
    std::vector<int64_t> all_block_sizes;
    std::vector<int64_t> all_weighted_sec_levels;

    sat::CpModelBuilder cp_model;
    Domain domain(0, horizon);
    for (int proc_id = 0; proc_id < cipher_times.size(); proc_id++)
    {
        all_tasks[proc_id] = std::vector<std::vector<OptimizeTask>>(block_sizes.size());
        for (int block_id = 0; block_id < block_sizes.size(); block_id++)
        {
            if (cipher_times[proc_id][block_id] == 0 || block_sizes[block_id] > file_size)
                continue;
            all_tasks[proc_id][block_id] = std::vector<OptimizeTask>(device_paces.size());
            for (int device_id = 0; device_id < device_paces.size(); device_id++)
            {
                sat::BoolVar chosen = cp_model.NewBoolVar();
                all_chosen.push_back(chosen);
                all_block_sizes.push_back(block_sizes[block_id]);

                // This assumes descending block order
                ulong block_rank = block_sizes.size() - block_id;
                all_weighted_sec_levels.push_back((int64_t) std::pow(block_rank, sec_levels[proc_id]));

                sat::IntVar p_time = cp_model.NewConstant(cipher_times[proc_id][block_id]);
                sat::IntVar p_start = cp_model.NewIntVar(domain);
                sat::IntVar p_end = cp_model.NewIntVar(domain);
                sat::IntervalVar p_interval = cp_model.NewOptionalIntervalVar(p_start, p_time, p_end, chosen);

                all_p_intervals.push_back(p_interval);

                sat::IntVar io_time = cp_model.NewConstant(block_sizes[block_id] * device_paces[device_id]);
                sat::IntVar io_end = cp_model.NewIntVar(domain);
                sat::IntervalVar io_interval = cp_model.NewOptionalIntervalVar(p_end, io_time, io_end, chosen);

                all_io_ends.push_back(io_end);
                per_device_intervals[device_id].push_back(io_interval);

                all_tasks[proc_id][block_id][device_id] = OptimizeTask{p_interval, io_interval, block_sizes[block_id]};
                task_count++;
            }
        }
    }

    /// Constraints
    cp_model.AddNoOverlap(all_p_intervals);
    for (int device_id = 0; device_id < device_paces.size(); device_id++)
    {
        cp_model.AddNoOverlap(per_device_intervals[device_id]);
    }

    sat::IntVar block_sum = cp_model.NewIntVar(domain);
    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_block_sizes), block_sum);
    cp_model.AddGreaterOrEqual(block_sum, file_size);

    sat::IntVar makespan = cp_model.NewIntVar(domain);
    cp_model.AddMaxEquality(makespan, all_io_ends);
    cp_model.AddLessOrEqual(makespan, time_available_ns);

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
        for (int proc_id = 0; proc_id < cipher_times.size(); proc_id++)
        {
            for (int device_id = 0; device_id < device_paces.size(); device_id++)
            {
                for (int block_id = 0; block_id < block_sizes.size(); block_id++)
                {
                    if (cipher_times[proc_id][block_id] == 0 || block_sizes[block_id] > file_size)
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
    auto &cipher_names = cipher_database.getCipherNames();
    auto &device_names = sys_info.getDeviceNames();
    auto &device_paths = sys_info.getDeviceStorePath();

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
    std::string device_path = device_paths[device_id];
    result.push_back({begin, block_len, lib_name, alg_name, key_len, mode_name, device_name, device_path});
}