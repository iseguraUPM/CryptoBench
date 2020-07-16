//
// Created by Juan Pablo Melgarejo on 7/14/20.
//

#include "engine.hpp"

Engine::Engine()
{

    devices = { 1, 40};
    device_names = {"ssd", "hdd"};

    std::ifstream f("/home/cc/CryptoBench/engine/cipher_paces.dat");

    if(!f)
    {
        std::cerr << "Error opening cipher data.\n";
        return;
    }

    std::string line;
    int64_t word;
    std::getline(f,line);
    std::istringstream iss_block(line);

    while (iss_block >> word) {
        blocks.push_back(word);
    }

    while(std::getline(f,line)){
        std::istringstream iss_cipher(line);
        std::string cipher_tmp;
        int64_t sec_tmp;
        iss_cipher >> cipher_tmp;
        cipher_names.push_back(cipher_tmp);
        iss_cipher >> sec_tmp;
        sec_levels.push_back(sec_tmp);

        std::vector<int64_t> processor_tmp;
        while (iss_cipher >> word) {
            processor_tmp.push_back(word);
        }
        processors.push_back(processor_tmp);
    }
}

std::vector<EncryptTask> Engine::minimizeTime(int64_t file_size, int sec_level)
{
    using namespace operations_research;

    // TODO: performance of INF horizon
    int64_t horizon = INT64_MAX - 1;

    struct Task {
        sat::IntervalVar p_interval;
        sat::IntervalVar io_interval;
        int64_t block_len;
    };

    std::vector<sat::IntervalVar> all_p_intervals;
    std::vector<sat::IntVar> all_io_ends;

    std::vector<std::vector<sat::IntervalVar>> per_device_intervals(devices.size());

    std::vector<std::vector<std::vector<Task>>> all_tasks(processors.size());
    long task_count = 0;

    std::vector<sat::BoolVar> all_chosen;
    std::vector<int64_t> all_block_sizes;
    std::vector<int64_t> all_sec_levels;

    sat::CpModelBuilder cp_model;
    Domain domain(0, horizon);
    for (int proc_id = 0; proc_id < processors.size(); proc_id++)
    {
        if (sec_levels[proc_id] != sec_level)
            continue;

        all_tasks[proc_id] = std::vector<std::vector<Task>>(blocks.size());
        for (int block_id = 0; block_id < blocks.size(); block_id++)
        {
            if (processors[proc_id][block_id] == 0 || blocks[block_id] > file_size)
                continue;
            all_tasks[proc_id][block_id] = std::vector<Task>(devices.size());
            for (int device_id = 0; device_id < devices.size(); device_id++)
            {
                std::stringstream ss;
                ss << "_" << block_id << "_" << proc_id << "_" << device_id;
                sat::BoolVar chosen = cp_model.NewBoolVar().WithName("chosen" + ss.str());
                all_chosen.push_back(chosen);
                all_block_sizes.push_back(blocks[block_id]);
                all_sec_levels.push_back(sec_levels[proc_id]);

                sat::IntVar p_time = cp_model.NewConstant(blocks[block_id] * processors[proc_id][block_id]);
                sat::IntVar p_start = cp_model.NewIntVar(domain).WithName("p_start" + ss.str());
                sat::IntVar p_end = cp_model.NewIntVar(domain).WithName("p_end" + ss.str());
                sat::IntervalVar p_interval = cp_model.NewOptionalIntervalVar(p_start, p_time, p_end, chosen).WithName("p_interval" + ss.str());

                all_p_intervals.push_back(p_interval);

                sat::IntVar io_time = cp_model.NewConstant(blocks[block_id] * devices[device_id]);
                sat::IntVar io_start = cp_model.NewIntVar(domain).WithName("io_start" + ss.str());
                sat::IntVar io_end = cp_model.NewIntVar(domain).WithName("io_end" + ss.str());
                sat::IntervalVar io_interval = cp_model.NewOptionalIntervalVar(io_start, io_time, io_end, chosen).WithName("io_interval" + ss.str());

                all_io_ends.push_back(io_end);
                per_device_intervals[device_id].push_back(io_interval);

                all_tasks[proc_id][block_id][device_id] = Task{p_interval, io_interval, blocks[block_id]};
                task_count++;

                /// Precedence constraint
                cp_model.AddGreaterOrEqual(io_start, p_end).OnlyEnforceIf(chosen);
            }
        }
    }

    std::cout << "Finished preparing data" << std::endl;
    std::cout << "\tConsidering " << task_count << " tasks" << std::endl;

    /// Constraints
    cp_model.AddNoOverlap(all_p_intervals);
    for (int device_id = 0; device_id < devices.size(); device_id++)
    {
        cp_model.AddNoOverlap(per_device_intervals[device_id]);
    }

    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_block_sizes), file_size);

    // Just for evaluation purposes
    sat::IntVar overall_security = cp_model.NewIntVar(domain).WithName("overall_security");
    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_sec_levels), overall_security);

    /// Objective
    sat::IntVar obj_var = cp_model.NewIntVar(domain).WithName("makespan");
    cp_model.AddMaxEquality(obj_var, all_io_ends);
    cp_model.Minimize(obj_var);

    sat::IntVar choices = cp_model.NewIntVar({0, task_count}).WithName("choices");
    cp_model.AddEquality(choices, sat::LinearExpr::BooleanSum(all_chosen));
    cp_model.Minimize(choices);


    /// Add time limit constraint in order to find feasible solutions
    sat::Model model;
    sat::SatParameters parameters;
    parameters.set_max_time_in_seconds(10.0);
    model.Add(NewSatParameters(parameters));

    /// Solver
    sat::CpModelProto model_proto = cp_model.Build();
    sat::CpSolverResponse response = sat::SolveCpModel(model_proto, &model);

    std::vector<EncryptTask> result;
    if (response.status() == sat::CpSolverStatus::OPTIMAL || response.status() == sat::CpSolverStatus::FEASIBLE)
    {
        auto mean_sec_level = (double) sat::SolutionIntegerValue(response, overall_security) / sat::SolutionIntegerValue(response, choices);

        std::stringstream processor_tasks;
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
                    // start_p, bytes, encryption, device
                    int64 begin = sat::SolutionIntegerValue(response, task.p_interval.StartVar());
                    int64 block_len = task.block_len;
                    std::string cipher_name = cipher_names[proc_id];
                    std::string device_name = device_names[device_id];
                    result.push_back({begin, block_len, cipher_name, device_name});
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

std::vector<EncryptTask> Engine::maximizeSecurity(int64_t file_size, int64_t time_available)
{
    using namespace operations_research;

    // TODO: performance of INF horizon
    int64_t horizon = INT64_MAX - 1;

    struct Task {
        sat::IntervalVar p_interval;
        sat::IntervalVar io_interval;
        int64_t block_len;
    };

    std::vector<sat::IntervalVar> all_p_intervals;
    std::vector<sat::IntVar> all_io_ends;

    std::vector<std::vector<sat::IntervalVar>> per_device_intervals(devices.size());

    std::vector<std::vector<std::vector<Task>>> all_tasks(processors.size());
    long task_count = 0;

    std::vector<sat::BoolVar> all_chosen;
    std::vector<int64_t> all_block_sizes;
    std::vector<int64_t> all_sec_levels;
    std::vector<int64_t> all_weighted_sec_levels;

    sat::CpModelBuilder cp_model;
    Domain domain(0, horizon);
    for (int proc_id = 0; proc_id < processors.size(); proc_id++)
    {
        all_tasks[proc_id] = std::vector<std::vector<Task>>(blocks.size());
        for (int block_id = 0; block_id < blocks.size(); block_id++)
        {
            if (processors[proc_id][block_id] == 0 || blocks[block_id] > file_size)
                continue;
            all_tasks[proc_id][block_id] = std::vector<Task>(devices.size());
            for (int device_id = 0; device_id < devices.size(); device_id++)
            {
                std::stringstream ss;
                ss << "_" << block_id << "_" << proc_id << "_" << device_id;
                sat::BoolVar chosen = cp_model.NewBoolVar().WithName("chosen" + ss.str());
                all_chosen.push_back(chosen);
                all_block_sizes.push_back(blocks[block_id]);
                all_sec_levels.push_back(sec_levels[proc_id]);

                // This assumes descending block order
                ulong block_rank = blocks.size() - block_id;
                all_weighted_sec_levels.push_back((int64_t) std::pow(block_rank, sec_levels[proc_id]));

                sat::IntVar p_time = cp_model.NewConstant(blocks[block_id] * processors[proc_id][block_id]);
                sat::IntVar p_start = cp_model.NewIntVar(domain).WithName("p_start" + ss.str());
                sat::IntVar p_end = cp_model.NewIntVar(domain).WithName("p_end" + ss.str());
                sat::IntervalVar p_interval = cp_model.NewOptionalIntervalVar(p_start, p_time, p_end, chosen).WithName("p_interval" + ss.str());

                all_p_intervals.push_back(p_interval);

                sat::IntVar io_time = cp_model.NewConstant(blocks[block_id] * devices[device_id]);
                sat::IntVar io_start = cp_model.NewIntVar(domain).WithName("io_start" + ss.str());
                sat::IntVar io_end = cp_model.NewIntVar(domain).WithName("io_end" + ss.str());
                sat::IntervalVar io_interval = cp_model.NewOptionalIntervalVar(io_start, io_time, io_end, chosen).WithName("io_interval" + ss.str());

                all_io_ends.push_back(io_end);
                per_device_intervals[device_id].push_back(io_interval);

                all_tasks[proc_id][block_id][device_id] = Task{p_interval, io_interval, blocks[block_id]};
                task_count++;

                /// Precedence constraint
                cp_model.AddGreaterOrEqual(io_start, p_end).OnlyEnforceIf(chosen);
            }
        }
    }

    std::cout << "Finished preparing data" << std::endl;
    std::cout << "\tConsidering " << task_count << " tasks" << std::endl;

    /// Constraints
    cp_model.AddNoOverlap(all_p_intervals);
    for (int device_id = 0; device_id < devices.size(); device_id++)
    {
        cp_model.AddNoOverlap(per_device_intervals[device_id]);
    }

    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_block_sizes), file_size);

    sat::IntVar makespan = cp_model.NewIntVar(domain).WithName("makespan");
    cp_model.AddMaxEquality(makespan, all_io_ends);
    cp_model.AddLessOrEqual(makespan, time_available * 1000000);

    // Just for evaluation purposes
    sat::IntVar overall_security = cp_model.NewIntVar(domain).WithName("overall_security");
    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_sec_levels), overall_security);

    /// Objective
    cp_model.Maximize(makespan);

    sat::IntVar weighted_security = cp_model.NewIntVar(domain).WithName("weighted_security");
    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_weighted_sec_levels), weighted_security);
    cp_model.Maximize(weighted_security);

    sat::IntVar choices = cp_model.NewIntVar({0, task_count}).WithName("choices");
    cp_model.AddEquality(choices, sat::LinearExpr::BooleanSum(all_chosen));
    cp_model.Minimize(choices);

    /// Add time limit constraint in order to find feasible solutions
    sat::Model model;
    sat::SatParameters parameters;
    parameters.set_max_time_in_seconds(20.0);
    model.Add(NewSatParameters(parameters));

    /// Solver
    sat::CpModelProto model_proto = cp_model.Build();
    sat::CpSolverResponse response = sat::SolveCpModel(model_proto, &model);

    std::vector<EncryptTask> result;
    if (response.status() == sat::CpSolverStatus::OPTIMAL || response.status() == sat::CpSolverStatus::FEASIBLE)
    {
        auto mean_sec_level = (double) sat::SolutionIntegerValue(response, overall_security) / sat::SolutionIntegerValue(response, choices);

        std::stringstream processor_tasks;
        for (int proc_id = 0; proc_id < processors.size(); proc_id++)
        {
            for (int device_id = 0; device_id < devices.size(); device_id++)
            {
                std::stringstream chosen_blocks;
                std::stringstream proc_times;
                bool print = false;
                for (int block_id = 0; block_id < blocks.size(); block_id++)
                {
                    if (processors[proc_id][block_id] == 0 || blocks[block_id] > file_size)
                        continue;

                    auto &task = all_tasks[proc_id][block_id][device_id];
                    if (!sat::SolutionBooleanValue(response, task.p_interval.PresenceBoolVar()))
                    {
                        continue;
                    }

                    // start_p, bytes, encryption, device
                    int64 begin = sat::SolutionIntegerValue(response, task.p_interval.StartVar());
                    int64 block_len = task.block_len;
                    std::string cipher_name = cipher_names[proc_id];
                    std::string device_name = device_names[device_id];
                    result.push_back({begin, block_len, cipher_name, device_name});
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

