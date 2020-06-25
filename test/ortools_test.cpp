//
// Created by ISU on 25/06/2020.
//

#include <gtest/gtest.h>

#include <vector>
#include <array>
#include <iostream>

#include <ortools/constraint_solver/constraint_solver.h>
#include <ortools/sat/cp_model.h>
#include <ortools/sat/integer_expr.h>

class OrtoolsFixture : public ::testing::Test
{
protected:

    void SetUp() override
    {
    }

    void TearDown() override
    {
    }

};

TEST_F(OrtoolsFixture, OriginalSatTest)
{
    GTEST_SKIP();
    using namespace operations_research;

    Solver solver("cryptoengine");

    std::array<int, 4> blocks = {1, 2, 3, 4};
    std::array<int, 2> devices = {1, 40};

    using Processor = std::vector<int64>;
    std::vector<Processor> processors = {
            { 13, 8, 5, 5, 5, 5, 5, 5, 5 },
            { 13, 7, 7, 6, 4, 1, 1, 1, 1 }
    };

    // TODO: performance of INF horizon
    int64 horizon = INT64_MAX;

    struct Task {
        IntervalVar * p_interval;
        IntervalVar * io_interval;
        int64 block_len;
    };

    std::vector<IntervalVar*> all_p_intervals;
    std::vector<std::vector<IntervalVar*>> device_tasks(devices.size());
    std::vector<IntervalVar*> all_io_intervals;

    std::vector<std::vector<std::vector<Task>>> all_tasks(processors.size());

    for (int proc_id = 0; proc_id < processors.size(); proc_id++)
    {
        all_tasks[proc_id] = std::vector<std::vector<Task>>(devices.size());
        for (int device_id = 0; device_id < devices.size(); device_id++)
        {
            all_tasks[proc_id][device_id] = std::vector<Task>(blocks.size());
            for (int block_id = 0; block_id < blocks.size(); block_id++)
            {
                std::stringstream ss;
                ss << "_" << block_id << "_" << proc_id << "_" << device_id;
                IntVar *chosen = solver.MakeIntVar(0, 1, "chosen" + ss.str());

                int64 p_time = blocks[block_id] * processors[proc_id][block_id];
                IntVar *p_start = solver.MakeIntVar(0, horizon, "p_start" + ss.str());
                IntervalVar *p_interval = solver.MakeFixedDurationIntervalVar(p_start, p_time, chosen,
                        "p_interval" + ss.str());
                all_p_intervals.push_back(p_interval);

                int64 io_time = blocks[block_id] * devices[device_id];
                IntVar *io_start = solver.MakeIntVar(0, horizon, "io_start" + ss.str());
                IntervalVar *io_interval = solver.MakeFixedDurationIntervalVar(io_start, io_time, chosen,
                        "io_interval" + ss.str());
                device_tasks[device_id].push_back(io_interval);
                all_io_intervals.push_back(io_interval);

                /// Precedence constraint
                solver.AddConstraint(solver.MakeIntervalVarRelation(io_interval, Solver::STARTS_AFTER_END, p_interval));
                all_tasks[proc_id][device_id][block_id] = Task{p_interval, io_interval, blocks[block_id]};
            }
        }
    }

    std::vector<SequenceVar*> p_sequences;
    auto p_no_overlap = solver.MakeDisjunctiveConstraint(all_p_intervals, "no_overlap_p_task");
    solver.AddConstraint(p_no_overlap);
    p_sequences.push_back(p_no_overlap->MakeSequenceVar());

    std::vector<std::vector<SequenceVar*>> io_sequences(devices.size());
    for (int device_id = 0; device_id < devices.size(); device_id++)
    {
        auto no_overlap = solver.MakeDisjunctiveConstraint(device_tasks[device_id], "no_overlap_io_" + std::to_string(device_id));
        solver.AddConstraint(no_overlap);
        io_sequences[device_id].push_back(no_overlap->MakeSequenceVar());
    }

    std::vector<IntVar*> all_ends;
    for (auto &io_interval : all_io_intervals)
    {
        all_ends.push_back(io_interval->EndExpr()->Var());
    }
    IntVar * obj_var = solver.MakeMax(all_ends)->Var();
    OptimizeVar * objective_monitor = solver.MakeMinimize(obj_var, 1);

    std::vector<DecisionBuilder*> all_decisions;
    all_decisions.push_back(solver.MakePhase(p_sequences, Solver::SEQUENCE_DEFAULT));
    for (int device_id = 0; device_id < devices.size(); device_id++)
        all_decisions.push_back(solver.MakePhase(io_sequences[device_id], Solver::SEQUENCE_DEFAULT));
    all_decisions.push_back(solver.MakePhase(obj_var, Solver::CHOOSE_FIRST_UNBOUND, Solver::ASSIGN_MIN_VALUE));
    DecisionBuilder * main_phase = solver.Compose(all_decisions);

    const int kLogFreq = 1000000;
    SearchMonitor * search_log = solver.MakeSearchLog(kLogFreq, objective_monitor);

    SearchLimit * limit = nullptr;

    SolutionCollector * collector = solver.MakeLastSolutionCollector();
    collector->AddObjective(obj_var);
    for (auto &sequence : p_sequences)
    {
        for (int i = 0; i < sequence->size(); i++)
        {
            auto interval = sequence->Interval(i);
            collector->Add(interval);
        }
    }
    for (int device_id = 0; device_id < devices.size(); device_id++)
    {
        for (auto &sequence : io_sequences[device_id])
        {
            for (int i = 0; i < sequence->size(); i++)
            {
                auto interval = sequence->Interval(i);
                collector->Add(interval);
            }
        }
    }

    if (!solver.Solve(main_phase, search_log, objective_monitor, limit, collector))
    {
        std::cerr << "Could not solve" << std::endl;
        FAIL();
    }

    std::cout << "Optimal Schedule Length: " << collector->objective_value(0) << "\n";
    std::stringstream processor_tasks;
    for (int proc_id = 0; proc_id < processors.size(); proc_id++)
    {
        for (int device_id = 0; device_id < devices.size(); device_id++)
        {
            processor_tasks << "Processor " << proc_id << " by " << device_id << " : \n";

            std::stringstream times;
            for (int block_id = 0; block_id < blocks.size(); block_id++)
            {
                auto &task = all_tasks[proc_id][device_id][block_id];
                if (collector->PerformedValue(0, task.p_interval) != 1)
                {
                    continue;
                }

                processor_tasks << "block " << task.block_len << " B | ";

                times << "p: [" << std::setw(10)
                      << collector->Value(0, task.p_interval->StartExpr()->Var()) << ", "
                      << std::setw(10)
                      << collector->Value(0, task.p_interval->EndExpr()->Var()) << "] ";

                times << "io: [" << std::setw(10)
                      << collector->Value(0, task.io_interval->StartExpr()->Var()) << ", "
                      << std::setw(10)
                      << collector->Value(0, task.io_interval->EndExpr()->Var()) << "] | ";
            }
            processor_tasks << "\n" << times.str() << "\n";
        }
    }

    std::cout << processor_tasks.str() << std::endl;
}

TEST_F(OrtoolsFixture, CpModelTest)
{
    const int64 FILE_SIZE = 128;

    using namespace operations_research;

    std::array<int, 9> blocks = { 1, 2, 4, 8, 16, 32, 64, 128};
    std::array<int, 2> devices = { 1, 40 };

    using Processor = std::vector<int64>;
    std::vector<Processor> processors = {
            { 13, 8, 5, 5, 5, 5, 5, 5},
            { 13, 7, 7, 6, 4, 1, 1, 1}
    };

    // TODO: performance of INF horizon
    int64 horizon = INT64_MAX - 1;

    struct Task {
        sat::IntervalVar p_interval;
        sat::IntervalVar io_interval;
        int64 block_len;
    };

    std::size_t num_tasks = processors.size() * devices.size() * blocks.size();
    std::vector<sat::IntervalVar> all_p_intervals;
    std::vector<sat::IntVar> all_io_ends;

    std::vector<std::vector<sat::IntervalVar>> per_device_intervals(devices.size());

    std::vector<std::vector<std::vector<Task>>> all_tasks(processors.size());

    std::vector<sat::BoolVar> all_chosen;
    std::vector<int64> all_block_sizes;

    sat::CpModelBuilder cp_model;
    Domain domain(0, horizon);
    for (int proc_id = 0; proc_id < processors.size(); proc_id++)
    {
        all_tasks[proc_id] = std::vector<std::vector<Task>>(devices.size());
        for (int device_id = 0; device_id < devices.size(); device_id++)
        {
            per_device_intervals[device_id] = std::vector<sat::IntervalVar>();
            all_tasks[proc_id][device_id] = std::vector<Task>(blocks.size());
            for (int block_id = 0; block_id < blocks.size(); block_id++)
            {
                std::stringstream ss;
                ss << "_" << block_id << "_" << proc_id << "_" << device_id;
                sat::BoolVar chosen = cp_model.NewBoolVar().WithName("chosen" + ss.str());
                all_chosen.push_back(chosen);
                all_block_sizes.push_back(blocks[block_id]);

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

                all_tasks[proc_id][device_id][block_id] = Task{p_interval, io_interval, blocks[block_id]};

                /// Precedence constraint
                cp_model.AddGreaterOrEqual(io_start, p_end).OnlyEnforceIf(chosen);
            }
        }
    }

    cp_model.AddNoOverlap(absl::Span<sat::IntervalVar>(all_p_intervals));

    for (int device_id = 0; device_id < devices.size(); device_id++)
    {
        cp_model.AddNoOverlap(absl::Span<sat::IntervalVar>(per_device_intervals[device_id]));
    }

    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(absl::Span<sat::BoolVar>(all_chosen), absl::Span<int64>(all_block_sizes)), FILE_SIZE);

    sat::IntVar obj_var = cp_model.NewIntVar(domain).WithName("makespan");
    cp_model.AddMaxEquality(obj_var, all_io_ends);
    cp_model.Minimize(obj_var);

    sat::CpModelProto model_proto = cp_model.Build();
    sat::CpSolverResponse response = sat::Solve(model_proto);
    std::cout << sat::CpSolverResponseStats(response) << std::endl;

    if (response.status() == sat::CpSolverStatus::OPTIMAL)
    {
        std::cout << "Optimal Schedule Length: " << sat::SolutionIntegerValue(response, obj_var) << "\n";
        std::stringstream processor_tasks;
        for (int proc_id = 0; proc_id < processors.size(); proc_id++)
        {
            for (int device_id = 0; device_id < devices.size(); device_id++)
            {
                processor_tasks << "Processor " << proc_id << " by " << device_id << " : \n";

                std::stringstream processor_times;
                for (int block_id = 0; block_id < blocks.size(); block_id++)
                {
                    auto &task = all_tasks[proc_id][device_id][block_id];
                    if (!sat::SolutionBooleanValue(response, task.p_interval.PresenceBoolVar()))
                    {
                        continue;
                    }

                    processor_tasks << std::setw(-30) << "block " << task.block_len << " B | ";

                    std::stringstream times;
                    times << "p: ["
                          << sat::SolutionIntegerValue(response, task.p_interval.StartVar()) << ", "
                          << sat::SolutionIntegerValue(response, task.p_interval.EndVar()) << "] ";

                    times << "io: ["
                          << sat::SolutionIntegerValue(response, task.io_interval.StartVar()) << ", "
                          << sat::SolutionIntegerValue(response, task.io_interval.EndVar()) << "] | ";

                    processor_times <<  std::setw(-30) << times.str();
                }
                processor_tasks << "\n" << processor_times.str() << "\n";
            }
        }


        std::cout << processor_tasks.str() << std::endl;

        SUCCEED();
        return;
    }

    FAIL();
}