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
    const int64 FILE_SIZE = 500000;
    const int SEC_LEVEL = 1;

    using namespace operations_research;

    std::vector<int64> blocks = {1, 8, 64, 512, 4096, 32768, 262144, 16777216 };
    std::vector<int> devices = { 1, 40};

    std::vector<std::string> cipher_names = {"botan-CAMELLIA-128-XTS", "botan-CAMELLIA-192-XTS", "botan-CAMELLIA-256-XTS", "cryptopp-AES-128-CBC", "cryptopp-AES-128-CBC", "cryptopp-AES-128-CFB", "cryptopp-AES-128-CFB", "cryptopp-AES-128-CTR", "cryptopp-AES-128-CTR", "cryptopp-AES-128-ECB", "cryptopp-AES-192-CBC", "cryptopp-AES-192-CBC", "cryptopp-AES-192-CFB", "cryptopp-AES-192-CTR", "cryptopp-AES-192-CTR", "cryptopp-AES-192-CTR", "cryptopp-AES-192-ECB", "cryptopp-AES-256-CBC", "cryptopp-AES-256-CBC", "cryptopp-AES-256-CFB", "cryptopp-AES-256-CTR", "cryptopp-AES-256-CTR", "cryptopp-AES-256-CTR", "cryptopp-AES-256-ECB", "cryptopp-AES-256-ECB", "cryptopp-AES-256-OFB", "cryptopp-ARIA-128-CBC", "cryptopp-ARIA-128-CBC", "cryptopp-ARIA-128-CBC", "cryptopp-ARIA-128-CFB", "cryptopp-ARIA-128-CFB", "cryptopp-ARIA-128-CFB", "cryptopp-ARIA-128-CTR", "cryptopp-ARIA-128-CTR", "cryptopp-ARIA-128-CTR", "cryptopp-ARIA-128-ECB", "cryptopp-ARIA-128-OFB", "cryptopp-ARIA-128-OFB", "cryptopp-ARIA-128-OFB", "cryptopp-ARIA-192-CFB", "cryptopp-ARIA-192-CFB", "cryptopp-ARIA-192-CFB", "cryptopp-ARIA-192-CTR", "cryptopp-ARIA-192-CTR", "cryptopp-ARIA-192-CTR", "cryptopp-ARIA-192-OFB", "cryptopp-ARIA-192-OFB", "cryptopp-ARIA-192-OFB", "cryptopp-ARIA-256-CFB", "cryptopp-ARIA-256-CFB", "cryptopp-ARIA-256-CFB", "cryptopp-ARIA-256-CFB", "cryptopp-ARIA-256-CTR", "cryptopp-ARIA-256-CTR", "cryptopp-ARIA-256-CTR", "cryptopp-ARIA-256-CTR", "cryptopp-ARIA-256-OFB", "cryptopp-ARIA-256-OFB", "cryptopp-ARIA-256-OFB", "cryptopp-ARIA-256-OFB", "cryptopp-CAMELLIA-128-CBC", "cryptopp-CAMELLIA-128-CBC", "cryptopp-CAMELLIA-128-CBC", "cryptopp-CAMELLIA-192-CBC", "cryptopp-CAMELLIA-192-CBC", "cryptopp-CAMELLIA-192-CBC", "cryptopp-CAMELLIA-192-OFB", "cryptopp-CAMELLIA-256-CBC", "gcrypt-AES-128-CFB", "gcrypt-AES-128-CFB", "gcrypt-AES-128-CTR", "gcrypt-AES-128-CTR", "gcrypt-AES-192-CFB", "gcrypt-AES-192-CFB", "gcrypt-AES-192-CFB", "gcrypt-AES-192-CTR", "gcrypt-AES-192-CTR", "gcrypt-AES-192-CTR", "gcrypt-AES-256-CFB", "gcrypt-AES-256-CTR", "gcrypt-AES-256-CTR", "gcrypt-AES-256-CTR", "gcrypt-CAMELLIA-128-CTR", "gcrypt-CAMELLIA-192-CFB", "gcrypt-CAMELLIA-192-CTR", "gcrypt-CAMELLIA-192-CTR", "gcrypt-CAMELLIA-256-CTR", "gcrypt-CAMELLIA-256-CTR", "openssl-AES-128-CBC", "openssl-AES-128-CBC", "openssl-AES-128-CFB", "openssl-AES-128-CFB", "openssl-AES-128-CTR", "openssl-AES-128-CTR", "openssl-AES-128-ECB", "openssl-AES-128-OFB", "openssl-AES-128-OFB", "openssl-AES-128-XTS", "openssl-AES-128-XTS", "openssl-AES-128-XTS", "openssl-AES-128-XTS", "openssl-AES-192-CBC", "openssl-AES-192-CBC", "openssl-AES-192-CBC", "openssl-AES-192-CFB", "openssl-AES-192-CFB", "openssl-AES-192-CFB", "openssl-AES-192-CTR", "openssl-AES-192-CTR", "openssl-AES-192-CTR", "openssl-AES-192-ECB", "openssl-AES-192-OFB", "openssl-AES-192-OFB", "openssl-AES-192-OFB", "openssl-AES-256-CBC", "openssl-AES-256-CBC", "openssl-AES-256-CBC", "openssl-AES-256-CFB", "openssl-AES-256-CFB", "openssl-AES-256-CFB", "openssl-AES-256-CTR", "openssl-AES-256-CTR", "openssl-AES-256-CTR", "openssl-AES-256-ECB", "openssl-AES-256-ECB", "openssl-AES-256-OFB", "openssl-AES-256-OFB", "openssl-AES-256-OFB", "openssl-AES-256-XTS", "openssl-AES-256-XTS", "openssl-AES-256-XTS", "openssl-AES-256-XTS", "openssl-ARIA-128-CFB", "openssl-ARIA-128-CFB", "openssl-ARIA-128-CFB", "openssl-ARIA-192-CFB", "openssl-ARIA-192-CFB", "openssl-ARIA-192-CFB", "openssl-ARIA-192-ECB", "openssl-ARIA-192-ECB", "openssl-ARIA-256-CBC", "openssl-ARIA-256-CBC", "openssl-ARIA-256-CBC", "openssl-ARIA-256-CBC", "openssl-ARIA-256-CFB", "openssl-ARIA-256-CFB", "openssl-ARIA-256-CFB", "openssl-ARIA-256-CTR", "openssl-ARIA-256-CTR", "openssl-ARIA-256-CTR", "openssl-ARIA-256-OFB", "openssl-SEED-128-CBC", "openssl-SEED-128-CBC", "openssl-SEED-128-CBC", "openssl-SEED-128-CFB", "wolfcrypt-AES-128-CTR", "wolfcrypt-AES-128-CTR", "wolfcrypt-AES-192-CTR", "wolfcrypt-AES-192-CTR", "wolfcrypt-AES-192-CTR", "wolfcrypt-AES-256-CTR", "wolfcrypt-AES-256-CTR", "wolfcrypt-AES-256-CTR" };

    std::vector<int> sec_levels = {5, 5, 5, 1, 2, 1, 2, 1, 2, 1, 2, 3, 3, 1, 2, 3, 1, 2, 3, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 1, 2, 3, 4, 4, 1, 2, 1, 2, 1, 2, 3, 1, 2, 3, 3, 1, 2, 3, 3, 4, 3, 4, 3, 4, 1, 2, 1, 2, 1, 2, 1, 1, 2, 1, 2, 3, 4, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 1, 2, 3, 1, 2, 3, 4, 1, 2, 3, 1, 2, 3, 1, 2, 1, 2, 3, 4, 1, 2, 3, 1, 2, 3, 4, 1, 2, 3, 2, 1, 2, 1, 2, 3, 1, 2, 3 };

    using Processor = std::vector<int64>;
    std::vector<Processor> processors = {
            {0, 0, 115799963541, 0, 0, 296405090, 0, 59731560 },
            {0, 0, 0, 15156259114, 1829022867, 0, 0, 0 },
            {0, 0, 0, 0, 0, 0, 96325098, 0 },
            {0, 0, 0, 0, 0, 0, 18454058, 2956596 },
            {0, 0, 0, 0, 0, 0, 18454058, 2956596 },
            {0, 0, 0, 0, 0, 0, 17064530, 3150268 },
            {0, 0, 0, 0, 0, 0, 17064530, 3150268 },
            {0, 0, 0, 0, 0, 0, 15904747, 1609633 },
            {0, 0, 0, 0, 0, 0, 15904747, 1609633 },
            {0, 0, 0, 0, 0, 0, 16644607, 1679524 },
            {0, 0, 0, 0, 0, 0, 22061453, 3527481 },
            {0, 0, 0, 0, 0, 0, 22061453, 3527481 },
            {0, 0, 0, 0, 0, 0, 20222979, 4618006 },
            {0, 0, 0, 0, 0, 0, 19420494, 1756688 },
            {0, 0, 0, 0, 0, 0, 19420494, 1756688 },
            {0, 0, 0, 0, 0, 0, 19420494, 1756688 },
            {0, 0, 0, 0, 0, 0, 0, 1977176 },
            {0, 0, 0, 0, 0, 0, 20947615, 3730304 },
            {0, 0, 0, 0, 0, 0, 20947615, 3730304 },
            {0, 0, 0, 0, 0, 0, 21640946, 4450674 },
            {0, 0, 0, 0, 0, 0, 19785268, 1953337 },
            {0, 0, 0, 0, 0, 0, 19785268, 1953337 },
            {0, 0, 0, 0, 0, 0, 19785268, 1953337 },
            {0, 0, 0, 0, 0, 0, 0, 1844867 },
            {0, 0, 0, 0, 0, 0, 0, 1844867 },
            {0, 0, 0, 0, 0, 0, 22843227, 0 },
            {0, 310258083333, 0, 0, 0, 0, 0, 0 },
            {0, 310258083333, 0, 0, 0, 0, 0, 0 },
            {0, 310258083333, 0, 0, 0, 0, 0, 0 },
            {2340359333333, 293983583333, 37044380208, 4694729817, 586254069, 97930674, 0, 0 },
            {2340359333333, 293983583333, 37044380208, 4694729817, 586254069, 97930674, 0, 0 },
            {2340359333333, 293983583333, 37044380208, 4694729817, 586254069, 97930674, 0, 0 },
            {2373356333333, 286479958333, 35805661458, 0, 612327311, 98889892, 0, 0 },
            {2373356333333, 286479958333, 35805661458, 0, 612327311, 98889892, 0, 0 },
            {2373356333333, 286479958333, 35805661458, 0, 612327311, 98889892, 0, 0 },
            {2485250000000, 297832458333, 36909083333, 0, 0, 0, 0, 0 },
            {2404719333333, 280296666666, 35395390625, 4487514973, 587487792, 94764455, 0, 0 },
            {2404719333333, 280296666666, 35395390625, 4487514973, 587487792, 94764455, 0, 0 },
            {2404719333333, 280296666666, 35395390625, 4487514973, 587487792, 94764455, 0, 0 },
            {0, 295673125000, 36339171875, 4562270182, 590669270, 97362294, 0, 0 },
            {0, 295673125000, 36339171875, 4562270182, 590669270, 97362294, 0, 0 },
            {0, 295673125000, 36339171875, 4562270182, 590669270, 97362294, 0, 0 },
            {2293082666666, 292039166666, 35461088541, 4532985026, 599193522, 95600545, 0, 0 },
            {2293082666666, 292039166666, 35461088541, 4532985026, 599193522, 95600545, 0, 0 },
            {2293082666666, 292039166666, 35461088541, 4532985026, 599193522, 95600545, 0, 0 },
            {2345911333333, 292887708333, 34881968750, 4352496744, 584506998, 0, 0, 0 },
            {2345911333333, 292887708333, 34881968750, 4352496744, 584506998, 0, 0, 0 },
            {2345911333333, 292887708333, 34881968750, 4352496744, 584506998, 0, 0, 0 },
            {2248630333333, 288783083333, 37265359375, 4695324218, 604588460, 95425018, 32188275, 0 },
            {2248630333333, 288783083333, 37265359375, 4695324218, 604588460, 95425018, 32188275, 0 },
            {2248630333333, 288783083333, 37265359375, 4695324218, 604588460, 95425018, 32188275, 0 },
            {2248630333333, 288783083333, 37265359375, 4695324218, 604588460, 95425018, 32188275, 0 },
            {2232288666666, 282065291666, 35506041666, 4556270182, 599900227, 99340861, 0, 0 },
            {2232288666666, 282065291666, 35506041666, 4556270182, 599900227, 99340861, 0, 0 },
            {2232288666666, 282065291666, 35506041666, 4556270182, 599900227, 99340861, 0, 0 },
            {2232288666666, 282065291666, 35506041666, 4556270182, 599900227, 99340861, 0, 0 },
            {2196793666666, 288329916666, 36248713541, 4612059895, 598551269, 0, 0, 0 },
            {2196793666666, 288329916666, 36248713541, 4612059895, 598551269, 0, 0, 0 },
            {2196793666666, 288329916666, 36248713541, 4612059895, 598551269, 0, 0, 0 },
            {2196793666666, 288329916666, 36248713541, 4612059895, 598551269, 0, 0, 0 },
            {2472843666666, 0, 38458625000, 0, 645124186, 99213887, 0, 0 },
            {2472843666666, 0, 38458625000, 0, 645124186, 99213887, 0, 0 },
            {2472843666666, 0, 38458625000, 0, 645124186, 99213887, 0, 0 },
            {0, 0, 0, 4849887369, 0, 0, 0, 0 },
            {0, 0, 0, 4849887369, 0, 0, 0, 0 },
            {0, 0, 0, 4849887369, 0, 0, 0, 0 },
            {0, 0, 0, 0, 0, 0, 31384869, 0 },
            {0, 0, 0, 0, 0, 0, 31921424, 0 },
            {0, 0, 0, 0, 0, 0, 0, 3162744 },
            {0, 0, 0, 0, 0, 0, 0, 3162744 },
            {0, 0, 0, 0, 0, 0, 0, 1907627 },
            {0, 0, 0, 0, 0, 0, 0, 1907627 },
            {0, 0, 0, 0, 0, 0, 0, 3485006 },
            {0, 0, 0, 0, 0, 0, 0, 3485006 },
            {0, 0, 0, 0, 0, 0, 0, 3485006 },
            {0, 0, 0, 0, 0, 0, 0, 2063934 },
            {0, 0, 0, 0, 0, 0, 0, 2063934 },
            {0, 0, 0, 0, 0, 0, 0, 2063934 },
            {0, 0, 0, 0, 0, 0, 0, 3864605 },
            {0, 0, 0, 0, 0, 0, 0, 2139195 },
            {0, 0, 0, 0, 0, 0, 0, 2139195 },
            {0, 0, 0, 0, 0, 0, 0, 2139195 },
            {0, 0, 0, 0, 0, 0, 0, 4046003 },
            {0, 0, 0, 0, 0, 0, 0, 12338333 },
            {0, 0, 0, 0, 0, 0, 0, 4829871 },
            {0, 0, 0, 0, 0, 0, 0, 4829871 },
            {0, 0, 0, 0, 0, 0, 0, 4969530 },
            {0, 0, 0, 0, 0, 0, 0, 4969530 },
            {2492034000000, 0, 0, 4730158854, 613864501, 77046203, 12796712, 2698915 },
            {2492034000000, 0, 0, 4730158854, 613864501, 77046203, 12796712, 2698915 },
            {2499171666666, 0, 0, 4801513020, 611127848, 88080098, 14959545, 0 },
            {2499171666666, 0, 0, 4801513020, 611127848, 88080098, 14959545, 0 },
            {0, 0, 0, 0, 0, 90488413, 12644320, 1442652 },
            {0, 0, 0, 0, 0, 90488413, 12644320, 1442652 },
            {0, 0, 38001614583, 0, 624293619, 76956542, 11384188, 1450764 },
            {0, 0, 0, 0, 0, 0, 16457644, 0 },
            {0, 0, 0, 0, 0, 0, 16457644, 0 },
            {0, 0, 31929463541, 4067502604, 504592285, 67008992, 10010742, 1503233 },
            {0, 0, 31929463541, 4067502604, 504592285, 67008992, 10010742, 1503233 },
            {0, 0, 31929463541, 4067502604, 504592285, 67008992, 10010742, 1503233 },
            {0, 0, 31929463541, 4067502604, 504592285, 67008992, 10010742, 1503233 },
            {2431504000000, 304960625000, 37560223958, 4787705729, 606080159, 80735758, 13991537, 3007328 },
            {2431504000000, 304960625000, 37560223958, 4787705729, 606080159, 80735758, 13991537, 3007328 },
            {2431504000000, 304960625000, 37560223958, 4787705729, 606080159, 80735758, 13991537, 3007328 },
            {2351602333333, 310263083333, 37491109375, 4820486328, 587285563, 83136220, 15314806, 0 },
            {2351602333333, 310263083333, 37491109375, 4820486328, 587285563, 83136220, 15314806, 0 },
            {2351602333333, 310263083333, 37491109375, 4820486328, 587285563, 83136220, 15314806, 0 },
            {0, 0, 0, 0, 0, 94239196, 13656906, 1526331 },
            {0, 0, 0, 0, 0, 94239196, 13656906, 1526331 },
            {0, 0, 0, 0, 0, 94239196, 13656906, 1526331 },
            {2399210666666, 0, 38299395833, 4784111979, 574796549, 77293599, 11260403, 1545353 },
            {0, 0, 0, 0, 0, 97777628, 17667816, 0 },
            {0, 0, 0, 0, 0, 97777628, 17667816, 0 },
            {0, 0, 0, 0, 0, 97777628, 17667816, 0 },
            {2447593000000, 295963500000, 38020822916, 4667077473, 596401123, 79633219, 13544932, 3562047 },
            {2447593000000, 295963500000, 38020822916, 4667077473, 596401123, 79633219, 13544932, 3562047 },
            {2447593000000, 295963500000, 38020822916, 4667077473, 596401123, 79633219, 13544932, 3562047 },
            {2502513333333, 299168416666, 38298916666, 4841250000, 594397542, 82947855, 16692353, 0 },
            {2502513333333, 299168416666, 38298916666, 4841250000, 594397542, 82947855, 16692353, 0 },
            {2502513333333, 299168416666, 38298916666, 4841250000, 594397542, 82947855, 16692353, 0 },
            {0, 0, 0, 0, 0, 87985168, 13110759, 1815380 },
            {0, 0, 0, 0, 0, 87985168, 13110759, 1815380 },
            {0, 0, 0, 0, 0, 87985168, 13110759, 1815380 },
            {2423898666666, 305697833333, 0, 0, 608670247, 78092458, 11524486, 1596154 },
            {2423898666666, 305697833333, 0, 0, 608670247, 78092458, 11524486, 1596154 },
            {0, 0, 0, 0, 0, 97637145, 18254603, 0 },
            {0, 0, 0, 0, 0, 97637145, 18254603, 0 },
            {0, 0, 0, 0, 0, 97637145, 18254603, 0 },
            {0, 0, 32891526041, 4248789062, 508409830, 67513458, 10544682, 1655172 },
            {0, 0, 32891526041, 4248789062, 508409830, 67513458, 10544682, 1655172 },
            {0, 0, 32891526041, 4248789062, 508409830, 67513458, 10544682, 1655172 },
            {0, 0, 32891526041, 4248789062, 508409830, 67513458, 10544682, 1655172 },
            {2422190000000, 0, 0, 0, 0, 0, 0, 0 },
            {2422190000000, 0, 0, 0, 0, 0, 0, 0 },
            {2422190000000, 0, 0, 0, 0, 0, 0, 0 },
            {0, 0, 38486812500, 4804779947, 0, 0, 0, 0 },
            {0, 0, 38486812500, 4804779947, 0, 0, 0, 0 },
            {0, 0, 38486812500, 4804779947, 0, 0, 0, 0 },
            {0, 305286458333, 0, 0, 0, 0, 0, 0 },
            {0, 305286458333, 0, 0, 0, 0, 0, 0 },
            {2440834333333, 308382750000, 0, 0, 0, 0, 0, 0 },
            {2440834333333, 308382750000, 0, 0, 0, 0, 0, 0 },
            {2440834333333, 308382750000, 0, 0, 0, 0, 0, 0 },
            {2440834333333, 308382750000, 0, 0, 0, 0, 0, 0 },
            {2475329666666, 0, 0, 0, 0, 0, 0, 0 },
            {2475329666666, 0, 0, 0, 0, 0, 0, 0 },
            {2475329666666, 0, 0, 0, 0, 0, 0, 0 },
            {0, 310408125000, 0, 0, 0, 0, 0, 0 },
            {0, 310408125000, 0, 0, 0, 0, 0, 0 },
            {0, 310408125000, 0, 0, 0, 0, 0, 0 },
            {0, 0, 0, 0, 0, 100893981, 0, 0 },
            {0, 0, 38879906250, 4822289713, 630934895, 0, 0, 0 },
            {0, 0, 38879906250, 4822289713, 630934895, 0, 0, 0 },
            {0, 0, 38879906250, 4822289713, 630934895, 0, 0, 0 },
            {0, 0, 38581239583, 0, 0, 0, 0, 0 },
            {1183328666666, 147389166666, 18271401041, 2230108072, 279479329, 42502827, 11955268, 0 },
            {1183328666666, 147389166666, 18271401041, 2230108072, 279479329, 42502827, 11955268, 0 },
            {1156343666666, 146651500000, 17934536458, 2260590494, 298894449, 48507446, 10610158, 0 },
            {1156343666666, 146651500000, 17934536458, 2260590494, 298894449, 48507446, 10610158, 0 },
            {1156343666666, 146651500000, 17934536458, 2260590494, 298894449, 48507446, 10610158, 0 },
            {1136255666666, 139081166666, 18541651041, 2331464843, 297151855, 45887410, 12434319, 0 },
            {1136255666666, 139081166666, 18541651041, 2331464843, 297151855, 45887410, 12434319, 0 },
            {1136255666666, 139081166666, 18541651041, 2331464843, 297151855, 45887410, 12434319, 0 }
    };

    // TODO: performance of INF horizon
    int64 horizon = INT64_MAX - 1;

    struct Task {
        sat::IntervalVar p_interval;
        sat::IntervalVar io_interval;
        int64 block_len;
    };

    std::vector<sat::IntervalVar> all_p_intervals;
    std::vector<sat::IntVar> all_io_ends;

    std::vector<std::vector<sat::IntervalVar>> per_device_intervals(devices.size());

    std::vector<std::vector<std::vector<Task>>> all_tasks(processors.size());
    long task_count = 0;

    std::vector<sat::BoolVar> all_chosen;
    std::vector<int64> all_block_sizes;

    sat::CpModelBuilder cp_model;
    Domain domain(0, horizon);
    for (int proc_id = 0; proc_id < processors.size(); proc_id++)
    {
        if (sec_levels[proc_id] != SEC_LEVEL)
            continue;

        all_tasks[proc_id] = std::vector<std::vector<Task>>(blocks.size());
        for (int block_id = 0; block_id < blocks.size(); block_id++)
        {
            if (processors[proc_id][block_id] == 0 || blocks[block_id] > FILE_SIZE)
                continue;
            all_tasks[proc_id][block_id] = std::vector<Task>(devices.size());
            for (int device_id = 0; device_id < devices.size(); device_id++)
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

    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_block_sizes), FILE_SIZE);

    /// Objective
    sat::IntVar obj_var = cp_model.NewIntVar(domain).WithName("makespan");
    cp_model.AddMaxEquality(obj_var, all_io_ends);
    cp_model.Minimize(obj_var);


    /// Add time limit constraint in order to find feasible solutions
    sat::Model model;
    sat::SatParameters parameters;
    parameters.set_max_time_in_seconds(10.0);
    model.Add(NewSatParameters(parameters));


    /// Solver
    sat::CpModelProto model_proto = cp_model.Build();
    sat::CpSolverResponse response = sat::SolveCpModel(model_proto, &model);
    std::cout << sat::CpSolverResponseStats(response) << std::endl;

    if (response.status() == sat::CpSolverStatus::OPTIMAL || response.status() == sat::CpSolverStatus::FEASIBLE)
    {
        std::cout << "Optimal Schedule Length: " << sat::SolutionIntegerValue(response, obj_var) << "\n";
        std::stringstream processor_tasks;
        for (int proc_id = 0; proc_id < processors.size(); proc_id++)
        {
            if (sec_levels[proc_id] != SEC_LEVEL)
                continue;

            for (int device_id = 0; device_id < devices.size(); device_id++)
            {
                std::stringstream chosen_blocks;
                std::stringstream proc_times;
                bool print = false;
                for (int block_id = 0; block_id < blocks.size(); block_id++)
                {
                    if (processors[proc_id][block_id] == 0 || blocks[block_id] > FILE_SIZE)
                        continue;

                    auto &task = all_tasks[proc_id][block_id][device_id];
                    if (!sat::SolutionBooleanValue(response, task.p_interval.PresenceBoolVar()))
                    {
                        continue;
                    }
                    print = true;

                    std::string blstr = "block " + std::to_string(task.block_len) + " B";
                    chosen_blocks << std::setw(-30) << blstr;

                    std::stringstream times;
                    times << "p: ["
                          << sat::SolutionIntegerValue(response, task.p_interval.StartVar()) << ", "
                          << sat::SolutionIntegerValue(response, task.p_interval.EndVar()) << "] ";

                    times << "io: ["
                          << sat::SolutionIntegerValue(response, task.io_interval.StartVar()) << ", "
                          << sat::SolutionIntegerValue(response, task.io_interval.EndVar()) << "]";

                    proc_times <<  std::setw(-30) << times.str();
                }
                if (print)
                {
                    processor_tasks << "Processor " << cipher_names[proc_id] << " by " << device_id << " : \n";
                    processor_tasks << chosen_blocks.str() << "\n" << proc_times.str() << "\n";
                }
            }
        }


        std::cout << processor_tasks.str() << std::endl;

        SUCCEED();
        return;
    }

    FAIL();
}